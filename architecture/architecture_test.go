package architecture_test

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const modulePath = "gosuda.org/ivnp"

type listedPackage struct {
	ImportPath string
	Imports    []string
}

func TestImportLayersAreAcyclic(t *testing.T) {
	command := exec.Command("go", "list", "-test", "-json", "./...")
	command.Dir = ".."
	output, err := command.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list failed: %v\n%s", err, exit.Stderr)
		}
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	var violations []string
	for decoder.More() {
		var pkg listedPackage
		if err := decoder.Decode(&pkg); err != nil {
			t.Fatal(err)
		}
		importer := canonicalPackage(pkg.ImportPath)
		if strings.HasSuffix(importer, ".test") {
			continue
		}
		importerLayer, internal := packageLayer(importer)
		if !internal {
			continue
		}
		for _, imported := range pkg.Imports {
			if violation := importViolation(importer, importerLayer, imported); violation != "" {
				violations = append(violations, violation)
			}
		}
	}
	if len(violations) != 0 {
		sort.Strings(violations)
		t.Fatalf("upward IVNP imports:\n%s", strings.Join(violations, "\n"))
	}
}

func importViolation(importer string, importerLayer int, imported string) string {
	importedLayer, internalImport := packageLayer(imported)
	if !internalImport {
		return ""
	}
	if belongsToSubsystem(imported, "networking") {
		return fmt.Sprintf("%s imports retired networking boundary %s", importer, imported)
	}
	if importedLayer > importerLayer {
		return fmt.Sprintf("%s (L%d) imports %s (L%d)", importer, importerLayer, imported, importedLayer)
	}
	if belongsToSubsystem(importer, "dataplane") && belongsToSubsystem(imported, "state") {
		return fmt.Sprintf("%s imports persistent control state %s", importer, imported)
	}
	if owner := subsystemInternalOwner(imported); owner != "" && !belongsToSubsystem(importer, owner) {
		return fmt.Sprintf("%s bypasses %s subsystem root via %s", importer, owner, imported)
	}
	return ""
}

func belongsToSubsystem(path, subsystem string) bool {
	root := modulePath + "/" + subsystem
	return path == root || strings.HasPrefix(path, root+"/")
}

func TestPublicImportsUseCanonicalPathsWithoutAliases(t *testing.T) {
	canonical := map[string]bool{
		modulePath:                             true,
		modulePath + "/foundation":             true,
		modulePath + "/cryptography":           true,
		modulePath + "/controlplane":           true,
		modulePath + "/dataplane":              true,
		modulePath + "/client":                 true,
		modulePath + "/state":                  true,
		modulePath + "/observability":          true,
		modulePath + "/node":                   true,
		modulePath + "/interfaces/stream":      true,
		modulePath + "/interfaces/destination": true,
	}
	err := filepath.Walk("..", func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, spec := range file.Imports {
			importPath := strings.Trim(spec.Path.Value, `"`)
			if importPath == modulePath+"/ivnp" {
				t.Errorf("%s imports forbidden nested facade %q; use %q", path, importPath, modulePath)
			}
			if canonical[importPath] && spec.Name != nil {
				t.Errorf("%s aliases canonical import %q as %q", path, importPath, spec.Name.Name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnsafeImportsAreRestrictedAndABIStructsUseHostLayout(t *testing.T) {
	allowedUnsafeFiles := map[string]bool{
		"dataplane/internal/transport/ssu2/batch_linux_vector.go": false,
		"state/internal/filesystem_store/secure_windows.go":       false,
	}
	err := filepath.Walk("..", func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, "../"))
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		importsUnsafe := false
		for _, spec := range file.Imports {
			if strings.Trim(spec.Path.Value, `"`) == "unsafe" {
				importsUnsafe = true
				break
			}
		}
		if !importsUnsafe {
			return nil
		}
		if _, allowed := allowedUnsafeFiles[rel]; !allowed {
			t.Errorf("%s imports \"unsafe\" outside the architecture allowlist", rel)
			return nil
		}
		allowedUnsafeFiles[rel] = true
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok || !isFixedABIStructCandidate(structType) {
					continue
				}
				if !hasLeadingHostLayoutField(structType) {
					t.Errorf("%s: struct %s in unsafe file must embed structs.HostLayout as its first field", rel, typeSpec.Name.Name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel, seen := range allowedUnsafeFiles {
		if !seen {
			t.Errorf("stale unsafe allowlist entry %s (file missing or no longer imports unsafe)", rel)
		}
	}
}

func isFixedABIStructCandidate(structType *ast.StructType) bool {
	if structType.Fields == nil || len(structType.Fields.List) == 0 {
		return false
	}
	for _, field := range structType.Fields.List {
		switch fieldType := field.Type.(type) {
		case *ast.ArrayType:
			if fieldType.Len == nil {
				return false
			}
		case *ast.MapType, *ast.ChanType, *ast.FuncType, *ast.InterfaceType:
			return false
		case *ast.Ident:
			if fieldType.Name == "string" || fieldType.Name == "error" || fieldType.Name == "any" {
				return false
			}
		}
	}
	return true
}

func hasLeadingHostLayoutField(structType *ast.StructType) bool {
	if structType.Fields == nil || len(structType.Fields.List) == 0 {
		return false
	}
	sel, ok := structType.Fields.List[0].Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	return ok && pkgIdent.Name == "structs" && sel.Sel.Name == "HostLayout"
}

func subsystemInternalOwner(path string) string {
	for _, subsystem := range []string{"cryptography", "foundation", "controlplane", "dataplane", "client", "state", "observability", "node"} {
		if strings.HasPrefix(path, modulePath+"/"+subsystem+"/internal/") {
			return subsystem
		}
	}
	return ""
}

func canonicalPackage(path string) string {
	path, _, _ = strings.Cut(path, " ")
	return strings.TrimSuffix(path, "_test")
}

func packageLayer(path string) (int, bool) {
	if path != modulePath && !strings.HasPrefix(path, modulePath+"/") {
		return 0, false
	}
	relative := strings.TrimPrefix(path, modulePath+"/")
	switch {
	case strings.HasPrefix(relative, "cmd/"), strings.HasPrefix(relative, "integration/"), strings.HasPrefix(relative, "tests/integration/"):
		return 9, true
	case path == modulePath:
		return 8, true
	case relative == "node", strings.HasPrefix(relative, "node/"):
		return 7, true
	case relative == "client", strings.HasPrefix(relative, "client/"):
		return 6, true
	case relative == "controlplane", strings.HasPrefix(relative, "controlplane/"):
		return 5, true
	case relative == "dataplane", strings.HasPrefix(relative, "dataplane/"):
		return 4, true
	case relative == "interfaces", strings.HasPrefix(relative, "interfaces/"),
		relative == "state", strings.HasPrefix(relative, "state/"):
		return 3, true
	case relative == "foundation", strings.HasPrefix(relative, "foundation/"),
		relative == "observability", strings.HasPrefix(relative, "observability/"):
		return 2, true
	case relative == "cryptography", strings.HasPrefix(relative, "cryptography/"):
		return 1, true
	case strings.HasPrefix(relative, "internal/"):
		return 0, true
	default:
		return 0, true
	}
}
