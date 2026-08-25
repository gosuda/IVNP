package architecture_test

import (
	"encoding/json"
	"fmt"
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
			importedLayer, internalImport := packageLayer(imported)
			if internalImport && importedLayer > importerLayer {
				violations = append(violations, fmt.Sprintf("%s (L%d) imports %s (L%d)", importer, importerLayer, imported, importedLayer))
			}
			if owner := subsystemInternalOwner(imported); owner != "" && !strings.HasPrefix(importer, modulePath+"/"+owner) {
				violations = append(violations, fmt.Sprintf("%s bypasses %s subsystem root via %s", importer, owner, imported))
			}
		}
	}
	if len(violations) != 0 {
		sort.Strings(violations)
		t.Fatalf("upward IVNP imports:\n%s", strings.Join(violations, "\n"))
	}
}

func TestSubsystemFacadeFilesExist(t *testing.T) {
	for _, path := range []string{
		"../foundation/foundation_subsystem.go",
		"../cryptography/cryptography_subsystem.go",
		"../networking/networking_subsystem.go",
		"../client/client_subsystem.go",
		"../state/state_subsystem.go",
		"../observability/observability_subsystem.go",
		"../node/node_subsystem.go",
	} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing subsystem facade %s: %v", path, err)
		}
	}
}

func TestPublicImportsUseCanonicalPathsWithoutAliases(t *testing.T) {
	canonical := map[string]bool{
		modulePath + "/ivnp":                   true,
		modulePath + "/foundation":             true,
		modulePath + "/cryptography":           true,
		modulePath + "/networking":             true,
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
			if importPath == modulePath {
				t.Errorf("%s imports forbidden module root %q; use %q", path, importPath, modulePath+"/ivnp")
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

func subsystemInternalOwner(path string) string {
	for _, subsystem := range []string{"cryptography", "foundation", "networking", "client", "state", "observability", "node"} {
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
	case strings.HasPrefix(relative, "command/"), strings.HasPrefix(relative, "integration/"):
		return 9, true
	case relative == "ivnp":
		return 8, true
	case relative == "node", strings.HasPrefix(relative, "node/"):
		return 7, true
	case relative == "client", strings.HasPrefix(relative, "client/"):
		return 6, true
	case relative == "networking":
		return 5, true
	case strings.HasPrefix(relative, "networking/"):
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
