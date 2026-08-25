package ivnp_test

import (
	"encoding/json"
	"fmt"
	"os/exec"
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
		}
	}
	if len(violations) != 0 {
		sort.Strings(violations)
		t.Fatalf("upward IVNP imports:\n%s", strings.Join(violations, "\n"))
	}
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
	case path == modulePath:
		return 7, true
	case strings.HasPrefix(relative, "cmd/"), strings.HasPrefix(relative, "integration/"):
		return 8, true
	case relative == "service/daemon":
		return 6, true
	case strings.HasPrefix(relative, "service/"):
		return 5, true
	case relative == "network/router":
		return 4, true
	case strings.HasPrefix(relative, "network/transport/"), relative == "api/stream":
		return 1, true
	case strings.HasPrefix(relative, "network/"), strings.HasPrefix(relative, "api/"):
		return 3, true
	case strings.HasPrefix(relative, "protocol/"):
		return 2, true
	case relative == "i2p", strings.HasPrefix(relative, "support/"):
		return 1, true
	case strings.HasPrefix(relative, "crypto/"), strings.HasPrefix(relative, "internal/"):
		return 0, true
	default:
		return 0, true
	}
}
