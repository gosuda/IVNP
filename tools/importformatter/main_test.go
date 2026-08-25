package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestFlattenImportsConsolidatesDeclarations(t *testing.T) {
	source := []byte(`package sample

import "fmt"

import (
    "context"
    alias "example.com/dependency"
)

func use(ctx context.Context) { fmt.Println(ctx, alias.Value) }
`)
	flattened, err := flattenImports("sample.go", source)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "sample.go", flattened, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	declarations := 0
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if ok && general.Tok == token.IMPORT {
			declarations++
		}
	}
	if declarations != 1 {
		t.Fatalf("import declarations = %d, want 1", declarations)
	}
	if len(file.Imports) != 3 {
		t.Fatalf("imports = %d, want 3", len(file.Imports))
	}
	if strings.Contains(string(flattened), "import \"fmt\"") {
		t.Fatalf("flattened source retained a standalone import:\n%s", flattened)
	}
}

func TestFlattenImportsRejectsCgo(t *testing.T) {
	_, err := flattenImports("cgo.go", []byte("package sample\n\nimport \"C\"\n"))
	if !errors.Is(err, errCgoImport) {
		t.Fatalf("cgo error = %v, want %v", err, errCgoImport)
	}
}
