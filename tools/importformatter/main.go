// Command importformatter formats and consolidates Go imports canonically across the repository.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

var errCgoImport = errors.New(`importformatter: import "C" must remain separate`)

func main() {
	writeChanges := flag.Bool("write", false, "write files whose canonical import layout differs")
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if err := run(*root, *writeChanges); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(root string, writeChanges bool) error {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	goimports, err := exec.LookPath("goimports")
	if err != nil {
		return errors.New("importformatter: goimports is required on PATH")
	}
	paths, err := trackedGoFiles(absoluteRoot)
	if err != nil {
		return err
	}
	changed := 0
	for _, relativePath := range paths {
		path := filepath.Join(absoluteRoot, relativePath)
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		flattened, flattenErr := flattenImports(relativePath, source)
		if flattenErr != nil {
			return flattenErr
		}
		canonical, formatErr := formatWithGoimports(goimports, absoluteRoot, relativePath, flattened)
		if formatErr != nil {
			return formatErr
		}
		if validateErr := validateImportDeclarationCount(relativePath, canonical); validateErr != nil {
			return validateErr
		}
		if bytes.Equal(source, canonical) {
			continue
		}
		changed++
		fmt.Println(relativePath)
		if writeChanges {
			if writeErr := writeFile(path, canonical); writeErr != nil {
				return writeErr
			}
		}
	}
	if changed == 0 {
		return nil
	}
	if !writeChanges {
		return fmt.Errorf("importformatter: %d files require formatting", changed)
	}
	fmt.Printf("importformatter: updated %d files\n", changed)
	return nil
}

func trackedGoFiles(root string) ([]string, error) {
	command := exec.Command("git", "ls-files", "-z", "--", "*.go")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("importformatter: list tracked Go files: %w", err)
	}
	var paths []string
	for path := range strings.SplitSeq(string(output), "\x00") {
		if path != "" {
			paths = append(paths, filepath.FromSlash(path))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func flattenImports(path string, source []byte) ([]byte, error) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, source, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("importformatter: parse %s: %w", path, err)
	}
	var importDeclarations []*ast.GenDecl
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if ok && general.Tok == token.IMPORT {
			importDeclarations = append(importDeclarations, general)
		}
	}
	if len(importDeclarations) == 0 {
		return source, nil
	}
	var specifications []ast.Spec
	for _, declaration := range importDeclarations {
		if declaration.Doc != nil {
			return nil, fmt.Errorf("importformatter: %s: import declaration has a doc comment", path)
		}
		for _, raw := range declaration.Specs {
			specification := raw.(*ast.ImportSpec)
			if specification.Path.Value == `"C"` {
				return nil, fmt.Errorf("%w in %s", errCgoImport, path)
			}
			if specification.Doc != nil || specification.Comment != nil {
				return nil, fmt.Errorf("importformatter: %s: import specification has a comment", path)
			}
			clone := &ast.ImportSpec{Path: &ast.BasicLit{Kind: token.STRING, Value: specification.Path.Value}}
			if specification.Name != nil {
				clone.Name = ast.NewIdent(specification.Name.Name)
			}
			specifications = append(specifications, clone)
		}
	}
	first := importDeclarations[0]
	first.Specs = specifications
	first.Lparen = first.Pos()
	first.Rparen = first.Pos()
	kept := make([]ast.Decl, 0, len(file.Decls)-len(importDeclarations)+1)
	retainedImport := false
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.IMPORT {
			kept = append(kept, declaration)
			continue
		}
		if !retainedImport {
			kept = append(kept, first)
			retainedImport = true
		}
	}
	file.Decls = kept
	var output bytes.Buffer
	if err := format.Node(&output, fileSet, file); err != nil {
		return nil, fmt.Errorf("importformatter: format flattened %s: %w", path, err)
	}
	return output.Bytes(), nil
}

func formatWithGoimports(binary, root, relativePath string, source []byte) ([]byte, error) {
	absolutePath := filepath.Join(root, relativePath)
	command := exec.Command(binary, "-srcdir", filepath.Dir(absolutePath))
	command.Dir = root
	command.Stdin = bytes.NewReader(source)
	var output bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &output
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("importformatter: goimports %s: %w: %s", relativePath, err, strings.TrimSpace(stderr.String()))
	}
	return output.Bytes(), nil
}

func validateImportDeclarationCount(path string, source []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
	if err != nil {
		return fmt.Errorf("importformatter: validate %s: %w", path, err)
	}
	declarations := 0
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if ok && general.Tok == token.IMPORT {
			declarations++
		}
	}
	if declarations > 1 {
		return fmt.Errorf("importformatter: %s has %d import declarations", path, declarations)
	}
	return nil
}

func writeFile(path string, content []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".importformatter-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
