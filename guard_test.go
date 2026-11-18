package mcpkit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/entur/go-mcpkit"

// setters are the kittest hooks, each with the only directory whose non-test
// files may refer to it.
var setters = map[string]string{"SetResultCheck": "mcpkittest/", "WithJWKSTransport": "mcpkittest/enturauthtest/"}

// TestTestSupportStaysOutOfProduction proves that no package of the module
// other than mcpkittest itself depends on mcpkittest, directly or
// transitively, and that only test support refers to a kittest setter.
// Consumers run the same go list over their own executables.
func TestTestSupportStaysOutOfProduction(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "go", "list", "-f", `{{.ImportPath}} {{join .Deps " "}}`, "./...")
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(out)) {
		pkg, deps, _ := strings.Cut(strings.TrimSpace(line), " ")
		if pkg == module+"/mcpkittest" || strings.HasPrefix(pkg, module+"/mcpkittest/") {
			continue
		}
		for dep := range strings.FieldsSeq(deps) {
			if dep == module+"/mcpkittest" || strings.HasPrefix(dep, module+"/mcpkittest/") {
				t.Errorf("%s depends on %s", pkg, dep)
			}
		}
	}

	fset := token.NewFileSet()
	err = filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && p != "." && strings.HasPrefix(d.Name(), "."):
			return fs.SkipDir
		case d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go"):
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, s := range setterRefs(f) {
			if !strings.HasPrefix(filepath.ToSlash(p), setters[s]) {
				t.Errorf("%s refers to kittest.%s outside %s", p, s, setters[s])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// setterRefs returns the kittest setters f refers to under whatever name it
// imports kittest, as a call or as a value.
func setterRefs(f *ast.File) []string {
	var refs []string
	for _, imp := range f.Imports {
		if path, _ := strconv.Unquote(imp.Path.Value); path != module+"/internal/kittest" {
			continue
		}
		name := "kittest"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if x, ok := n.X.(*ast.Ident); ok && x.Name == name && setters[n.Sel.Name] != "" {
					refs = append(refs, n.Sel.Name)
				}
			case *ast.Ident:
				if name == "." && setters[n.Name] != "" {
					refs = append(refs, n.Name)
				}
			}
			return true
		})
	}
	return refs
}

func TestSetterRefs(t *testing.T) {
	const aliased = `import kt "github.com/entur/go-mcpkit/internal/kittest"; `
	for _, tc := range []struct{ name, src, want string }{
		{"default name", `import "github.com/entur/go-mcpkit/internal/kittest"; func f() { kittest.SetResultCheck(nil) }`, "SetResultCheck"},
		{"alias call", aliased + `func f(ctx context.Context) context.Context { return kt.WithJWKSTransport(ctx, nil) }`, "WithJWKSTransport"},
		{"function value", aliased + `var set = kt.WithJWKSTransport`, "WithJWKSTransport"},
		{"dot import", `import . "github.com/entur/go-mcpkit/internal/kittest"; var set = SetResultCheck`, "SetResultCheck"},
		{"getter only", aliased + `func f(ctx context.Context) { kt.JWKSTransport(ctx) }`, ""},
		{"another package of that name", `import "example.com/kittest"; func f() { kittest.SetResultCheck(nil) }`, ""},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "probe.go", "package probe; "+tc.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(setterRefs(f), " "); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}
