package mcpkit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
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

	violations, err := setterViolations(os.DirFS("."))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violations {
		t.Error(v)
	}
}

// setterViolations names every non-test Go file in fsys that refers to a
// kittest setter outside its approved directory. It skips only .git and
// testdata: a package under any other directory, a hidden one included, can
// be imported by path.
func setterViolations(fsys fs.FS) ([]string, error) {
	var found []string
	fset := token.NewFileSet()
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && d.Name() == ".git":
			return fs.SkipDir
		case d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go"):
			return nil
		}
		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, s := range setterRefs(f) {
			if !strings.HasPrefix(p, setters[s]) {
				found = append(found, p+" refers to kittest."+s+" outside "+setters[s])
			}
		}
		return nil
	})
	return found, err
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

	install := []byte(`package x; import ("context"; "github.com/entur/go-mcpkit/internal/kittest")
func Install(ctx context.Context) context.Context { return kittest.WithJWKSTransport(ctx, nil) }`)
	got, err := setterViolations(fstest.MapFS{
		".hidden/x/install.go":                {Data: install}, // importable by path, though ./... skips it
		"mcpkittest/enturauthtest/install.go": {Data: install}, // approved
		"x/install_test.go":                   {Data: install}, // a test
		"testdata/x/install.go":               {Data: install}, // importable by path, though ./... skips it
		".git/x/install.go":                   {Data: install}, // repository metadata
	})
	if want := ".hidden/x/install.go refers to kittest.WithJWKSTransport outside mcpkittest/enturauthtest/; testdata/x/install.go refers to kittest.WithJWKSTransport outside mcpkittest/enturauthtest/"; err != nil || strings.Join(got, "; ") != want {
		t.Errorf("setterViolations: %q, %v; want %q", got, err, want)
	}
}
