package mcpkit

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestTestSupportStaysOutOfProduction proves that no package of the module
// other than mcpkittest itself depends on mcpkittest, directly or
// transitively, and that the kittest hooks are installed only from test
// support. Consumers run the same go list over their own executables.
func TestTestSupportStaysOutOfProduction(t *testing.T) {
	const module = "github.com/entur/go-mcpkit"
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

	setters := map[string]string{"kittest.SetResultCheck(": "mcpkittest/", "kittest.WithJWKSTransport(": "mcpkittest/enturauthtest/"}
	err = filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		src, err := os.ReadFile(p)
		for call, dir := range setters {
			if bytes.Contains(src, []byte(call)) && !strings.HasPrefix(filepath.ToSlash(p), dir) {
				t.Errorf("%s calls %s outside %s", p, call, dir)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
