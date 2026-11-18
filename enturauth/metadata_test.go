package enturauth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entur/go-mcpkit/enturauth"
	"github.com/entur/go-mcpkit/mcpkittest/enturauthtest"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	a0 := enturauthtest.New(t)
	for _, tc := range []struct{ resource, path string }{
		{resource, "/.well-known/oauth-protected-resource/partner"},
		{"https://mcp.example.com", "/.well-known/oauth-protected-resource"},
	} {
		cfg := config()
		cfg.Resource, cfg.RequiredScopes = tc.resource, []string{"mcp:read", "mcp:write"}
		a := start(t, t.Context(), a0, cfg)
		mux := http.NewServeMux()
		if err := a.MountMetadata(mux); err != nil {
			t.Fatal(err)
		}
		if err := a.MountMetadata(mux); err == nil || !strings.Contains(err.Error(), tc.path) {
			t.Errorf("%s: second mount: %v", tc.path, err)
		}
		doc := `{"resource":"` + tc.resource + `","authorization_servers":["https://partner.dev.entur.org/"],"scopes_supported":["mcp:read","mcp:write"],"bearer_methods_supported":["header"]}`
		for _, m := range []struct {
			method, path string
			status       int
			body, header string
		}{
			{http.MethodGet, tc.path, 200, doc, "application/json public, max-age=300 * "},
			{http.MethodHead, tc.path, 200, "", "application/json public, max-age=300 * "},
			{http.MethodOptions, tc.path, 204, "", "  * GET, HEAD"},
			{http.MethodPost, tc.path, 405, "method not allowed\n", "text/plain; charset=utf-8   "},
			{http.MethodGet, tc.path + "/x", 404, "404 page not found\n", "text/plain; charset=utf-8   "},
		} {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(m.method, m.path, nil))
			h := rec.Header()
			header := strings.Join([]string{h.Get("Content-Type"), h.Get("Cache-Control"), h.Get("Access-Control-Allow-Origin"), h.Get("Access-Control-Allow-Methods")}, " ")
			if rec.Code != m.status || header != m.header || (m.method != http.MethodHead && rec.Body.String() != m.body) {
				t.Errorf("%s %s: %d %q %q", m.method, m.path, rec.Code, header, rec.Body)
			}
		}
		rec, _ := serve(a, t.Context(), "/partner")
		if want := `resource_metadata="https://mcp.example.com` + tc.path + `"`; !strings.Contains(rec.Header().Get("WWW-Authenticate"), want) {
			t.Errorf("challenge %q, want %s", rec.Header().Get("WWW-Authenticate"), want)
		}
	}
	if err := (&enturauth.Authenticator{}).MountMetadata(nil); err == nil {
		t.Error("mounted on a nil mux")
	}
}
