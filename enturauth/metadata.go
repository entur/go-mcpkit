package enturauth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// metadataDocument is the RFC 9728 protected-resource metadata, fixed in New.
func metadataDocument(resource, issuer string, scopes []string) []byte {
	b, _ := json.Marshal(struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
		BearerMethods        []string `json:"bearer_methods_supported"`
	}{resource, []string{issuer}, scopes, []string{"header"}})
	return b
}

// MountMetadata serves the metadata at the path-inserted well-known URL of
// Resource (/.well-known/oauth-protected-resource followed by its path) on
// mux, the application's HTTPOptions.Mux. A pattern conflict is an error.
func (a *Authenticator) MountMetadata(mux *http.ServeMux) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("enturauth: metadata route %q: %v", a.metaPath, p)
		}
	}()
	mux.Handle(a.metaPath, http.HandlerFunc(a.serveMetadata))
	return nil
}

func (a *Authenticator) serveMetadata(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", "public, max-age=300")
		h.Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(a.metadata)
	case http.MethodOptions:
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, HEAD")
		h.Set("Access-Control-Allow-Headers", "*")
		w.WriteHeader(http.StatusNoContent)
	default:
		h.Set("Allow", "GET, HEAD, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
