package mcpkit_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/time/rate"

	"github.com/entur/go-mcpkit"
	"github.com/entur/go-mcpkit/httpguard"
	"github.com/entur/go-mcpkit/output"
)

type echoIn struct {
	Text string `json:"text" jsonschema:"the text to echo"`
}

type echoOut struct {
	Text string `json:"text"`
}

// addEcho registers a read-only tool that echoes its input.
func addEcho(ep *mcpkit.Endpoint) error {
	return mcpkit.AddReadTool(ep, mcpkit.ReadTool[echoIn, echoOut]{
		Tool:     &mcp.Tool{Name: "echo", Title: "Echo", Description: "Echoes the text."},
		Output:   output.Policy{MaxEnvelopeBytes: 4 * output.KiB, MaxStringBytes: 512},
		Failures: mcpkit.Failures{Fallback: "The lookup failed."},
		Handle: func(_ context.Context, _ *mcp.CallToolRequest, in echoIn) (echoOut, error) {
			return echoOut(in), nil
		},
	})
}

func newEndpoint(b *mcpkit.Builder, name string, access mcpkit.Access, profile mcpkit.Profile) *mcpkit.Endpoint {
	instructions, err := mcpkit.UntrustedDataRule(mcpkit.English, "an echo result", "", "Use echo to repeat text.")
	if err != nil {
		log.Fatal(err)
	}
	ep, err := b.Endpoint(name, mcpkit.EndpointOptions{
		Implementation: mcp.Implementation{Name: name, Version: "0.1.0"},
		Access:         access,
		Instructions:   instructions,
		Profile:        profile,
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := addEcho(ep); err != nil {
		log.Fatal(err)
	}
	return ep
}

// call posts one tools/call to the handler's path and returns the response body.
func call(h http.Handler, path, token string) string {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out, _ := io.ReadAll(rec.Result().Body)
	return fmt.Sprintf("%d %s", rec.Code, strings.TrimSpace(string(out)))
}

// A local server for a user's own MCP client: one endpoint, one tool, stdio.
// It is not run as a test because RunStdio reads standard input.
func Example_minimalStdio() {
	ep := newEndpoint(mcpkit.New(mcpkit.Options{}), "echo", mcpkit.LocalProcess("started by the user's own MCP client"), mcpkit.ProfileDefault)
	if err := ep.RunStdio(context.Background()); err != nil {
		log.Fatal(err)
	}
}

// A Protected endpoint states its own authentication: a wrapper the kit runs
// after the body cap and before the subject limiter. This one is a toy.
func Example_protectedHTTP() {
	type subjectKey struct{}
	bearer := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer secret" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), subjectKey{}, "alice")))
		})
	}
	b := mcpkit.New(mcpkit.Options{})
	ep := newEndpoint(b, "echo", mcpkit.Protected(bearer, "holders of the demo token"), mcpkit.ProfileDefault)
	h, err := b.Handler(mcpkit.HTTPOptions{
		Routes:  []mcpkit.Route{{Path: "/mcp", Endpoint: ep}},
		Limiter: httpguard.NewSubjectLimiter(rate.Every(time.Second), 10, time.Minute),
		Subject: func(ctx context.Context) (string, bool) {
			s, ok := ctx.Value(subjectKey{}).(string)
			return s, ok
		},
		BodyBytes:     64 * output.KiB,
		WriteDeadline: time.Minute,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(call(h, "/mcp", ""))
	fmt.Println(strings.Contains(call(h, "/mcp", "secret"), `\"untrusted_data\":{\"text\":\"hi\"}`))
	// Output:
	// 401 unauthorized
	// true
}

// One builder serves several endpoints, each with its own posture and
// descriptor profile: here a public one and a Microsoft 365 Copilot one that
// publishes no output schema.
func Example_multipleEndpoints() {
	b := mcpkit.New(mcpkit.Options{})
	public := newEndpoint(b, "public", mcpkit.PublicReadOnly("open timetable data"), mcpkit.ProfileDefault)
	m365 := newEndpoint(b, "m365", mcpkit.PublicReadOnly("open timetable data"), mcpkit.ProfileM365)
	h, err := b.Handler(mcpkit.HTTPOptions{
		Routes:        []mcpkit.Route{{Path: "/mcp", Endpoint: public}, {Path: "/m365/mcp", Endpoint: m365}},
		BodyBytes:     64 * output.KiB,
		WriteDeadline: time.Minute,
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range b.Posture() {
		fmt.Println(p.Name, p.Kind)
	}
	fmt.Println(strings.HasPrefix(call(h, "/mcp", ""), "200 "), strings.HasPrefix(call(h, "/m365/mcp", ""), "200 "))
	// Output:
	// public public-read-only
	// m365 public-read-only
	// true true
}
