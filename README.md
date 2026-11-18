# go-mcpkit

Shared Go building blocks for Entur's [Model Context Protocol](https://modelcontextprotocol.io) (MCP) servers: read-only tools whose results all cross one trust boundary, served over stdio or stateless HTTP.

**Status:** `v0.1.0`. The API may still change before 1.0.

```sh
go get github.com/entur/go-mcpkit # Go 1.26 or later
```

## The locked contract

Every server built with the kit behaves the same on the wire. The normative description is [doc/contract.md](doc/contract.md); in short:

- Every successful result is a schema-v2 envelope `{schema_version, event_id, untrusted_data}`; server data lives only below `untrusted_data`.
- A call that fails inside a registered tool returns one of its fixed error texts, chosen at registration; an error's own text is never rendered. SDK protocol errors (an unknown tool name, say) are JSON-RPC errors.
- The transport is stateless with JSON responses. Tools by default (prompts, resources and completions are opt-in content), `listChanged: false`, no logging capability, `private` cache scope on every cacheable result.
- Tools are read-only, and their descriptors and schemas are frozen at registration.
- Each endpoint states an access posture and a reason: `Protected` (HTTP behind the application's authentication), `PublicReadOnly`, or `LocalProcess` (stdio only). The zero value is refused.
- HTTP guards run in a fixed order: panic recovery, security headers, write deadline, body cap, authentication, subject rate limit, transport.
- `enturauth` makes a `Protected` endpoint an OAuth resource server for one Entur Auth0 issuer; the bearer never reaches a tool handler.

## Quick start

A local server over stdio with one tool:

```go
package main

import (
	"context"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/entur/go-mcpkit"
	"github.com/entur/go-mcpkit/output"
)

type in struct {
	Text string `json:"text" jsonschema:"the text to echo"`
}
type out struct {
	Text string `json:"text"`
}

func main() {
	rule, err := mcpkit.UntrustedDataRule(mcpkit.English, "an echo result", "", "Use echo to repeat text.")
	if err != nil {
		log.Fatal(err)
	}
	ep, err := mcpkit.New(mcpkit.Options{}).Endpoint("echo", mcpkit.EndpointOptions{
		Implementation: mcp.Implementation{Name: "echo", Version: "0.1.0"},
		Access:         mcpkit.LocalProcess("started by the user's own MCP client"),
		Instructions:   rule,
	})
	if err != nil {
		log.Fatal(err)
	}
	err = mcpkit.AddReadTool(ep, mcpkit.ReadTool[in, out]{
		Tool:     &mcp.Tool{Name: "echo", Title: "Echo", Description: "Echoes the text."},
		Output:   output.Policy{MaxEnvelopeBytes: 4 * output.KiB, MaxStringBytes: 512},
		Failures: mcpkit.Failures{Fallback: "The lookup failed."},
		Handle:   func(_ context.Context, _ *mcp.CallToolRequest, i in) (out, error) { return out(i), nil },
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := ep.RunStdio(context.Background()); err != nil {
		log.Fatal(err)
	}
}
```

[example_test.go](example_test.go) has runnable examples of a protected HTTP endpoint with its own toy authentication and of several endpoints, one with the Microsoft 365 descriptor profile.

## Packages

| Package | Purpose |
|---|---|
| `mcpkit` | Builder, endpoints, read-only tools, failure catalogs, instructions, observer, `Handler` |
| `output` | The schema-v2 envelope, output budgets, failure classes, schema generation |
| `retrieved` | Normalises and bounds externally authored text before it enters a result |
| `pagepack` | Packs ordered records into size-bounded pages |
| `httpguard` | The HTTP guards `Handler` composes, for use on their own |
| `enturauth` | OAuth resource server for Entur's Auth0 tenants: RFC 9068 token validation for a `Protected` endpoint, RFC 9728 metadata |
| `mcpkittest` | Test helpers; import only from `_test.go` files |
| `mcpkittest/enturauthtest` | An in-memory Auth0 stand-in that mints test tokens; import only from `_test.go` files |

## Protected HTTP with Auth0

An MCP host logs the user in at Auth0 and sends the access token as a bearer; `enturauth` validates it on every request and publishes the protected-resource metadata. Login, consent and token issuance stay at Auth0. The behaviour is in [doc/contract.md](doc/contract.md#auth0-resource-server), the decision in [ADR 0001](doc/adr/0001-enturauth.adoc).

```go
// ctx is the server's lifetime: the signing keys stay fresh until it ends.
auth, err := enturauth.New(ctx, enturauth.Config{
	Tenant:         enturauth.Partner,
	Env:            enturauth.Prd,
	Resource:       "https://mcp.example.com/partner", // the Auth0 API identifier
	ClientIDs:      []string{"pre-registered-public-client"},
	RequiredScopes: []string{"mcp:read"},
	Admission:      enturauth.AllowAnyOrganisation("data every partner organisation may read"),
})
if err != nil {
	log.Fatal(err)
}
b := mcpkit.New(mcpkit.Options{})
ep, err := b.Endpoint("partner", mcpkit.EndpointOptions{
	Implementation: mcp.Implementation{Name: "partner", Version: "1.0.0"},
	Access:         auth.Access(),
	Instructions:   rule,
})
// ... add tools; a handler reads the caller with enturauth.FromContext(ctx).
mux := http.NewServeMux()
if err := auth.MountMetadata(mux); err != nil {
	log.Fatal(err)
}
h, err := b.Handler(mcpkit.HTTPOptions{
	Mux:           mux,
	Routes:        []mcpkit.Route{{Path: "/partner", Endpoint: ep}},
	Limiter:       httpguard.NewSubjectLimiter(rate.Every(time.Second), 10, time.Minute),
	Subject:       enturauth.SubjectKey,
	BodyBytes:     64 * output.KiB,
	WriteDeadline: time.Minute,
})
```

`auth.Ready()` serves a startup probe. Tests build the authenticator from `enturauthtest.New(t).Context(ctx)` and mint tokens with its `Token` and `Claims`.

Security reports: [SECURITY.md](SECURITY.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

License: [EUPL-1.2](LICENSE.txt)
