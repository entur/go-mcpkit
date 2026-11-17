# go-mcpkit

Shared Go building blocks for Entur's [Model Context Protocol](https://modelcontextprotocol.io) (MCP) servers: read-only tools whose results all cross one trust boundary, served over stdio or stateless HTTP.

**Status:** `v0.1.0`. The API may still change before 1.0.

```sh
go get github.com/entur/go-mcpkit # Go 1.26 or later
```

## The locked contract

Every server built with the kit behaves the same on the wire. The normative description is [doc/contract.md](doc/contract.md); in short:

- Every successful result is a schema-v2 envelope `{schema_version, event_id, untrusted_data}`; server data lives only below `untrusted_data`.
- A failing call returns one of the tool's fixed error texts, chosen at registration. An error's own text is never rendered.
- The transport is stateless with JSON responses. Tools by default (prompts, resources and completions are opt-in content), `listChanged: false`, no logging capability, `private` cache scope on every cacheable result.
- Tools are read-only, and their descriptors and schemas are frozen at registration.
- Each endpoint states an access posture and a reason: `Protected` (HTTP behind the application's authentication), `PublicReadOnly`, or `LocalProcess` (stdio only). The zero value is refused.
- HTTP guards run in a fixed order: panic recovery, security headers, write deadline, body cap, authentication, subject rate limit, transport.

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

[example_test.go](example_test.go) has runnable examples of a protected HTTP endpoint with its own access policy and of several endpoints, one with the Microsoft 365 descriptor profile.

## Packages

| Package | Purpose |
|---|---|
| `mcpkit` | Builder, endpoints, read-only tools, failure catalogs, instructions, observer, `Handler` |
| `output` | The schema-v2 envelope, output budgets, failure classes, schema generation |
| `retrieved` | Normalises and bounds externally authored text before it enters a result |
| `pagepack` | Packs ordered records into size-bounded pages |
| `httpguard` | The HTTP guards `Handler` composes, for use on their own |
| `mcpkittest` | Test helpers; import only from `_test.go` files |

## Not in v0.1.0

Auth0 resource-server validation (token verification and the `Protected` policy built on it) arrives in v0.2.0. Until then a `Protected` endpoint takes the application's own authentication wrapper.

Security reports: [SECURITY.md](SECURITY.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

License: [EUPL-1.2](LICENSE.txt)
