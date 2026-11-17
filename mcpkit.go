// Package mcpkit assembles read-only MCP servers whose tool results all cross
// one trust boundary. Every tool is registered through a single core that
// validates its input, renders only failure text frozen at registration and
// wraps results in the schema-v2 envelope of package output.
//
// A Builder holds endpoints. Each endpoint has an access posture, its own
// implementation metadata and instructions, and a locked SDK configuration:
// tools only, with listChanged false; no logging capability; private cache
// scope on every cacheable result; a stateless JSON transport. Handler serves
// endpoints over HTTP in a fixed guard chain (package httpguard), RunStdio
// over standard I/O. The first of them seals the builder: content is
// installed once, against the tools actually registered, and later
// registrations fail.
package mcpkit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/entur/go-mcpkit/output"
)

var errSealed = errors.New("mcpkit: the builder is serving; registration is closed")

// Options configure a Builder.
type Options struct {
	// Observer receives tool events for every endpoint. Its zero value
	// observes nothing.
	Observer Observer
}

// Builder holds the endpoints of one process.
type Builder struct {
	observer  Observer
	once      sync.Once
	mu        sync.Mutex
	endpoints []*Endpoint
	sealed    bool
	sealErr   error
}

// New returns an empty Builder.
func New(opts Options) *Builder { return &Builder{observer: opts.Observer} }

// Profile is a descriptor compatibility profile. It changes how tool
// descriptors are published, never results, authorization or content.
type Profile uint8

const (
	// ProfileDefault publishes inferred schemas unchanged, with an output
	// schema.
	ProfileDefault Profile = iota
	// ProfileM365 collapses every nullable type array of an input schema to
	// its single non-null type and publishes no output schema, because
	// Microsoft 365 Copilot truncates or drops tool definitions with either.
	ProfileM365
)

// EndpointOptions describe one endpoint.
type EndpointOptions struct {
	Implementation mcp.Implementation
	Access         Access
	Instructions   Instructions
	Profile        Profile
	// SchemaText words the envelope's root property descriptions.
	SchemaText output.SchemaText
	// Content adds prompts, resources and completions; nil serves tools
	// only. Not supported with ProfileM365.
	Content Content
}

// Endpoint is one MCP server: an SDK server the kit constructs and never
// exposes, and the names of the tools registered on it.
type Endpoint struct {
	b          *Builder
	name       string
	access     Access
	profile    Profile
	schemaText output.SchemaText
	content    Content
	contentOpt ContentOptions
	server     *mcp.Server
	tools      []string
	filtered   bool
}

// Endpoint adds an endpoint. name identifies it in Posture.
func (b *Builder) Endpoint(name string, opts EndpointOptions) (*Endpoint, error) {
	fail := func(why string) (*Endpoint, error) { return nil, fmt.Errorf("mcpkit: endpoint %q: %s", name, why) }
	if err := opts.Access.validate(); err != nil {
		return fail(err.Error())
	}
	switch {
	case strings.TrimSpace(name) == "":
		return fail("no name")
	case opts.Implementation.Name == "":
		return fail("no implementation name")
	case opts.Instructions.text == "":
		return fail("no instructions; use UntrustedDataRule")
	case opts.Profile > ProfileM365:
		return fail("unknown profile")
	case opts.Content != nil && opts.Profile == ProfileM365:
		return fail("content is not supported with ProfileM365")
	}
	so := &mcp.ServerOptions{
		Instructions: opts.Instructions.text,
		// Explicit and non-nil: a nil Tools makes the SDK advertise
		// listChanged as soon as a tool is registered, and nil Capabilities
		// brings logging back.
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: false}},
		SetCacheable: privateCacheScope,
	}
	var co ContentOptions
	if opts.Content != nil {
		var err error
		if co, err = contentOptions(opts.Content.ServerOptions(privateCacheScope)); err != nil {
			return fail(err.Error())
		}
		so.Capabilities.Prompts, so.Capabilities.Resources, so.Capabilities.Completions = co.Prompts, co.Resources, co.Completions
		so.CompletionHandler = co.Complete
	}
	impl, err := snapshot(opts.Implementation)
	if err != nil {
		return fail(err.Error())
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.sealed:
		return nil, errSealed
	case slices.ContainsFunc(b.endpoints, func(e *Endpoint) bool { return e.name == name }):
		return fail("duplicate name")
	}
	ep := &Endpoint{b: b, name: name, access: opts.Access, profile: opts.Profile, schemaText: opts.SchemaText,
		content: opts.Content, contentOpt: co, server: mcp.NewServer(&impl, so)}
	b.endpoints = append(b.endpoints, ep)
	return ep, nil
}

// privateCacheScope marks every cacheable result private: a catalog may vary
// by principal, and nothing gives an intermediary or another user's client a
// reason to reuse it. The SDK calls it with its server lock held.
func privateCacheScope(_ context.Context, _ mcp.Request, c *mcp.Cacheable) { c.CacheScope = "private" }

// EndpointPosture is one endpoint's access posture, for startup logging.
type EndpointPosture struct{ Name, Kind, Reason string }

// Posture returns a copy of every endpoint's access posture, in creation
// order.
func (b *Builder) Posture() []EndpointPosture {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]EndpointPosture, 0, len(b.endpoints))
	for _, ep := range b.endpoints {
		out = append(out, EndpointPosture{Name: ep.name, Kind: ep.access.kind.String(), Reason: ep.access.reason})
	}
	return out
}

// seal closes registration once and installs every endpoint's content.
func (b *Builder) seal() error {
	b.once.Do(func() {
		b.mu.Lock()
		b.sealed = true
		endpoints := slices.Clone(b.endpoints)
		b.mu.Unlock()
		for _, ep := range endpoints {
			if err := ep.install(); err != nil {
				b.sealErr = fmt.Errorf("mcpkit: endpoint %q: %w", ep.name, err)
				return
			}
		}
	})
	return b.sealErr
}

// RunStdio seals the builder and serves the endpoint on standard input and
// output until ctx ends or the client disconnects. A Protected endpoint is
// refused: stdio has no HTTP authentication to apply.
func (ep *Endpoint) RunStdio(ctx context.Context) error {
	if ep.access.kind == accessProtected {
		return fmt.Errorf("mcpkit: endpoint %q is Protected and cannot be served over stdio", ep.name)
	}
	if err := ep.b.seal(); err != nil {
		return err
	}
	return ep.server.Run(ctx, &mcp.StdioTransport{})
}
