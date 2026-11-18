// Package kittest holds the module's test hooks: the one piece of mutable
// package state, a hook the registration core consults when it registers a
// tool, and the context-scoped signing-key transport enturauth.New reads.
// Production code never sets either; only mcpkittest and its subpackages do,
// from tests.
package kittest

import (
	"context"
	"net/http"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ResultCheck returns, for a published descriptor, the check every
// successful packed result of that tool is passed to (nil for none).
type ResultCheck func(tool *mcp.Tool) func(packed []byte)

var resultCheck atomic.Pointer[ResultCheck]

// SetResultCheck installs c, or clears the hook when c is nil, and returns a
// function that restores the previous hook.
func SetResultCheck(c ResultCheck) (restore func()) {
	var next *ResultCheck
	if c != nil {
		next = &c
	}
	prev := resultCheck.Swap(next)
	return func() { resultCheck.Store(prev) }
}

// For returns the check for tool, or nil when no hook is set or the tool
// publishes no output schema.
func For(tool *mcp.Tool) func(packed []byte) {
	if c := resultCheck.Load(); c != nil && tool.OutputSchema != nil {
		return (*c)(tool)
	}
	return nil
}

type jwksTransportKey struct{}

// WithJWKSTransport returns ctx carrying rt, which enturauth.New then uses
// for its signing-key fetches instead of the network. Only
// mcpkittest/enturauthtest and tests call it.
func WithJWKSTransport(ctx context.Context, rt http.RoundTripper) context.Context {
	return context.WithValue(ctx, jwksTransportKey{}, rt)
}

// JWKSTransport returns the transport ctx carries, or nil.
func JWKSTransport(ctx context.Context) http.RoundTripper {
	rt, _ := ctx.Value(jwksTransportKey{}).(http.RoundTripper)
	return rt
}
