// Package kittest holds the module's one piece of mutable package state: a
// test hook the registration core consults when it registers a tool.
// Production code never sets it; only package mcpkittest does, from tests.
package kittest

import (
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
