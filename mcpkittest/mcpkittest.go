// Package mcpkittest holds test helpers for applications built on mcpkit.
// Import it only from _test.go files.
package mcpkittest

import (
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/entur/go-mcpkit/internal/kittest"
)

// ValidateResults makes every tool registered from now on check each
// successful result, exactly as the registration core packed it, against the
// output schema its descriptor publishes, read back the way a client holds
// it. report receives each mismatch; a nil report clears the check. It
// returns a function that restores the previous setting. Call it from
// TestMain, before anything registers a tool. A tool that publishes no output
// schema (ProfileM365) is not checked.
func ValidateResults(report func(tool string, err error)) (restore func()) {
	if report == nil {
		return kittest.SetResultCheck(nil)
	}
	return kittest.SetResultCheck(func(tool *mcp.Tool) func([]byte) {
		check, err := ResultCheck(tool.OutputSchema)
		if err != nil {
			report(tool.Name, fmt.Errorf("published outputSchema does not resolve: %w", err))
			return nil
		}
		return func(packed []byte) {
			if err := check(packed); err != nil {
				report(tool.Name, err)
			}
		}
	})
}

// ResultCheck resolves a published output schema as a client holds it (the
// JSON the server serialized, not the Go value) and returns a validator for
// one serialized structured result.
func ResultCheck(published any) (func(structured []byte) error, error) {
	raw, err := json.Marshal(published)
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		return nil, err
	}
	return func(structured []byte) error {
		var instance any
		if err := json.Unmarshal(structured, &instance); err != nil {
			return fmt.Errorf("structured result is not JSON: %w", err)
		}
		return resolved.Validate(instance)
	}, nil
}
