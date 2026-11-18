package mcpkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/entur/go-mcpkit/internal/kittest"
	"github.com/entur/go-mcpkit/output"
)

// ReadTool is a typed read-only tool. Its input schema is inferred from I and
// its output schema from O; Tool carries neither.
type ReadTool[I, O any] struct {
	// Tool supplies the name, a non-blank title, the description and
	// optional annotations. The kit copies it and marks it read-only.
	Tool     *mcp.Tool
	Output   output.Policy
	Failures Failures
	// Handle runs only for input that validated and decoded into I. Its
	// error selects a Failures text and is never rendered.
	Handle func(context.Context, *mcp.CallToolRequest, I) (O, error)
}

// AddReadTool registers t on ep.
func AddReadTool[I, O any](ep *Endpoint, t ReadTool[I, O]) error {
	if t.Handle == nil {
		return toolError(t.Tool, errors.New("no handler"))
	}
	if t.Tool != nil && t.Tool.InputSchema != nil {
		return toolError(t.Tool, errors.New("the input schema is inferred; leave InputSchema nil"))
	}
	in, err := jsonschema.For[I](nil)
	if err != nil {
		return toolError(t.Tool, fmt.Errorf("input schema: %w", err))
	}
	var out *jsonschema.Schema
	if ep.profile != ProfileM365 {
		if out, err = output.SchemaFor[O](ep.schemaText); err != nil {
			return toolError(t.Tool, fmt.Errorf("output schema: %w", err))
		}
	}
	return ep.add(t.Tool, in, out, t.Output, t.Failures,
		func(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage, _ any, invalid error) (any, bool, error) {
			if invalid != nil {
				return nil, false, invalid
			}
			var in I
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, false, output.ErrInvalidArgument
			}
			out, err := t.Handle(ctx, req, in)
			return out, false, err
		})
}

// ProjectedTool is a read-only tool whose input and payload are described by
// reviewed schemas rather than Go types: a projection of data the
// application fetched or holds.
type ProjectedTool struct {
	// Tool supplies the name, a non-blank title, the description, optional
	// annotations and InputSchema, a *jsonschema.Schema of type object. The
	// kit copies all of it and marks it read-only.
	Tool *mcp.Tool
	// DataSchema describes the payload below untrusted_data; the kit wraps a
	// copy in the envelope schema.
	DataSchema *jsonschema.Schema
	Output     output.Policy
	Failures   Failures
	// Handle runs for every call, also when the input failed validation:
	// invalid is then output.ErrInvalidArgument and args is nil, so the
	// application can decide what a refused call still records before it
	// answers. It returns the payload, whether that payload reports a tool
	// error, and an error that selects a Failures text.
	Handle func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any, invalid error) (data any, isError bool, err error)
}

// AddProjectedReadTool registers t on ep.
func AddProjectedReadTool(ep *Endpoint, t ProjectedTool) error {
	if t.Handle == nil || t.Tool == nil || t.DataSchema == nil {
		return toolError(t.Tool, errors.New("needs a tool, a payload schema and a handler"))
	}
	in, ok := t.Tool.InputSchema.(*jsonschema.Schema)
	if !ok || in == nil {
		return toolError(t.Tool, errors.New("InputSchema must be a *jsonschema.Schema"))
	}
	in, err := snapshot(in)
	if err != nil {
		return toolError(t.Tool, err)
	}
	var out *jsonschema.Schema
	if ep.profile != ProfileM365 {
		data, err := snapshot(t.DataSchema)
		if err == nil {
			out, err = output.SchemaForData(data, ep.schemaText)
		}
		if err != nil {
			return toolError(t.Tool, fmt.Errorf("output schema: %w", err))
		}
	}
	return ep.add(t.Tool, in, out, t.Output, t.Failures,
		func(ctx context.Context, req *mcp.CallToolRequest, _ json.RawMessage, args any, invalid error) (any, bool, error) {
			m, _ := args.(map[string]any)
			return t.Handle(ctx, req, m, invalid)
		})
}

// invoker is a front end's part of a call: args is the validated instance
// (nil when invalid is set).
type invoker func(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage, args any, invalid error) (any, bool, error)

// add is the one registration core. It owns the descriptor, the only raw
// SDK registration, input validation, failure text and the envelope.
func (ep *Endpoint) add(t *mcp.Tool, in, out *jsonschema.Schema, policy output.Policy, failures Failures, invoke invoker) error {
	d, err := readOnlyDescriptor(t)
	if err != nil {
		return toolError(t, err)
	}
	if in.Type != "object" {
		return toolError(t, errors.New("input schema must be an object"))
	}
	if policy.MaxEnvelopeBytes <= 0 || policy.MaxStringBytes <= 0 {
		return toolError(t, errors.New("output policy budgets must be positive"))
	}
	f, err := failures.frozen()
	if err != nil {
		return toolError(t, err)
	}
	if ep.profile == ProfileM365 {
		collapseNullableTypes(in)
	}
	resolved, err := in.Resolve(nil)
	if err != nil {
		return toolError(t, fmt.Errorf("resolve input schema: %w", err))
	}
	d.InputSchema = in
	if out != nil {
		d.OutputSchema = out
	}

	b := ep.b
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.sealed:
		return errSealed
	case slices.Contains(ep.tools, d.Name):
		return toolError(t, errors.New("already registered on this endpoint"))
	}
	ep.tools = append(ep.tools, d.Name)
	if b.observer.Registered != nil {
		b.observer.Registered(d.Name)
	}
	// The raw API, never the SDK's typed mcp.AddTool: its validation errors
	// would reach the client as text outside the failure catalog.
	ep.server.AddTool(d, ep.handler(d.Name, resolved, policy, f, invoke, kittest.For(d)))
	return nil
}

// handler builds a tool's call path. check is the test hook's validator for
// this tool's packed results; it is nil outside tests.
func (ep *Endpoint) handler(name string, schema *jsonschema.Resolved, policy output.Policy, f Failures, invoke invoker, check func([]byte)) mcp.ToolHandler {
	obs := ep.b.observer
	return func(ctx context.Context, req *mcp.CallToolRequest) (result *mcp.CallToolResult, _ error) {
		start := time.Now()
		raw := json.RawMessage("{}")
		begin := Start{Tool: name, HasInput: req != nil && req.Params != nil}
		if begin.HasInput {
			begin.InputBytes = len(req.Params.Arguments)
			if len(req.Params.Arguments) > 0 {
				raw = req.Params.Arguments
			}
		}
		if obs.Started != nil {
			obs.Started(ctx, begin)
		}
		if obs.Completed != nil {
			defer func() {
				done := Completion{Tool: name, Duration: time.Since(start), HasOutput: result != nil}
				if result != nil {
					done.IsError = result.IsError
					done.OutputBytes = len(result.Content[0].(*mcp.TextContent).Text)
				}
				obs.Completed(ctx, done)
			}()
		}
		// A panic in the handler or while packing becomes the tool's fixed
		// fallback failure. The SDK runs this on its own goroutine, where no
		// HTTP recovery reaches, so an unrecovered panic would end the process.
		// Registered after the Completed defer, so that one sees the result.
		defer func() {
			if v := recover(); v != nil {
				result = failure(f.Fallback)
				if obs.Recovered != nil {
					obs.Recovered(ctx, Recovery{Tool: name, Value: v, Stack: debug.Stack()})
				}
			}
		}()
		packFailed := func(pf PackFailure) {
			if obs.PackFailed != nil {
				obs.PackFailed(ctx, pf)
			}
		}

		var args any
		var invalid error
		if json.Unmarshal(raw, &args) != nil || schema.Validate(args) != nil {
			args, invalid = nil, output.ErrInvalidArgument
		}
		data, isError, err := invoke(ctx, req, raw, args, invalid)
		if err != nil {
			return failure(f.Text(err)), nil
		}
		envelope, err := output.Wrap(data, policy)
		if err != nil {
			packFailed(PackFailure{Tool: name, Err: err})
			if errors.Is(err, output.ErrResultTooLarge) {
				return failure(f.Text(err)), nil
			}
			return failure(f.Fallback), nil
		}
		wire, err := json.Marshal(envelope)
		if err != nil {
			packFailed(PackFailure{Tool: name, Err: err, Marshal: true})
			return failure(f.Fallback), nil
		}
		result = &mcp.CallToolResult{
			Content:           []mcp.Content{&mcp.TextContent{Text: string(wire)}},
			StructuredContent: json.RawMessage(wire),
			IsError:           isError,
		}
		if check != nil {
			check(wire)
		}
		return result, nil
	}
}

func failure(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// readOnlyDescriptor snapshots t without its schemas, so later changes to t
// cannot reach the published descriptor, and marks it read-only.
func readOnlyDescriptor(t *mcp.Tool) (*mcp.Tool, error) {
	switch {
	case t == nil || t.Name == "":
		return nil, errors.New("no tool name")
	case strings.TrimSpace(t.Title) == "":
		return nil, errors.New("no title")
	case t.OutputSchema != nil:
		return nil, errors.New("the output schema is the kit's; leave OutputSchema nil")
	case t.Meta != nil:
		return nil, errors.New("_meta is not supported")
	case t.Annotations != nil && t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint:
		return nil, errors.New("a read-only tool cannot be destructive")
	}
	c := *t
	c.InputSchema = nil
	d, err := snapshot(&c)
	if err != nil {
		return nil, err
	}
	if d.Annotations == nil {
		d.Annotations = &mcp.ToolAnnotations{}
	}
	d.Annotations.ReadOnlyHint = true
	return d, nil
}

// collapseNullableTypes rewrites every {"type": ["null", X]} that inference
// produces for pointers and slices into {"type": X}. Omitting a key already
// expresses absence, and Microsoft 365 Copilot truncates a tool definition
// whose schema uses an array of types.
func collapseNullableTypes(s *jsonschema.Schema) {
	if s == nil {
		return
	}
	if len(s.Types) > 0 {
		kept := make([]string, 0, len(s.Types))
		for _, typ := range s.Types {
			if typ != "null" {
				kept = append(kept, typ)
			}
		}
		switch {
		case len(kept) == 1:
			s.Type, s.Types = kept[0], nil
		case len(kept) > 1:
			s.Types = kept
		}
	}
	for _, sub := range s.Properties {
		collapseNullableTypes(sub)
	}
	for _, sub := range s.PatternProperties {
		collapseNullableTypes(sub)
	}
	for _, sub := range s.PrefixItems {
		collapseNullableTypes(sub)
	}
	for _, sub := range s.Defs {
		collapseNullableTypes(sub)
	}
	collapseNullableTypes(s.Items)
	collapseNullableTypes(s.AdditionalProperties)
}

func toolError(t *mcp.Tool, err error) error {
	name := ""
	if t != nil {
		name = t.Name
	}
	return fmt.Errorf("mcpkit: tool %q: %w", name, err)
}
