package mcpkit

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Content is an application's prompts, resources and completions: the one
// extension of an endpoint beyond tools. It cannot reach the SDK server, its
// tools or its locked options.
type Content interface {
	// ServerOptions is called once, when the endpoint is created. setCacheable
	// is the endpoint's cache-scope callback, for measuring results as the
	// SDK will send them.
	ServerOptions(setCacheable func(context.Context, mcp.Request, *mcp.Cacheable)) ContentOptions
	// Install is called once, when the builder seals, after every tool and
	// catalog filter, with the names of the tools registered on the endpoint.
	// The registrar is unusable once Install returns.
	Install(r *ContentRegistrar, tools []string)
}

// ContentOptions are the capabilities content may advertise. listChanged and
// subscribe must be false, and Completions and Complete come together.
type ContentOptions struct {
	Prompts     *mcp.PromptCapabilities
	Resources   *mcp.ResourceCapabilities
	Completions *mcp.CompletionCapabilities
	Complete    func(context.Context, *mcp.CompleteRequest) (*mcp.CompleteResult, error)
}

// contentOptions validates co and returns copies of its capability objects.
func contentOptions(co ContentOptions) (ContentOptions, error) {
	switch {
	case co.Prompts != nil && co.Prompts.ListChanged,
		co.Resources != nil && (co.Resources.ListChanged || co.Resources.Subscribe):
		return ContentOptions{}, errors.New("content capabilities must not advertise listChanged or subscribe")
	case (co.Completions == nil) != (co.Complete == nil):
		return ContentOptions{}, errors.New("the completions capability and its handler come together")
	}
	var errs [3]error
	co.Prompts, errs[0] = snapshot(co.Prompts)
	co.Resources, errs[1] = snapshot(co.Resources)
	co.Completions, errs[2] = snapshot(co.Completions)
	return co, errors.Join(errs[:]...)
}

// ContentRegistrar registers an endpoint's content during Content.Install.
// It accepts prompts and resources only under the capability the content
// declared, snapshots their descriptors, and confines receiving middleware to
// the six content methods in both directions, so content can neither
// re-enable list-change inference nor intercept or dispatch a tool call.
type ContentRegistrar struct {
	server *mcp.Server
	opts   ContentOptions
	closed atomic.Bool
	err    error
}

func (r *ContentRegistrar) use() bool {
	if r.closed.Load() {
		panic("mcpkit: content registrar used after Install returned")
	}
	return r.err == nil
}

func (r *ContentRegistrar) refuse(why string) {
	r.err = errors.New("mcpkit: content " + why)
}

// AddPrompt registers a prompt; the content must have declared the prompts
// capability.
func (r *ContentRegistrar) AddPrompt(p *mcp.Prompt, h mcp.PromptHandler) {
	if !r.use() {
		return
	}
	if r.opts.Prompts == nil {
		r.refuse("registered a prompt without declaring the prompts capability")
		return
	}
	p, err := snapshot(p)
	if err != nil {
		r.refuse("prompt: " + err.Error())
		return
	}
	r.server.AddPrompt(p, h)
}

// AddResource registers a resource; the content must have declared the
// resources capability.
func (r *ContentRegistrar) AddResource(res *mcp.Resource, h mcp.ResourceHandler) {
	if !r.use() {
		return
	}
	if r.opts.Resources == nil {
		r.refuse("registered a resource without declaring the resources capability")
		return
	}
	res, err := snapshot(res)
	if err != nil {
		r.refuse("resource: " + err.Error())
		return
	}
	r.server.AddResource(res, h)
}

// AddReceivingMiddleware adds middleware that sees only the content methods;
// every other request bypasses it. Each content request gets its own
// continuation, bound to that request: it dispatches only the method that
// entered, and only with a context derived from the one it entered with.
// Anything else — a tool call, another method, a bare context or a context
// kept from another request, finished or still running — is refused without
// dispatch. The middleware is therefore applied to a fresh continuation per
// request; it must be cheap and stateless to construct.
func (r *ContentRegistrar) AddReceivingMiddleware(middleware ...mcp.Middleware) {
	if !r.use() {
		return
	}
	scoped := make([]mcp.Middleware, len(middleware))
	for i, mw := range middleware {
		scoped[i] = func(next mcp.MethodHandler) mcp.MethodHandler {
			return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
				if !contentMethod(method) {
					return next(ctx, method, req)
				}
				entry := &contentEntry{method: method}
				bound := func(ctx context.Context, m string, req mcp.Request) (mcp.Result, error) {
					if ctx.Value(contentEntryKey{}) != entry || m != method {
						return nil, errContentDispatch
					}
					return next(ctx, m, req)
				}
				return mw(bound)(context.WithValue(ctx, contentEntryKey{}, entry), method, req)
			}
		}
	}
	r.server.AddReceivingMiddleware(scoped...)
}

// contentEntry marks one content request; its address is the request's
// identity (it is never zero-sized, so every allocation is distinct).
type contentEntry struct{ method string }

type contentEntryKey struct{}

var errContentDispatch = &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "content middleware dispatched a method other than its own"}

func contentMethod(method string) bool {
	switch method {
	case "prompts/list", "prompts/get", "resources/list", "resources/templates/list", "resources/read", "completion/complete":
		return true
	}
	return false
}

// install runs at seal time: the page bound of a filtered catalog, then the
// endpoint's content against its registered tools.
func (ep *Endpoint) install() error {
	if ep.filtered && len(ep.tools) >= mcp.DefaultPageSize {
		return errors.New("filtered catalog does not fit one page")
	}
	if ep.content == nil {
		return nil
	}
	r := &ContentRegistrar{server: ep.server, opts: ep.contentOpt}
	ep.content.Install(r, slices.Clone(ep.tools))
	r.closed.Store(true)
	return r.err
}
