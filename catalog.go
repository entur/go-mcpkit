package mcpkit

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CatalogFilter narrows tools/list per caller while keeping the catalog one
// complete page. Hiding a tool is not authorization: a hidden tool's calls
// must still be refused by the tool itself.
type CatalogFilter struct {
	// Visible reports whether the caller of ctx may see the named tool.
	Visible func(ctx context.Context, tool string) bool
	// CursorError answers a tools/list request carrying a cursor (JSON-RPC
	// invalid params).
	CursorError string
	// IncompletePageError answers when the unfiltered catalog would not fit
	// one page (JSON-RPC internal error).
	IncompletePageError string
}

// UseCatalogFilter installs f on ep's tools/list. The filtered list is
// sorted by name and cache-private. At most one filter per endpoint; the
// endpoint's tool count must stay below mcp.DefaultPageSize when it serves.
func (ep *Endpoint) UseCatalogFilter(f CatalogFilter) error {
	if f.Visible == nil || strings.TrimSpace(f.CursorError) == "" || strings.TrimSpace(f.IncompletePageError) == "" {
		return errors.New("mcpkit: catalog filter needs Visible and both error messages")
	}
	ep.b.mu.Lock()
	defer ep.b.mu.Unlock()
	switch {
	case ep.b.sealed:
		return errSealed
	case ep.filtered:
		return errors.New("mcpkit: catalog filter installed twice")
	}
	ep.filtered = true
	ep.server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != "tools/list" {
				return next(ctx, method, req)
			}
			if p, _ := req.GetParams().(*mcp.ListToolsParams); p != nil && p.Cursor != "" {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: f.CursorError}
			}
			res, err := next(ctx, method, req)
			if err != nil {
				return nil, err
			}
			list, ok := res.(*mcp.ListToolsResult)
			if !ok || list.NextCursor != "" || len(list.Tools) >= mcp.DefaultPageSize {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: f.IncompletePageError}
			}
			visible := make([]*mcp.Tool, 0, len(list.Tools))
			for _, t := range list.Tools {
				if f.Visible(ctx, t.Name) {
					visible = append(visible, t)
				}
			}
			slices.SortFunc(visible, func(a, b *mcp.Tool) int { return strings.Compare(a.Name, b.Name) })
			return &mcp.ListToolsResult{Tools: visible, Cacheable: mcp.Cacheable{CacheScope: "private"}}, nil
		}
	})
	return nil
}
