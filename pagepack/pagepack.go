// Package pagepack is the byte-budget half of paging an MCP tool result.
//
// Every tool that returns a multiplicative array has to answer the same
// question: how many of these items fit the response? The output envelope
// is rejected WHOLE when it exceeds its budget, so a tool that guesses hands
// its caller nothing rather than a trimmed list, and a count cap alone
// cannot guess right: item sizes vary by an order of magnitude.
//
// The other half of paging (what a cursor means, how a tool resumes, what
// ordering makes resumption deterministic) is deliberately NOT here. It is
// source-specific: one source resumes on a timestamp, another on an
// upstream token, a snapshot on a key.
//
// SIZING IS MARSHAL-BASED, not estimated. Summing an item's raw text length
// undercounts by the JSON string escaping, which doubles every quote,
// backslash and control byte. The Marshal cost is negligible at these sizes
// and trades guess-the-inflation tuning for accounting that is accurate by
// construction.
package pagepack

import "encoding/json"

// Prefix returns the longest prefix of items whose complete JSON array
// encoding — the two brackets and the separating commas included — fits
// budget, and reports whether anything was left out.
//
// THERE IS NO OVERSIZE-FIRST-ITEM EXCEPTION. An item too large to fit
// alone yields an empty prefix and dropped=true, rather than a
// one-element array over budget: the envelope cap downstream is hard, so
// admitting it would turn a trimmed result into no result at all. Tools
// keep per-field caps on their items precisely so this stays unreachable
// for real data.
//
// A caller that pairs this with a cursor MUST NOT emit one when the
// prefix is empty and dropped is true. The next call would resume at the
// same item, drop it again, and return the same empty page forever. Such
// a caller either reports the item as omitted and moves past it, or
// returns no cursor at all.
//
// An item that fails to marshal ends the prefix and is reported as a
// drop. It is the caller's job to decide whether that is a data fault
// worth counting separately.
func Prefix[T any](items []T, budget int) (kept []T, dropped bool) {
	const brackets = 2 // '[' + ']'
	if budget < brackets {
		return nil, len(items) > 0
	}
	kept = make([]T, 0, len(items))
	used := brackets
	for _, item := range items {
		encoded, err := json.Marshal(item)
		if err != nil {
			return kept, true
		}
		size := len(encoded)
		if len(kept) > 0 {
			size++ // the comma separating it from the previous item
		}
		if used+size > budget {
			return kept, true
		}
		used += size
		kept = append(kept, item)
	}
	return kept, false
}

// PrefixCount is Prefix for a tool that reports how many items it left
// out rather than a flag. The count is exact: it is the tail this call
// did not admit, so a caller can publish it as omitted_by_budget without
// recounting.
func PrefixCount[T any](items []T, budget int) (kept []T, omitted int) {
	kept, dropped := Prefix(items, budget)
	if !dropped {
		return kept, 0
	}
	return kept, len(items) - len(kept)
}
