// Package retrieved normalizes and bounds externally authored text before it
// is returned below the MCP schema-v2 untrusted_data subtree.
//
// The public JSON object boundary, applied centrally at tool registration,
// prevents structural delimiter breakout. This package keeps
// the text readable while removing characters that can hide or visually
// reorder it. Its byte limits are measured after encoding/json string
// escaping, matching the representation the MCP SDK serializes; quotes,
// backslashes, newlines, and angle brackets therefore cannot expand a field
// beyond its declared budget.
//
// This is defence in depth, not semantic prompt-injection prevention. Natural
// language below untrusted_data remains data that clients must not allow to
// authorize tool calls, disclosure, transmission, permission changes, or
// writes.
package retrieved

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	blockMark   = "\n[truncated]"
	inlineMark  = " [truncated]"
	replacement = '�'
)

// Block normalizes multi-line externally authored text while preserving
// newlines and tabs. The returned string's JSON-encoded content (excluding its
// surrounding quotes) is at most max bytes. Empty input and non-positive
// budgets fail closed to an empty string.
func Block(text string, max int) string {
	if text == "" || max <= 0 {
		return ""
	}
	return capJSON(normalizeBlock(text), max, blockMark)
}

// Offset and budget failures of BlockPage. Callers map the offset errors to
// their own invalid-argument class; ErrPageBudgetTooSmall is a configuration
// fault, not a caller mistake.
var (
	ErrPageOffsetNegative        = errors.New("page offset is negative")
	ErrPageOffsetPastEnd         = errors.New("page offset is past the end of the text")
	ErrPageOffsetNotRuneBoundary = errors.New("page offset is not on a UTF-8 rune boundary")
	ErrPageBudgetTooSmall        = errors.New("page budget is below the minimum")
)

// MinPageJSONBytes is the smallest BlockPage budget: two JSON string quotes
// plus the most expensive single rune (six bytes), so every page can make
// progress.
const MinPageJSONBytes = 8

// BlockPageResult is one marker-free window of a normalized block.
type BlockPageResult struct {
	// Text is the normalized text in [offset, End). It carries no truncation
	// marker; concatenating the pages of one body in order yields the whole
	// normalized body exactly.
	Text string
	// End is the normalized byte offset just past Text.
	End int
	// TotalBytes is the length in bytes of the entire normalized text.
	TotalBytes int
	// Normalized reports whether normalization changed the entire input,
	// independent of the requested page.
	Normalized bool
}

// BlockPage normalizes raw exactly as Block does and returns the largest
// rune-aligned prefix of the normalized text starting at offset whose
// JSON-encoded string, including its two quotes, is at most maxJSONBytes.
// offset is a UTF-8 byte position in the normalized text, not in raw.
// Content is never skipped to fit a cheaper later rune, and no marker is
// added: remaining text exists exactly when End < TotalBytes. For any offset
// below TotalBytes the page is non-empty, so End > offset; at TotalBytes it
// is empty.
func BlockPage(raw string, offset, maxJSONBytes int) (BlockPageResult, error) {
	if maxJSONBytes < MinPageJSONBytes {
		return BlockPageResult{}, ErrPageBudgetTooSmall
	}
	if offset < 0 {
		return BlockPageResult{}, ErrPageOffsetNegative
	}
	normalized := normalizeBlock(raw)
	total := len(normalized)
	if offset > total {
		return BlockPageResult{}, ErrPageOffsetPastEnd
	}
	if offset < total && !utf8.RuneStart(normalized[offset]) {
		return BlockPageResult{}, ErrPageOffsetNotRuneBoundary
	}
	text := capJSONPrefix(normalized[offset:], maxJSONBytes-2)
	return BlockPageResult{
		Text:       text,
		End:        offset + len(text),
		TotalBytes: total,
		Normalized: normalized != raw,
	}, nil
}

// Inline normalizes short externally authored text for titles, names,
// subjects, and label values. Runs of whitespace or unsafe characters become
// one space, and the JSON-encoded content is capped at max bytes.
func Inline(text string, max int) string {
	if text == "" || max <= 0 {
		return ""
	}
	return capJSON(normalizeInline(text), max, inlineMark)
}

// Structural normalizes an externally supplied identifier, path, URL, enum,
// or similar single-line value without collapsing ordinary spaces. Control
// and bidirectional-formatting characters become a visible replacement rune;
// the JSON-encoded content is capped at max bytes. Values that require a
// stricter grammar must be validated at their package boundary as well.
func Structural(text string, max int) string {
	if text == "" || max <= 0 {
		return ""
	}
	text = strings.ToValidUTF8(text, string(replacement))
	text = strings.Map(func(r rune) rune {
		if isUnsafe(r) {
			return replacement
		}
		return r
	}, text)
	return capJSON(text, max, inlineMark)
}

// Opaque validates a token, hash, cursor, or other follow-up argument that
// cannot be safely rewritten. It returns the original value only when
// Structural normalization would leave it byte-for-byte unchanged and within
// max JSON-content bytes; otherwise it returns an empty string. Callers may
// omit the value or surface a domain truncation signal, but must never return
// a mutated opaque token with a truncation marker.
func Opaque(text string, max int) string {
	if normalized := Structural(text, max); normalized == text {
		return text
	}
	return ""
}

// Slice inline-normalizes each non-empty element and returns at most maxItems.
// It returns nil when no usable values remain so omitempty fields drop cleanly.
func Slice(items []string, maxPerItem, maxItems int) []string {
	if maxPerItem <= 0 || maxItems <= 0 {
		return nil
	}
	out := make([]string, 0, min(len(items), maxItems))
	for _, item := range items {
		if len(out) >= maxItems {
			break
		}
		if normalized := Inline(item, maxPerItem); normalized != "" {
			out = append(out, normalized)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// OpaqueSlice bounds a collection of follow-up arguments without rewriting
// any element. Invalid, empty, or over-budget values are omitted; changed is
// true when an element or tail was dropped. This lets callers surface a
// truncation signal instead of returning identifiers that no longer work.
func OpaqueSlice(items []string, maxPerItem, maxItems int) ([]string, bool) {
	if len(items) == 0 {
		return nil, false
	}
	if maxPerItem <= 0 || maxItems <= 0 {
		return nil, true
	}
	out := make([]string, 0, min(len(items), maxItems))
	changed := false
	for _, item := range items {
		if len(out) >= maxItems {
			changed = true
			break
		}
		normalized := Opaque(item, maxPerItem)
		if normalized == "" {
			changed = true
			continue
		}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return nil, changed
	}
	return out, changed
}

// StringMap deterministically projects a map of externally supplied labels or
// attributes. Keys and values use Structural normalization, duplicate keys
// created by normalization are dropped, and both item count and the complete
// JSON object encoding are bounded. The boolean reports any normalization,
// collision, truncation, or omission so callers can expose that loss when it
// matters to the domain.
func StringMap(values map[string]string, maxItems, maxKeyBytes, maxValueBytes, maxJSONBytes int) (map[string]string, bool) {
	if len(values) == 0 {
		return nil, false
	}
	if maxItems <= 0 || maxKeyBytes <= 0 || maxValueBytes <= 0 || maxJSONBytes < 2 {
		return nil, true
	}
	keys := slices.Sorted(maps.Keys(values))

	out := make(map[string]string, min(len(values), maxItems))
	changed := false
	for _, key := range keys {
		if len(out) >= maxItems {
			changed = true
			break
		}
		normalizedKey := Structural(key, maxKeyBytes)
		normalizedValue := Structural(values[key], maxValueBytes)
		if normalizedKey == "" {
			changed = true
			continue
		}
		if normalizedKey != key || normalizedValue != values[key] {
			changed = true
		}
		if _, exists := out[normalizedKey]; exists {
			changed = true
			continue
		}
		out[normalizedKey] = normalizedValue
		encoded, err := json.Marshal(out)
		if err != nil || len(encoded) > maxJSONBytes {
			delete(out, normalizedKey)
			changed = true
		}
	}
	if len(out) == 0 {
		return nil, true
	}
	return out, changed
}

// capJSON caps a valid UTF-8 string by the number of bytes encoding/json uses
// inside the string's quotes. Rune costs are additive for valid UTF-8; the
// special cases mirror encoding/json's appendString implementation, including
// its default HTML-safe escaping of <, >, and &.
func capJSON(text string, max int, mark string) string {
	if text == "" || max <= 0 {
		return ""
	}
	if jsonStringBytes(text) <= max {
		return text
	}

	markCost := jsonStringBytes(mark)
	bodyBudget := max - markCost
	if bodyBudget <= 0 {
		return capJSONPrefix(text, max)
	}
	body := capJSONPrefix(text, bodyBudget)
	if body == "" {
		return capJSONPrefix(text, max)
	}
	return body + mark
}

func capJSONPrefix(text string, max int) string {
	if max <= 0 {
		return ""
	}
	cost := 0
	end := 0
	for i, r := range text {
		runeCost := jsonRuneBytes(r)
		if cost+runeCost > max {
			break
		}
		cost += runeCost
		end = i + utf8.RuneLen(r)
	}
	return text[:end]
}

func jsonStringBytes(text string) int {
	total := 0
	for _, r := range text {
		total += jsonRuneBytes(r)
	}
	return total
}

func jsonRuneBytes(r rune) int {
	switch r {
	case '\\', '"', '\b', '\f', '\n', '\r', '\t':
		return 2
	case '<', '>', '&', '\u2028', '\u2029':
		return 6
	default:
		if r < 0x20 {
			return 6
		}
		return utf8.RuneLen(r)
	}
}

func normalizeBlock(text string) string {
	text = strings.ToValidUTF8(text, string(replacement))
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' {
			return r
		}
		if isUnsafe(r) {
			return replacement
		}
		return r
	}, text)
}

func normalizeInline(text string) string {
	text = strings.ToValidUTF8(text, string(replacement))
	var b strings.Builder
	b.Grow(len(text))
	pendingSpace := false
	for _, r := range text {
		if unicode.IsSpace(r) || isUnsafe(r) {
			pendingSpace = true
			continue
		}
		if pendingSpace && b.Len() > 0 {
			b.WriteByte(' ')
		}
		pendingSpace = false
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func isUnsafe(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || !utf8.ValidRune(r)
}
