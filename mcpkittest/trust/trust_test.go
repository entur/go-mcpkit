package trust_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/entur/go-mcpkit/mcpkittest/trust"
	"github.com/entur/go-mcpkit/retrieved"
)

// TestUnsafeConstructedFromCodePoints proves the ASCII-only source really does
// build the bidi/control runes it documents, so downstream neutralization
// assertions are exercising the intended input.
func TestUnsafeConstructedFromCodePoints(t *testing.T) {
	for _, r := range []rune{0x202E, 0x202C, 0x0007, 0x0085, 0x009B} {
		if !strings.ContainsRune(trust.Unsafe, r) {
			t.Errorf("Unsafe is missing code point %U", r)
		}
	}
	if !utf8.ValidString(trust.Unsafe) {
		t.Fatal("Unsafe is not valid UTF-8")
	}
}

// TestRetrievedNeutralizesEveryCanary is the load-bearing cross-check: every
// retrieved projection helper must neutralize each canary, and the readable
// instruction text must survive as inert data (the boundary is structural, not
// keyword scrubbing).
func TestRetrievedNeutralizesEveryCanary(t *testing.T) {
	for _, canary := range trust.Corpus() {
		for _, tc := range []struct {
			name string
			got  string
		}{
			{"Block", retrieved.Block(canary, 4096)},
			{"Inline", retrieved.Inline(canary, 4096)},
			{"Structural", retrieved.Structural(canary, 4096)},
		} {
			trust.AssertNeutralized(t, tc.name, tc.got)
		}
	}

	// Inertness as data: the readable canary keeps its instruction words.
	if got := retrieved.Block(trust.Readable, 4096); got != trust.Readable {
		t.Errorf("readable canary was scrubbed rather than kept as inert data: %q", got)
	}

	// Opaque tokens fail closed: an unsafe value cannot round-trip unchanged.
	if got := retrieved.Opaque(trust.Unsafe, 4096); got != "" {
		t.Errorf("Opaque returned a mutated unsafe token %q, want empty", got)
	}
}

// TestWithinJSONBudgetMeasuresEscapedBytes confirms the helper counts real wire
// bytes: a string of quotes costs two bytes each once serialized, so a Go
// length under budget can still exceed the JSON budget.
func TestWithinJSONBudgetMeasuresEscapedBytes(t *testing.T) {
	payload := struct {
		S string `json:"s"`
	}{S: strings.Repeat(`"`, 20)}
	// Go length of the struct's string is 20; the marshaled object is far
	// larger once every quote is escaped and the envelope keys are added.
	if n := trust.AssertWithinJSONBudget(t, "quotes", payload, 4096); n <= 20 {
		t.Errorf("measured %d bytes; expected escaped serialization to exceed the raw length", n)
	}
}
