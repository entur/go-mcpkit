package pagepack

import (
	"encoding/json"
	"strings"
	"testing"
)

type item struct {
	Name string `json:"name"`
}

// TestPrefixFitsTheCompleteArray is the contract every caller depends on:
// the budget is measured against what actually goes on the wire, brackets
// and commas included, not against the sum of the items.
func TestPrefixFitsTheCompleteArray(t *testing.T) {
	items := make([]item, 20)
	for i := range items {
		items[i] = item{Name: strings.Repeat("x", 10)}
	}
	for _, budget := range []int{0, 1, 2, 3, 25, 26, 40, 100, 1000} {
		kept, dropped := Prefix(items, budget)
		encoded, err := json.Marshal(kept)
		if err != nil {
			t.Fatalf("budget %d: marshal: %v", budget, err)
		}
		if budget >= 2 && len(encoded) > budget {
			t.Errorf("budget %d: kept %d items encoding to %d bytes", budget, len(kept), len(encoded))
		}
		if dropped != (len(kept) < len(items)) {
			t.Errorf("budget %d: dropped=%v with %d of %d kept", budget, dropped, len(kept), len(items))
		}
	}
}

// TestPrefixAdmitsNoOversizeFirstItem pins the rule the envelope cap
// downstream depends on. A one-element array over budget would be
// rejected whole by the output envelope, so the packer must return nothing rather
// than something unshippable.
func TestPrefixAdmitsNoOversizeFirstItem(t *testing.T) {
	huge := []item{{Name: strings.Repeat("x", 1000)}, {Name: "small"}}
	kept, dropped := Prefix(huge, 100)
	if len(kept) != 0 {
		t.Errorf("kept %d items, want none: the first does not fit alone", len(kept))
	}
	if !dropped {
		t.Error("dropped=false although nothing was returned")
	}

	// And the caller can see it made no progress, which is what stops a
	// cursor loop: kept is empty AND dropped is true.
	if len(kept) == 0 && !dropped {
		t.Error("an empty prefix must report dropped so a caller can refuse to emit a cursor")
	}
}

// TestPrefixCountReportsTheExactTail: a tool publishes this number as
// omitted_by_budget, so an approximation would be a wrong count in a
// response rather than an internal detail.
func TestPrefixCountReportsTheExactTail(t *testing.T) {
	items := make([]item, 10)
	for i := range items {
		items[i] = item{Name: "abcdefghij"}
	}
	full, omitted := PrefixCount(items, 10_000)
	if len(full) != 10 || omitted != 0 {
		t.Errorf("whole list: kept %d omitted %d, want 10 and 0", len(full), omitted)
	}
	kept, omitted := PrefixCount(items, 60)
	if omitted != len(items)-len(kept) {
		t.Errorf("omitted = %d, want %d", omitted, len(items)-len(kept))
	}
	if len(kept) == 0 || len(kept) == len(items) {
		t.Fatalf("budget did not trim: kept %d of %d", len(kept), len(items))
	}
}

// TestPrefixStopsAtAnUnmarshallableItem: the item ends the prefix and is
// reported as a drop, rather than being skipped, so a caller pairing this
// with a cursor cannot resume past data it never returned.
func TestPrefixStopsAtAnUnmarshallableItem(t *testing.T) {
	items := []any{item{Name: "fine"}, make(chan int), item{Name: "unreachable"}}
	kept, dropped := Prefix(items, 10_000)
	if len(kept) != 1 || !dropped {
		t.Errorf("kept %d items, dropped=%v; want the one good item and a drop", len(kept), dropped)
	}
}

// TestPrefixKeepsOrder: paging by position requires the packer to be a
// prefix, not a subset.
func TestPrefixKeepsOrder(t *testing.T) {
	items := []item{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}}
	kept, _ := Prefix(items, 30)
	for i, k := range kept {
		if k != items[i] {
			t.Fatalf("kept[%d] = %v, want %v: the result must be a prefix", i, k, items[i])
		}
	}
}
