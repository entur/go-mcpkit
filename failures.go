package mcpkit

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"
)

// Summary is one fixed failure text, selected when a failing call's error
// matches Class with errors.Is and, for a keyed summary, when the catalog's
// key selector returns Key.
type Summary struct {
	Class error
	Key   string
	Text  string
}

// Failures is a tool's failure catalog: the only text a failing call can
// return. The kit never renders an error; it selects one of these literals.
type Failures struct {
	// Fallback answers an error no summary matches, and a result the kit
	// could not encode.
	Fallback string
	// Ordered is searched first to last. Put a keyed summary before the
	// unkeyed summary of the same class, and a narrower class before the
	// broader classes it also wraps.
	Ordered []Summary
	// Key optionally picks a keyed summary for an error. A key no summary
	// registers falls through to the unkeyed ones; it is never rendered.
	Key func(error) string
}

// Text returns the literal a failing call with err receives.
func (f Failures) Text(err error) string {
	if err == nil {
		return f.Fallback
	}
	key := ""
	if f.Key != nil {
		key = f.Key(err)
	}
	for _, s := range f.Ordered {
		if (s.Key == "" || s.Key == key) && errors.Is(err, s.Class) {
			return s.Text
		}
	}
	return f.Fallback
}

// frozen validates f and returns a copy the caller can no longer change.
func (f Failures) frozen() (Failures, error) {
	if !fixedText(f.Fallback) {
		return Failures{}, errors.New("failure catalog has no usable fallback")
	}
	type id struct {
		class error
		key   string
	}
	seen := map[id]bool{}
	for i, s := range f.Ordered {
		switch {
		case s.Class == nil || !reflect.TypeOf(s.Class).Comparable():
			return Failures{}, fmt.Errorf("failure summary %d has no comparable class", i)
		case !fixedText(s.Text):
			return Failures{}, fmt.Errorf("failure summary %d has no usable text", i)
		case seen[id{s.Class, s.Key}]:
			return Failures{}, fmt.Errorf("failure summary %d repeats class %q with key %q", i, s.Class, s.Key)
		}
		seen[id{s.Class, s.Key}] = true
	}
	f.Ordered = slices.Clone(f.Ordered)
	return f, nil
}

func fixedText(s string) bool { return strings.TrimSpace(s) != "" && utf8.ValidString(s) }
