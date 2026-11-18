package retrieved

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBlockNormalizesReadableText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "hello world", want: "hello world"},
		{name: "markup stays readable", in: `<tag a="b">x & y</tag>`, want: `<tag a="b">x & y</tag>`},
		{name: "CDATA terminator is ordinary data", in: "before]]>after", want: "before]]>after"},
		{name: "CRLF becomes LF", in: "one\r\ntwo\rthree", want: "one\ntwo\nthree"},
		{name: "tab preserved", in: "one\ttwo", want: "one\ttwo"},
		{name: "controls replaced", in: "a\x00\x01b", want: "a��b"},
		{name: "invalid UTF-8 replaced", in: "a\xffb", want: "a�b"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Block(test.in, 1024); got != test.want {
				t.Fatalf("Block(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

func TestInlineCollapsesWhitespaceAndUnsafeText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "My Title", want: "My Title"},
		{name: "whitespace", in: "  one\n\t two   three  ", want: "one two three"},
		{name: "controls", in: "one\x00\x01two", want: "one two"},
		{name: "bidi", in: "one\u202Etwo", want: "one two"},
		{name: "terminator", in: "one]]>two", want: "one]]>two"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Inline(test.in, 1024); got != test.want {
				t.Fatalf("Inline(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

func TestBlockCapsJSONEncodedBytes(t *testing.T) {
	const max = 128
	inputs := []string{
		strings.Repeat("a", 1000),
		strings.Repeat(`"\\`, 1000),
		strings.Repeat("]]>", 1000),
		strings.Repeat("<>&", 1000),
		strings.Repeat("ø", 1000),
		strings.Repeat("line\n", 1000),
	}
	for _, input := range inputs {
		out := Block(input, max)
		if got := encodedContentBytes(t, out); got > max {
			t.Errorf("encoded Block size = %d, want <= %d for input prefix %q", got, max, input[:min(len(input), 12)])
		}
		if !utf8.ValidString(out) {
			t.Errorf("Block returned invalid UTF-8: %q", out)
		}
		if !strings.Contains(out, "[truncated]") {
			t.Errorf("Block omitted truncation marker: %q", out)
		}
	}
}

func TestInlineCapsJSONEncodedBytes(t *testing.T) {
	const max = 64
	out := Inline(strings.Repeat(`<&>"\\`, 100), max)
	if got := encodedContentBytes(t, out); got > max {
		t.Fatalf("encoded Inline size = %d, want <= %d", got, max)
	}
	if !strings.HasSuffix(out, "[truncated]") {
		t.Fatalf("Inline omitted truncation marker: %q", out)
	}
}

func TestStructuralPreservesUsableSpacingAndNeutralizesUnsafeText(t *testing.T) {
	got := Structural("dir/two  spaces\nfile\u202e.go", 128)
	want := "dir/two  spaces�file�.go"
	if got != want {
		t.Fatalf("Structural = %q, want %q", got, want)
	}
	if collapsed := Inline("dir/two  spaces", 128); collapsed == Structural("dir/two  spaces", 128) {
		t.Fatalf("fixture did not prove Structural preserves repeated spaces: %q", collapsed)
	}
}

func TestStructuralCapsJSONEncodedBytes(t *testing.T) {
	const max = 64
	out := Structural(strings.Repeat(`path/<&>"\\`, 100), max)
	if got := encodedContentBytes(t, out); got > max {
		t.Fatalf("encoded Structural size = %d, want <= %d", got, max)
	}
	if !strings.HasSuffix(out, "[truncated]") {
		t.Fatalf("Structural omitted truncation marker: %q", out)
	}
}

func TestOpaqueNeverMutatesFollowUpValues(t *testing.T) {
	if got := Opaque("abc_DEF-123", 32); got != "abc_DEF-123" {
		t.Fatalf("Opaque valid token = %q", got)
	}
	for _, value := range []string{"bad\ntoken", "abc\u202etoken", strings.Repeat("x", 33)} {
		if got := Opaque(value, 32); got != "" {
			t.Fatalf("Opaque(%q) = %q, want empty", value, got)
		}
	}
}

func TestExactBudgetDoesNotTruncate(t *testing.T) {
	if got := Block("abcde", 5); got != "abcde" {
		t.Fatalf("Block exact budget = %q, want abcde", got)
	}
	// encoding/json renders > as \u003e, so "]]>" costs eight bytes.
	if got := Block("]]>", 8); got != "]]>" {
		t.Fatalf("Block escaped exact budget = %q, want ]]>", got)
	}
}

func TestBudgetFailsClosed(t *testing.T) {
	for _, max := range []int{0, -1, -100} {
		if got := Block("secret", max); got != "" {
			t.Errorf("Block max=%d = %q, want empty", max, got)
		}
		if got := Inline("secret", max); got != "" {
			t.Errorf("Inline max=%d = %q, want empty", max, got)
		}
	}
	if got := Block("ørn", 1); got != "" {
		t.Fatalf("Block split a multibyte rune: %q", got)
	}
}

func TestSlice(t *testing.T) {
	got := Slice([]string{"one", "", " two\nlines ", "three", "four"}, 64, 3)
	want := []string{"one", "two lines", "three"}
	if len(got) != len(want) {
		t.Fatalf("Slice len = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Slice[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if got := Slice([]string{"one"}, 64, 0); got != nil {
		t.Fatalf("Slice maxItems=0 = %v, want nil", got)
	}
}

func TestOpaqueSliceOmitsInsteadOfRewriting(t *testing.T) {
	got, changed := OpaqueSlice([]string{"usable-id", "bad\nvalue", strings.Repeat("x", 20), "tail"}, 12, 3)
	if !changed {
		t.Fatal("OpaqueSlice changed=false, want true")
	}
	want := []string{"usable-id", "tail"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("OpaqueSlice = %#v, want %#v", got, want)
	}
	for _, value := range got {
		if strings.Contains(value, "truncated") {
			t.Fatalf("opaque value was rewritten: %q", value)
		}
	}
}

func TestStringMapBoundsAndNormalizes(t *testing.T) {
	values := map[string]string{
		"z":                 strings.Repeat(`"<&>`, 100),
		"a\nunsafe":         "value\u202e",
		"a unsafe":          "collision",
		"third":             "three",
		"fourth-is-omitted": "four",
	}
	got, changed := StringMap(values, 3, 32, 64, 128)
	if !changed {
		t.Fatal("StringMap did not report normalization/omission")
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal map: %v", err)
	}
	if len(encoded) > 128 {
		t.Fatalf("encoded map bytes = %d, want <= 128: %s", len(encoded), encoded)
	}
	if len(got) > 3 {
		t.Fatalf("map items = %d, want <= 3", len(got))
	}
	for key, value := range got {
		if strings.ContainsAny(key+value, "\r\n\t\u202e") {
			t.Fatalf("unsafe key/value survived: %q=%q", key, value)
		}
	}
}

func TestStringMapFailsClosed(t *testing.T) {
	for _, args := range [][4]int{{0, 1, 1, 2}, {1, 0, 1, 2}, {1, 1, 0, 2}, {1, 1, 1, 1}} {
		got, changed := StringMap(map[string]string{"key": "value"}, args[0], args[1], args[2], args[3])
		if got != nil || !changed {
			t.Fatalf("StringMap%v = %v, %v; want nil, true", args, got, changed)
		}
	}
}

func TestNeutralizesBidiAndControls(t *testing.T) {
	for _, r := range []rune{0x202E, 0x2066, 0x2069, 0x200F, 0x061C, 0x009B, 0x0085} {
		input := "before" + string(r) + "after"
		for _, out := range []string{Block(input, 100), Inline(input, 100)} {
			if strings.ContainsRune(out, r) {
				t.Errorf("U+%04X survived normalization: %q", r, out)
			}
		}
	}
}

func FuzzBlock(f *testing.F) {
	for _, seed := range []string{"", "hello", "a]]>b", "</retrieved>", "\x00\x01", "ø", `"quote" & <tag>`} {
		f.Add(seed, uint16(256))
	}
	f.Fuzz(func(t *testing.T, input string, rawMax uint16) {
		max := int(rawMax % 4096)
		out := Block(input, max)
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 for input %q: %q", input, out)
		}
		if max <= 0 {
			if out != "" {
				t.Fatalf("max=%d returned %q", max, out)
			}
			return
		}
		if got := encodedContentBytes(t, out); got > max {
			t.Fatalf("encoded size %d exceeds max %d for input %q", got, max, input)
		}
	})
}

func FuzzInline(f *testing.F) {
	for _, seed := range []string{"", "hello\nworld", "a]]>b", "\x00", "ø", `"quote" & <tag>`} {
		f.Add(seed, uint16(256))
	}
	f.Fuzz(func(t *testing.T, input string, rawMax uint16) {
		max := int(rawMax % 2048)
		out := Inline(input, max)
		if strings.ContainsAny(out, "\r\n\t") {
			t.Fatalf("inline returned whitespace control for input %q: %q", input, out)
		}
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 for input %q: %q", input, out)
		}
		if max > 0 {
			if got := encodedContentBytes(t, out); got > max {
				t.Fatalf("encoded size %d exceeds max %d for input %q", got, max, input)
			}
		}
	})
}

func encodedContentBytes(t *testing.T, text string) int {
	t.Helper()
	encoded, err := json.Marshal(text)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if len(encoded) < 2 {
		t.Fatalf("invalid encoded JSON string: %q", encoded)
	}
	return len(encoded) - 2
}
