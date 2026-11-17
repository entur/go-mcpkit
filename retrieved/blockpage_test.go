package retrieved

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"unicode/utf8"
)

// marshaledBytes is the independent oracle: the real encoding/json size of
// the page including both quotes.
func marshaledBytes(t *testing.T, s string) int {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

// walkPages follows End until the text is exhausted and returns the pages.
func walkPages(t *testing.T, raw string, budget int) []BlockPageResult {
	t.Helper()
	var pages []BlockPageResult
	offset := 0
	for i := 0; i <= len(raw)*3+2; i++ {
		p, err := BlockPage(raw, offset, budget)
		if err != nil {
			t.Fatalf("offset %d: %v", offset, err)
		}
		pages = append(pages, p)
		if p.End >= p.TotalBytes {
			return pages
		}
		if p.End <= offset || p.Text == "" {
			t.Fatalf("no progress at offset %d: end=%d text=%q", offset, p.End, p.Text)
		}
		offset = p.End
	}
	t.Fatal("pagination did not terminate")
	return nil
}

func TestBlockPageReconstructsNormalizedText(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"ascii", strings.Repeat("hello world\n", 40), strings.Repeat("hello world\n", 40)},
		{"accented", strings.Repeat("blåbærsyltetøy ", 30), strings.Repeat("blåbærsyltetøy ", 30)},
		{"cjk", strings.Repeat("日本語のテキスト", 30), strings.Repeat("日本語のテキスト", 30)},
		{"emoji", strings.Repeat("a😀b", 50), strings.Repeat("a😀b", 50)},
		{"combining", strings.Repeat("é", 60), strings.Repeat("é", 60)},
		{"crlf", strings.Repeat("a\r\nb", 40), strings.Repeat("a\nb", 40)},
		{"lone cr", strings.Repeat("a\rb", 40), strings.Repeat("a\nb", 40)},
		{"controls and bidi", strings.Repeat("a\x00b‮c", 30), strings.Repeat("a�b�c", 30)},
		{"invalid utf8", strings.Repeat("a\xff\xfeb", 30), strings.Repeat("a�b", 30)},
		{"escape heavy", strings.Repeat("<>&  \"\\", 20), strings.Repeat("<>&  \"\\", 20)},
	}
	for _, tc := range tests {
		for _, budget := range []int{MinPageJSONBytes, 9, 17, 64, 1000} {
			var got strings.Builder
			pages := walkPages(t, tc.raw, budget)
			for i, p := range pages {
				got.WriteString(p.Text)
				if p.TotalBytes != len(tc.want) {
					t.Fatalf("%s/%d page %d: total %d, want %d", tc.name, budget, i, p.TotalBytes, len(tc.want))
				}
				if !utf8.ValidString(p.Text) {
					t.Fatalf("%s/%d page %d: invalid UTF-8 %q", tc.name, budget, i, p.Text)
				}
				if p.Normalized != (tc.want != tc.raw) {
					t.Fatalf("%s/%d page %d: normalized=%v", tc.name, budget, i, p.Normalized)
				}
			}
			if got.String() != tc.want {
				t.Fatalf("%s/%d: reconstruction %q, want %q", tc.name, budget, got.String(), tc.want)
			}
		}
	}
}

// Normalization happens once, before slicing: a CRLF and an invalid run that
// a raw cut would split keep a single replacement/LF, and offsets address the
// normalized text.
func TestBlockPageOffsetsAddressNormalizedText(t *testing.T) {
	p, err := BlockPage("A\r\nB", 0, 1000)
	if err != nil || p.Text != "A\nB" || p.TotalBytes != 3 || p.End != 3 || !p.Normalized {
		t.Fatalf("got %+v, %v", p, err)
	}
	p, err = BlockPage("A\r\nB", 2, 1000)
	if err != nil || p.Text != "B" || p.End != 3 {
		t.Fatalf("offset 2: got %+v, %v", p, err)
	}
	// Budget 8 holds "A\n" (1+2) but not the next rune cost beyond 6.
	p, _ = BlockPage("A\r\nBBBBBBBB", 0, 8)
	if p.Text != "A\nBBB" || p.End != 5 {
		t.Fatalf("got %+v", p)
	}
}

func TestBlockPageOffsetValidation(t *testing.T) {
	body := "aø😀b" // offsets 0,1,3,7,8 are boundaries; total 8
	for offset, wantErr := range map[int]error{
		-1:          ErrPageOffsetNegative,
		2:           ErrPageOffsetNotRuneBoundary,
		4:           ErrPageOffsetNotRuneBoundary,
		5:           ErrPageOffsetNotRuneBoundary,
		6:           ErrPageOffsetNotRuneBoundary,
		9:           ErrPageOffsetPastEnd,
		math.MaxInt: ErrPageOffsetPastEnd,
	} {
		if _, err := BlockPage(body, offset, 100); !errors.Is(err, wantErr) {
			t.Errorf("offset %d: got %v, want %v", offset, err, wantErr)
		}
	}
	for _, offset := range []int{0, 1, 3, 7} {
		p, err := BlockPage(body, offset, 100)
		if err != nil || p.End != 8 || p.Text != body[offset:] {
			t.Errorf("offset %d: %+v, %v", offset, p, err)
		}
	}
	p, err := BlockPage(body, 8, 100)
	if err != nil || p.Text != "" || p.End != 8 || p.TotalBytes != 8 {
		t.Errorf("EOF page: %+v, %v", p, err)
	}
	p, err = BlockPage("", 0, 100)
	if err != nil || p.Text != "" || p.End != 0 || p.TotalBytes != 0 || p.Normalized {
		t.Errorf("empty body: %+v, %v", p, err)
	}
	if _, err := BlockPage("", 1, 100); !errors.Is(err, ErrPageOffsetPastEnd) {
		t.Errorf("empty body offset 1: %v", err)
	}
}

func TestBlockPageBudgetMinimum(t *testing.T) {
	for _, budget := range []int{-1, 0, 7} {
		if _, err := BlockPage("abc", 0, budget); !errors.Is(err, ErrPageBudgetTooSmall) {
			t.Errorf("budget %d: %v", budget, err)
		}
	}
	if _, err := BlockPage("abc", 0, 8); err != nil {
		t.Errorf("budget 8: %v", err)
	}
}

// The budget includes both quotes, the cut is maximal, and a rune that does
// not fit starts the next page intact instead of being skipped.
func TestBlockPageExactCuts(t *testing.T) {
	// 6 'a' cost 6; with quotes 8.
	body := "aaaaaaaa"
	for budget, want := range map[int]string{8: "aaaaaa", 9: "aaaaaaa", 10: "aaaaaaaa", 100: "aaaaaaaa"} {
		p, err := BlockPage(body, 0, budget)
		if err != nil || p.Text != want {
			t.Errorf("budget %d: %q, %v, want %q", budget, p.Text, err, want)
		}
	}
	// '<' costs 6: budget 8 fits exactly one, never the cheaper 'a' behind it.
	p, _ := BlockPage("<<a", 0, 8)
	if p.Text != "<" || p.End != 1 {
		t.Errorf("got %+v", p)
	}
	p, _ = BlockPage("a<a", 0, 8)
	if p.Text != "a" {
		t.Errorf("expensive rune must start the next page, got %q", p.Text)
	}
	p, _ = BlockPage("a<a", 1, 8)
	if p.Text != "<" || p.End != 2 {
		t.Errorf("got %+v", p)
	}
}

func TestBlockPageJSONWorstCase(t *testing.T) {
	const budget = 6 * 1024
	for name, unit := range map[string]string{
		"html":        "<>&",
		"separator":   "  ",
		"quotes":      "\"\\",
		"whitespace":  "\n\t",
		"emoji":       "😀",
		"replacement": "\x00",
		"mixed":       "<a\"\\\n😀é >&",
	} {
		raw := strings.Repeat(unit, 5000)
		offset := 0
		for {
			p, err := BlockPage(raw, offset, budget)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if got := marshaledBytes(t, p.Text); got > budget {
				t.Fatalf("%s: page at %d marshals to %d bytes, budget %d", name, offset, got, budget)
			}
			if p.End >= p.TotalBytes {
				break
			}
			// Maximality: the next normalized rune would not have fit.
			norm := normalizeBlock(raw)
			r, _ := utf8.DecodeRuneInString(norm[p.End:])
			if marshaledBytes(t, p.Text+string(r)) <= budget {
				t.Fatalf("%s: page at %d is not maximal", name, offset)
			}
			offset = p.End
		}
	}
	// A page of '<' holds at most (6144-2)/6 = 1023 characters.
	p, _ := BlockPage(strings.Repeat("<", 2000), 0, budget)
	if len(p.Text) != 1023 {
		t.Errorf("'<' page holds %d, want 1023", len(p.Text))
	}
}

// A literal truncation marker authored in the source survives exactly once
// and no synthetic marker appears at any boundary.
func TestBlockPageMarkerLiteralSurvivesOnce(t *testing.T) {
	raw := strings.Repeat("x", 30) + blockMark + strings.Repeat("y", 30) + blockMark
	for budget := MinPageJSONBytes; budget < 80; budget++ {
		var got strings.Builder
		for _, p := range walkPages(t, raw, budget) {
			got.WriteString(p.Text)
		}
		if got.String() != raw {
			t.Fatalf("budget %d: %q != %q", budget, got.String(), raw)
		}
		if n := strings.Count(got.String(), blockMark); n != 2 {
			t.Fatalf("budget %d: marker count %d, want 2", budget, n)
		}
	}
}

func FuzzBlockPageProgress(f *testing.F) {
	for _, seed := range []string{"", "hello", "a\r\nb", "<<<<<<", "  ", "ø😀", "\xff\xfe", blockMark, "a\x00b"} {
		f.Add(seed, uint8(8))
		f.Add(seed, uint8(40))
	}
	f.Fuzz(func(t *testing.T, raw string, rawBudget uint8) {
		budget := MinPageJSONBytes + int(rawBudget)%200
		norm := normalizeBlock(raw)
		var got strings.Builder
		offset := 0
		for pages := 0; ; pages++ {
			if pages > len(norm)+1 {
				t.Fatalf("too many pages for %q", raw)
			}
			p, err := BlockPage(raw, offset, budget)
			if err != nil {
				t.Fatalf("offset %d: %v", offset, err)
			}
			if !utf8.ValidString(p.Text) || p.End != offset+len(p.Text) || p.TotalBytes != len(norm) {
				t.Fatalf("bad page %+v at %d", p, offset)
			}
			if marshaledBytes(t, p.Text) > budget {
				t.Fatalf("page over budget at %d", offset)
			}
			got.WriteString(p.Text)
			if offset < p.TotalBytes && (p.Text == "" || p.End <= offset) {
				t.Fatalf("no progress at %d", offset)
			}
			if p.End >= p.TotalBytes {
				break
			}
			offset = p.End
		}
		if got.String() != norm {
			t.Fatalf("reconstruction mismatch for %q", raw)
		}
	})
}
