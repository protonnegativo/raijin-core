package schema

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// finding and group stand in for a tool's own types. They follow the rules every tool follows: a Count
// that is written only when the budget cut the locations, and a Fingerprint that never is.
type finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence,omitempty"`
	Locations   []string `json:"locations"`
	Count       int      `json:"count,omitempty"`
	Fingerprint string   `json:"-"`
	New         bool     `json:"new,omitempty"`
}

func (f finding) MarshalJSON() ([]byte, error) {
	type plain finding
	p := plain(f)
	p.Count = OmitCount(p.Count, len(p.Locations))
	return Marshal(p)
}

type group struct {
	ID        string   `json:"id"`
	Locations []string `json:"locations,omitempty"`
	Count     int      `json:"count,omitempty"`
}

func (g group) MarshalJSON() ([]byte, error) {
	type plain group
	p := plain(g)
	p.Count = OmitCount(p.Count, len(p.Locations))
	return Marshal(p)
}

type result = Result[finding, group]

func TestResultOmitsWhatCanBeRebuilt(t *testing.T) {
	res := result{
		Tool:     "raijin-x",
		Findings: []finding{{ID: "a", Locations: []string{"https://a/1", "https://b/1"}, Count: 2, Fingerprint: "fp"}},
		Groups:   []group{{ID: "g", Locations: []string{"https://a"}, Count: 1}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "count", "confidence", "omitted", "errors", "next", "raw", "budget", "origin", "url", "match", "filter", "new"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := result{
		Findings: []finding{{ID: "a", Locations: []string{"https://a/1"}, Count: 7}},
		Groups:   []group{{ID: "g", Count: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"locations":["https://a/1"],"count":7`) || !strings.Contains(s, `{"id":"g","count":4}`) {
		t.Errorf("count must be written when locations were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
}

func TestResultJSON(t *testing.T) {
	full := result{
		Tool: "raijin-x", Version: "1.2.3", Target: "example.com", Summary: "1 finding",
		Origin: "https://example.com", URL: "https://example.com/FUZZ", Match: "status 200", Filter: "size 0",
		Findings: []finding{{ID: "a", Title: "A", Severity: "high", Confidence: "verified", Locations: []string{"/x?a=1&b=<2>"}, New: true}},
		Groups:   []group{{ID: "g", Locations: []string{"/y"}}},
		Omitted:  map[string]int{"out_of_scope": 2, "duplicates": 1},
		Errors:   []Error{{Kind: "engine", Hint: "install it"}},
		Next:     []string{"raijin-y -l raw.txt"},
		Raw:      "/tmp/raw.txt",
		Budget:   Budget{MaxItems: 5, MaxBytes: 100, Truncated: true},
	}
	tests := []struct {
		name string
		res  result
		want string
	}{
		{"every field, in order", full,
			`{"tool":"raijin-x","version":"1.2.3","target":"example.com","summary":"1 finding",` +
				`"origin":"https://example.com","url":"https://example.com/FUZZ","match":"status 200","filter":"size 0",` +
				`"findings":[{"id":"a","title":"A","severity":"high","confidence":"verified","locations":["/x?a=1&b=<2>"],"new":true}],` +
				`"groups":[{"id":"g","locations":["/y"]}],` +
				`"omitted":{"duplicates":1,"out_of_scope":2},"errors":[{"kind":"engine","hint":"install it"}],` +
				`"next":["raijin-y -l raw.txt"],"raw":"/tmp/raw.txt","budget":{"max_items":5,"max_bytes":100,"truncated":true}}`},
		{"empty", result{Tool: "raijin-x", Budget: Budget{MaxBytes: 100}},
			`{"tool":"raijin-x","version":"","target":"","summary":"","findings":[],"groups":[]}`},
		{"nil and empty lists are both []", result{Findings: []finding{}, Groups: []group{}},
			`{"tool":"","version":"","target":"","summary":"","findings":[],"groups":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := Marshal(tt.res)
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != tt.want {
				t.Errorf("got  %s\nwant %s", b, tt.want)
			}
			if !json.Valid(b) {
				t.Error("invalid JSON")
			}
		})
	}
}

// A Result must marshal the same through json.Marshal, a json.Encoder and Marshal, once HTML escaping is
// off; and a pointer to a Result must work too.
func TestResultMarshalsThroughAnyEncoder(t *testing.T) {
	res := result{Tool: "t", Findings: []finding{{ID: "a", Locations: []string{"a&b"}}}}
	want, _ := Marshal(res)
	var buf bytes.Buffer
	if err := Write(&buf, &res, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSuffix(buf.String(), "\n"); got != string(want) {
		t.Errorf("Write = %s, want %s", got, want)
	}
	viaStd, _ := json.Marshal(res)
	var a, b any
	_ = json.Unmarshal(viaStd, &a)
	_ = json.Unmarshal(want, &b)
	if !jsonEqual(a, b) {
		t.Errorf("json.Marshal and Marshal disagree: %s vs %s", viaStd, want)
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func TestMarshalDoesNotEscapeHTML(t *testing.T) {
	b, err := Marshal(map[string]string{"k": "a->b <c> & d"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"k":"a->b <c> & d"}` {
		t.Errorf("got %s", b)
	}
}

func TestWrite(t *testing.T) {
	v := map[string]any{"a": 1, "b": "<x>"}
	var plain, pretty bytes.Buffer
	if err := Write(&plain, v, false); err != nil {
		t.Fatal(err)
	}
	if plain.String() != "{\"a\":1,\"b\":\"<x>\"}\n" {
		t.Errorf("plain = %q", plain.String())
	}
	if err := Write(&pretty, v, true); err != nil {
		t.Fatal(err)
	}
	if pretty.String() != "{\n  \"a\": 1,\n  \"b\": \"<x>\"\n}\n" {
		t.Errorf("pretty = %q", pretty.String())
	}
}

func TestOmitCount(t *testing.T) {
	tests := []struct{ count, listed, want int }{
		{0, 0, 0}, {0, 3, 0}, {3, 3, 0}, {2, 3, 0}, {4, 3, 4}, {7, 0, 7},
	}
	for _, tt := range tests {
		if got := OmitCount(tt.count, tt.listed); got != tt.want {
			t.Errorf("OmitCount(%d, %d) = %d, want %d", tt.count, tt.listed, got, tt.want)
		}
	}
}

func TestRanks(t *testing.T) {
	order := []string{"critical", "high", "medium", "low", "info", "unknown"}
	for i := 1; i < len(order); i++ {
		if SeverityRank[order[i-1]] <= SeverityRank[order[i]] {
			t.Errorf("%s should rank above %s", order[i-1], order[i])
		}
	}
	if SeverityRank["made-up"] != SeverityRank["unknown"] {
		t.Error("a severity that is not listed ranks as unknown")
	}
	if !(ConfidenceRank["verified"] > ConfidenceRank[""] && ConfidenceRank[""] > ConfidenceRank["heuristic"]) {
		t.Error("verified > matched (empty) > heuristic")
	}
}

func TestSortedKeys(t *testing.T) {
	if got := strings.Join(SortedKeys(map[string]int{"b": 1, "a": 2, "c": 3}), ","); got != "a,b,c" {
		t.Errorf("got %s", got)
	}
	if got := SortedKeys(map[string]bool(nil)); len(got) != 0 || got == nil {
		t.Errorf("a nil map gives an empty, non-nil list: %#v", got)
	}
}
