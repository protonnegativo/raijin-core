package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEntryKeepsFieldOrderAndDoesNotEscape(t *testing.T) {
	in := `{"id":"x","severity":"low","route":"/s","locations":["/s?a=1&b=2","http://d -> https://d/"],"cvss":9.8}`
	var e Entry
	if err := json.Unmarshal([]byte(in), &e); err != nil {
		t.Fatal(err)
	}
	b, _ := Marshal(e)
	if string(b) != in {
		t.Errorf("got %s\nwant %s", b, in)
	}
}

func TestEntryEscapedAndPlainInputCompareEqual(t *testing.T) {
	var a, b Entry
	_ = json.Unmarshal([]byte(`{"id":"x","l":["a&b"]}`), &a)
	_ = json.Unmarshal([]byte(`{"id":"x","l":["a&b"]}`), &b)
	x, _ := Marshal(a)
	y, _ := Marshal(b)
	if string(x) != string(y) {
		t.Errorf("%s != %s", x, y)
	}
}

func TestPrettyInputComparesEqual(t *testing.T) {
	var a, b Entry
	_ = json.Unmarshal([]byte(`{"id":"x","a":["1","2"],"n":{"k":1}}`), &a)
	_ = json.Unmarshal([]byte("{\n  \"id\": \"x\",\n  \"a\": [\n    \"1\",\n    \"2\"\n  ],\n  \"n\": {\"k\": 1}\n}"), &b)
	x, _ := Marshal(a)
	y, _ := Marshal(b)
	if string(x) != string(y) {
		t.Errorf("%s != %s", x, y)
	}
}

func TestEntryKeepsLargeNumbersExact(t *testing.T) {
	var e Entry
	if err := json.Unmarshal([]byte(`{"n":12345678901234567890,"f":1.50}`), &e); err != nil {
		t.Fatal(err)
	}
	if b, _ := Marshal(e); string(b) != `{"n":12345678901234567890,"f":1.50}` {
		t.Errorf("got %s", b)
	}
}

func TestEntryRejectsNonObjects(t *testing.T) {
	for _, in := range []string{`[1]`, `"x"`, `1`, `null`, `{"a":`, `{"a":1`} {
		var e Entry
		if err := json.Unmarshal([]byte(in), &e); err == nil && in != `null` {
			t.Errorf("Unmarshal(%s) should fail", in)
		}
	}
}

func TestEntryAccessors(t *testing.T) {
	var e Entry
	if err := json.Unmarshal([]byte(`{"id":"x","severity":"low","tags":["a","b"],"n":3}`), &e); err != nil {
		t.Fatal(err)
	}
	if e.String("id") != "x" || e.String("n") != "" || e.String("missing") != "" {
		t.Errorf("String: %q %q %q", e.String("id"), e.String("n"), e.String("missing"))
	}
	if got := strings.Join(e.Strings("tags"), ","); got != "a,b" {
		t.Errorf("Strings = %s", got)
	}
	if e.Strings("id") != nil || e.Strings("missing") != nil {
		t.Error("Strings of a non-list is nil")
	}
	if v, ok := e.Get("n"); !ok || string(v) != "3" {
		t.Errorf("Get = %s %v", v, ok)
	}
	if _, ok := e.Get("missing"); ok {
		t.Error("Get of a missing key")
	}
	if !e.IsFinding() {
		t.Error("an entry with severity is a finding")
	}
}

func TestSetDeleteClone(t *testing.T) {
	var e Entry
	e.Set("a", 1)
	e.Set("b", []string{"x"})
	e.Set("a", 2)
	e.Set("c", json.RawMessage(`{"k":"<v>"}`))
	c := e.Clone()
	e.Delete("b")
	e.Delete("missing")
	if b, _ := Marshal(e); string(b) != `{"a":2,"c":{"k":"<v>"}}` {
		t.Errorf("got %s", b)
	}
	if b, _ := Marshal(c); string(b) != `{"a":2,"b":["x"],"c":{"k":"<v>"}}` {
		t.Errorf("a clone must not change with the original: %s", b)
	}
	if e.IsFinding() {
		t.Error("no severity: a group")
	}
	if b, _ := Marshal(Entry{}); string(b) != `{}` {
		t.Errorf("empty entry = %s", b)
	}
}

func TestParse(t *testing.T) {
	in := `{"tool":"raijin-cors","version":"0.3.0","target":"https://a","summary":"s","origin":"https://a",` +
		`"findings":[{"id":"f","severity":"high","locations":["/x"]}],"groups":[{"id":"g"}],` +
		`"omitted":{"out_of_scope":2},"errors":[{"kind":"k","hint":"h"}],"raw":"/tmp/r",` +
		`"budget":{"max_items":1,"max_bytes":2,"truncated":true}}`
	r, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if r.Tool != "raijin-cors" || r.Origin != "https://a" || r.Raw != "/tmp/r" || r.Omitted["out_of_scope"] != 2 ||
		len(r.Errors) != 1 || r.Errors[0].Kind != "k" || r.Budget == nil || !r.Budget.Truncated {
		t.Errorf("unexpected run: %+v", r)
	}
	if len(r.Findings) != 1 || !r.Findings[0].IsFinding() || len(r.Groups) != 1 || r.Groups[0].IsFinding() {
		t.Errorf("findings/groups: %+v %+v", r.Findings, r.Groups)
	}
	r, err = Parse([]byte(`{"tool":"raijin-scan","findings":[],"groups":[]}`))
	if err != nil || r.Budget != nil {
		t.Errorf("a missing budget is nil: %v %+v", err, r)
	}
}

func TestParseRejectsNonRaijin(t *testing.T) {
	for _, in := range []string{``, `not json`, `{"findings":[]}`, `[1,2]`, `null`, `{"tool":""}`} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("Parse(%q) should fail", in)
		}
	}
}

// What a tool writes, Parse reads and Marshal writes back unchanged.
func TestRoundTrip(t *testing.T) {
	type f struct {
		ID        string   `json:"id"`
		Severity  string   `json:"severity"`
		Status    int      `json:"status,omitempty"`
		Locations []string `json:"locations"`
	}
	res := Result[f, f]{
		Tool: "raijin-x", Version: "1", Origin: "https://a",
		Findings: []f{{ID: "a", Severity: "low", Status: 200, Locations: []string{"/a?x=1&y=2"}}},
		Groups:   []f{},
		Budget:   Budget{MaxItems: 1, MaxBytes: 2, Truncated: true},
	}
	out, err := Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	run, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Marshal(Result[Entry, Entry]{
		Tool: run.Tool, Version: run.Version, Target: run.Target, Summary: run.Summary, Origin: run.Origin,
		Findings: run.Findings, Groups: run.Groups, Omitted: run.Omitted, Errors: run.Errors, Raw: run.Raw, Budget: *run.Budget,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(out) {
		t.Errorf("got  %s\nwant %s", back, out)
	}
}
