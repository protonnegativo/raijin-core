// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns, and reads it back.
//
// Nothing the engine found is dropped silently: every finding and every location where it matched is
// listed, and anything a budget cuts is counted in Omitted. What an agent can rebuild is left out of the
// JSON to save tokens: empty lists, the budget when nothing was cut, a count equal to the locations
// listed, and fields at their documented default.
//
// The package owns the envelope that is the same in every tool (Result, Error, Budget, the severity and
// confidence order, how JSON is written). The finding and group fields are not shared: each tool has
// its own (a probe finding has status and server, a subs finding has cname and a), so a tool declares
// its Finding and Group types and plugs them in as type parameters of Result. To read the output of any
// tool without knowing those fields, use Parse and Entry.
//
// The JSON field names, their order and which of them are left out are part of the contract: raijin-diff
// and raijin-mcp read what the tools write.
package schema

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
)

// Marshal is json.Marshal without HTML escaping: "<", ">" and "&" stay as written instead of becoming
// "<", which costs tokens and nothing else. The result has no trailing newline.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Write writes v as one JSON document followed by a newline, without HTML escaping. With pretty the
// document is indented by two spaces.
func Write(w io.Writer, v any, pretty bool) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}

// Result is the top-level object a Raijin tool writes to stdout. F and G are the tool's finding and
// group types, so a tool declares its own fields and keeps the envelope from here:
//
//	type Result = schema.Result[Finding, Group]
//
// The fields are written in the order they are declared here. Origin, URL, Match and Filter sit between
// the summary and the findings; a tool sets only the ones it documents and the rest are left out.
type Result[F, G any] struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Target  string `json:"target"`
	Summary string `json:"summary"`
	// Origin is the scheme and host every URL of the result shares; locations are then written without
	// it (raijin-crawl, raijin-js, raijin-params, raijin-xss, raijin-diff).
	Origin string `json:"origin,omitempty"`
	// URL is the URL a fuzzer ran against, with its keywords (raijin-fuzz). It is left out when it is
	// the target.
	URL string `json:"url,omitempty"`
	// Match and Filter are the engine's matchers and filters, left out when it ran with its defaults
	// (raijin-fuzz).
	Match    string         `json:"match,omitempty"`
	Filter   string         `json:"filter,omitempty"`
	Findings []F            `json:"findings"`
	Groups   []G            `json:"groups"`
	Omitted  map[string]int `json:"omitted,omitempty"`
	Errors   []Error        `json:"errors,omitempty"`
	Next     []string       `json:"next,omitempty"`
	// Raw is the file with the engine's full output, for details the result leaves out.
	Raw    string `json:"raw,omitempty"`
	Budget Budget `json:"budget"`
}

// plainResult has the fields of Result and none of its methods.
type plainResult[F, G any] Result[F, G]

// MarshalJSON writes the budget only when something was cut, and findings and groups as [] (never
// null) when there are none.
func (r Result[F, G]) MarshalJSON() ([]byte, error) {
	if r.Findings == nil {
		r.Findings = []F{}
	}
	if r.Groups == nil {
		r.Groups = []G{}
	}
	out := struct {
		plainResult[F, G]
		Budget *Budget `json:"budget,omitempty"`
	}{plainResult: plainResult[F, G](r)}
	if r.Budget.Truncated {
		out.Budget = &r.Budget
	}
	return Marshal(out)
}

// Error is a problem during the run, with a hint about what to try next.
type Error struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
}

// Budget reports the output limits that were applied.
type Budget struct {
	MaxItems  int  `json:"max_items"`
	MaxBytes  int  `json:"max_bytes"`
	Truncated bool `json:"truncated"`
}

// OmitCount returns the value to put in a finding's or group's Count field when it is written: 0 (left
// out of the JSON) when count does not exceed the locations listed, because the reader can count them,
// and count when the budget cut the list. Call it from the MarshalJSON of a type whose Count is
// omitempty:
//
//	p := plain(f)
//	p.Count = schema.OmitCount(p.Count, len(p.Locations))
//	return schema.Marshal(p)
func OmitCount(count, listed int) int {
	if count <= listed {
		return 0
	}
	return count
}

// SeverityRank orders severities from most to least important. A severity that is not listed ranks as
// "unknown", 0.
var SeverityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
	"unknown":  0,
}

// ConfidenceRank orders confidence values: a verified finding before a matched one before a heuristic one.
var ConfidenceRank = map[string]int{
	"verified":  2,
	"":          1,
	"heuristic": 0,
}

// SortedKeys returns the keys of m in order.
func SortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
