package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Run is one Raijin tool output, read back from its JSON. It does not know each tool's finding and group
// fields, so it keeps every entry as an Entry.
type Run struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Target   string         `json:"target"`
	Summary  string         `json:"summary"`
	Origin   string         `json:"origin"`
	Findings []Entry        `json:"findings"`
	Groups   []Entry        `json:"groups"`
	Omitted  map[string]int `json:"omitted"`
	Errors   []Error        `json:"errors"`
	Raw      string         `json:"raw"`
	Budget   *Budget        `json:"budget"`
}

// Parse reads one Raijin tool output. It fails when b is not a JSON object with a tool field.
func Parse(b []byte) (*Run, error) {
	var r Run
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("not a Raijin output: %w", err)
	}
	if r.Tool == "" {
		return nil, errors.New("not a Raijin output: no tool field")
	}
	return &r, nil
}

// Field is one key of a finding or group with its value as compact JSON.
type Field struct {
	Key   string
	Value json.RawMessage
}

// Entry is one finding or group, with its fields in the order the tool wrote them.
type Entry struct {
	Fields []Field
}

// UnmarshalJSON keeps the field order and rewrites each value as compact JSON without HTML escaping,
// so two runs that escaped the same value differently still compare equal.
func (e *Entry) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("entry is not an object")
	}
	e.Fields = nil
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := t.(string)
		var v any
		if err := dec.Decode(&v); err != nil {
			return err
		}
		raw, err := Marshal(v)
		if err != nil {
			return err
		}
		e.Set(key, json.RawMessage(raw))
	}
	_, err := dec.Token()
	return err
}

// MarshalJSON writes the fields in order.
func (e Entry) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range e.Fields {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := Marshal(f.Key)
		b.Write(k)
		b.WriteByte(':')
		b.Write(f.Value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// Get returns the JSON value of key.
func (e Entry) Get(key string) (json.RawMessage, bool) {
	for _, f := range e.Fields {
		if f.Key == key {
			return f.Value, true
		}
	}
	return nil, false
}

// String returns the value of key when it is a string, and "" otherwise.
func (e Entry) String(key string) string {
	v, _ := e.Get(key)
	var s string
	_ = json.Unmarshal(v, &s)
	return s
}

// Strings returns the value of key when it is a list of strings, and nil otherwise.
func (e Entry) Strings(key string) []string {
	v, _ := e.Get(key)
	var s []string
	_ = json.Unmarshal(v, &s)
	return s
}

// Set replaces the value of key, or appends key when it is not there. v is a json.RawMessage or any
// value Marshal accepts.
func (e *Entry) Set(key string, v any) {
	raw, ok := v.(json.RawMessage)
	if !ok {
		raw, _ = Marshal(v)
	}
	for i := range e.Fields {
		if e.Fields[i].Key == key {
			e.Fields[i].Value = raw
			return
		}
	}
	e.Fields = append(e.Fields, Field{Key: key, Value: raw})
}

// Delete removes key.
func (e *Entry) Delete(key string) {
	out := e.Fields[:0]
	for _, f := range e.Fields {
		if f.Key != key {
			out = append(out, f)
		}
	}
	e.Fields = out
}

// Clone returns a copy that can be changed without changing e.
func (e Entry) Clone() Entry {
	return Entry{Fields: append([]Field(nil), e.Fields...)}
}

// IsFinding is true for a finding: every Raijin finding has a severity, no group has one.
func (e Entry) IsFinding() bool {
	_, ok := e.Get("severity")
	return ok
}
