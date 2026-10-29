package state

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type finding struct {
	ID          string
	Fingerprint string
	New         bool
}

func mark(s *State, fs []finding, locs map[string][]string) int {
	return Mark(s, fs, locs, func(f *finding) string { return f.Fingerprint }, func(f *finding) { f.New = true })
}

func TestMarkAcrossRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	first := []finding{{ID: "git-config", Fingerprint: "fp1"}}
	if n := mark(st, first, map[string][]string{"fp1": {"a"}}); n != 1 || !first[0].New {
		t.Fatalf("first run: n=%d new=%v", n, first[0].New)
	}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}

	st, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	same := []finding{{ID: "git-config", Fingerprint: "fp1"}}
	if n := mark(st, same, map[string][]string{"fp1": {"a"}}); n != 0 || same[0].New {
		t.Errorf("same finding on the same host should not be new: n=%d", n)
	}

	newHost := []finding{{ID: "git-config", Fingerprint: "fp1"}}
	if n := mark(st, newHost, map[string][]string{"fp1": {"a", "b"}}); n != 1 || !newHost[0].New {
		t.Errorf("a new host should mark the finding as new: n=%d", n)
	}
}

func TestMark(t *testing.T) {
	tests := []struct {
		name     string
		seen     map[string][]string
		findings []string // keys
		locs     map[string][]string
		wantNew  []bool
		wantSeen map[string][]string
	}{
		{"first run", nil, []string{"a", "b"}, map[string][]string{"a": {"x"}, "b": {"y", "x"}},
			[]bool{true, true}, map[string][]string{"a": {"x"}, "b": {"x", "y"}}},
		{"nothing changed", map[string][]string{"a": {"x"}}, []string{"a"}, map[string][]string{"a": {"x"}},
			[]bool{false}, map[string][]string{"a": {"x"}}},
		{"fewer locations than before", map[string][]string{"a": {"x", "y"}}, []string{"a"}, map[string][]string{"a": {"x"}},
			[]bool{false}, map[string][]string{"a": {"x", "y"}}},
		{"one new location", map[string][]string{"a": {"x"}}, []string{"a"}, map[string][]string{"a": {"x", "z"}},
			[]bool{true}, map[string][]string{"a": {"x", "z"}}},
		{"only the changed finding is new", map[string][]string{"a": {"x"}, "b": {"y"}}, []string{"a", "b"},
			map[string][]string{"a": {"x"}, "b": {"y", "z"}}, []bool{false, true},
			map[string][]string{"a": {"x"}, "b": {"y", "z"}}},
		{"no locations is never new", nil, []string{"a"}, nil,
			[]bool{false}, map[string][]string{"a": {}}},
		{"duplicate locations count once", nil, []string{"a"}, map[string][]string{"a": {"x", "x"}},
			[]bool{true}, map[string][]string{"a": {"x"}}},
		{"same key twice in a run", nil, []string{"a", "a"}, map[string][]string{"a": {"x"}},
			[]bool{true, false}, map[string][]string{"a": {"x"}}},
		{"keys that are not in this run are kept", map[string][]string{"gone": {"x"}}, []string{"a"}, map[string][]string{"a": {"x"}},
			[]bool{true}, map[string][]string{"gone": {"x"}, "a": {"x"}}},
		{"no findings", map[string][]string{"a": {"x"}}, nil, nil, nil, map[string][]string{"a": {"x"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &State{Seen: tt.seen}
			var fs []finding
			for _, k := range tt.findings {
				fs = append(fs, finding{Fingerprint: k})
			}
			wantN := 0
			for _, b := range tt.wantNew {
				if b {
					wantN++
				}
			}
			if n := mark(st, fs, tt.locs); n != wantN {
				t.Errorf("n = %d, want %d", n, wantN)
			}
			for i, f := range fs {
				if f.New != tt.wantNew[i] {
					t.Errorf("finding %d new = %v, want %v", i, f.New, tt.wantNew[i])
				}
			}
			if !reflect.DeepEqual(st.Seen, tt.wantSeen) {
				t.Errorf("seen = %v, want %v", st.Seen, tt.wantSeen)
			}
		})
	}
}

func TestObserveOnZeroState(t *testing.T) {
	var s State
	if !s.Observe("k", []string{"a"}) || s.Observe("k", []string{"a"}) {
		t.Error("a zero State should work")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := []struct {
		name    string
		path    string
		want    map[string][]string
		wantErr bool
	}{
		{"missing file is empty", filepath.Join(dir, "none.json"), map[string][]string{}, false},
		{"file in the format the tools write", write("ok.json", "{\n  \"seen\": {\n    \"fp1\": [\n      \"a\",\n      \"b\"\n    ]\n  }\n}"),
			map[string][]string{"fp1": {"a", "b"}}, false},
		{"seen is null", write("null.json", `{"seen":null}`), map[string][]string{}, false},
		{"no seen", write("empty.json", `{}`), map[string][]string{}, false},
		{"corrupt", write("bad.json", `{"seen":`), nil, true},
		{"wrong type", write("type.json", `{"seen":{"a":"x"}}`), nil, true},
		{"empty file", write("zero.json", ``), nil, true},
		{"a directory", dir, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, err := Load(tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && !reflect.DeepEqual(st.Seen, tt.want) {
				t.Errorf("seen = %v, want %v", st.Seen, tt.want)
			}
		})
	}
}

// The file format is shared with every tool and with older versions of them, so pin it.
func TestSaveFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st := &State{Seen: map[string][]string{"fp1": {"a", "b"}}}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\n  \"seen\": {\n    \"fp1\": [\n      \"a\",\n      \"b\"\n    ]\n  }\n}"; string(b) != want {
		t.Errorf("got %q, want %q", b, want)
	}
}

func TestSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	st := &State{Seen: map[string][]string{"fp1": {"a"}}}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	// overwrite keeps working and leaves no temporary file behind
	st.Seen["fp2"] = []string{"b"}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || !reflect.DeepEqual(got.Seen, st.Seen) {
		t.Errorf("reload = %v %v", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected only state.json, found %d entries", len(entries))
	}
}

func TestSaveErrors(t *testing.T) {
	st := &State{Seen: map[string][]string{}}
	missing := filepath.Join(t.TempDir(), "no", "such", "dir", "state.json")
	if err := st.Save(missing); err == nil {
		t.Error("saving into a missing directory should fail")
	}
	dir := t.TempDir()
	if err := st.Save(dir); err == nil {
		t.Error("saving over a directory should fail")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("a failed save must not leave temporary files: %s", strings.Join(names, ","))
	}
}
