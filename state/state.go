// Package state remembers findings between runs so a rerun can mark what is new.
//
// A state file is JSON, {"seen": {"<key>": ["<location>", ...]}}: for each finding key, the locations
// where it has been seen. The key is whatever the tool uses to say two findings are the same finding
// (a fingerprint derived from the finding ID). A finding is new when it has a location the file does not
// have yet.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
)

// State maps a finding key to the locations it was seen at.
type State struct {
	Seen map[string][]string `json:"seen"`
}

// Load reads a state file. A missing file is an empty state. A file that is not a state file is an error.
func Load(path string) (*State, error) {
	s := &State{Seen: map[string][]string{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	if s.Seen == nil {
		s.Seen = map[string][]string{}
	}
	return s, nil
}

// Observe records that the finding with the given key was seen at locations, and reports whether it is
// new: whether any of the locations was not known for the key. A key seen with no locations is recorded
// and never new.
func (s *State) Observe(key string, locations []string) bool {
	if s.Seen == nil {
		s.Seen = map[string][]string{}
	}
	known := map[string]bool{}
	for _, l := range s.Seen[key] {
		known[l] = true
	}
	isNew := false
	for _, l := range locations {
		if !known[l] {
			isNew = true
			known[l] = true
		}
	}
	merged := make([]string, 0, len(known))
	for l := range known {
		merged = append(merged, l)
	}
	sort.Strings(merged)
	s.Seen[key] = merged
	return isNew
}

// Mark flags findings that are new, or that appeared at a location not seen before, and records them. It
// returns how many are new.
//
// key returns the state key of a finding, locations maps a state key to every location the finding was
// seen at in this run (not only the ones the output lists, which the budget may cut), and setNew is
// called for each finding that is new:
//
//	n := state.Mark(st, res.Findings, allLocations,
//		func(f *Finding) string { return f.Fingerprint },
//		func(f *Finding) { f.New = true })
func Mark[F any](s *State, findings []F, locations map[string][]string, key func(*F) string, setNew func(*F)) int {
	n := 0
	for i := range findings {
		k := key(&findings[i])
		if s.Observe(k, locations[k]) {
			setNew(&findings[i])
			n++
		}
	}
	return n
}

// Save writes the state file, readable by its owner only. The file is replaced in one step, so a run
// that is interrupted while saving leaves the previous state in place.
func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, 0o600)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
