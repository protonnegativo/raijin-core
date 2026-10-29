package scope

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parseOne parses a scope of one rule plus a valid include, and returns the LineError for the rule.
func parseOne(t *testing.T, rule string) *LineError {
	t.Helper()
	_, err := Parse([]string{"ok.example", rule})
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("Parse(%q): expected a *ParseError, got %v", rule, err)
	}
	if len(pe.Lines) != 1 {
		t.Fatalf("Parse(%q): expected one problem, got %d: %v", rule, len(pe.Lines), pe)
	}
	return pe.Lines[0]
}

func TestLineErrors(t *testing.T) {
	tests := []struct {
		rule       string
		wantReason string
		wantHint   string // must appear in the hint: what to write instead
	}{
		{"example.com:443", "port in rule", "'example.com'"},
		{"!example.com:443", "port in rule", "'!example.com'"},
		{"*.example.com:443", "port in rule", "'*.example.com'"},
		{"EXAMPLE.com:8443", "port in rule", "'example.com'"},
		{"example.com:", "':' in rule", "'example.com'"},
		{"2001:db8::zz", "':' in rule", "use the host only"},
		{"https://example.com", "URL in rule", "'example.com'"},
		{"https://user:pw@Example.com:8443/x?y=1", "URL in rule", "'example.com'"},
		{"!https://example.com/admin", "URL in rule", "'!example.com'"},
		{"example.com/path", "path in rule", "'example.com'"},
		{"10.0.0.7/24", "CIDR has host bits set", "'10.0.0.0/24'"},
		{"10.0.0.7/24", "CIDR has host bits set", "'10.0.0.7'"},
		{"!10.0.0.7/24", "CIDR has host bits set", "'!10.0.0.0/24'"},
		{"2001:db8::1/32", "CIDR has host bits set", "'2001:db8::/32'"},
		{"10.0.0.0/99", "invalid CIDR", "10.0.0.0/24"},
		{"10.0.0.0/", "invalid CIDR", "prefix length"},
		{"*", "misplaced wildcard", "'*.example.com'"},
		{"*example.com", "misplaced wildcard", "'*.example.com'"},
		{"a.*.example.com", "misplaced wildcard", "first label"},
		{"*.*.example.com", "misplaced wildcard", "first label"},
		{"!*example.com", "misplaced wildcard", "'!*.example.com'"},
		{"*.", "wildcard without a domain", "'*.example.com'"},
		{"example.com # prod", "space in rule", "own line starting with '#'"},
		{"example.com extra", "space in rule", "one rule per line"},
		{"a..example.com", "empty label", "'a.example.com'"},
		{".example.com", "empty label", "'example.com'"},
		{"!.admin.example.com", "empty label", "'!admin.example.com'"},
		{".", "empty label", "'example.com'"},
		{"10.0.0", "numeric last label", "10.0.0.0/24"},
		{"010.0.0.7", "numeric last label", "full dotted address"},
		{"0x0a.0.0.7", "numeric last label", "full dotted address"},
		{"caf\u00e9$.com", "invalid character", "punycode"},
		{"[::1]", "bracketed IPv6", "'::1'"},
		{"exa$mple.com", "invalid character", "letters, digits"},
		{"bücher.de/x", "path in rule", "'bücher.de'"},
		{"!", "empty exclusion", "after '!'"},
		{"!   ", "empty exclusion", "after '!'"},
	}
	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			le := parseOne(t, tt.rule)
			if !strings.HasPrefix(le.Reason, tt.wantReason) {
				t.Errorf("Reason = %q, want prefix %q", le.Reason, tt.wantReason)
			}
			if !strings.Contains(le.Hint, tt.wantHint) {
				t.Errorf("Hint = %q, want it to contain %q", le.Hint, tt.wantHint)
			}
			if le.Line != 2 {
				t.Errorf("Line = %d, want 2", le.Line)
			}
			if want := strings.TrimSpace(tt.rule); le.Rule != want {
				t.Errorf("Rule = %q, want %q", le.Rule, want)
			}
			if se := le.SchemaError(); se.Kind != "scope" || se.Hint != le.Error() || !strings.HasPrefix(se.Hint, "line 2: ") {
				t.Errorf("SchemaError = %+v", se)
			}
		})
	}
}

// Every hint that suggests a rule must suggest one Parse accepts.
func TestHintsSuggestValidRules(t *testing.T) {
	for _, rule := range []string{
		"example.com:443", "!example.com:443", "*.example.com:443", "https://u@Example.com:81/x", "example.com/p",
		"10.0.0.7/24", "!10.0.0.7/24", "2001:db8::1/32", "*example.com", "!*example.com", "a..example.com", ".example.com",
		"[::1]", "!.admin.example.com",
	} {
		le := parseOne(t, rule)
		parts := strings.Split(le.Hint, "'")
		for i := 1; i < len(parts); i += 2 {
			sug := parts[i]
			if _, err := Parse([]string{"ok.example", sug}); err != nil {
				t.Errorf("rule %q: the hint %q suggests %q, which does not parse: %v", rule, le.Hint, sug, err)
			}
		}
	}
}

func TestParseReportsEveryInvalidLine(t *testing.T) {
	lines := []string{
		"example.com",     // 1 ok
		"example.com:443", // 2
		"# comment",       // 3
		"",                // 4
		"10.0.0.7/24",     // 5
		"*.example.com",   // 6 ok
		"!*admin.com",     // 7
		"a..b.com",        // 8
	}
	sc, err := Parse(lines)
	if sc != nil || err == nil {
		t.Fatalf("expected an error and no scope, got %v %v", sc, err)
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("not a *ParseError: %T", err)
	}
	var got []int
	for _, l := range pe.Lines {
		got = append(got, l.Line)
	}
	if fmt.Sprint(got) != "[2 5 7 8]" {
		t.Errorf("lines = %v, want [2 5 7 8]", got)
	}
	// each LineError is reachable through errors.As too
	var le *LineError
	if !errors.As(err, &le) || le.Line != 2 {
		t.Errorf("errors.As(*LineError) = %v", le)
	}
	// and the message has them all, one per line
	if msg := err.Error(); strings.Count(msg, "\n") != 3 || !strings.HasPrefix(msg, "invalid scope: line 2: port in rule") {
		t.Errorf("message:\n%s", msg)
	}
	ses := SchemaErrors(err)
	if len(ses) != 4 {
		t.Fatalf("SchemaErrors = %v", ses)
	}
	if ses[0].Kind != "scope" || ses[0].Hint != "line 2: port in rule 'example.com:443'; use the host only: 'example.com'" {
		t.Errorf("first schema error = %+v", ses[0])
	}
	if ses[1].Hint != "line 5: CIDR has host bits set '10.0.0.7/24'; write '10.0.0.0/24' for the whole network, or '10.0.0.7' for the single address" {
		t.Errorf("second schema error = %q", ses[1].Hint)
	}
}

func TestNoIncludeRules(t *testing.T) {
	for _, lines := range [][]string{nil, {"# nothing"}, {"!only-an-exclusion.com"}} {
		_, err := Parse(lines)
		var pe *ParseError
		if !errors.As(err, &pe) || len(pe.Lines) != 1 {
			t.Fatalf("Parse(%v) = %v", lines, err)
		}
		le := pe.Lines[0]
		if le.Line != 0 || le.Reason != "no include rules" || !strings.Contains(le.Hint, "example.com") {
			t.Errorf("%+v", le)
		}
		if se := le.SchemaError(); se.Kind != "scope" || !strings.HasPrefix(se.Hint, "no include rules; add at least one") {
			t.Errorf("schema error = %+v", se)
		}
	}
	// when lines are invalid, the missing include is not reported on top: fixing the lines may fix it
	_, err := Parse([]string{"example.com:443"})
	var pe *ParseError
	if !errors.As(err, &pe) || len(pe.Lines) != 1 || pe.Lines[0].Line != 1 {
		t.Errorf("got %v", err)
	}
}

func TestLoadReportsEveryInvalidLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(path, []byte("example.com\nexample.com:443\n10.0.0.7/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if ses := SchemaErrors(err); len(ses) != 2 || ses[0].Kind != "scope" {
		t.Errorf("SchemaErrors = %v", ses)
	}
	// wrapping does not hide it
	if ses := SchemaErrors(fmt.Errorf("loading scope: %w", err)); len(ses) != 2 {
		t.Errorf("SchemaErrors through %%w = %v", ses)
	}
}

func TestSchemaErrorsOtherErrors(t *testing.T) {
	if SchemaErrors(nil) != nil {
		t.Error("nil error gives nil")
	}
	_, err := Load(filepath.Join(t.TempDir(), "missing.txt"))
	ses := SchemaErrors(err)
	if len(ses) != 1 || ses[0].Kind != "scope" || !strings.HasPrefix(ses[0].Hint, "cannot read the scope file: ") {
		t.Errorf("SchemaErrors = %v", ses)
	}
}

// TestMigrationChanges pins S1-S9 of docs/MIGRATION.md, one subtest each.
func TestMigrationChanges(t *testing.T) {
	sc := mustParse(t, "example.com", "*.example.com", "!admin.example.com", "10.0.0.0/30", "!10.0.0.2", "2001:db8::/32", "example.com", "*.example.com")
	t.Run("S1 bare IPv6", func(t *testing.T) {
		if !sc.Allowed("2001:db8::1") || sc.Allowed("2001:db9::1") {
			t.Error("a bare IPv6 address is matched like the bracketed one")
		}
	})
	t.Run("S2 malformed hosts are denied", func(t *testing.T) {
		for _, h := range []string{".admin.example.com", ".example.com", "a..example.com", "*.example.com", "a.*.example.com", "exa mple.com", "a%2eexample.com"} {
			if sc.Allowed(h) {
				t.Errorf("Allowed(%q) should be false", h)
			}
		}
	})
	t.Run("S3 rules that never match are errors", func(t *testing.T) {
		for _, r := range []string{"example.com:443", "*", "*example.com", "a.*.b.com", "example.com # c", "a..b.com", "[::1]", "10.0.0", "010.0.0.7"} {
			parseOne(t, r)
		}
	})
	t.Run("S4 CIDR with host bits is an error", func(t *testing.T) {
		if le := parseOne(t, "10.0.0.7/24"); le.Reason != "CIDR has host bits set" {
			t.Errorf("%+v", le)
		}
	})
	t.Run("S5 trailing dot on a wildcard rule", func(t *testing.T) {
		s := mustParse(t, "*.example.org.")
		if !s.Allowed("a.example.org") {
			t.Error("the rule should match")
		}
	})
	t.Run("S6 URL in the query", func(t *testing.T) {
		if got := Hostname("example.com/go?next=http://evil.com"); got != "example.com" {
			t.Errorf("Hostname = %q", got)
		}
		if got := Hostname("evil.com/go?next=http://example.com"); got != "evil.com" {
			t.Errorf("Hostname = %q", got)
		}
	})
	t.Run("S7 canonical IP", func(t *testing.T) {
		for in, want := range map[string]string{"::ffff:10.0.0.7": "10.0.0.7", "[2001:DB8:0:0::1]": "2001:db8::1"} {
			if got := Hostname(in); got != want {
				t.Errorf("Hostname(%q) = %q, want %q", in, got, want)
			}
		}
	})
	t.Run("S8 Targets lists once", func(t *testing.T) {
		targets, wildcards, _ := sc.Targets()
		if len(wildcards) != 1 || strings.Count(strings.Join(targets, ","), "example.com") != 1 {
			t.Errorf("%v %v", targets, wildcards)
		}
	})
	t.Run("S9 odd host forms are denied", func(t *testing.T) {
		for _, h := range []string{"[fe80::1%25eth0]", "010.0.0.1", "0x0a.0.0.1", "167772161", "еxample.com"} {
			if sc.Allowed(h) {
				t.Errorf("Allowed(%q) should be false", h)
			}
		}
	})
}
