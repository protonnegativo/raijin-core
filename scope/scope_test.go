package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustParse(t *testing.T, lines ...string) *Scope {
	t.Helper()
	s, err := Parse(lines)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAllowed(t *testing.T) {
	sc := mustParse(t,
		"# comment",
		"example.com",
		"*.example.com",
		"!admin.example.com",
		"10.0.0.0/24",
		"192.0.2.10",
	)
	tests := []struct {
		target string
		want   bool
	}{
		{"example.com", true},
		{"https://example.com/login", true},
		{"api.example.com:8443", true},
		{"a.b.example.com", true},
		{"admin.example.com", false},
		{"https://admin.example.com/", false},
		{"notexample.com", false},
		{"example.com.evil.com", false},
		{"10.0.0.7", true},
		{"http://10.0.0.7:8080", true},
		{"10.0.1.7", false},
		{"192.0.2.10", true},
		{"192.0.2.11", false},
		{"", false},
		{"   ", false},
	}
	for _, tt := range tests {
		if got := sc.Allowed(tt.target); got != tt.want {
			t.Errorf("Allowed(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

// TestAllowedBypasses covers the ways a target can look in scope to a naive matcher.
func TestAllowedBypasses(t *testing.T) {
	sc := mustParse(t, "example.com", "*.example.com", "!admin.example.com", "!*.internal.example.com", "10.0.0.0/24", "!10.0.0.2")
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		// suffix and prefix tricks
		{"suffix: rule is a suffix of the host", "evilexample.com", false},
		{"suffix: rule as a subdomain of another domain", "example.com.evil.com", false},
		{"suffix: wildcard rule as a subdomain of another domain", "a.example.com.evil.com", false},
		{"prefix: host starts with the rule", "example.community", false},
		{"prefix: URL path holds the rule", "https://evil.com/example.com", false},
		{"prefix: query holds the rule", "https://evil.com/?next=https://example.com", false},
		{"prefix: fragment holds the rule", "https://evil.com/#example.com", false},
		{"bare host with a URL in the query", "evil.com/go?next=http://example.com", false},
		{"bare host with a URL in the query, in scope", "example.com/go?next=http://evil.com", true},
		{"wildcard does not match the apex of another domain", "example.org", false},
		{"hyphen is not a label separator", "evil-example.com", false},

		// userinfo
		{"userinfo: rule before the @", "https://example.com@evil.com/", false},
		{"userinfo: rule before the @ with password", "https://example.com:pw@evil.com/", false},
		{"userinfo: real host after the @", "https://evil.com@example.com/", true},
		{"userinfo: two @", "https://a@b@example.com/", true},
		{"userinfo: two @, evil last", "https://example.com@a@evil.com/", false},
		{"userinfo: bare host", "example.com@evil.com", false},
		{"userinfo: backslash is not a separator", `https://example.com\@evil.com/`, false},
		{"userinfo: backslash in host", `https://evil.com\.example.com/`, false},
		{"userinfo: excluded host behind userinfo", "https://example.com@admin.example.com/", false},

		// port
		{"port: default", "example.com:443", true},
		{"port: with scheme", "https://api.example.com:8443/x", true},
		{"port: empty", "example.com:", true},
		{"port: not a number", "example.com:abc", false},
		{"port: second colon", "example.com:80:80", false},
		{"port: evil host with the rule as port", "evil.com:example.com", false},
		{"port: excluded host", "admin.example.com:8443", false},

		// IPv6 and IP forms
		{"ipv4 with port", "10.0.0.7:8080", true},
		{"ipv4 excluded", "10.0.0.2", false},
		{"ipv4 excluded with port", "http://10.0.0.2:80", false},
		{"ipv4 trailing dot", "10.0.0.7.", true},
		{"ipv4 leading zeros are not an IP", "010.0.0.7", false},
		{"ipv4 hex is not an IP", "0x0a.0.0.7", false},
		{"ipv4 decimal is not an IP", "167772167", false},
		{"ipv4 short form is not an IP", "10.0.7", false},
		{"ipv4 mapped in ipv6", "[::ffff:10.0.0.7]", true},
		{"ipv4 mapped in ipv6, excluded", "[::ffff:10.0.0.2]", false},
		{"ipv4 mapped in ipv6, bare", "::ffff:10.0.0.7", true},
		{"ipv4 mapped in ipv6, outside", "[::ffff:10.0.1.7]", false},
		{"ipv6 loopback is not in an ipv4 range", "[::1]", false},
		{"ip as a subdomain label", "10.0.0.7.example.com", true},
		{"ip as a subdomain of another domain", "10.0.0.7.evil.com", false},
		{"ip with a path", "http://10.0.0.7/admin", true},

		// case
		{"case: upper host", "EXAMPLE.COM", true},
		{"case: mixed subdomain", "Api.Example.Com", true},
		{"case: upper exclusion", "ADMIN.EXAMPLE.COM", false},
		{"case: upper exclusion in URL", "HTTPS://Admin.Example.com/", false},
		{"case: unicode lookalike", "еxample.com", false},
		{"case: fullwidth", "ｅxample.com", false},
		{"case: ideographic full stop", "example。com", false},

		// trailing dot
		{"dot: fqdn", "example.com.", true},
		{"dot: fqdn subdomain", "api.example.com.", true},
		{"dot: fqdn exclusion", "admin.example.com.", false},
		{"dot: fqdn in URL", "https://admin.example.com./x", false},
		{"dot: two dots", "example.com..", false},
		{"dot: leading dot", ".example.com", false},
		{"dot: leading dot before an exclusion", ".admin.example.com", false},
		{"dot: empty label", "a..example.com", false},
		{"dot: evil fqdn", "example.com.evil.com.", false},

		// wildcard
		{"wildcard: one label", "a.example.com", true},
		{"wildcard: many labels", "a.b.c.example.com", true},
		{"wildcard: apex is allowed by its own rule", "example.com", true},
		{"wildcard: exclusion of a subtree", "x.internal.example.com", false},
		{"wildcard: exclusion of a subtree, deeper", "x.y.internal.example.com", false},
		{"wildcard: exclusion of a subtree does not cover its apex", "internal.example.com", true},
		{"wildcard: the target is itself a wildcard", "*.example.com", false},
		{"wildcard: star in the middle", "a.*.example.com", false},

		// malformed
		{"malformed: space in host", "exam ple.com", false},
		{"malformed: tab inside", "example.com\t.evil.com", false},
		{"malformed: newline inside", "example.com\nevil.com", false},
		{"malformed: percent-encoded dot", "https://example.com%2eevil.com/", false},
		{"malformed: percent-encoded letter", "https://exampl%65.com/", false},
		{"malformed: NUL", "example.com\x00.evil.com", false},
		{"malformed: comma list", "example.com,evil.com", false},
		{"malformed: no host", "https:///example.com", false},
		{"malformed: empty port host", "http://:80", false},
		{"malformed: only a scheme", "https://", false},
		{"malformed: opaque URL", "javascript:alert(1)", false},
		{"malformed: surrounding whitespace is trimmed", "  example.com \n", true},
		{"malformed: ipv6 zone", "[fe80::1%25eth0]", false},
		{"malformed: ipv6 without a valid address", "[example.com]", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sc.Allowed(tt.target); got != tt.want {
				t.Errorf("Allowed(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestAllowedIPv6(t *testing.T) {
	sc := mustParse(t, "2001:db8::/32", "!2001:db8:bad::/48", "fd00::1", "example.com")
	tests := []struct {
		target string
		want   bool
	}{
		{"2001:db8::1", true}, // bare IPv6, no brackets
		{"[2001:db8::1]", true},
		{"[2001:db8::1]:443", true},
		{"https://[2001:db8::1]:443/x", true},
		{"2001:DB8::1", true},
		{"2001:0db8:0:0:0:0:0:1", true},
		{"2001:db8:bad::1", false},
		{"[2001:db8:bad::1]:443", false},
		{"2001:db9::1", false},
		{"fd00::1", true},
		{"fd00::2", false},
		{"::1", false},
		{"10.0.0.1", false},
	}
	for _, tt := range tests {
		if got := sc.Allowed(tt.target); got != tt.want {
			t.Errorf("Allowed(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

func TestExclusionsWinInAnyOrder(t *testing.T) {
	for _, lines := range [][]string{
		{"*.example.com", "!admin.example.com"},
		{"!admin.example.com", "*.example.com"},
		{"admin.example.com", "*.example.com", "!admin.example.com"},
		{"!admin.example.com", "admin.example.com"},
	} {
		sc := mustParse(t, append(lines, "other.org")...)
		if sc.Allowed("admin.example.com") {
			t.Errorf("%v: an exclusion must win over an inclusion", lines)
		}
		if !sc.Allowed("other.org") {
			t.Errorf("%v: other.org should stay in scope", lines)
		}
	}
}

func TestHostname(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.com.", "example.com"},
		{"https://User:Pw@Example.com:8443/a?b=c#d", "example.com"},
		{"example.com:8443/path", "example.com"},
		{"example.com/go?next=http://other.org", "example.com"},
		{"ftp://example.com", "example.com"},
		{"10.0.0.7:80", "10.0.0.7"},
		{"[::1]:80", "::1"},
		{"::1", "::1"},
		{"2001:DB8:0:0:0:0:0:1", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"::ffff:10.0.0.7", "10.0.0.7"},
		{"a_b.example.com", "a_b.example.com"},
		{"https://example.com@evil.com", "evil.com"},
		{"", ""},
		{"  ", ""},
		{"https://", ""},
		{"https://:80", ""},
		{"a..b", ""},
		{".example.com", ""},
		{"example.com..", ""},
		{"exa mple.com", ""},
		{"exa%6dple.com", ""},
		{"*.example.com", ""},
		{"example.com:abc", ""},
		{"010.0.0.7", ""},
		{"10.1", ""},
		{"1234", ""},
		{"[fe80::1%25eth0]", ""},
	}
	for _, tt := range tests {
		if got := Hostname(tt.in); got != tt.want {
			t.Errorf("Hostname(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		lines   []string
		wantErr string
	}{
		{"ok", []string{"example.com", "*.example.com", "10.0.0.0/8", "::1", "!x.example.com"}, ""},
		{"comments and blanks", []string{"", "  # c", "example.com", "\t"}, ""},
		{"trailing dot", []string{"example.com."}, ""},
		{"wildcard trailing dot", []string{"*.example.com."}, ""},
		{"upper case", []string{"EXAMPLE.COM", "10.0.0.0/8"}, ""},
		{"only exclusions", []string{"!only-an-exclusion.com"}, "no include rules"},
		{"empty", nil, "no include rules"},
		{"only comments", []string{"# nothing"}, "no include rules"},
		{"invalid CIDR", []string{"10.0.0.0/99"}, "invalid CIDR"},
		{"CIDR text", []string{"example.com/24"}, "path in rule"},
		{"URL as a rule", []string{"https://example.com"}, "URL in rule"},
		{"CIDR with host bits", []string{"10.0.0.7/24"}, "host bits"},
		{"ipv6 CIDR with host bits", []string{"2001:db8::1/32"}, "host bits"},
		{"exclusion CIDR with host bits", []string{"example.com", "!10.0.0.7/24"}, "host bits"},
		{"empty exclusion", []string{"example.com", "!"}, "empty exclusion"},
		{"blank exclusion", []string{"example.com", "!   "}, "empty exclusion"},
		{"port in a rule", []string{"example.com:443"}, "port in rule"},
		{"star alone", []string{"*"}, "misplaced wildcard"},
		{"star without dot", []string{"*example.com"}, "misplaced wildcard"},
		{"star in the middle", []string{"a.*.example.com"}, "misplaced wildcard"},
		{"empty wildcard", []string{"*."}, "wildcard without a domain"},
		{"bare dot", []string{"."}, "empty label"},
		{"double star", []string{"*.*.example.com"}, "misplaced wildcard"},
		{"space in rule", []string{"example.com extra"}, "space in rule"},
		{"inline comment", []string{"example.com # prod"}, "space in rule"},
		{"empty label", []string{"a..example.com"}, "empty label"},
		{"leading dot", []string{".example.com"}, "empty label"},
		{"numeric last label", []string{"10.0.0"}, "numeric last label"},
		{"bracketed ipv6", []string{"[::1]"}, "bracketed IPv6"},
		{"error names the line", []string{"example.com", "", "bad rule"}, "line 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.lines)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Errorf("expected an error containing %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseNormalizesRules(t *testing.T) {
	sc := mustParse(t, "EXAMPLE.COM.", "*.Foo.Org.", "!ADMIN.foo.org")
	for target, want := range map[string]bool{
		"example.com": true, "a.foo.org": true, "admin.foo.org": false, "foo.org": false,
	} {
		if got := sc.Allowed(target); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(path, []byte("# scope\nexample.com\n\n*.example.com\n!admin.example.com\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sc, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !sc.Allowed("a.example.com") || sc.Allowed("admin.example.com") {
		t.Error("Load should read the rules in the file, including CRLF line ends")
	}
	if _, err := Load(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("a missing file should be an error")
	}
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte("10.0.0.0/99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Error("an invalid rule should be an error")
	}
}

func TestTargets(t *testing.T) {
	sc := mustParse(t,
		"example.com",
		"*.example.com",
		"api.example.com",
		"example.com",
		"10.0.0.0/30",
		"!10.0.0.2",
		"192.0.2.10",
		"172.16.0.0/16",
		"*.example.com",
	)
	targets, wildcards, ranges := sc.Targets()
	if got := strings.Join(targets, ","); got != "example.com,api.example.com,10.0.0.0,10.0.0.1,10.0.0.3,192.0.2.10" {
		t.Errorf("targets = %s", got)
	}
	if strings.Join(wildcards, ",") != "*.example.com" {
		t.Errorf("wildcards = %v", wildcards)
	}
	if strings.Join(ranges, ",") != "172.16.0.0/16" {
		t.Errorf("ranges larger than a /24 are not expanded: %v", ranges)
	}
}

func TestTargetsUpTo(t *testing.T) {
	lines := []string{"example.com", "10.0.0.0/30", "!10.0.0.2", "172.16.0.0/16", "10.0.0.0/8", "2001:db8::/126", "2001:db8:1::/64"}
	tests := []struct {
		name       string
		max        int
		wantTarget []string
		wantRanges []string
	}{
		{"limit below the smallest range", 1,
			[]string{"example.com"},
			[]string{"10.0.0.0/30", "172.16.0.0/16", "10.0.0.0/8", "2001:db8::/126", "2001:db8:1::/64"}},
		{"default limit", MaxExpand,
			[]string{"example.com", "10.0.0.0", "10.0.0.1", "10.0.0.3", "2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"},
			[]string{"172.16.0.0/16", "10.0.0.0/8", "2001:db8:1::/64"}},
		{"a /16 is allowed", 1 << 16, nil, []string{"10.0.0.0/8", "2001:db8:1::/64"}},
		{"the limit is capped at a /16", 1 << 30, nil, []string{"10.0.0.0/8", "2001:db8:1::/64"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, ranges := mustParse(t, lines...).TargetsUpTo(tt.max)
			if tt.wantTarget != nil {
				if strings.Join(got, ",") != strings.Join(tt.wantTarget, ",") {
					t.Errorf("targets = %v, want %v", got, tt.wantTarget)
				}
			} else if len(got) != 1+3+65536+4 {
				t.Errorf("got %d targets", len(got))
			}
			if strings.Join(ranges, ",") != strings.Join(tt.wantRanges, ",") {
				t.Errorf("ranges = %v, want %v", ranges, tt.wantRanges)
			}
		})
	}
}

func TestTargetsAppliesExclusionsToExpandedRanges(t *testing.T) {
	sc := mustParse(t, "10.0.0.0/24", "!10.0.0.128/25", "!10.0.0.7", "192.0.2.1", "!192.0.2.1")
	targets, _, _ := sc.Targets()
	if len(targets) != 127 {
		t.Fatalf("got %d targets, want 127 (a /24 minus a /25 minus one address)", len(targets))
	}
	for _, tg := range targets {
		if !sc.Allowed(tg) {
			t.Errorf("Targets listed %s, which Allowed rejects", tg)
		}
	}
}

func TestTargetsOnlyWildcard(t *testing.T) {
	targets, wildcards, ranges := mustParse(t, "*.example.com").Targets()
	if len(targets) != 0 || len(ranges) != 0 || len(wildcards) != 1 {
		t.Errorf("a wildcard names no host: %v %v %v", targets, wildcards, ranges)
	}
}

func TestCovers(t *testing.T) {
	sc := mustParse(t, "*.example.com", "other.org", "!*.blocked.example.com", "!excluded.example.com", "10.0.0.0/24")
	tests := []struct {
		root string
		want bool
	}{
		{"example.com", true},     // its subdomains are in scope
		{"dev.example.com", true}, // a subdomain root
		{"other.org", true},       // the root itself
		{"sub.other.org", false},  // other.org has no wildcard
		{"excluded.example.com", false},
		{"x.blocked.example.com", false},
		{"blocked.example.com", true}, // the exclusion is for its subdomains only
		{"example.net", false},
		{"notexample.com", false},
		{"example.com.evil.com", false},
		{"EXAMPLE.COM.", true},
		{"https://dev.example.com/x", true},
		{"10.0.0.5", true},
		{"10.0.1.5", false},
		{"", false},
		{"*.example.com", false},
		{".example.com", false},
	}
	for _, tt := range tests {
		if got := sc.Covers(tt.root); got != tt.want {
			t.Errorf("Covers(%q) = %v, want %v", tt.root, got, tt.want)
		}
	}
	if mustParse(t, "!example.com", "*.example.com").Covers("example.com") {
		t.Error("an exclusion of the root wins over the wildcard")
	}
}

// TestCoversIsNotAllowed pins the difference between the two: a wildcard covers its apex for
// enumeration, but the apex itself is not a host the scope lets a tool touch.
func TestCoversIsNotAllowed(t *testing.T) {
	sc := mustParse(t, "*.example.com")
	if !sc.Covers("example.com") || sc.Allowed("example.com") {
		t.Error("*.example.com covers example.com but does not allow it")
	}
}

// FuzzAllowed checks, for any input, that Allowed never panics and that the only host a scope of
// "example.com" lets through is example.com itself, whatever the target looks like. Plain "go test" runs
// the seeds; "go test -fuzz FuzzAllowed ./scope" explores.
func FuzzAllowed(f *testing.F) {
	for _, seed := range []string{
		"example.com", "https://example.com@evil.com", "example.com.evil.com", "evil.com/example.com",
		"http://[::1]:80", "example.com:80:80", `http://example.com\@evil.com`, "EXAMPLE.com.", "example.com%00.evil.com",
		"http://user:pass@example.com:99/x?y=http://evil.com#z", "\x00", "[", "::", "//example.com",
	} {
		f.Add(seed)
	}
	sc, err := Parse([]string{"example.com", "!blocked.example.com"})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, target string) {
		if !sc.Allowed(target) {
			return
		}
		if h := Hostname(target); h != "example.com" {
			t.Errorf("Allowed(%q) is true but the host is %q", target, h)
		}
	})
}
