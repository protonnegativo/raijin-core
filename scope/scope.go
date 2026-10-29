// Package scope decides whether a target is allowed to be scanned.
//
// A scope file has one rule per line:
//
//	example.com        the domain itself
//	*.example.com      any subdomain (not the apex)
//	10.0.0.0/24        an IP range
//	192.0.2.10         a single IP
//	!admin.example.com an exclusion; exclusions win over inclusions
//
// Blank lines and lines starting with # are ignored.
//
// The matcher is built to fail closed. A target is allowed only when its host is parsed without
// ambiguity and an include rule matches it exactly (or, for a wildcard, by whole DNS labels) and no
// exclusion matches it. A target the package cannot parse is never allowed. Rules are checked when
// the scope is loaded, so a rule that could never match (a port, a path, a stray "*") is an error
// instead of a silent hole in the exclusions.
//
// Hostnames are compared as written, lowercased and without one trailing dot. There is no IDNA
// conversion: write internationalized names in punycode in the scope file.
package scope

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

type rule struct {
	exclude  bool
	domain   string
	wildcard bool
	ipnet    *net.IPNet
}

// Scope is a parsed set of include and exclude rules. It is safe for concurrent use.
type Scope struct {
	rules []rule
}

// Load reads a scope file.
func Load(path string) (*Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return Parse(lines)
}

// Parse builds a Scope from rule lines. It returns an error for a rule it cannot use and for a scope
// with no include rule.
func Parse(lines []string) (*Scope, error) {
	s := &Scope{}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r := rule{}
		if strings.HasPrefix(line, "!") {
			r.exclude = true
			line = strings.TrimSpace(line[1:])
		}
		line = strings.ToLower(line)
		if line == "" {
			return nil, fmt.Errorf("scope line %d: empty exclusion", i+1)
		}
		switch {
		case strings.Contains(line, "/"):
			ip, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("scope line %d: invalid CIDR %q", i+1, line)
			}
			if !ip.Equal(ipnet.IP) {
				// 10.0.0.7/24 would silently become the whole /24.
				return nil, fmt.Errorf("scope line %d: CIDR %q has host bits set; write %s", i+1, line, ipnet)
			}
			r.ipnet = ipnet
		case net.ParseIP(line) != nil:
			ip := net.ParseIP(line)
			bits := 128
			if ip.To4() != nil {
				ip = ip.To4()
				bits = 32
			}
			r.ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		case strings.HasPrefix(line, "*."):
			r.wildcard = true
			r.domain = strings.TrimSuffix(strings.TrimPrefix(line, "*."), ".")
		default:
			r.domain = strings.TrimSuffix(line, ".")
		}
		if r.ipnet == nil && !validDomain(r.domain) {
			return nil, fmt.Errorf("scope line %d: invalid domain %q (use example.com or *.example.com, with no scheme, port or path)", i+1, line)
		}
		s.rules = append(s.rules, r)
	}
	if len(s.includes()) == 0 {
		return nil, fmt.Errorf("scope has no include rules")
	}
	return s, nil
}

func (s *Scope) includes() []rule {
	var out []rule
	for _, r := range s.rules {
		if !r.exclude {
			out = append(out, r)
		}
	}
	return out
}

// MaxExpand is the largest IP range Targets lists address by address (a /24).
const MaxExpand = 256

// maxExpandLimit is the most addresses TargetsUpTo will ever list for one range (a /16).
const maxExpandLimit = 1 << 16

// Targets lists the hosts the scope itself names, so a tool can run on the scope file alone:
// every domain, every single IP, and every address of ranges up to MaxExpand addresses, minus
// exclusions. A wildcard names no host (it leaves out the apex), so it is returned in wildcards for
// the caller to enumerate first; larger ranges are returned in ranges.
//
// A range in ranges may contain excluded addresses; check each address with Allowed after expanding it.
func (s *Scope) Targets() (targets, wildcards, ranges []string) {
	return s.TargetsUpTo(MaxExpand)
}

// TargetsUpTo is Targets with a different limit: ranges of at most maxAddrs addresses are listed
// address by address (exclusions applied), larger ones are returned in ranges. maxAddrs is capped at
// 65536 (a /16), so a typo cannot make it list millions of addresses.
func (s *Scope) TargetsUpTo(maxAddrs int) (targets, wildcards, ranges []string) {
	if maxAddrs > maxExpandLimit {
		maxAddrs = maxExpandLimit
	}
	seenT, seenW, seenR := map[string]bool{}, map[string]bool{}, map[string]bool{}
	add := func(t string) {
		if !seenT[t] && s.Allowed(t) {
			seenT[t] = true
			targets = append(targets, t)
		}
	}
	for _, r := range s.includes() {
		switch {
		case r.wildcard:
			if w := "*." + r.domain; !seenW[w] {
				seenW[w] = true
				wildcards = append(wildcards, w)
			}
		case r.ipnet != nil:
			ones, bits := r.ipnet.Mask.Size()
			hostBits := bits - ones
			if hostBits > 16 || 1<<hostBits > maxAddrs {
				if c := r.ipnet.String(); !seenR[c] {
					seenR[c] = true
					ranges = append(ranges, c)
				}
				continue
			}
			for ip := r.ipnet.IP.Mask(r.ipnet.Mask); r.ipnet.Contains(ip); ip = nextIP(ip) {
				add(ip.String())
			}
		default:
			add(r.domain)
		}
	}
	return targets, wildcards, ranges
}

func nextIP(ip net.IP) net.IP {
	out := append(net.IP(nil), ip...)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// Allowed reports whether a target (a hostname, host:port, IP or URL) is in scope. A target whose host
// cannot be extracted unambiguously is not in scope.
func (s *Scope) Allowed(target string) bool {
	host := Hostname(target)
	if host == "" {
		return false
	}
	included := false
	for _, r := range s.rules {
		if !r.match(host) {
			continue
		}
		if r.exclude {
			return false
		}
		included = true
	}
	return included
}

// Covers reports whether a root domain may be enumerated: the root itself is in scope, or a wildcard
// rule allows its subdomains (*.example.com covers example.com, whose subdomains are the results). An
// exclusion that matches the root still wins.
//
// Covers is for tools that discover hosts under a root (subdomain enumeration). Use Allowed for a host
// a tool is about to touch.
func (s *Scope) Covers(root string) bool {
	host := Hostname(root)
	if host == "" {
		return false
	}
	covered := false
	for _, r := range s.rules {
		if r.exclude {
			if r.match(host) {
				return false
			}
			continue
		}
		if r.match(host) || (r.wildcard && (host == r.domain || strings.HasSuffix(host, "."+r.domain))) {
			covered = true
		}
	}
	return covered
}

func (r rule) match(host string) bool {
	if r.ipnet != nil {
		ip := net.ParseIP(host)
		return ip != nil && r.ipnet.Contains(ip)
	}
	if r.wildcard {
		return strings.HasSuffix(host, "."+r.domain)
	}
	return host == r.domain
}

// Hostname extracts the lowercase hostname from a URL, host:port or bare host. An IP address is
// returned in its canonical form (an IPv6 address without brackets). It returns "" when the target has
// no host or the host is malformed: userinfo is never part of the host ("http://example.com@evil.com/"
// is evil.com), and a host with an empty label, a space, a "%", a "*" or any character that is not a
// letter, digit, "-", "_" or "." is rejected, as is an IPv6 zone.
func Hostname(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if ip := net.ParseIP(t); ip != nil {
		return ip.String() // a bare IPv6 address has no brackets to parse as a URL host
	}
	if !hasScheme(t) {
		t = "scheme://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	if !validDomain(host) {
		return ""
	}
	return host
}

// hasScheme reports whether t starts with "scheme://". A "://" that comes after a "/", "?" or "#" is part
// of a path or query ("example.com/go?next=http://x"), not a scheme.
func hasScheme(t string) bool {
	i := strings.Index(t, "://")
	return i > 0 && !strings.ContainsAny(t[:i], "/?#")
}

// validDomain reports whether d is a plausible hostname: non-empty labels of letters, digits, "-" and
// "_" (bytes >= 0x80 are kept so a Unicode name is compared literally and never matches an ASCII
// rule), and a last label that is not all digits, which would be an IPv4 address written in a form
// some clients read differently ("010.0.0.7", "10.1", "0x7f.1").
func validDomain(d string) bool {
	if d == "" {
		return false
	}
	labels := strings.Split(d, ".")
	for _, l := range labels {
		if l == "" {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c >= 0x80:
			default:
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}
