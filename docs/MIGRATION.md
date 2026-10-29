# Migrating a tool to raijin-core

Each Raijin tool has its own copy of `internal/scope`, `internal/schema` and `internal/state`. This module
replaces them. The binaries stay independent: the core is compiled into each tool, and whoever installs one
tool never sees the core.

```
go get github.com/protonnegativo/raijin-core@<version>
```

Until the module is published, point at the local clone while migrating:

```
go mod edit -require=github.com/protonnegativo/raijin-core@v0.0.0 -replace=github.com/protonnegativo/raijin-core=../raijin-core
```

Remove the `replace` before the tool is released.

## What the core owns

| Package | Public API |
|---|---|
| `scope` | `Load`, `Parse`, `Scope.Allowed`, `Scope.Covers`, `Scope.Targets`, `Scope.TargetsUpTo`, `MaxExpand`, `Hostname` |
| `schema` | `Result[F, G]`, `Error`, `Budget`, `Marshal`, `Write`, `OmitCount`, `SeverityRank`, `ConfidenceRank`, `SortedKeys`; reading side: `Parse`, `Run`, `Entry`, `Field` |
| `state` | `State`, `Load`, `State.Save`, `State.Observe`, `Mark` |

What stays in each tool: its `Finding` and `Group` types and the structs they embed (`Endpoint`, `Request`,
`Service`, `Response`, `Secret`, `Answer`, `Shape`, `Cert`, `Policy`). Their JSON field names, order and
`omitempty` are the tool's contract with raijin-diff and raijin-mcp, and they differ per tool on purpose.
The core does not touch them.

## Suggested order

1. Replace `internal/state` (smallest, mechanical).
2. Replace `internal/scope` (read "Scope behavior changes" below first).
3. Replace the envelope in `internal/schema`.

One tool at a time, one PR each. For each step: `go vet ./... && go test ./... -race`, and compare the JSON a
fixture run writes before and after with `diff <(old | jq -S .) <(new | jq -S .)`; it must be empty (see
"Output compatibility").

## state

Old API: `state.Load(path) (*State, error)`, `(*State).Mark(findings []schema.Finding, locations map[string][]string) int`,
`(*State).Save(path) error`.

New API: `state.Load`, `(*State).Save` are the same. `Mark` is now a function, generic over the tool's finding
type, so the package no longer imports the tool's schema:

```go
newCount = state.Mark(st, res.Findings, allLocations,
	func(f *schema.Finding) string { return f.Fingerprint },
	func(f *schema.Finding) { f.New = true })
```

`(*State).Observe(key, locations) bool` is the one-finding form if a tool does not hold findings in a slice.

The state file format does not change (`{"seen": {"<key>": ["<location>", ...]}}`), so existing `--state`
files keep working. `Save` now writes to a temporary file and renames it, so an interrupted run no longer
leaves a half-written state; the file is still mode 0600.

## scope

Old import `github.com/protonnegativo/raijin-<tool>/internal/scope` becomes
`github.com/protonnegativo/raijin-core/scope`. `Load`, `Parse`, `Allowed`, `Targets`, `MaxExpand`,
`Hostname` keep their names and signatures. Delete `internal/scope`, and move any tool-specific test to the
tool's package.

### Scope behavior changes

The matcher fails closed. Where the copies disagreed, or where the old code let something odd through, the
stricter reading won. Review each against the tool's own tests.

| # | Change | Why | Tools affected |
|---|---|---|---|
| S1 | A bare IPv6 address (`2001:db8::1`, no brackets) is now parsed as an IP. Before it was rejected. | It is the same host as `[2001:db8::1]`, which was already allowed; ports and tls already had this fix, the other copies were behind. Not a loosening: matching is still by CIDR or exact address. | all except ports, tls |
| S2 | A host with an empty label (`.example.com`, `a..example.com`), a `*`, a space, a `%` or any other character outside letters, digits, `-`, `_`, `.` is rejected (not in scope). Before, `.admin.example.com` matched `*.example.com` and was **not** caught by `!admin.example.com`, and `*.example.com` or `a.*.example.com` as a target were allowed. | Closes an exclusion bypass. Go's URL parser already rejected most other forms. | all scope users |
| S3 | `Parse` rejects a rule that could never match: a port (`example.com:443`), a stray `*` (`*`, `*example.com`, `a.*.b.com`), a space or inline comment (`example.com # prod`), an empty label, a bracketed IPv6, a numeric last label (`10.0.0`, `010.0.0.7`). Before they were accepted and silently matched nothing. | A typo in an exclusion was a silent hole. Scope files that load today and have such a line will now fail with the line number. | all scope users |
| S4 | `Parse` rejects a CIDR with host bits set (`10.0.0.7/24`). Before it silently widened to `10.0.0.0/24`. | Silent widening of scope. The error says what to write. | all scope users |
| S5 | A trailing dot on a wildcard rule (`*.example.com.`) is trimmed like on a domain rule. Before the rule never matched. | Same host in FQDN form. | all scope users |
| S6 | `Hostname` finds the host of `example.com/go?next=http://x` correctly (the `://` in a query is not a scheme). Before it returned "" (not in scope). | Only changes a false "out of scope" into the right answer; an `evil.com/?u=http://example.com` is still `evil.com`. | all scope users |
| S7 | `Hostname` returns an IP in canonical form (`::ffff:10.0.0.7` is `10.0.0.7`, IPv6 lowercase and compressed). | Same host, one spelling; matching already compared parsed IPs. | crawl and js use it for the katana scope regex |
| S8 | `Targets` lists wildcards and ranges once each. | Duplicates in the scope file no longer repeat. | all that call `Targets` |
| S9 | An IPv6 zone (`fe80::1%eth0`), a non-canonical IPv4 (`010.0.0.7`, `0x0a.0.0.7`, `167772167`) and a Unicode lookalike of an ASCII name are not in scope. | Clients read these forms differently from Go. They were already denied; now it is tested and documented. | none (tests only) |

Not changed: a wildcard `*.example.com` still does not include `example.com`; exclusions still win over
inclusions in any order; names are compared as written, lowercased, with one trailing dot trimmed, and
there is no IDNA conversion (write internationalized names in punycode).

### Targets and ports

`raijin-ports` returned CIDR strings from `Targets()` for ranges up to a /16 and expanded them later in its
own `filter`. The core has one rule: `Targets()` lists addresses of ranges up to `MaxExpand` (a /24), exclusions
already applied; `TargetsUpTo(n)` raises the limit (capped at 65536, a /16).

| ports (old) | ports (new) |
|---|---|
| `scope.MaxRange` (16, host bits) | `sc.TargetsUpTo(1 << 16)` |
| `sc.Targets()` returned `10.0.0.0/30` | returns `10.0.0.0`, `10.0.0.1`, `10.0.0.3` (excluded `10.0.0.2` is gone) |
| ranges above a /16 in `ranges` | unchanged |

`filter` and `expand` stay for `-host`/`-l` input; they handle plain addresses fine. The ports `TestTargets`
expectation changes from CIDR strings to addresses. The result set after `filter` is the same.

### Covers (subs, takeover)

`Covers` moves to the core unchanged. It is the "may I enumerate under this root" question; `Allowed` is "may I
touch this host". `*.example.com` covers `example.com` but does not allow it.

### secrets

`raijin-secrets/internal/scope` is a different matcher (local paths and git repository URLs, not hosts) that
shares only the syntax of `!` and `#`. It does not move to the core; keep it in the tool (renaming it to
`internal/sources` would stop it looking like a copy). Three things in it are worth fixing there, none of
them done by this module:

- A URL rule ending in `*` is a plain prefix: `https://github.com*` also allows `https://github.com.evil.com/x`.
  Require the `*` to follow a `/` (`https://github.com/*`), or reject the rule in `Parse`.
- The prefix match is on the raw string, so `https://gitlab.com/acme/../evil/x` matches
  `https://gitlab.com/acme/*`. Clean the path of a URL target before matching.
- Paths are matched lexically after `filepath.Abs`; a symlink inside an allowed directory that points outside
  it (`/srv/app/link` to `/etc`) is allowed. Decide whether to resolve with `filepath.EvalSymlinks`.

## schema

The envelope moves; findings and groups stay. For a tool with `Finding` and `Group` in its own
`internal/schema`:

```go
package schema

import core "github.com/protonnegativo/raijin-core/schema"

type (
	Result = core.Result[Finding, Group]
	Error  = core.Error
	Budget = core.Budget
)

var (
	Marshal        = core.Marshal
	SeverityRank   = core.SeverityRank
	ConfidenceRank = core.ConfidenceRank
)
```

With those aliases no call site changes. Inline them later if you like. Delete from the tool: `Result`,
`Result.MarshalJSON`, `Error`, `Budget`, `Marshal`, `SeverityRank`, `ConfidenceRank`. Keep the tool's
`Finding`, `Group` and their `MarshalJSON`. In `MarshalJSON`, replace the count test with `OmitCount`:

```go
p := plain(f)
p.Count = schema.OmitCount(p.Count, len(p.Locations))
return schema.Marshal(p)
```

`main.go` can replace its encoder block with `schema.Write(w, res, pretty)`.

Differences in `Result` between the copies are all absorbed by the core `Result`. The fields run in the order
the JSON is written: `tool, version, target, summary, origin, url, match, filter, findings, groups, omitted,
errors, next, raw, budget`. `origin` is set by crawl, js, params, xss and diff; `url`, `match`, `filter` only by
fuzz; everyone else leaves them empty and they are not written. `findings` and `groups` are always written, as
`[]` when empty (a nil slice no longer becomes `null`). `budget` is written only when `Truncated`.

### Output compatibility

Checked against the 13 tool copies of the envelope with sample documents (all fields, no optional fields,
counts): the bytes are identical for every tool except scan, below. diff's `Result` is
`core.Result[core.Entry, core.Entry]` and round-trips (see `schema/entry_test.go`).

### Per tool

| Tool | Scope | Schema | State | Other |
|---|---|---|---|---|
| raijin-scan | drop the copy; S1-S6 apply | Needs `Marshal`/`ConfidenceRank` (it had neither): switch `Finding.MarshalJSON` and `Group.MarshalJSON` from `json.Marshal` to `schema.Marshal`. **This changes bytes**: `&`, `<`, `>` in strings are written as themselves instead of `&`, `<`, `>`. Same JSON value, fewer tokens, and what the other 12 tools already do. The result-level `Marshal` is core's, so scan was the only one escaping. | `Fingerprint`, `New` | `Finding` has `cve`, `cvss`, `engine_ref`, keep |
| raijin-probe | drop; S1-S6 | `Response` embedded in Finding/Group stays; `Title` is `omitempty` here, required elsewhere | `Fingerprint`, `New` | |
| raijin-subs | drop; uses `Covers`, `Targets` | `Answer` stays | `Fingerprint`, `New` | |
| raijin-ports | drop; replace `MaxRange` with `TargetsUpTo(1<<16)` and update `TestTargets` (see above); S1 already there | `Service` stays | `Fingerprint`, `New`; key type is `out.AllLocations` | |
| raijin-crawl | drop; `scope.Hostname` in `katana.HostScope` (S7) | `Endpoint`, `Origin` stays on `Result`; Finding/Group have no `MarshalJSON` today, so `Count` is set by the reducer only when the budget cut | `Fingerprint`, `New` | |
| raijin-js | drop; `scope.Hostname` in `HostScope` (S7) | `Origin`; Finding/Group have no `MarshalJSON` | `Fingerprint`, `New` | |
| raijin-params | drop | `Request` stays; `Origin` | `Fingerprint`, `New` | |
| raijin-fuzz | drop | `Shape` stays; `URL`, `Match`, `Filter` move into the core `Result` (same names, same JSON); `Tags` is `omitempty` here only | `Fingerprint`, `New`; locations are `out.Inputs` | |
| raijin-tls | drop; S1 already there | `Cert`, `Group` has no `Title`; `Finding` has no `Tags` | `Fingerprint`, `New` | |
| raijin-secrets | **keep its own scope** (paths and repositories), not the core's | `Secret` stays; `Tags` is `omitempty` here only | `Fingerprint`, `New` (the second argument was named `allLocations` there, no change) | |
| raijin-xss | drop | `Origin`; Finding/Group have no `MarshalJSON` | `Fingerprint`, `New` | |
| raijin-cors | drop | `Policy` stays | `Fingerprint`, `New` | |
| raijin-takeover | drop; uses `Covers` and `Targets` | `Answer` stays; `Claim` and a **serialized** `fingerprint` field stay in the tool. The state key is `StateKey`, not `Fingerprint` | key func returns `f.StateKey` | the only tool whose state key is not `Fingerprint` |
| raijin-diff | none | Replace the whole package with the core: `Marshal`, `Parse`, `Run`, `Entry`, `Field`, `SortedKeys`, `Error`, `Budget`, ranks. `type Result = core.Result[core.Entry, core.Entry]` | none | `Origin` is the shared origin of both runs |
| raijin-mcp | none | No import needed today: it only writes `{"tool": ..., "errors": [{"kind", "hint"}]}` (tools.go `fail`). It may use `schema.Error` there; do not use it in `update`, whose `Error` has an extra `target` field | none | |

### JSON contract the core guarantees

`Result`: `tool`, `version`, `target`, `summary`, `origin`, `url`, `match`, `filter`, `findings`, `groups`,
`omitted`, `errors`, `next`, `raw`, `budget`. `Error`: `kind`, `hint`. `Budget`: `max_items`, `max_bytes`,
`truncated`. Tests in `schema/schema_test.go` pin the order and which fields are left out.
