# raijin-core

Shared building blocks of the [Raijin](https://github.com/protonnegativo/raijin) tools: AI-native offensive security tools that return signal, not noise.

Every Raijin tool is a standalone binary. This module is compiled into each of them, so people who install one tool never see it. It exists so all the tools decide the same way and print the same JSON.

| Package | What it does |
|---|---|
| `scope` | Parses a scope file and answers "is this host in scope?". Strict by design: an invalid line is an error that names the line and the fix, never a warning. |
| `schema` | The JSON envelope every tool prints (`schema_version` first), the structured `Error`, the size `Budget`, and a reader for any tool's output. |
| `state` | Remembers what a tool already reported, so the next run can mark only what is new. |

## Why strict scope

The consumers of these tools are AI agents. A warning is easy to skip; an error that says `line 3: port in rule 'example.com:443'; use the host only` is something an agent fixes and retries. A scope that silently matches nothing, or too much, is how a tool ends up scanning what it should not.

## Install

```sh
go get github.com/protonnegativo/raijin-core@latest
```

See [docs/MIGRATION.md](docs/MIGRATION.md) for the API, the exit-code contract (`2` = structured error with JSON on stdout, `1` = wrong usage) and the list of scope hardening changes.

## License

[MIT](LICENSE)
