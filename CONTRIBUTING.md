# Contributing to raijin-core

Thanks for helping. This module is small on purpose and security-sensitive: the `scope` package decides what a tool may touch.

- Open an issue before a large change. Bug reports with a failing input are the best kind.
- `go vet ./...` and `go test ./... -race -count=1` must pass. A change to `scope` needs a test case for the input that was wrong (and the fuzz target `FuzzAllowed` must keep passing).
- The JSON field names and order of `schema.Result` are a contract used by every tool and by `raijin-mcp`. Changing them is a breaking change.
- Keep commits short and in the imperative ("Reject empty labels").
- AI-assisted contributions are welcome if you understand and have tested every line.
