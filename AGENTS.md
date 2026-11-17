# AGENTS.md

Follow [entur/ai](https://github.com/entur/ai) ([CONVENTIONS.md](https://github.com/entur/ai/blob/main/CONVENTIONS.md), [guides/reference/go.md](https://github.com/entur/ai/blob/main/guides/reference/go.md)); the rules below take precedence.

- Module `github.com/entur/go-mcpkit`, root `package mcpkit`. v0.x: the API may change before 1.0.
- Go floor 1.26: build, vet and test with `GOTOOLCHAIN=go1.26.0` as well as the current toolchain.
- A locked default changes only with an ADR in `doc/adr/` (AsciiDoc). The wire contract is `doc/contract.md`; change it in the same pull request as the code.
- Security paths (see `CODEOWNERS`) are never auto-merged.
- No mutable package-level state, no `init`. The exceptions are sentinel errors (`var ErrX = errors.New(...)`), the one test hook in `internal/kittest` (an `atomic.Pointer`, set only through `mcpkittest`, which only `_test.go` files import) and the process-wide `sync.Once` that reports an unsupported write deadline once in `httpguard`.
- Dev tools live in `tools/`, never in the root `go.mod`.
- HTTP is served only through `Handler` (`http.go`). Its guard order is a security boundary, pinned by `TestHandlerComposition`; a `ResponseWriter` wrapper must implement `Unwrap() http.ResponseWriter`.
- Every tool registers through the one core in `tool.go`; nothing else calls the SDK's `AddTool`. Descriptors, schemas and content are snapshotted at registration; interface-held values are frozen as their JSON, and a value that cannot be snapshotted is a registration error.
- Workflows: every `uses:` pinned to a full SHA with a `# vX.Y.Z` comment; `permissions: {}` at the top, job-level grants, `persist-credentials: false`, no caches, no secrets. Run `actionlint` and `zizmor` after changes.
- Public repository: nothing internal to Entur in files, commits or PRs.
- Signed Conventional Commits; run the checks in CONTRIBUTING.md first.

`CLAUDE.md` is a symlink to this file; edit `AGENTS.md`.
