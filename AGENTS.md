# AGENTS.md

Follow [entur/ai](https://github.com/entur/ai) ([CONVENTIONS.md](https://github.com/entur/ai/blob/main/CONVENTIONS.md), [guides/reference/go.md](https://github.com/entur/ai/blob/main/guides/reference/go.md)); the rules below take precedence.

- Module `github.com/entur/go-mcpkit`, root `package mcpkit`. Pre-release: no API yet.
- A locked default changes only with an ADR in `doc/adr/` (AsciiDoc).
- Security paths (see `CODEOWNERS`) are never auto-merged.
- No mutable package-level state, no `init`; sentinel errors (`var ErrX = errors.New(...)`) are the exception. Dev tools live in `tools/`, never in the root `go.mod`.
- Workflows: every `uses:` pinned to a full SHA with a `# vX.Y.Z` comment; `permissions: {}` at the top, job-level grants, `persist-credentials: false`, no caches, no secrets. Run `actionlint` and `zizmor` after changes.
- Public repository: nothing internal to Entur in files, commits or PRs.
- Signed Conventional Commits; run the checks in CONTRIBUTING.md first.

`CLAUDE.md` is a symlink to this file; edit `AGENTS.md`.
