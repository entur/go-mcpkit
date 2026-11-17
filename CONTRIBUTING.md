# Contributing

Read [AGENTS.md](AGENTS.md). Maintainer material: [doc/maintainers.md](doc/maintainers.md).

## Checks

```sh
gofmt -l .                                   # must print nothing
go mod tidy -diff && go -C tools mod tidy -diff
go vet ./... && go test -race -shuffle=on ./...
GOTOOLCHAIN=go1.26.0 go test ./...           # the Go floor
GOARCH=386 go test ./...                     # 32-bit
golangci-lint run                            # v2.15.0
go -C tools tool govulncheck -C .. ./...
actionlint && uvx zizmor@1.31.1 --offline .github/
shellcheck .github/scripts/*.sh && bash .github/scripts/tag-audit_test.sh
```

Tests never use the network and stay quick.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/), signed, squash-merged only (the squash message is the commit release-please reads). `feat:` is a minor release, `fix:` a patch; below 1.0.0 a breaking `!` bumps the minor.

## Never auto-merged

Changes under `/output/`, `/httpguard/`, `/retrieved/`, `/mcpkittest/`, `/internal/`, `/enturauth/`, the root `*.go` files, `doc/contract.md`, `/.github/`, the release-please files, `go.mod`, `go.sum` and `CODEOWNERS` need a code owner's review, dependency updates included. A locked default changes only with an ADR in `doc/adr/`, accepted before the code change merges.
