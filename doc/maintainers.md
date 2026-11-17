# Maintainer guide

Operations, CI and release material for the people who run this repository. Users of the library need only the [README](../README.md).

## CI and required checks

| Workflow | Jobs | When |
|---|---|---|
| `ci.yml` | `test (floor)`, `test (stable)`, `test-386`, `lint`, `vuln`, `scripts`, `zizmor` | pull requests, pushes to `main`, weekly |
| `codeql.yml` | `CodeQL (go)`, `CodeQL (actions)` on pull requests; the shared code-scan workflow on `main` and weekly | as stated |
| `scorecard.yml` | OpenSSF Scorecard | pushes to `main`, weekly |
| `release.yml` | release-please, `verify-module`, tag audit | pushes to `main` |
| `tag-guard.yml` | tag audit and issue on failure | `v*` tag push, daily, on demand from `main`, from `release.yml` |

`test (floor)` runs the exact Go version in `go.mod`'s `go` directive, and `test (stable)` the latest Go release. The weekly run refreshes the vulnerability data. 

## Supply-chain policy

- Every action and reusable workflow is pinned to a full SHA with a `# vX.Y.Z` comment; the shared code-scan workflow (`entur/gha-security`) too.
- `permissions: {}` at the top of every workflow, job-level grants, `persist-credentials: false`, no caches, no secrets, no `pull_request_target`, `GOTOOLCHAIN: local`.
- CodeQL: pull requests run a local job (`go` manual build, `actions`); `main` and the weekly run use the shared workflow, granted exactly the permission union its jobs declare at the pinned SHA (re-check on every bump). The shared workflow's scanner reads an allowlist from the checked-out tree and can dismiss alerts, so it must not run on pull requests; do not add that allowlist file.
- `govulncheck` and `modhash` are `tool` dependencies of the nested `tools/` module, never of the library. golangci-lint runs at an exact version (`v2.15.0`).
- Dependabot: monthly, 7-day cooldown. `github.com/modelcontextprotocol/go-sdk` has its own group (`mcp-go-sdk`, all update types) and is excluded from the other Go groups, security group included, so SDK behaviour changes always arrive as their own pull request. `ci(deps)`/`chore(deps)` never release.

## Releases

1. release-please opens or updates a release pull request on every push to `main`. The pull request is created with `GITHUB_TOKEN`, so its workflow runs start in an approval-required state: a maintainer must use **Approve workflows to run** on the pull request, then review and merge it.
2. On merge, release-please creates the tag and an immutable GitHub release. `verify-module` then:
   - downloads the version through proxy.golang.org, which records it in sum.golang.org;
   - checks that its `h1:` hash equals `modhash -rev <tag>` of the tagged tree;
   - runs `gh release verify`.
3. The release workflow then runs the tag audit explicitly, because a tag pushed with `GITHUB_TOKEN` does not trigger `tag-guard.yml`.
4. **A bad release** is fixed forward:
   - a `fix:` pull request adds `retract vX.Y.Z // reason` to `go.mod`;
   - a maintainer edits the GitHub release title to say "retracted";
   - tags are never deleted or moved.

### First release is v0.1.0

release-please's default first version is 1.0.0, which is why go-calendar's first release was 1.0.0. This repository sets the first version explicitly.

Mechanism: `"initial-version": "0.1.0"` in `release-please-config.json`, with an empty `.release-please-manifest.json` (`{}`), so there is no recorded last version.

Evidence (release-please source and docs, checked 2026-11-17; `release-please-action` v5.0.0, which pins release-please `^17.6.0`):

- `src/strategies/base.ts`: when no latest release is found, the next version is `initialReleaseVersion()`, which returns `initialVersion` if set and otherwise the literal `1.0.0`. Because it does not depend on commit types, a `fix:`-only first release also gives 0.1.0.
- `schemas/config.json`: `initial-version` — "Releases the initial library with a specified version". It exists at v17.6.0 and on `main`.
- `docs/manifest-releaser.md`: a manifest entry is the last-released version, and the next version is then computed from conventional commits. A `"0.0.0"` entry would therefore yield 0.0.1 for a `fix:` and, with `bump-minor-pre-major`, 0.1.0 for a `feat:`; it does not guarantee 0.1.0, so the manifest stays empty.
- `bump-minor-pre-major: true` keeps later breaking changes below 1.0.0 as minor bumps; moving to 1.0.0 is then a deliberate `Release-As: 1.0.0`.

This was not run against GitHub from this repository; confirm that the first release pull request is titled `chore(main): release 0.1.0`. If it proposes anything else, do not merge it. Use the fallback: put a `Release-As: 0.1.0` footer in the body of the first feature pull request's squash message (release-please README, "How do I change the version number?": a `Release-As: x.x.x` footer on a commit to the default branch makes the release pull request use that version), or push an empty commit with that footer. After the first release, `initial-version` is inert and may stay.

## Tag audit

`.github/scripts/tag-audit.sh` checks every `v*` tag with read-only API calls. Each tag must point at a commit that:

- has the release-please release subject for its version;
- is on `main`;
- records that version in `.release-please-manifest.json`;
- came from a merged `release-please--branches--main` pull request by an allowed author.

The allowed authors are `ALLOWED_RELEASE_AUTHORS` at the top of the script; add the release App's bot login there when one is introduced. `.github/scripts/tag-audit_test.sh` tests the script against a fake `gh`. A failed audit opens an issue. The audit detects stray tags after they are created; it does not prevent their publication or consumption.

## Repository settings checklist (repository admin, before the first release)

- [ ] **Ruleset `main`:**
  - pull request required, 1 approval, code-owner review, dismiss stale approvals, approval of the latest push, conversation resolution;
  - squash merge only, linear history, signed commits;
  - required checks: the CI jobs above, `CodeQL (go)`, `CodeQL (actions)`, and the code-scanning results gate;
  - block force pushes and deletion; no bypass actors.
- [ ] **Ruleset `v*` tags:** restrict updates and deletions, block force pushes. Restricting tag creation needs a release GitHub App as the only bypass actor, because `GITHUB_TOKEN` cannot be one. Until then the tag audit detects stray tags.
- [ ] **Immutable releases** enabled before the first release (they apply only to later releases).
- [ ] **Actions settings:**
  - read-only default token;
  - "Allow GitHub Actions to create and approve pull requests" on (release-please);
  - fork pull request workflows require approval;
  - require full-length SHA pins once a test pull request shows that the shared code-scan workflow's `$/` references pass.
- [ ] **Security features:** private vulnerability reporting, Dependabot alerts and security updates, secret scanning and push protection.
- [ ] **Merging:** squash merge only; delete head branches on merge. The owning team (see `CODEOWNERS`) has admin access.

## Working with an SSH remote

Signed commits and the `main` ruleset apply to pushes over SSH as well. If `origin` is an SSH remote (`git@github.com:entur/go-mcpkit.git`), the `gh` CLI still talks to the API over HTTPS with its own token, and `go get github.com/entur/go-mcpkit` needs no credentials because the module is public. Do not rewrite an SSH remote to HTTPS to work around a failed push; check the signing key and the ruleset instead.

## Organisation-admin follow-ups

- **Release App.** Install a repository-scoped release GitHub App. Then:
  - switch release-please to its token, which removes the manual "approve workflows" step;
  - add the App as the only bypass actor of a "restrict creations" rule on `v*` tags;
  - add its bot login to `ALLOWED_RELEASE_AUTHORS`;
  - turn off "Allow GitHub Actions to create and approve pull requests".
- **Organisation policies**, if repository-level settings are locked: the immutable-releases policy and the SHA-pinning policy.
