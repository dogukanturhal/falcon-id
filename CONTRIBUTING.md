# Contributing to Falcon ID

Thanks for helping. Falcon ID is an AGPL-3.0-or-later identity provider
written in Go.

## Before you start

- For a new endpoint, a new grant or profile, or a change to how tokens or
  authorization decisions are made, open an issue first and describe the
  design. Small fixes, tests and docs can go straight to a pull request.
- The README lists known gaps under "Status and limitations". Fixes for those
  are welcome, and so are issues that argue for a different order.
- Security issues do not belong in issues: see [SECURITY.md](SECURITY.md).

## Sign off your commits (DCO)

Every commit needs a `Signed-off-by` line, which certifies the
[Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s -m "oauth: reject empty redirect_uri on PAR"
```

To fix a missing sign-off: `git commit --amend -s` or
`git rebase --signoff main`.

## Development setup

You need the Go version in `go.mod` and Docker.

```sh
docker compose up -d      # Postgres, Redis, SpiceDB
go vet ./...
go test ./...             # most tests need no services
```

Tests that need a real Postgres read `TEST_DATABASE_URL` (or `DATABASE_URL`)
and skip themselves when it is not set. Lint with
[golangci-lint](https://golangci-lint.run/) v2 using the `.golangci.yml` in the
repository root.

## Pull requests

- Branch from `main`; keep the change focused.
- Commit messages: short imperative subject (`area: what changed`), body
  explains why.
- Add or update tests. Bug fixes should have a test that fails without the fix.
- Update `CHANGELOG.md` under `[Unreleased]` for anything user-visible.
- Describe what you ran. For protocol changes, name the RFC section you
  followed.

## Licensing of contributions

Contributions are licensed under AGPL-3.0-or-later. New source files should
carry an `SPDX-License-Identifier: AGPL-3.0-or-later` header.

## Conduct

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
