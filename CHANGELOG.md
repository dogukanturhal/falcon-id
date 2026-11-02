# Changelog

All notable changes to Falcon ID are documented here. The project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.1]

### Fixed

- Quickstart client creation on a fresh database; standalone mode.

### Changed

- Synced the public tree with the development repository, picking up the
  changes made since the first public snapshot.
- Product-specific names, hostnames and deployment details were replaced with
  neutral placeholders, and internal runbooks, audits and one-off migration
  tools were left out of the public tree.
- The Dockerfile was rewritten so it builds from this repository alone.
  `docker compose up` starts Postgres (schema loaded from `hack/schema`),
  Redis, an in-memory SpiceDB and the server.
- Added a README with an honest status section, GitHub Actions for CI,
  CodeQL, OpenSSF Scorecard and signed releases, issue templates and
  Dependabot.

- Security hardening.

### Known gaps

See "Status and limitations" in the README.
