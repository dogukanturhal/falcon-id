# Changelog

All notable changes to Falcon ID are documented here. The project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- Synced the public tree with the development repository, picking up the
  changes made since the first public snapshot.
- Product-specific names, hostnames and deployment details were replaced with
  neutral placeholders, and internal runbooks, audits and one-off migration
  tools were left out of the public tree.
- The Dockerfile and `docker-compose.yml` were rewritten for local use:
  Postgres, Redis and SpiceDB (in-memory) start with `docker compose up`.
- Added a README with an honest status section, GitHub Actions for CI,
  CodeQL, OpenSSF Scorecard and signed releases, issue templates and
  Dependabot.

- Security hardening.

### Known gaps

See "Status and limitations" in the README.
