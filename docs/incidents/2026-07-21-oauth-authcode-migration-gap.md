# Incident + Remediation: OAuth token exchange outage — migration `0009` never applied

**Date:** 2026-07-21
**Severity:** P1 — cluster-wide SSO outage (every `*.ops` login failed at the Talon → Falcon-ID token exchange).
**Status:** Mitigated (hotfix applied). Permanent fixes below (A/B/C) pending.

## Symptom

Every OIDC `authorization_code` exchange returned
`invalid_grant: "authorization code has already been used"`; Falcon-ID
`/oauth/token` returned **0× 200 / all 400**. SSO worked earlier in the day on
image `c231a327`; broke after the `a52ed361` ("feat/asvs-oauth-refresh-hibp-tls")
deploy at ~21:30 the previous night (first surfaced on the next morning's login —
nobody logged in overnight).

## Root cause

`a52ed361` added RFC 9700 refresh-token-family reuse detection. Its code writes a
new `iam_oauth_tokens.token_family_id` column on every token creation, and ships
migration `internal/migrations/0009_oauth_token_family.sql` to add it. **The
migration never applied to the existing tenant databases** — so the write failed.

The failure was *catastrophic rather than recoverable* because
`OAuthProviderService.ExchangeAuthorizationCode`
(`internal/services/oauth_provider_service.go:1404`) calls
`MarkAuthorizationCodeUsed` **before** `generateTokens`. So the first attempt
burned the code, then `generateTokens` failed on the missing column → the retry
saw `IsUsed = true` → "already used". No `200` ever occurred.

### Why the migration never applied — the systemic gap

Migrations only apply at **tenant-provisioning** time
(`ProvisioningOrchestrator.stepMigrate → migrateMultiDB → runSingleDBMigration`).
For an **existing** tenant, a **new** migration is never applied:
`FleetOperationsRunner.RunMigrations`
(`internal/services/fleet_operations.go:145`) is *intentionally a
connectivity/schema-version **check** in this phase* — it pings targets and
reports schema version but does not apply. There is **no deploy-time migration
hook** (no `helm.sh/hook` in `deploy/helm/falcon-id/templates/`). So code can (and
did) ship ahead of schema with no gate.

Affected DBs (both on the `falcon-id-pg` CNPG cluster): `hexxlock_falcon_id`,
`hexxlock_realm_platform` (where `svc-talon`'s tokens live). No other tenant DBs
were affected (verified: only these two carry `iam_oauth_tokens`).

## Mitigation applied (triage — not permanent)

Ran `0009` manually against both DBs (idempotent `ADD COLUMN IF NOT EXISTS` +
backfill `token_family_id = id` + partial index). SSO recovered immediately
(`/oauth/token` returned `200`). This is untracked in the migration state and does
not prevent recurrence — hence the permanent fixes below.

---

## Permanent fixes

### Fix A (primary) — deploy-time fleet-wide migration apply + fail-closed gate

**Kills the outage class.** Schema must never lag code in production.

- **Apply engine:** promote `FleetOperationsRunner.RunMigrations` from check-only
  to a real fleet-wide apply, reusing the proven per-DB path
  (`runSingleDBMigration` + the embedded migration registry,
  `internal/services/product_migration_registry.go`). Enumerate active tenants via
  the ProductInstance repo (`ListActive`-style) and apply pending migrations per
  instance DB **inside a per-DB transaction**, recording `schema_migrations`.
- **CLI entrypoint:** `cmd/migrate-fleet` (mirror `cmd/migrate-user-realm`) →
  `falcon-id migrate-fleet --all-tenants`, non-zero exit on any failure.
- **Deploy gate:** a Helm **pre-upgrade/pre-install hook Job**
  (`deploy/helm/falcon-id/templates/migrate-hook-job.yaml`, mirroring
  `spicedb-schema-hook.yaml`) that runs the CLI. Helm blocks the rollout if it
  fails → **fail-closed, schema-before-code.** `hook-weight` before the Deployment;
  `hook-delete-policy: before-hook-creation,hook-succeeded`.
- **Large-table safety:** per-migration `statement_timeout`; `CREATE INDEX
  CONCURRENTLY` for big indexes (outside the tx); advisory lock so parallel pods
  don't double-apply.

### Fix B (resilience) — transactional / post-success code consumption

**Turns catastrophic → recoverable.** In `ExchangeAuthorizationCode`, run
`MarkAuthorizationCodeUsed` and `generateTokens`' writes in **one DB transaction**
(the repos already accept a `DBTX`; add a `WithTx` constructor and thread the tx
through `generateTokens`). On any downstream failure the tx rolls back → the code
stays unused → the client can retry. Preserves single-use semantics (the CAS
mark-used inside the tx still blocks a concurrent second exchange) while removing
the "one transient failure permanently bricks login" footgun. Add a regression
test: `generateTokens` failure must leave the auth code reusable.

### Fix C (guardrail) — catch "code ahead of schema" before prod

Two layers:
1. **Deploy-gate check (part of Fix A's hook):** before rolling new pods, assert
   every tenant DB's `schema_migrations` version ≥ the migration set embedded in
   the new image; fail closed if behind.
2. **PR-time integration test:** run the `authorization_code` + `refresh_token`
   exchange against a DB migrated to the **last released** migration set (not
   HEAD) to catch code that depends on an unreleased/unapplied migration — the
   exact shape that passed CI here (tests use a fresh fully-migrated DB, so the
   gap was invisible).

## Sequencing

1. **Now:** mitigation applied (done). Record `0009` as applied in the migration
   tracking so Fix A's engine treats it as complete.
2. **Fix B** first (small, high-value, no infra) → then **Fix A** (the gate) →
   then **Fix C**. A and B are independent; C depends on A's hook.
3. Each ships as its own reviewed MR, through the canary, no direct-to-prod.

## Owners / notes

The check-only `RunMigrations` was a *deliberate phase decision*, so completing it
(Fix A) should be reviewed with the asvs-oauth-refresh authors. Fix B is a
localized correctness fix in `oauth_provider_service.go`.
