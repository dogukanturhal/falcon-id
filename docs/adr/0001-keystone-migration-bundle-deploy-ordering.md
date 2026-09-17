# ADR 0001 (falcon-id): Keystone migration-bundle coupling + deploy-ordering gate

- Status: Accepted
- Date: 2026-07-21
- Scope: falcon-id repository (numbering is repo-local, distinct from the
  platform-wide ADR series in the GitOps repository)
- Related: 2026-07-21 OAuth migration-gap P1 outage; Fix A
  (`internal/migrations/bundled.lock` + `hack/bundle-lock-check`), Fix C
  (PR-time schema-gap test), Fix H (bundle `v0.232.262` in the GitOps repository
  MR !1048)

## Context

falcon-id's public-schema migrations (`internal/migrations/000N_*.sql`) are
**not** applied on the production databases by `pkg/database.Migrator`. That
golang-migrate-style engine and its `schema_migrations` table have never run on
`hexxlock_falcon_id` / `hexxlock_realm_platform`; it is used only at
tenant-provisioning and in local dev. The **authoritative** production applier
is the **Keystone MigrationBundle operator** (GitOps via the separate
the GitOps repository repo). Each migration must be rendered into a
`MigrationBundle` CR committed at:

```
the GitOps repository: platform/keystone/resources/falcon-id/migration-bundles/falcon-id-v0.232.NNN.yaml
```

`NNN` is Keystone's monotonic bundle counter, independent of the migration
number (`0006→258`, `0007→259`, `0008→261`, `0009→262`). The operator applies
the bundle transactionally and records the version in the per-database
`keystone_schema_migrations` tracking table. Every bundle header mandates the
**deploy-ordering rule**: *apply the bundle FIRST, verify, THEN roll the code.*

### The outage

The `a52ed36` merge shipped migration `0009` (`iam_oauth_tokens.token_family_id`)
and code that writes that column on every token issuance, **but no bundle was
ever rendered**. The column never got added, so every `/oauth/token` exchange
failed with SQLSTATE `42703`, returning `0×200 / all 400` — a cluster-wide SSO
outage. The failure was invisible pre-merge because:

1. **No in-repo visibility of the cross-repo bundle.** Nothing in falcon-id's CI
   could see that a migration lacked a released Keystone bundle in a *different*
   repository.
2. **No deploy-time ordering enforcement.** Nothing blocked the falcon-id image
   from rolling ahead of its schema. `FleetOperationsRunner.RunMigrations` is a
   deliberate check-only stub and there is no migration hook in the chart.
3. **CI tests ran against a fully-migrated DB.** They exercised `HEAD` of
   `internal/migrations`, not the *released* bundle set, so the gap was masked.

### Why not "just run `database.Migrator` at deploy time"

Rejected. On the prod DBs the `schema_migrations` tracking table is empty (or
Keystone-shaped), so a deploy-time `Migrator.Run` would attempt to re-apply the
entire `0001…00NN` history against a live database. Any non-idempotent migration
would corrupt prod — a *second* outage. Keystone remains the single applier;
falcon-id's job is to make the coupling **visible** and the ordering
**enforced**, not to introduce a competing applier.

## Decision

Three complementary controls, two of them fully owned by this repo.

### 1. In-repo migration↔bundle lock (Fix A — implemented here)

`internal/migrations/bundled.lock` records, for every on-disk migration, the
released vehicle that applies it in production:

```
<migration-file>  <vehicle>  <sha256-hex>
# vehicle = "v0.232.NNN" (released Keystone bundle) OR "baseline"
#           (DDL folded into schema-definition-main.yaml)
```

`hack/bundle-lock-check` (CI stage `lint`, `allow_failure: false`) fails when:

- a migration file has **no** lock entry — the exact recurrence guard: you
  cannot merge a migration without recording its released bundle;
- a lock entry is **stale** (names a deleted migration);
- a locked migration's bytes **drift** from the recorded SHA-256 — an edit after
  release means the released bundle no longer matches the file; render a new
  bundle and update the lock.

The lock is embedded into binaries via `//go:embed` (`internal/migrations`
package) so the deploy-ordering gate and the PR-time schema-gap test evaluate the
exact migration HEAD the image was built against.

### 2. Fail-closed deploy-ordering PreSync gate (implemented here, opt-in)

`cmd/keystone-migration-gate` connects to the target DB and asserts that the
**HEAD** bundle version from the embedded lock is present (and not `dirty`) in
`keystone_schema_migrations`, using the official
`keystone-sdk/go/migration.Runner.IsApplied`. Exit codes: `0` applied (or
baseline-only), `1` **not applied → fail closed**, `2` config/connectivity
error.

It is wired as an Argo CD **PreSync hook Job** in the falcon-id chart
(`deploy/helm/falcon-id/templates/keystone-migration-gate-hook.yaml`, gated by
`keystoneMigrationGate.enabled`). Exact mechanism:

```yaml
metadata:
  annotations:
    argocd.argoproj.io/hook: PreSync                     # before the Rollout syncs
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation,HookSucceeded
    argocd.argoproj.io/sync-wave: "-5"                   # early among PreSync hooks
spec:
  template:
    metadata:
      annotations:
        linkerd.io/inject: disabled                      # one-shot Job must reach Completed
    spec:
      containers:
        - image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"   # the INCOMING image
          command: ["./keystone-migration-gate"]
          envFrom: [{ secretRef: { name: <fullname>-vault } }]              # DATABASE_URL
```

Because the hook runs the **incoming** image, its embedded lock is the new code's
schema HEAD. If the bundle has not been applied, the hook fails and Argo aborts
the sync; the image never rolls. Argo retries on the next reconcile, so the
deploy proceeds automatically once the bundle lands — schema-before-code, with no
human in the loop for the happy path.

Scope limit: the gate checks the **primary** DB reachable via `DATABASE_URL` (the
schema carrying `iam_oauth_tokens` for the platform realm where the outage
occurred). Fleet-wide per-tenant verification is a future extension (below).

### 3. Argo sync-wave ordering between the bundle and the workload (the GitOps repository — OUT OF SCOPE HERE)

The PreSync gate is a *verifier*, not the *applier*. The MigrationBundle CRs live
in the GitOps repository and are reconciled by Keystone from its own Argo
Application. To make ordering robust rather than merely retry-until-consistent,
the GitOps repository must ensure the bundle is applied before the falcon-id
workload app is considered healthy. The required changes there:

1. **Sync-wave / app ordering.** Place the falcon-id `MigrationBundle` resources
   (and the Keystone reconcile that applies them) in an **earlier** Argo
   sync-wave than the falcon-id workload Application — e.g. annotate the
   migration-bundle resources `argocd.argoproj.io/sync-wave: "-10"` relative to
   the workload, or gate the workload app on the Keystone app's health via an App
   dependency. This guarantees `keystone_schema_migrations` carries the target
   version before the workload's PreSync gate runs.
2. **Arm the gate.** Set `keystoneMigrationGate.enabled: true` in the
   environment overlay
   (`environments/prod-eu-west-1-workload/falcon-id/values.yaml`) after confirming
   `schema` (`public`), `trackingTable` (`keystone_schema_migrations`), and
   `DATABASE_URL` against a canary sync.
3. **Release discipline stays manual + reviewed.** Rendering/merging the bundle
   (Fix H flow, `migration-bundle:render` CI job on tag) and adding the
   `bundled.lock` entry remain explicit, reviewed steps — the forcing function is
   that neither falcon-id CI (Fix A) nor the workload sync (this gate) will go
   green until both are done.

## Consequences

- A migration can no longer merge without its released bundle being recorded in
  `bundled.lock` (Fix A), and — once armed — the workload cannot roll ahead of its
  applied schema (gate). Fix C independently proves the *code* runs against the
  released schema.
- The gate is opt-in to avoid a self-inflicted block before the schema/DSN/
  tracking-table assumptions are validated in a canary; arming it is a
  one-line the GitOps repository values change.
- `bundled.lock` must be maintained by hand per release. This is intentional: it
  is the reviewed record of a cross-repo release decision, and the CI checker
  makes forgetting it a hard failure rather than a production incident.

## Future extensions

- **Fleet-wide gate.** Enumerate active ProductInstance DBs and assert the HEAD
  bundle on each, not only the primary DB, for migrations that fan out to
  per-tenant schemas.
- **Optional cross-repo existence check.** `bundle-lock-check` could additionally
  confirm the named bundle file exists in the GitOps repository via the in-cluster
  GitLab API (reusing the `bump-manifest` token pattern), turning a fabricated
  lock entry into a CI failure. Kept out of the core checker to keep it offline
  and deterministic.
