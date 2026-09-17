# migrate-user-realm

One-off operator CLI that re-assigns a user's `realm_id` from one realm to
another. Built for Sprint-1 #5 (FI!135 created the bootstrap admin in
`WellKnownRealmShared` instead of `WellKnownRealmPlatform`), but generic
enough for any future similar realm-correction need.

## When to use this

- A user row was created with the wrong `realm_id` (FI!135-style stale
  data, post-recovery scenarios, manual seed fixup).
- The application's runtime path cannot fix it because:
  - `services.User.Update()` does not include `realm_id` in its column
    list (deliberate — realm migration is a security-relevant scope
    change that should NOT happen as a side effect of a profile edit).
  - `bootstrapAdminUser` skips creation when a user with the same email
    already exists in the tenant, regardless of realm.

## Safety

- **Default mode is dry-run.** The tool prints the `UPDATE` statement it
  WOULD run and exits 0 without touching the DB. Pass `--confirm` to
  apply.
- **Atomic UPDATE** with `WHERE id = $1 AND tenant_id = $2 AND realm_id = $3`.
  A second run is a no-op (RowsAffected=0) — the tool reports "already
  migrated" and exits 0.
- **Cross-tenant safety check.** If the resolved user's tenant does not
  match the `--tenant-id` flag, the tool refuses to migrate.
- **Target realm pre-flight.** The tool calls `repos.Realm.GetByID` on
  `--to-realm` and refuses if the realm row does not exist.

## Required environment

The tool runs in a pod that already has `DATABASE_URL` and
`ENCRYPTION_KEY` from the falcon-id ExternalSecret. `kubectl exec` from
inside the running falcon-id pod is the simplest invocation path.

## Usage

```bash
# Dry-run (default — reports without changing anything):
kubectl -n falcon-id exec deploy/falcon-id-falcon-id -- \
  /app/migrate-user-realm \
    --email=dogukanturhal@example.com \
    --tenant-id=00000000-0000-0000-0000-000000000002 \
    --from-realm=00000000-0000-0000-0000-000000000001 \
    --to-realm=00000000-0000-0000-0000-000000000003

# Apply (--confirm):
kubectl -n falcon-id exec deploy/falcon-id-falcon-id -- \
  /app/migrate-user-realm \
    --email=dogukanturhal@example.com \
    --tenant-id=00000000-0000-0000-0000-000000000002 \
    --from-realm=00000000-0000-0000-0000-000000000001 \
    --to-realm=00000000-0000-0000-0000-000000000003 \
    --confirm
```

## Sprint-1 #5 specific invocation

```
--email      dogukanturhal@example.com
--tenant-id  00000000-0000-0000-0000-000000000002  (exampletenant)
--from-realm 00000000-0000-0000-0000-000000000001  (WellKnownRealmShared — wrong)
--to-realm   00000000-0000-0000-0000-000000000003  (WellKnownRealmPlatform — correct)
```

**Pre-conditions**:

1. FI!139 (Argo Rollouts AT trap fix) is merged and has deployed.
2. `fix/seed-platform-realm-bootstrap` (the realm seed MR) is merged and
   has deployed — `realms` row for `WellKnownRealmPlatform` must exist
   for the pre-flight check to pass.

## After-migration follow-up

Existing OAuth/refresh tokens and IdP sessions for the migrated user may
carry the old realm context. The tool prints SQL to invalidate them; run
those statements (or use the admin API's session-revoke endpoint) so the
user re-authenticates and their tokens carry the new realm.

## Why this is a CLI (not a boot-time auto-fix)

A boot-time auto-fix would re-run on every pod start, which is the wrong
semantics for a one-time data correction. Adding a "did we already
migrate?" guard pollutes the boot path with cleanup state. A CLI is
auditable: the operator runs it once, the action finishes, the cleanup
is done. Same pattern as `cmd/resetpw`.
