# ENT-11 — Add `consumer` value to `tenant_type` enum

**Status**: operator-only procedure (pending execution).
**Owner**: platform team / DBA on duty.
**Related**: !224 (consumer tenant), !226 (currently uses `personal` enum as a fallback).

## Why this is operator-only, not a regular MR

`<gitops-repo>/keystone/resources/falcon-id/schema-definition-tenant.yaml` is **auto-generated** by `keystonectl inspect` against a representative falcon-id-pg database. Hand-editing the YAML to add a new enum value works once, but the next `inspect` re-render reverts it. The proper path is:

1. Apply the DDL directly to the source database (the falcon-id-pg cluster)
2. Re-run `keystonectl inspect` against that same database
3. Commit the regenerated YAML
4. Let ArgoCD reconcile the regen into the Keystone bundle that gets applied to every realm-tenant database

This is the documented operator procedure for any enum addition in this codebase.

## Steps

### 1. Apply `ALTER TYPE` directly to falcon-id-pg

```bash
# From a workstation with WireGuard up + ~/.ssh/infra-key:
ssh -i ~/.ssh/infra-key hexxlock@10.0.70.100 \
  "sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml \
     -n cnpg-clusters exec -i falcon-id-pg-2 -c postgres -- \
     psql -U postgres -d hexxlock_falcon_id -c \
     \"ALTER TYPE tenant_type ADD VALUE IF NOT EXISTS 'consumer';\""
```

Verify:

```sql
SELECT enumlabel FROM pg_enum
WHERE  enumtypid = 'tenant_type'::regtype
ORDER BY enumsortorder;
```

Expected output: `customer | internal | trial | partner | demo | personal | consumer`.

### 2. Apply the same `ALTER TYPE` to every other realm-tenant database

`tenant_type` exists in every realm-tenant DB (hexxlock_realm_platform, hexxlock_realm_customer_*, etc.). The enum value must be added in each, or the Keystone differ will emit a "missing enum value" diff per database every reconcile.

```bash
# List realm-tenant databases:
ssh -i ~/.ssh/infra-key hexxlock@10.0.70.100 \
  "sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml \
     -n cnpg-clusters exec -i falcon-id-pg-2 -c postgres -- \
     psql -U postgres -lA | grep hexxlock_realm_ | cut -d'|' -f1"

# For each database name from above, apply:
DB=hexxlock_realm_<...>
ssh ... "... psql -U postgres -d $DB -c \"ALTER TYPE tenant_type ADD VALUE IF NOT EXISTS 'consumer';\""
```

### 3. Regenerate the Keystone schema-definition-tenant.yaml

```bash
# Requires Go toolchain + keystonectl >= v0.1.58 on your workstation.
# Port-forward the falcon-id-pg-rw service from cp-01:
ssh -i ~/.ssh/infra-key -L 25432:falcon-id-pg-rw.cnpg-clusters.svc.cluster.local:5432 \
  hexxlock@10.0.70.100 -N &

# Fetch the keystone-admin password:
PGPASS=$(ssh -i ~/.ssh/infra-key hexxlock@10.0.70.100 \
  "sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml \
     -n keystone-system get secret falcon-id-pg-keystone-admin \
     -o jsonpath='{.data.password}' | base64 -d")

# Run keystonectl against hexxlock_realm_platform (the canonical tenant DB):
PGPASSWORD="$PGPASS" keystonectl inspect \
  --host 127.0.0.1 --port 25432 \
  --user keystone_admin \
  --database hexxlock_realm_platform \
  --strip-dangling-refs \
  > ~/projects/platform/<gitops-repo>/keystone/resources/falcon-id/schema-definition-tenant.yaml

# Kill the port-forward
kill %1
```

Verify diff:

```bash
cd ~/projects/platform/the GitOps repository
git diff platform/keystone/resources/falcon-id/schema-definition-tenant.yaml
```

The only change should be the addition of `- consumer` to the `tenant_type` enum values list.

### 4. Commit + open MR

```bash
cd ~/projects/platform/the GitOps repository
git checkout -b feat/falcon-id-add-consumer-tenant-type-enum origin/main
git add platform/keystone/resources/falcon-id/schema-definition-tenant.yaml
git commit -m "feat(keystone): add 'consumer' value to tenant_type enum (ENT-11)

Adds the 'consumer' value to the tenant_type enum, replacing the
fallback use of 'personal' for the shared hexxlock-consumer tenant
introduced in falcon-id!224.

Source-DB DDL already applied to falcon-id-pg + every realm-tenant
DB per the operator runbook (falcon-id/docs/operator-runbooks/
ent11-add-consumer-tenant-type-enum.md). This regen captures the
result for declarative reconciliation."
git push origin feat/falcon-id-add-consumer-tenant-type-enum
```

### 5. After the the GitOps repository MR merges, switch the falcon-id bootstrap

`cmd/consumer_tenant_bootstrap.go` line 121 currently has:

```go
Type: models.TenantType("personal"),
```

Change to:

```go
Type: models.TenantType("consumer"),
```

…in a follow-up falcon-id MR titled `fix(consumer-tenant): use 'consumer' enum value post-keystone-migration (ENT-11)`. The Keystone differ will then converge the existing `00000000-0000-0000-0000-000000000004` row to type='consumer' via an ALTER on next reconcile.

Frontend conditional rendering (`isConsumerTenantUser` in apps/accounts/src/lib/well-known-ids.ts) keys off the TENANT ID and is unaffected by this enum change.

## Rollback

`ALTER TYPE … ADD VALUE` is irreversible in PostgreSQL (you can't drop enum values that are in use). The migration is forward-only. If it must be backed out:

1. Revert the the GitOps repository MR (regenerates the YAML to remove `- consumer`).
2. Revert the falcon-id bootstrap MR (back to `personal`).
3. The orphaned `consumer` enum value stays in pg_enum forever — but the Keystone differ will emit a benign "extra value" warning that can be filtered.

## Why not just keep `personal`?

`personal` works today. The reason to migrate is **type-filter clarity** — downstream code (analytics queries, billing rules, frontend label maps) that wants to distinguish "individual personal tenant" from "shared consumer pool" has no signal under the current model. With per-user `personal-XXXX` tenants now extinct (all 0 of them), there's no collision risk, but a clean enum value makes future filtering unambiguous. Low priority — defer until a downstream consumer actually needs the distinction.
