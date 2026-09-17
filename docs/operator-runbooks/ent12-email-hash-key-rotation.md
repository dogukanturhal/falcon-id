# ENT-12 — Email-hash-key rotation runbook

**Status**: documented procedure (tooling pending).
**Owner**: platform team + DBA on duty.
**Risk**: HIGH — incorrect execution breaks email-based login for every user in the database.

## Why this is hard

`email_hash` is a deterministic HMAC-SHA256(EMAIL_HASH_KEY, lower(trim(email))). Every row's hash is bound to the key in effect at the time the row was created or last updated. Rotating the key without re-hashing every row breaks every lookup in `UserRepository.GetByEmail` / `GetByEmailGlobal` (discover, login, password-reset, anti-enumeration negative-cache).

There is **no in-band tooling** for this today — `cmd/consumer_tenant_bootstrap.go` style boot-hooks don't address rotation. This runbook documents the safe procedure for when rotation is required (key compromise, periodic rotation policy, post-leak forensics).

## When rotation is REQUIRED

- The EMAIL_HASH_KEY value leaks (e.g. accidental git commit, ex-employee access).
- A scheduled rotation policy elapses (recommend ≥ 90 days for non-critical, < 7 days post-compromise).
- The MR `EMAIL_HASH_KEY-fail-fast` (!219) was deployed with a stub or test value and the real key needs to be installed.

## When rotation is NOT required

- Routine maintenance / "we should rotate" sentiment.
- After image upgrades (the key is environment-scoped, not image-scoped).

Rotation has real cost (cluster-wide downtime risk during cutover); do not do it casually.

## Procedure (dual-key cutover, future tooling-assisted)

### Phase 0 — Decide on the rotation window

- Pick a low-traffic window of ≥ 30 minutes (login + discover broken for the duration).
- Notify users via status page IF compromise-driven.
- Have rollback secret ready (the OLD EMAIL_HASH_KEY, write to a tmpfile chmod 600).

### Phase 1 — Generate the new key

```bash
NEW_KEY="$(openssl rand -hex 32)"
echo "${NEW_KEY}" > /tmp/new_email_hash_key.txt
chmod 600 /tmp/new_email_hash_key.txt
```

Mirror to `SECRETS.local.txt` with a clearly-labelled block per standing rule #4:

```
# === <ISO date> EMAIL_HASH_KEY rotation candidate ===
# Status: candidate (not yet cut over)
# Rotation reason: <leak / scheduled / fix-deploy>
FALCON_ID_EMAIL_HASH_KEY_NEW=<NEW_KEY>
```

### Phase 2 — Pre-compute new hashes

Before cutover, recompute every `email_hash` value using the new key, in a single transaction. The application is still serving with the OLD key during this step, so it's safe.

```sql
-- One-off psql session against the master falcon-id-pg + every realm-tenant DB.
BEGIN;

CREATE TEMP TABLE email_hash_rotation AS
SELECT id,
       email,                                                    -- decrypted email available via the PII envelope; if not, JOIN the GDPR data-export shadow
       encode(hmac(lower(trim(email)), '<NEW_KEY>', 'sha256'), 'hex') AS new_hash
FROM   iam_users
WHERE  email IS NOT NULL AND email <> '';

-- Sanity check — how many rows would change?
SELECT COUNT(*) AS rotate_count FROM email_hash_rotation;

-- Apply:
UPDATE iam_users u
SET    email_hash = r.new_hash, updated_at = NOW()
FROM   email_hash_rotation r
WHERE  u.id = r.id;

COMMIT;
DROP TABLE email_hash_rotation;
```

Important: `iam_users.email` is the encrypted PII column on production. If it's empty (the row was never properly bootstrapped with an email), the row CANNOT be rotated automatically — note + skip + flag for manual repair. The 2026-05-22 incident left `dogukanturhal@example.com` in exactly this state (email=''); use the data-repair pattern from `falcon-id!219` description for those rows.

### Phase 3 — Vault swap

```bash
ssh -i "$VAULT_BASTION_KEY" "$VAULT_BASTION" \
  'TOK="${VAULT_TOKEN:?export a short-lived Vault token; never paste one into this file}"; \
   curl -sk -H "X-Vault-Token: $TOK" \
     -X POST \
     -d "{\"data\":{\"email_hash_key\":\"<NEW_KEY>\"}}" \
     https://vault.example.com/v1/example/data/platform/falcon-id/app'
```

This writes a new version to KV v2; previous version remains for ROLLBACK via `vault kv rollback`.

### Phase 4 — Force ESO refresh + restart falcon-id pods

```bash
ssh -i "$VAULT_BASTION_KEY" "$VAULT_BASTION" \
  "sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml \
     -n falcon-id annotate externalsecret falcon-id-falcon-id-vault \
     force-sync=\"\$(date +%s)\" --overwrite"

# Wait ~10s for ESO refresh, then:
ssh -i "$VAULT_BASTION_KEY" "$VAULT_BASTION" \
  "sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml \
     -n falcon-id rollout restart rollout/falcon-id-falcon-id"
```

### Phase 5 — Verify

- New pods running with the new EMAIL_HASH_KEY env var.
- `POST /api/v1/auth/discover` with a known existing email returns `email_known: true`.
- Login flow works end-to-end.

### Phase 6 — Update SECRETS.local.txt

Mark the new key as live, the old key as historical:

```
# === <ISO date> EMAIL_HASH_KEY rotation completed ===
# OLD_FALCON_ID_EMAIL_HASH_KEY=<OLD_KEY>  # historical, retained for incident-response IR window
FALCON_ID_EMAIL_HASH_KEY=<NEW_KEY>
```

### Rollback (Phase 3-5 reverse)

If Phase 5 verification fails:

```bash
# Vault rollback to prior version:
vault kv rollback -mount=example -version=<prev> platform/falcon-id/app

# Then re-trigger ESO + pod restart.
```

The rows updated in Phase 2 are now MISMATCHED against the old key. Either:
- Re-run Phase 2 with the OLD key on the rotated rows (forward-fix), or
- Restore from the pre-rotation backup if Phase 2 corrupted state catastrophically.

Hence the strong recommendation: take a `pg_dump` snapshot BEFORE Phase 2.

## Future tooling (deferred)

Phase 1 of ENT-12 (this runbook) documents the manual procedure. Phase 2 is the **automated dual-key tooling**:

1. `EMAIL_HASH_KEY_PREVIOUS` env var added to the chart. When present, `repositories.computeEmailHash` is wrapped so lookups try the NEW key first + fall back to the OLD key. This eliminates Phase 2's pre-compute requirement at the cost of a brief dual-serving period.
2. A `falcon-id-key-rotate` Job (Helm chart subchart) that does Phase 2 + tracks progress + writes audit rows.
3. After back-fill completes, the OLD key is removed from env in a second rotation MR.

Until that tooling exists, this manual procedure is the only safe path.

## Why rotation has been deferred to date

- The EMAIL_HASH_KEY only landed properly in production on 2026-05-22 (!219+!220 cycle). Pre-2026-05-22 rotation wasn't possible because the runtime used an empty key.
- Post-2026-05-22, the key has been in service for less than the typical 90-day rotation window.
- No known compromise.

Schedule first scheduled rotation for **2026-08-22** (90 days post-install) or earlier if any of the WHEN-REQUIRED triggers fires.
