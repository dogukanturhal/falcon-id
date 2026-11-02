SET LOCAL statement_timeout = '60s';
SET LOCAL lock_timeout = '5s';

-- WO#20 tenant API keys: extend iam_api_keys (legacy rows keep working) and
-- seed the four developer-access permissions. Purely additive and idempotent.
--
--   kind             'legacy' (hxk_, argon2, platform-admin surface) or
--                    'tenant' (lgk_live_<key_id>_<secret>, HMAC-SHA256).
--   key_id           public lookup id of a tenant key (also stored in
--                    key_prefix so the legacy unique index still holds).
--   hash_alg         how key_hash was produced: 'argon2' (legacy rows) or
--                    'hmac-sha256:<version>' (e.g. 'hmac-sha256:v1'; the
--                    pepper itself comes from Vault, never from the DB, and
--                    the version picks which pepper verifies the hash).
--   access           'read' or 'write' (tenant keys only).
--   role_ids         tenant roles the key acts with (SpiceDB role edges).
--   company_ids      companies the key may reach (business-side edges).
--   prev_hash,
--   prev_valid_until old secret kept valid for the rotation grace window.
--   rotated_at       last rotation time.
--   company_sync_*   outbox state for the business-side company edges
--                    (synced | pending_add | pending_remove); a worker and the
--                    SpiceDB reconciler retry the HTTP call until it lands.
ALTER TABLE iam_api_keys
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'legacy'
        CHECK (kind IN ('legacy', 'tenant')),
    ADD COLUMN IF NOT EXISTS key_id TEXT NULL,
    ADD COLUMN IF NOT EXISTS hash_alg TEXT NOT NULL DEFAULT 'argon2'
        CHECK (hash_alg = 'argon2' OR hash_alg ~ '^hmac-sha256:v[0-9]+$'),
    ADD COLUMN IF NOT EXISTS access TEXT NULL
        CHECK (access IS NULL OR access IN ('read', 'write')),
    ADD COLUMN IF NOT EXISTS role_ids UUID[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS company_ids UUID[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS prev_hash TEXT NULL,
    ADD COLUMN IF NOT EXISTS prev_valid_until TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS company_sync_state TEXT NOT NULL DEFAULT 'synced'
        CHECK (company_sync_state IN ('synced', 'pending_add', 'pending_remove', 'failed')),
    ADD COLUMN IF NOT EXISTS company_sync_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS company_sync_next_at TIMESTAMPTZ NULL;

CREATE UNIQUE INDEX IF NOT EXISTS iam_api_keys_key_id_unique
    ON iam_api_keys (key_id);

CREATE INDEX IF NOT EXISTS idx_iam_api_keys_tenant_kind_active
    ON iam_api_keys (tenant_id)
    WHERE kind = 'tenant' AND is_active = TRUE AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_iam_api_keys_company_sync_pending
    ON iam_api_keys (company_sync_next_at)
    WHERE company_sync_state <> 'synced';

-- Developer-access permissions. The service also self-registers these at
-- startup (ON CONFLICT (name) upsert); seeding here lets the role backfill
-- below resolve them before the first pod of the new version has booted.
INSERT INTO iam_permissions (module, resource, action, name, display_name, description, is_system, source)
VALUES
    ('iam', 'api_keys', 'read', 'iam:api_keys:read', 'api_keys:read', 'View tenant API keys', TRUE, 'seed'),
    ('iam', 'api_keys', 'manage', 'iam:api_keys:manage', 'api_keys:manage', 'Create, rotate and revoke tenant API keys', TRUE, 'seed'),
    ('iam', 'webhooks', 'read', 'iam:webhooks:read', 'webhooks:read', 'View tenant webhook endpoints', TRUE, 'seed'),
    ('iam', 'webhooks', 'manage', 'iam:webhooks:manage', 'webhooks:manage', 'Manage tenant webhook endpoints and secrets', TRUE, 'seed')
ON CONFLICT (name) DO NOTHING;

-- Backfill: grant the four permissions to every existing owner and org_admin
-- role. iam_roles has ENABLE+FORCE RLS keyed on app.current_tenant_id and the
-- Keystone apply role is NOBYPASSRLS (see 0025 / bundle v0.232.278), so the
-- loop runs per tenant under that GUC (tenants come from iam_tenants, since
-- iam_roles itself shows no rows without the GUC). set_config(..., true) is
-- transaction-local. The SpiceDB role->permission edges for these grants are
-- converged by the reconciler (reconcileRolePermissions) from this table.
DO $backfill$
DECLARE
    tid uuid;
BEGIN
    FOR tid IN SELECT id FROM iam_tenants LOOP
        PERFORM set_config('app.current_tenant_id', tid::text, true);
        INSERT INTO iam_role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM iam_roles r
        CROSS JOIN iam_permissions p
        WHERE r.tenant_id = tid
          AND lower(r.name) IN ('owner', 'org_admin')
          AND p.name IN ('iam:api_keys:read', 'iam:api_keys:manage',
                         'iam:webhooks:read', 'iam:webhooks:manage')
        ON CONFLICT (role_id, permission_id) DO NOTHING;
    END LOOP;
    PERFORM set_config('app.current_tenant_id', '', true);
END
$backfill$;
