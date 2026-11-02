-- 0025_iam_membership_multi_company.sql
--
-- Real multi-company membership (team1 decision D1): one global falcon-id
-- account per person, one iam_user_memberships row per person<->tenant, and
-- roles stay tenant-scoped through iam_roles.tenant_id. iam_users.tenant_id is
-- kept as the person's home / default tenant only.
--
-- The membership table itself, its seat_class/status columns and the
-- self-select RLS policy already exist (0013, 0019, 0021). This migration is
-- purely additive and idempotent:
--   1. last_used_at: stamped by the tenant token exchange so a sign-in with
--      more than one active membership can pick the last-used company.
--   2. an index on user_id for the switcher query (list a person's memberships).
--   3. backfill: one membership per existing human user for the user's home
--      tenant. 0013 did this once; users created after it (signups, admin
--      created users) never got a row, so the ledger is repaired here.
--      Service identities (svc-%) and users scheduled for deletion are skipped,
--      matching 0013. ON CONFLICT keeps every existing row untouched.
--
-- No column is dropped or retyped, no NOT NULL is added to a populated column.

SET LOCAL statement_timeout = '60s';
SET LOCAL lock_timeout = '5s';

ALTER TABLE iam_user_memberships
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ NULL;

COMMENT ON COLUMN iam_user_memberships.last_used_at IS
    'Set when the member last obtained a token for this tenant (tenant token exchange / sign-in). Used to pick the default company when a person has more than one active membership.';

CREATE INDEX IF NOT EXISTS idx_iam_user_memberships_user
    ON iam_user_memberships (user_id);

-- Backfill runs per tenant: iam_user_memberships has ENABLE+FORCE RLS with a
-- tenant policy (0013) keyed on app.current_tenant_id, and the Keystone apply
-- role is NOBYPASSRLS, so a set-based INSERT with no tenant GUC is rejected
-- (SQLSTATE 42501, bundle v0.232.278). set_config(..., true) is transaction-
-- local, so nothing leaks past this migration. RLS stays ENABLE+FORCE.
DO $backfill$
DECLARE
    tid uuid;
BEGIN
    FOR tid IN SELECT DISTINCT tenant_id FROM iam_users WHERE tenant_id IS NOT NULL LOOP
        PERFORM set_config('app.current_tenant_id', tid::text, true);
        INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class, status, created_at, deactivated_at)
        SELECT
            u.tenant_id,
            u.id,
            'member',
            CASE WHEN u.is_active THEN 'active' ELSE 'deactivated' END,
            u.created_at,
            CASE WHEN NOT u.is_active THEN now() ELSE NULL END
        FROM iam_users u
        WHERE u.tenant_id = tid
          AND u.username NOT ILIKE 'svc-%'
          AND u.deletion_scheduled_at IS NULL
        ON CONFLICT (tenant_id, user_id) DO NOTHING;
    END LOOP;
    PERFORM set_config('app.current_tenant_id', '', true);
END
$backfill$;
