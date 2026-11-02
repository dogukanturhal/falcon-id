SET LOCAL statement_timeout = '30s';

-- iam_user_memberships has FORCE ROW LEVEL SECURITY with a tenant-only
-- policy (0013), and falcon_id_app is NOBYPASSRLS. A user's own
-- memberships in OTHER tenants (an external accountant's client tenants)
-- were therefore invisible to the tenant switcher and the tenant token
-- exchange, which look memberships up by user, not by tenant.
--
-- This adds a second, SELECT-only permissive policy: a row is readable when
-- its user_id equals app.current_user_id, which falcon-id sets with
-- set_config(..., true) inside a short transaction for the authenticated
-- user only (repositories.WithUserMembershipScope). Writes are unaffected:
-- INSERT/UPDATE/DELETE still need the tenant policy.
DROP POLICY IF EXISTS iam_user_memberships_self_select ON iam_user_memberships;
CREATE POLICY iam_user_memberships_self_select ON iam_user_memberships
    FOR SELECT
    USING (user_id::text = NULLIF(current_setting('app.current_user_id', true), ''));
