-- 0010_user_admin_review_flag.sql
-- Admin-review flag for local accounts caught behind an SSO-only tenant
-- policy (t-431, d-169 Q3).
--
-- THE GAP THIS CLOSES: when a tenant enables local_auth_disabled (t-431),
-- a user may still hold a pre-existing, valid local password (e.g. signed up
-- before the tenant's domain was claimed / before SSO was enforced). d-169's
-- ruling on Q3 is explicit: do NOT auto-migrate that identity and do NOT
-- silently keep password auth working for it (same shape as c-035's
-- rejection of silent account-linking by email match alone) -- the login
-- must be rejected, AND the account must be flagged for admin review:
-- visible, reversible, audited. This migration adds the visible+reversible
-- half; AuthService.Login (rejection) and the audit log (audited half)
-- carry the rest.
--
-- Shape deliberately mirrors the existing IsLocked/LockReason/LockedAt
-- columns (same table, same pattern): a boolean an admin UI can filter on,
-- a human-readable reason, and a timestamp -- not a new side table, so the
-- existing user list/detail screens can surface it without a join.
--
-- Additive + non-breaking: ADD COLUMN IF NOT EXISTS, all nullable/defaulted.
-- See 0009's note on the Keystone MigrationBundle being the authoritative
-- applier in real/fresh/DR environments; this file is canonical DDL +
-- local-dev application.

SET LOCAL statement_timeout = '30s';

ALTER TABLE iam_users
    ADD COLUMN IF NOT EXISTS requires_admin_review BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS admin_review_reason TEXT,
    ADD COLUMN IF NOT EXISTS admin_review_flagged_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_iam_users_requires_admin_review
    ON iam_users (tenant_id)
    WHERE requires_admin_review = TRUE;

COMMENT ON COLUMN iam_users.requires_admin_review IS
    'Set when a login attempt was rejected for a policy reason that leaves the account in an ambiguous state requiring a human decision -- e.g. a valid local password under a local_auth_disabled tenant (t-431, d-169 Q3). Never auto-cleared; an admin action resolves it via ClearAdminReviewFlag.';
