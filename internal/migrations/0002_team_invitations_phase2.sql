-- Migration: team invitations Phase 2 prereq
-- Creates iam_team_invitations for the Mearax Team settings page.
--
-- This table is distinct from the existing iam_user_invitations, which ties an
-- invitation to a pre-existing user row (user_id FK). This new table supports
-- inviting net-new users who don't yet have an iam_users row. When the invitee
-- accepts, a user row is either matched by email or created, and the role_ids
-- array is applied via iam_user_roles.

CREATE TABLE IF NOT EXISTS iam_team_invitations (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES iam_tenants(id),
    email       TEXT        NOT NULL,
    role_ids    UUID[]      NOT NULL DEFAULT '{}',
    invited_by  UUID        NOT NULL REFERENCES iam_users(id),
    token       TEXT        NOT NULL UNIQUE,
    status      TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','accepted','expired','revoked')),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at TIMESTAMPTZ NULL
);

COMMENT ON TABLE iam_team_invitations IS
    'Phase 2 Team page invite/RSVP workflow. '
    'Distinct from iam_user_invitations (which requires a pre-existing user row). '
    'role_ids soft-references iam_roles; no array FK constraint (application-enforced).';

COMMENT ON COLUMN iam_team_invitations.token IS
    'Cryptographically random 32-byte hex string. '
    'Never logged or returned to the client; provided to the invitee via email.';

CREATE INDEX IF NOT EXISTS idx_team_invitations_tenant_status
    ON iam_team_invitations (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_team_invitations_token
    ON iam_team_invitations (token);

CREATE INDEX IF NOT EXISTS idx_team_invitations_email_tenant
    ON iam_team_invitations (tenant_id, email);
