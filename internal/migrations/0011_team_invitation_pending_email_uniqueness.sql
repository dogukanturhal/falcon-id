-- Migration: canonical pending Team invitation uniqueness
-- The authoritative Keystone SchemaDefinition carries the same generated
-- column and partial unique index and must deploy before the consuming code.

COMMENT ON COLUMN iam_team_invitations.token IS
    'SHA-256 digest (sha256:<hex>) of a cryptographically random token for new rows. '
    'Legacy plaintext rows remain readable only through their bounded expiry window.';

ALTER TABLE iam_team_invitations
    ADD COLUMN IF NOT EXISTS email_normalized TEXT
    GENERATED ALWAYS AS (lower(btrim(email))) STORED;

CREATE UNIQUE INDEX IF NOT EXISTS idx_iam_team_invitations_pending_tenant_email_normalized_unique
    ON iam_team_invitations (tenant_id, email_normalized)
    WHERE status = 'pending';
