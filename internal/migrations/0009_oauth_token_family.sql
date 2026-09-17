-- 0009_oauth_token_family.sql
-- Refresh-token FAMILY (lineage) tracking for RFC 9700 §4.14 reuse detection.
--
-- THE GAP THIS CLOSES: iam_oauth_tokens rotates refresh tokens on every use
-- (RefreshTokens → generateTokens), but a rotated (already-revoked) refresh
-- token that is REPLAYED was only rejected for the single presented row —
-- there was no way to identify, and revoke, every other token descended from
-- the same original authorization grant. RFC 9700 §4.14.2 (OAuth 2.0 Security
-- BCP) prescribes that on detected reuse the authorization server revoke the
-- ENTIRE token family. This column is that lineage key.
--
-- SEMANTICS:
--   * Every rotation descended from one authorization grant shares one
--     token_family_id.
--   * A ROOT token (first issuance from an authorization_code /
--     client_credentials / token-exchange grant) carries
--     token_family_id = id (it is its own family root).
--   * On reuse detection the service issues
--     `UPDATE ... SET is_revoked=true WHERE token_family_id=$1` to kill the
--     whole family (see OAuthClientRepository.RevokeRefreshTokenFamily).
--
-- BACKFILL: existing rows get token_family_id = id so every legacy token is
-- the root of its own single-member family. A replay of a legacy token then
-- only ever revokes that one row — it can never revoke a family it was never
-- genuinely part of.
--
-- Additive + non-breaking: ADD COLUMN IF NOT EXISTS (nullable — the app
-- stamps it on every new INSERT; the partial index and backfill make the
-- NULL window transient). Existing INSERTs that omit the column still succeed.
--
-- NOTE (parity with 0004/0007/0008): the embedded golang-migrate runner was
-- retired (cmd/services.go). On a real/fresh/DR DB the AUTHORITATIVE applier
-- is the Keystone MigrationBundle in the GitOps repository
-- (platform/keystone/resources/falcon-id/migration-bundles/falcon-id-vX.Y.Z.yaml),
-- generated from this file via hack/render-migration-bundle.sh and applied
-- transactionally by the Keystone operator. This file is the canonical DDL
-- reference + local-dev (applied by hand). IF NOT EXISTS = both paths idempotent.

SET LOCAL statement_timeout = '30s';

ALTER TABLE iam_oauth_tokens
    ADD COLUMN IF NOT EXISTS token_family_id UUID;

-- Backfill legacy rows: each becomes the root of its own single-member family.
UPDATE iam_oauth_tokens
SET token_family_id = id
WHERE token_family_id IS NULL;

-- Family-revocation reads/writes filter on token_family_id; index it. Partial
-- (IS NOT NULL) keeps the index tight during the transient backfill window.
CREATE INDEX IF NOT EXISTS idx_iam_oauth_tokens_family
    ON iam_oauth_tokens (token_family_id)
    WHERE token_family_id IS NOT NULL;

COMMENT ON COLUMN iam_oauth_tokens.token_family_id IS
    'RFC 9700 §4.14 refresh-token family/lineage id. All rotations descended from one authorization grant share this id; on detected reuse of a rotated (revoked) refresh token the whole family is revoked (OAuthClientRepository.RevokeRefreshTokenFamily). Root tokens carry token_family_id = id.';
