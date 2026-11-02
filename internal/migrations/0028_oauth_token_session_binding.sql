SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

-- Session-bound refresh tokens.
--
-- Explicit session end (logout, admin/user session revoke, password change,
-- deactivation) must revoke every refresh token issued under that login
-- session and its rotation families; idle/absolute expiry of the browser SSO
-- session must NOT (refresh tokens keep their own lifetime).
--
-- iam_oauth_tokens.idp_session_id is the opaque falcon_idp_session / `sid`
-- value, not the iam_sessions row that logout and admin revoke know. This adds
-- session_id = that iam_sessions row id, stamped at issuance and carried across
-- rotations (OAuthClientRepository.RevokeTokensBySession,
-- OAuthProviderService.RefreshTokens).
--
-- Nullable with no FK and no backfill: legacy tokens keep working and are
-- simply not bound to a session. The partial index keeps the NULL tail
-- (client_credentials, legacy rows) free; idp_session_id is already indexed
-- (iam_oauth_tokens_idp_session_id_idx). IF NOT EXISTS keeps this idempotent
-- for the Keystone MigrationBundle apply and local-dev hand-apply (same
-- convention as 0009).
ALTER TABLE iam_oauth_tokens
    ADD COLUMN IF NOT EXISTS session_id UUID;

CREATE INDEX IF NOT EXISTS idx_iam_oauth_tokens_session
    ON iam_oauth_tokens (session_id)
    WHERE session_id IS NOT NULL;

COMMENT ON COLUMN iam_oauth_tokens.session_id IS
    'iam_sessions.id of the login session this token was issued under. Explicit session end revokes by it (RevokeTokensBySession); NULL = legacy token, unbound.';
