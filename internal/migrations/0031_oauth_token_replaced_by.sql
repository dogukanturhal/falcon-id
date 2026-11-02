SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

-- Refresh-token lineage for lost-response recovery.
--
-- A rotation consumes the presented refresh token and mints a successor. When
-- the rotated pair never reaches the client (response cut off), the client
-- later replays the consumed token. replaced_by records, on the CONSUMED row,
-- the id of the successor minted from it, so OAuthProviderService.RefreshTokens
-- can tell "successor never used" (lost response: re-issue from this lineage)
-- from "lineage advanced" (genuine reuse: revoke the family).
--
-- Nullable with no FK and no backfill: legacy rows keep their old behaviour
-- (no recovery). IF NOT EXISTS keeps this idempotent for the Keystone
-- MigrationBundle apply and local-dev hand-apply (same convention as 0028).
--
-- revoke_reason distinguishes a normal rotation ('rotated') from a successor
-- revoked by a recovery ('recovery_superseded'); presenting a superseded token
-- is always treated as theft. recovery_count caps a consumed token at ONE
-- recovery so a stolen cookie cannot keep a session alive by replaying.
ALTER TABLE iam_oauth_tokens
    ADD COLUMN IF NOT EXISTS replaced_by UUID,
    ADD COLUMN IF NOT EXISTS revoke_reason TEXT,
    ADD COLUMN IF NOT EXISTS recovery_count SMALLINT NOT NULL DEFAULT 0;

COMMENT ON COLUMN iam_oauth_tokens.replaced_by IS
    'iam_oauth_tokens.id of the successor minted when this refresh token was rotated (or recovered). NULL = never rotated or legacy row; no lost-response recovery.';

COMMENT ON COLUMN iam_oauth_tokens.revoke_reason IS
    'Why a refresh token row was revoked by the rotation path: rotated | recovery_superseded. NULL = other / legacy.';
COMMENT ON COLUMN iam_oauth_tokens.recovery_count IS
    'How many lost-response recoveries were served for this consumed refresh token (max 1).';
