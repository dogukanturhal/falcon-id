-- 0026_iam_signup_continuation.sql
--
-- Self-service signup that starts from an OIDC /oauth/authorize request must
-- resume that request after email verification, even when the verification link
-- is opened in another tab, browser or device. The continuation is therefore
-- persisted server-side on the signup request instead of living in browser state.
--
--   1. iam_signup_requests.continuation: the validated relative
--      /oauth/authorize URL (path, active client and registered redirect_uri are
--      checked before it is stored and again before it is returned). NULL for
--      signups that did not start from an authorize request. Bounded to 4096
--      characters, matching the validator and the API input limit.
--      iam_signup_requests.completion_secret_hash: SHA-256 of the single-use secret
--      issued to the caller of verify-email; signup completion requires it, so
--      the signup id alone (returned to anyone who starts a signup) cannot claim
--      the mailbox's account. NULL until verified; cleared on completion.
--   2. Backfill: accounts created by a completed self-service signup were
--      created after the person followed the verification link, but the account
--      was never flagged is_email_verified. Mark them verified so the signed-in
--      "my invitations" flow (which requires a verified mailbox) works for them.
--      Only users linked from a verified AND completed signup request are touched.
--
-- Historical signups completed with the request id alone (before the completion
-- secret existed) are trusted as they stand: the backfill treats every verified
-- and completed row as first-party proof.
--
-- Additive and idempotent: no column is dropped or retyped, no NOT NULL is added
-- to a populated column. iam_users has no row-level security, so the backfill
-- needs no tenant GUC.

SET LOCAL statement_timeout = '60s';
SET LOCAL lock_timeout = '5s';

ALTER TABLE iam_signup_requests
    ADD COLUMN IF NOT EXISTS continuation TEXT NULL,
    ADD COLUMN IF NOT EXISTS completion_secret_hash TEXT NULL;

DO $constraint$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'iam_signup_requests_continuation_len_check'
          AND conrelid = 'iam_signup_requests'::regclass
    ) THEN
        ALTER TABLE iam_signup_requests
            ADD CONSTRAINT iam_signup_requests_continuation_len_check
            CHECK (continuation IS NULL OR char_length(continuation) <= 4096);
    END IF;
END
$constraint$;

COMMENT ON COLUMN iam_signup_requests.continuation IS
    'Validated relative /oauth/authorize URL the signup started from; returned as redirect_url on completion so the OIDC flow resumes after verification.';

COMMENT ON COLUMN iam_signup_requests.completion_secret_hash IS
    'SHA-256 (hex) of the single-use secret returned by verify-email and required by signup completion; cleared once the signup completes.';

UPDATE iam_users u
SET is_email_verified = true
WHERE u.is_email_verified = false
  AND u.id IN (
      SELECT s.user_id
      FROM iam_signup_requests s
      WHERE s.user_id IS NOT NULL
        AND s.verified
        AND s.completed
  );
