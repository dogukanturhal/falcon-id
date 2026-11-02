SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

-- Signup email verification by 6-digit one-time code.
--
-- The emailed 64-character hex token is replaced by a 6-digit code. Only a hash
-- is stored (HMAC-SHA256 bound to the signup request id, see
-- SignupService.hashVerificationCode); the plaintext exists only in the email.
--
--   verification_code_hash          hex hash of the current code; NULL = the row
--                                   predates codes and still uses the legacy
--                                   verification_token (accepted during rollout).
--   verification_code_expires_at    code expiry (15 minutes after it was sent);
--                                   set to NOW() when the code is consumed.
--   verification_attempts           guesses made against the current code; the
--                                   code is burned at 5. Reset by a resend.
--   verification_failed_total       wrong guesses over the row's lifetime; a
--                                   resend does NOT reset it. Capped at 15; a
--                                   successful verify refunds its own attempt.
--   verification_resends            codes re-sent in the current window.
--   verification_resend_window_start start of the hourly resend window.
--   verification_last_sent_at       last send time, for the resend cooldown.
--
-- Additive and idempotent: no column is dropped or retyped, no NOT NULL without
-- a default is added to a populated table, no backfill (legacy rows keep their
-- token).
ALTER TABLE iam_signup_requests
    ADD COLUMN IF NOT EXISTS verification_code_hash TEXT,
    ADD COLUMN IF NOT EXISTS verification_code_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS verification_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS verification_failed_total INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS verification_resends INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS verification_resend_window_start TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS verification_last_sent_at TIMESTAMPTZ;

COMMENT ON COLUMN iam_signup_requests.verification_code_hash IS
    'HMAC-SHA256 (hex) of the 6-digit email code, bound to the request id. NULL = legacy row verified by verification_token.';
