SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

-- Signing-key rotation: publish before activate.
--
-- KeyManager.Rotate() now inserts the next key as 'pending' (published in
-- JWKS, not yet used for signing). A single elected rotator promotes it to
-- 'active' once the publish delay (SIGNING_KEY_PUBLISH_DELAY) has elapsed, so
-- every replica and every JWKS cache already knows the kid before a token
-- carrying it exists. activated_at on a pending row is the scheduled
-- activation time.
--
-- Widens the status CHECK only; no data change. Idempotent: DROP IF EXISTS +
-- re-add keeps the Keystone MigrationBundle apply and local hand-apply safe.
ALTER TABLE iam_signing_keys
    DROP CONSTRAINT IF EXISTS iam_signing_keys_status_check;

ALTER TABLE iam_signing_keys
    ADD CONSTRAINT iam_signing_keys_status_check
    CHECK (status = ANY (ARRAY['pending'::text, 'active'::text, 'rotated'::text, 'revoked'::text]));
