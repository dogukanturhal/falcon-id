-- Migration 0039: authenticator-app (TOTP) fallback for the ZTNA
-- device-enrollment witness.
--
--   iam_users.mfa_totp_enabled_at          when the TOTP factor was enabled.
--       NULL = legacy row enrolled before this column existed; the witness
--       treats NULL as "old enough". The witness refuses a TOTP factor
--       younger than 24h so a hijacked session cannot enrol its own
--       authenticator and immediately vouch for a device.
--       A trigger stamps it on false->true and clears it on disable; the app
--       also stamps it when a secret is re-enrolled while already enabled
--       (MFAService.VerifyAndEnableTOTP).
--   realms.device_witness_totp_allowed     per-realm policy switch (default true;
--       the global kill switch FALCON_WITNESS_TOTP_ENABLED defaults to false).
--   iam_devices.witness_method             how the enrollment was witnessed:
--       'passkey' | 'otp' | '' (legacy / unknown). jess caps the renewal
--       lifetime of 'otp' devices.
--
-- Delivered to production by Keystone MigrationBundle falcon-id v0.232.294
-- (the GitOps repository); see bundled.lock. NOTE: the runtime reads realms from
-- the control-plane database (hexxlock_falcon_id_control), which the
-- falcon-id-public bundle does not reach; the realms ALTER is shipped there by
-- the falcon-id-control bundle 2026-11-01-falcon-id-control-realm-witness-totp-v1.
--
-- Additive, idempotent.

SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

ALTER TABLE iam_users
    ADD COLUMN IF NOT EXISTS mfa_totp_enabled_at TIMESTAMPTZ;

COMMENT ON COLUMN iam_users.mfa_totp_enabled_at IS
    'When mfa_totp_enabled last became true. NULL = legacy row (treated as old enough by the device witness).';

CREATE OR REPLACE FUNCTION iam_users_stamp_mfa_totp_enabled_at() RETURNS trigger AS $$
BEGIN
    IF NEW.mfa_totp_enabled IS NOT TRUE THEN
        NEW.mfa_totp_enabled_at := NULL;
    ELSIF TG_OP = 'INSERT' OR OLD.mfa_totp_enabled IS NOT TRUE THEN
        NEW.mfa_totp_enabled_at := NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_iam_users_mfa_totp_enabled_at ON iam_users;
CREATE TRIGGER trg_iam_users_mfa_totp_enabled_at
    BEFORE INSERT OR UPDATE OF mfa_totp_enabled ON iam_users
    FOR EACH ROW EXECUTE FUNCTION iam_users_stamp_mfa_totp_enabled_at();

ALTER TABLE IF EXISTS realms
    ADD COLUMN IF NOT EXISTS device_witness_totp_allowed BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE iam_devices
    ADD COLUMN IF NOT EXISTS witness_method TEXT NOT NULL DEFAULT '';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iam_devices_witness_method_check') THEN
        ALTER TABLE iam_devices
            ADD CONSTRAINT iam_devices_witness_method_check
            CHECK (witness_method IN ('', 'passkey', 'otp'));
    END IF;
END $$;

COMMENT ON COLUMN iam_devices.witness_method IS
    'How the enrollment was witnessed: passkey | otp. Empty for legacy rows.';
