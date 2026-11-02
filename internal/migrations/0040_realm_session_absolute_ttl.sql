-- Migration 0040: per-realm absolute lifetime of the IdP SSO session.
--
--   realms.session_absolute_ttl_seconds   cap (seconds, counted from AuthTime)
--       on the falcon_idp_session SSO session for users of the realm. NULL =
--       use the global default (SESSION_TTL_REMEMBER_ME, 30d). The platform
--       realm (models.WellKnownRealmPlatform, the workforce/admin realm whose
--       users reach *.ops apps through Talon) is set to 86400 (24h, NIST
--       800-63B AAL2 reauthentication).
--
-- Delivered to production by Keystone MigrationBundle falcon-id v0.232.295
-- (the GitOps repository); see bundled.lock. NOTE: the runtime reads realms from
-- the control-plane database (hexxlock_falcon_id_control), which the
-- falcon-id-public bundle does not reach; the realms ALTER + platform-realm
-- UPDATE are shipped there by the falcon-id-control bundle
-- 2026-11-01-falcon-id-control-realm-session-ttl-v1.
--
-- Additive, idempotent.

SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

ALTER TABLE IF EXISTS realms
    ADD COLUMN IF NOT EXISTS session_absolute_ttl_seconds INTEGER NULL;

DO $$
BEGIN
    IF to_regclass('realms') IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'realms_session_absolute_ttl_range_check') THEN
        ALTER TABLE realms
            ADD CONSTRAINT realms_session_absolute_ttl_range_check
            CHECK (session_absolute_ttl_seconds IS NULL
                   OR session_absolute_ttl_seconds BETWEEN 3600 AND 7776000);
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('realms') IS NOT NULL THEN
        UPDATE realms
           SET session_absolute_ttl_seconds = 86400
         WHERE id = '00000000-0000-0000-0000-000000000003'
           AND session_absolute_ttl_seconds IS NULL;
    END IF;
END $$;
