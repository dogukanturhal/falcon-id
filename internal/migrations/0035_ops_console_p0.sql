-- Migration 0035: platform-admin console P0 (security foundation).
--
-- Numbering note: the console plan called this "0017"; 0017 was already taken
-- by 0017_tenant_seat_limit_version.sql, so this is the next free number.
--
-- 1. Extends the platform role_key CHECKs (iam_platform_roles and
--    iam_jit_elevations) with platform_compliance and platform_sre. Both are
--    JIT-only: the iam_platform_roles_enforce trigger (migration 0016) already
--    refuses any non-viewer role_key without an active elevation, so no
--    trigger change is needed. The matching hxl_platform relations and the
--    ops_<domain>_<verb> permissions are in deploy/helm/spicedb-schema/files/
--    spicedb.zed (same commit).
--
-- 2. ops_approval_requests: four-eyes approvals for T3 operator actions
--    (purge apply, refunds over the threshold, ...). The two-person rule is a
--    plain CHECK (approver_id <> requester_id), same idea as migration 0016.
--    A target service consumes an approval exactly once with
--      UPDATE ops_approval_requests SET used_at = now(), status = 'consumed'
--       WHERE id = $1 AND used_at IS NULL AND status = 'approved' AND expires_at > now()
--    (the endpoint that issues/consumes approval tokens ships in a later phase;
--    only the table lands here).
--
-- 3. platform_admin_audit_log becomes the INSERT-only operator audit sink fed
--    by the Kafka topic platform.ops-audit.v1 (internal/opsaudit): new columns
--    for the operator audit record, an event_id dedupe key, a hash chain
--    (prev_hash/entry_hash, written under an advisory lock by the consumer),
--    and a trigger that refuses UPDATE and DELETE. Existing rows are untouched
--    (new columns are nullable).
--
-- Delivered to production by Keystone MigrationBundle falcon-id v0.232.289
-- (the GitOps repository); see bundled.lock.
--
-- Idempotent: IF NOT EXISTS / DROP IF EXISTS + ADD / CREATE OR REPLACE.

SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

-- ---------------------------------------------------------------------
-- 1. role_key CHECKs
-- ---------------------------------------------------------------------

ALTER TABLE iam_platform_roles DROP CONSTRAINT IF EXISTS iam_platform_roles_role_key_check;
ALTER TABLE iam_platform_roles ADD CONSTRAINT iam_platform_roles_role_key_check
    CHECK (role_key IN (
        'platform_admin',
        'platform_support',
        'platform_billing',
        'platform_security',
        'platform_viewer',
        'platform_compliance',
        'platform_sre'
    ));

ALTER TABLE iam_jit_elevations DROP CONSTRAINT IF EXISTS iam_jit_elevations_role_key_check;
ALTER TABLE iam_jit_elevations ADD CONSTRAINT iam_jit_elevations_role_key_check
    CHECK (role_key IN (
        'platform_admin',
        'platform_support',
        'platform_billing',
        'platform_security',
        'platform_viewer',
        'platform_compliance',
        'platform_sre'
    ));

-- ---------------------------------------------------------------------
-- 2. ops_approval_requests
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ops_approval_requests (
    id              uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    action          text        NOT NULL CHECK (length(btrim(action)) > 0),
    resource        text        NOT NULL CHECK (length(btrim(resource)) > 0),
    audience        text        NOT NULL CHECK (length(btrim(audience)) > 0),
    payload_sha256  text        NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    reason          text        NOT NULL CHECK (length(btrim(reason)) > 0),
    requester_id    uuid        NOT NULL REFERENCES iam_users(id),
    approver_id     uuid        NULL REFERENCES iam_users(id),
    status          text        NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'consumed', 'cancelled')),
    expires_at      timestamptz NOT NULL,
    decided_at      timestamptz NULL,
    used_at         timestamptz NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ops_approval_requests_two_person_check
        CHECK (approver_id IS NULL OR approver_id <> requester_id),
    CONSTRAINT ops_approval_requests_used_requires_approver_check
        CHECK (used_at IS NULL OR approver_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_ops_approval_requests_status_expires
    ON ops_approval_requests (status, expires_at);
CREATE INDEX IF NOT EXISTS idx_ops_approval_requests_requester
    ON ops_approval_requests (requester_id);

COMMENT ON TABLE ops_approval_requests IS
    'Four-eyes approval requests for T3 operator actions. approver_id <> requester_id is enforced by CHECK; consumption is a single atomic UPDATE ... WHERE used_at IS NULL.';

GRANT SELECT, INSERT, UPDATE ON ops_approval_requests TO falcon_id_app;

-- ---------------------------------------------------------------------
-- 3. platform_admin_audit_log: operator audit sink, INSERT-only
-- ---------------------------------------------------------------------

ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS event_id        uuid NULL;
ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS source_service  text NULL;
ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS elevation_id    uuid NULL;
ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS approval_id     uuid NULL;
ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS reason_code     text NULL;
ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS reason          text NULL;
ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS resource        text NULL;
ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS before_hash     text NULL;
ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS after_hash      text NULL;
ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS occurred_at     timestamptz NULL;
ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS prev_hash       text NULL;
ALTER TABLE platform_admin_audit_log ADD COLUMN IF NOT EXISTS entry_hash      text NULL;

-- Kafka is at-least-once: event_id is the idempotency key.
CREATE UNIQUE INDEX IF NOT EXISTS uq_platform_admin_audit_log_event_id
    ON platform_admin_audit_log (event_id)
    WHERE event_id IS NOT NULL;

CREATE OR REPLACE FUNCTION platform_admin_audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'platform_admin_audit_log is append-only; % is not permitted', TG_OP
        USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_platform_admin_audit_log_immutable ON platform_admin_audit_log;
CREATE TRIGGER trg_platform_admin_audit_log_immutable
    BEFORE UPDATE OR DELETE ON platform_admin_audit_log
    FOR EACH ROW EXECUTE FUNCTION platform_admin_audit_log_immutable();

-- Grants half of "INSERT-only via grants plus trigger". The trigger is what
-- binds the table owner.
REVOKE UPDATE, DELETE ON platform_admin_audit_log FROM falcon_id_app;
