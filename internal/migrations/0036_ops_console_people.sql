-- Migration 0036: platform-admin console "people" area (operator chain).
--
-- 1. ops_approval_requests gains the columns the approvals API needs:
--    reason_code (fixed operator reason list), decision_note (approver /
--    rejecter note) and tenant_id (optional subject tenant, for filtering).
-- 2. ops_audit_exports: server-side generated, short-lived audit exports
--    (T3: created only against a consumed four-eyes approval). The file is
--    kept in the row, downloadable once by its requester inside 15 minutes,
--    then purged lazily on the next export request.
-- (The global user search needs no new index: id and email_hash lookups use the
--  PK / idx_iam_users_email_hash; the username prefix branch is bounded by LIMIT.)
--
-- Delivered to production by Keystone MigrationBundle falcon-id v0.232.291
-- (the GitOps repository); see bundled.lock.
--
-- Idempotent: IF NOT EXISTS.

SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

ALTER TABLE ops_approval_requests ADD COLUMN IF NOT EXISTS reason_code   text NULL;
ALTER TABLE ops_approval_requests ADD COLUMN IF NOT EXISTS decision_note text NULL;
ALTER TABLE ops_approval_requests ADD COLUMN IF NOT EXISTS tenant_id     uuid NULL;

CREATE INDEX IF NOT EXISTS idx_ops_approval_requests_created
    ON ops_approval_requests (created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS ops_audit_exports (
    id             uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    requester_id   uuid        NOT NULL REFERENCES iam_users(id),
    approval_id    uuid        NOT NULL REFERENCES ops_approval_requests(id),
    format         text        NOT NULL CHECK (format IN ('csv', 'ndjson')),
    filters        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    reason_code    text        NOT NULL,
    reason         text        NOT NULL,
    row_count      integer     NOT NULL DEFAULT 0,
    truncated      boolean     NOT NULL DEFAULT false,
    content        bytea       NOT NULL,
    expires_at     timestamptz NOT NULL,
    downloaded_at  timestamptz NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ops_audit_exports_expires ON ops_audit_exports (expires_at);

COMMENT ON TABLE ops_audit_exports IS
    'Short-lived operator audit exports (PII masked). One download by the requester within 15 minutes; expired rows are deleted lazily.';

GRANT SELECT, INSERT, UPDATE, DELETE ON ops_audit_exports TO falcon_id_app;
