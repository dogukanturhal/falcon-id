SET LOCAL statement_timeout = '30s';

CREATE TABLE IF NOT EXISTS iam_tenant_status (
    tenant_id          UUID PRIMARY KEY,
    suspended          BOOLEAN NOT NULL DEFAULT FALSE,
    status             TEXT NOT NULL DEFAULT 'active',
    reason             TEXT NULL,
    event_version      BIGINT NOT NULL DEFAULT 0,
    source_updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE iam_tenant_status IS
    'Per-tenant suspension state mirrored from tenant-management via example.tenant.status (R1-GAPS row 27). Fail-OPEN by design: absence of a row means "not suspended" -- only a row with suspended = true blocks login/token issue/refresh/session use. The Hexxlock internal and consumer well-known tenants are never persisted as suspended (enforced by the consumer, not by a CHECK).';

COMMENT ON COLUMN iam_tenant_status.event_version IS
    'Monotonic per-tenant ordering key (tenant-management sends Unix microseconds taken under the tenant row lock). The consumer applies an event only when its version is strictly greater than this column, so redelivered or out-of-order events are no-ops.';

GRANT SELECT, INSERT, UPDATE ON iam_tenant_status TO falcon_id_app;
