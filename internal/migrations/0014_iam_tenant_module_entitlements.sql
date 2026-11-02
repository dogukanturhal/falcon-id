-- Migration 267: tenant module entitlements (the product roadmap §4.1).
-- Additive + non-breaking. Canonical DDL source: falcon-id
-- internal/migrations/0014_iam_tenant_module_entitlements.sql.
-- Idempotent.

SET LOCAL statement_timeout = '30s';

CREATE TABLE IF NOT EXISTS iam_tenant_module_entitlements (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    module_code         TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('active', 'trialing', 'grace', 'expired')),
    seats               INTEGER,
    expires_at          TIMESTAMPTZ,
    ever_trialed        BOOLEAN NOT NULL DEFAULT FALSE,
    ever_subscribed     BOOLEAN NOT NULL DEFAULT FALSE,
    event_version       BIGINT NOT NULL DEFAULT 0,
    source_updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT iam_tenant_module_entitlements_tenant_module_uq UNIQUE (tenant_id, module_code)
);

CREATE INDEX IF NOT EXISTS idx_iam_tenant_module_entitlements_tenant
    ON iam_tenant_module_entitlements (tenant_id);

COMMENT ON TABLE iam_tenant_module_entitlements IS
    'Per-tenant, per-module entitlement snapshot mirrored from subscription-management via example.tenant.modules.sync (the product roadmap §4.1). Fail-closed: absence of a row means "not entitled", never "allowed".';

CREATE TABLE IF NOT EXISTS iam_tenant_entitlement_flags (
    tenant_id           UUID PRIMARY KEY,
    flags               JSONB NOT NULL DEFAULT '{}'::jsonb,
    event_version       BIGINT NOT NULL DEFAULT 0,
    source_updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE iam_tenant_entitlement_flags IS
    'Tenant-wide feature flags surfaced in GET /api/v1/tenant/entitlements envelope.flags. One row per tenant (not per module) -- see 0014 migration header for why this is a separate table from iam_tenant_module_entitlements.';
