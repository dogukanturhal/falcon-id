SET LOCAL statement_timeout = '30s';

-- Integer entitlement limits (R6, b40). The envelope's `flags` object is
-- map[string]bool and cannot carry a numeric plan limit such as the
-- production BOM max depth (3 / 10 / unlimited). `limits` is the tenant-wide
-- map[string]int64 counterpart, delivered in the same snapshot (Kafka
-- example.tenant.modules.sync payload.limits or the internal PUT) and
-- guarded by the same event_version as `flags`. Value -1 = unlimited; keys
-- absent = the consumer's own fallback. Additive and idempotent.
ALTER TABLE iam_tenant_entitlement_flags
    ADD COLUMN IF NOT EXISTS limits JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN iam_tenant_entitlement_flags.limits IS
    'Tenant-wide integer entitlement limits served as GET /api/v1/tenant/entitlements `limits` (e.g. production_bom_depth). Values are integers >= -1; -1 = unlimited. Written only with the row''s event_version guard (UpsertFlags); a snapshot without limits leaves the stored value unchanged.';
