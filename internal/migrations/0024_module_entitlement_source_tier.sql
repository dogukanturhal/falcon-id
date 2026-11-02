SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

-- Nullable mirror metadata, populated by the next authoritative full
-- tenant-management snapshot. Do not guess the source/tier of legacy rows.
-- Existing table only: no new tables or RLS policies.
ALTER TABLE iam_tenant_module_entitlements
    ADD COLUMN IF NOT EXISTS source TEXT,
    ADD COLUMN IF NOT EXISTS tier_code TEXT;
