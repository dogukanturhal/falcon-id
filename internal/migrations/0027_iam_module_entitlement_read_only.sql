SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

-- Grace read-only flag mirrored from tenant-management (read_only, only
-- ever true with status grace). Existing table only: no new tables or RLS
-- policies. Existing rows default to false (full access) until the next
-- authoritative snapshot says otherwise.
ALTER TABLE iam_tenant_module_entitlements
    ADD COLUMN IF NOT EXISTS read_only BOOLEAN NOT NULL DEFAULT FALSE;
