SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

-- FLOW-9 (b64): fix the platform-seeded SoD defaults (EDGE-CASES-FLOW S7, S8). 0015 stays untouched (applied).
--
-- S7: 0015 seeded mm:requisition:create <-> mm:requisition:approve, but the real catalogue permissions are
-- mm:purchase_requisitions:create / approve (rule matching is exact, sod_service.go EvaluateUser), so that default can never
-- fire. The dead default is DISABLED (disabled_at set; the row is kept as an archive, nothing is deleted) and the pair is
-- re-seeded with the real names.
-- S8: cross-module warn defaults (spec 23 §3.3/§8.3), all names taken from the business permission manifests:
--   purchase order create <-> invoice-match override (mm), vendor master update <-> Pre-accounting money-movement create,
--   payroll run calculate <-> pay, Pre-accounting expense create <-> approve.
-- All rules are warn mode (record only, never block). Purely additive and idempotent: the INSERTs target the partial unique
-- index idx_iam_sod_rules_active_pair, the UPDATE only touches still-active platform defaults.
-- Prerequisite guard: 0015 (v0.232.268) created iam_sod_rules.
DO $$
BEGIN
    IF to_regclass(current_schema() || '.iam_sod_rules') IS NULL THEN
        RAISE EXCEPTION 'falcon-id 0023 SoD seed fix requires 0015 (v0.232.268 iam_sod) to be applied first';
    END IF;
END $$;

UPDATE iam_sod_rules
   SET disabled_at = now(), updated_at = now()
 WHERE tenant_id IS NULL
   AND is_default
   AND disabled_at IS NULL
   AND permission_a = 'mm:requisition:create'
   AND permission_b = 'mm:requisition:approve';

INSERT INTO iam_sod_rules (tenant_id, module, permission_a, permission_b, mode, description, is_default)
VALUES
    (NULL, 'mm', 'mm:purchase_requisitions:create', 'mm:purchase_requisitions:approve', 'warn',
     'A user who can create a purchase requisition should not also be able to approve it (maker-checker).', true),
    (NULL, 'mm', 'mm:purchase_orders:create', 'mm:invoice-match:override', 'warn',
     'A user who can create a purchase order should not also be able to override its invoice three-way-match (procure-to-pay maker-checker).', true),
    (NULL, 'mm', 'mm:vendors:update', 'preaccounting:payments:create', 'warn',
     'A user who can change vendor master data (e.g. bank details) should not also be able to create the payment money movement (vendor-fraud control).', true),
    (NULL, 'payroll', 'payroll:runs:calculate', 'payroll:runs:pay', 'warn',
     'A user who can calculate a payroll run should not also be able to mark it paid (maker-checker).', true),
    (NULL, 'preaccounting', 'preaccounting:expenses:create', 'preaccounting:expenses:approve', 'warn',
     'A user who can create an expense should not also be able to approve it (maker-checker).', true)
ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), permission_a, permission_b)
    WHERE disabled_at IS NULL
    DO NOTHING;
