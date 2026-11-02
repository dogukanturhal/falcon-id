-- Migration 268 (mirrors internal/migrations/0015_iam_sod.sql):
-- ADR-A10 SoD (Separation of Duties) rule matrix + violation log.
-- See that file's header for full design rationale.

SET LOCAL statement_timeout = '30s';

CREATE TABLE IF NOT EXISTS iam_sod_rules (
    id           uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id    uuid        NULL REFERENCES iam_tenants(id) ON DELETE CASCADE,
    module       text        NOT NULL,
    permission_a text        NOT NULL,
    permission_b text        NOT NULL,
    mode         text        NOT NULL DEFAULT 'warn' CHECK (mode IN ('warn', 'block')),
    description  text        NULL,
    is_default   boolean     NOT NULL DEFAULT false,
    created_by   uuid        NULL REFERENCES iam_users(id),
    disabled_at  timestamptz NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CHECK (permission_a <> permission_b)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_iam_sod_rules_active_pair
    ON iam_sod_rules (
        COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid),
        permission_a,
        permission_b
    )
    WHERE disabled_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_iam_sod_rules_tenant_active
    ON iam_sod_rules (tenant_id)
    WHERE disabled_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_iam_sod_rules_module
    ON iam_sod_rules (module);

COMMENT ON TABLE iam_sod_rules IS
    'SoD conflicting-permission-pair rules. tenant_id NULL = platform '
    'default visible to every tenant; non-NULL = tenant-specific rule '
    'or disabling override. R1 ships warn mode only.';

COMMENT ON COLUMN iam_sod_rules.tenant_id IS
    'NULL = platform default, applies to every tenant. '
    'Non-NULL = tenant-owned rule.';

COMMENT ON COLUMN iam_sod_rules.mode IS
    'warn (R1, all seeded rules): never blocks the write, only records '
    'iam_sod_violations. block (R2+ per-module flip): rejects the '
    'role-assignment write with 409 sod_conflict — not yet exercised '
    'by any seeded rule.';

CREATE TABLE IF NOT EXISTS iam_sod_violations (
    id           uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id    uuid        NOT NULL REFERENCES iam_tenants(id) ON DELETE CASCADE,
    user_id      uuid        NOT NULL REFERENCES iam_users(id) ON DELETE CASCADE,
    rule_id      uuid        NOT NULL REFERENCES iam_sod_rules(id) ON DELETE CASCADE,
    permission_a text        NOT NULL,
    permission_b text        NOT NULL,
    mode         text        NOT NULL,
    role_ids     uuid[]      NOT NULL DEFAULT '{}',
    detected_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at  timestamptz NULL,
    resolved_by  uuid        NULL REFERENCES iam_users(id),
    details      jsonb       NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_iam_sod_violations_tenant_user_rule
    ON iam_sod_violations (tenant_id, user_id, rule_id);

CREATE INDEX IF NOT EXISTS idx_iam_sod_violations_tenant_open
    ON iam_sod_violations (tenant_id)
    WHERE resolved_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_iam_sod_violations_user
    ON iam_sod_violations (user_id);

COMMENT ON TABLE iam_sod_violations IS
    'One row per (tenant, user, rule) currently or historically in '
    'conflict. Upserted on every role-assignment write (warn mode: '
    'never blocks) and by POST /internal/v1/sod/evaluate.';

-- Platform-seeded default rules (23-authorization-rbac-abac-rebac.md
-- §9.3/§9.4/§9.6). ON CONFLICT targets the partial unique index above
-- so re-running this migration is a no-op.
INSERT INTO iam_sod_rules (tenant_id, module, permission_a, permission_b, mode, description, is_default)
VALUES
    (NULL, 'accounting', 'accounting:journal_entries:create', 'accounting:journal_entries:approve', 'warn',
     'A user who can create a journal entry should not also be able to approve it (maker-checker).', true),
    (NULL, 'accounting', 'accounting:journal_entries:update', 'accounting:journal_entries:approve', 'warn',
     'A user who can edit a journal entry should not also be able to approve it (maker-checker).', true),
    (NULL, 'accounting', 'accounting:periods:close', 'accounting:periods:reopen', 'warn',
     'Closing and reopening a fiscal period should not be held by the same role (period-lock integrity).', true),
    (NULL, 'mm', 'mm:requisition:create', 'mm:requisition:approve', 'warn',
     'A user who can create a purchase requisition should not also be able to approve it (maker-checker).', true),
    (NULL, 'qms', 'qms:calibration:record_result', 'cmms:calibration:update', 'warn',
     'Recording a calibration''s pass/fail disposition must stay separate from scheduling/executing the calibration work order.', true)
ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), permission_a, permission_b)
    WHERE disabled_at IS NULL
    DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON iam_sod_rules TO falcon_id_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON iam_sod_violations TO falcon_id_app;
