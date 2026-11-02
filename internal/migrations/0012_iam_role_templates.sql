-- Migration 265: role templates (the product roadmap §4.1). Additive +
-- non-breaking. Canonical DDL source: falcon-id
-- internal/migrations/0012_iam_role_templates.sql. Idempotent.

SET LOCAL statement_timeout = '30s';

CREATE TABLE IF NOT EXISTS iam_role_templates (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key                 TEXT NOT NULL,
    version             INTEGER NOT NULL CHECK (version >= 1),
    module              TEXT NOT NULL,
    name                TEXT NOT NULL,
    name_i18n           JSONB NOT NULL DEFAULT '{}'::jsonb,
    description         TEXT,
    description_i18n    JSONB NOT NULL DEFAULT '{}'::jsonb,
    permissions         JSONB NOT NULL DEFAULT '[]'::jsonb,
    spicedb_relations   JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT iam_role_templates_key_version_uq UNIQUE (key, version)
);

CREATE INDEX IF NOT EXISTS idx_iam_role_templates_module
    ON iam_role_templates (module);

CREATE INDEX IF NOT EXISTS idx_iam_role_templates_key_version
    ON iam_role_templates (key, version DESC);

COMMENT ON TABLE iam_role_templates IS
    'Versioned, module-published starter role catalog (the product roadmap §4.1). One row per (key, version); rows are never updated in place after creation, only new versions inserted.';

ALTER TABLE iam_roles
    ADD COLUMN IF NOT EXISTS template_key TEXT,
    ADD COLUMN IF NOT EXISTS template_version INTEGER,
    ADD COLUMN IF NOT EXISTS module TEXT;

CREATE INDEX IF NOT EXISTS idx_iam_roles_template_key
    ON iam_roles (tenant_id, template_key)
    WHERE template_key IS NOT NULL;

COMMENT ON COLUMN iam_roles.template_key IS
    'iam_role_templates.key this role was instantiated from, or NULL for a tenant-custom role. Never touch a role whose template_key is NULL from template reconciliation.';
COMMENT ON COLUMN iam_roles.template_version IS
    'iam_role_templates.version this role was instantiated from (or last reconciled to). NULL iff template_key is NULL.';
COMMENT ON COLUMN iam_roles.module IS
    'Owning module slug for a template-derived role (copy of iam_role_templates.module at instantiation time), or NULL for a tenant-custom role.';
