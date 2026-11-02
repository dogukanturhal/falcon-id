-- HR employment synchronization provenance. Additive; never changes existing roles or memberships.
CREATE TABLE IF NOT EXISTS iam_hr_sync_scopes (
    tenant_id uuid NOT NULL,
    legal_entity_id uuid NOT NULL,
    mode text NOT NULL CHECK (mode IN ('disabled', 'manual', 'automatic')),
    enabled boolean NOT NULL DEFAULT false,
    version bigint NOT NULL CHECK (version > 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, legal_entity_id)
);

CREATE TABLE IF NOT EXISTS iam_hr_employment_links (
    tenant_id uuid NOT NULL,
    legal_entity_id uuid NOT NULL,
    employee_id uuid NOT NULL,
    iam_user_id uuid NULL,
    hr_owned_role_id uuid NULL,
    contract_version integer NOT NULL CHECK (contract_version = 1),
    relationship_version bigint NOT NULL CHECK (relationship_version > 0),
    scope_version bigint NOT NULL CHECK (scope_version > 0),
    state text NOT NULL CHECK (state IN ('pending', 'active', 'terminated')),
    department_id uuid NULL,
    manager_employee_id uuid NULL,
    account_hr_owned boolean NOT NULL DEFAULT false,
    manual_approved boolean NOT NULL DEFAULT false,
    manual_review_actor_id uuid NULL,
    manual_review_reason text NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, legal_entity_id, employee_id),
    CONSTRAINT iam_hr_employment_links_manual_review_check CHECK (
        NOT manual_approved OR (
            manual_review_actor_id IS NOT NULL
            AND length(btrim(manual_review_reason)) > 0
        )
    ),
    CONSTRAINT iam_hr_employment_links_owned_role_check CHECK (
        NOT account_hr_owned OR hr_owned_role_id IS NOT NULL
    )
);

CREATE TABLE IF NOT EXISTS iam_hr_sync_receipts (
    event_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    legal_entity_id uuid NOT NULL,
    employee_id uuid NOT NULL,
    contract_version integer NOT NULL CHECK (contract_version = 1),
    relationship_version bigint NOT NULL CHECK (relationship_version > 0),
    scope_version bigint NOT NULL CHECK (scope_version > 0),
    payload_fingerprint text NOT NULL,
    manual_approved boolean NOT NULL DEFAULT false,
    manual_review_actor_id uuid NULL,
    manual_review_reason text NULL,
    outcome text NOT NULL,
    stage text NOT NULL DEFAULT 'claimed' CHECK (stage IN ('claimed', 'provisioned', 'complete')),
    lease_until timestamptz NOT NULL DEFAULT now() + interval '5 minutes',
    provisioned_iam_user_id uuid NULL,
    provisioned_hr_role_id uuid NULL,
    linked_iam_user_id uuid NULL,
    candidate_iam_user_id uuid NULL,
    reason text NULL,
    attempts integer NOT NULL DEFAULT 1 CHECK (attempts > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iam_hr_sync_receipts_manual_review_check CHECK (
        NOT manual_approved OR (
            manual_review_actor_id IS NOT NULL
            AND length(btrim(manual_review_reason)) > 0
        )
    ),
    CONSTRAINT iam_hr_sync_receipts_provisioned_role_check CHECK (
        provisioned_iam_user_id IS NULL OR provisioned_hr_role_id IS NOT NULL
    )
);

CREATE TABLE IF NOT EXISTS iam_hr_sync_failures (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    legal_entity_id uuid NOT NULL,
    employee_id uuid NOT NULL,
    contract_version integer NOT NULL CHECK (contract_version = 1),
    relationship_version bigint NOT NULL CHECK (relationship_version > 0),
    failure_code text NOT NULL,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iam_hr_sync_failures_tenant_employee_relationship_key
        UNIQUE (tenant_id, legal_entity_id, employee_id, relationship_version)
);

CREATE INDEX IF NOT EXISTS idx_iam_hr_sync_failures_retry
    ON iam_hr_sync_failures (next_attempt_at) WHERE next_attempt_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iam_hr_sync_receipts_tenant_employee
    ON iam_hr_sync_receipts (tenant_id, legal_entity_id, employee_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON iam_hr_sync_scopes, iam_hr_employment_links,
    iam_hr_sync_receipts, iam_hr_sync_failures TO falcon_id_app;

ALTER TABLE iam_hr_sync_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam_hr_employment_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam_hr_sync_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam_hr_sync_failures ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'iam_hr_sync_scopes'::regclass AND polname = 'iam_hr_sync_scopes_tenant') THEN
        CREATE POLICY iam_hr_sync_scopes_tenant ON iam_hr_sync_scopes FOR ALL TO falcon_id_app
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'iam_hr_employment_links'::regclass AND polname = 'iam_hr_employment_links_tenant') THEN
        CREATE POLICY iam_hr_employment_links_tenant ON iam_hr_employment_links FOR ALL TO falcon_id_app
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'iam_hr_sync_receipts'::regclass AND polname = 'iam_hr_sync_receipts_tenant') THEN
        CREATE POLICY iam_hr_sync_receipts_tenant ON iam_hr_sync_receipts FOR ALL TO falcon_id_app
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = 'iam_hr_sync_failures'::regclass AND polname = 'iam_hr_sync_failures_tenant') THEN
        CREATE POLICY iam_hr_sync_failures_tenant ON iam_hr_sync_failures FOR ALL TO falcon_id_app
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
    END IF;
END;
$$;
