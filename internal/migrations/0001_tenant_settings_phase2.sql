-- Migration: tenant settings Phase 2 prereq
-- Adds timezone and default_sender_domain_id columns to iam_tenants.
--
-- timezone: IANA TZ identifier (e.g. "Europe/Istanbul"). NOT NULL with
--   default 'UTC' so existing rows get a sensible value without a
--   back-fill step.
--
-- default_sender_domain_id: soft reference to the domain row owned by
--   the domain-management service. No hard FK is declared here because
--   iam_tenants and the domain table live in separate bounded contexts.
--   Enforcement is application-level. NULL means "no default configured".

ALTER TABLE iam_tenants
    ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT 'UTC',
    ADD COLUMN IF NOT EXISTS default_sender_domain_id UUID NULL;

COMMENT ON COLUMN iam_tenants.timezone IS
    'IANA TZ identifier, e.g. "Europe/Istanbul". Defaults to UTC.';

COMMENT ON COLUMN iam_tenants.default_sender_domain_id IS
    'Soft reference to domain-management domain row. No hard FK — cross-service boundary.';
