-- 0007_iam_device_preregistrations.sql
-- Corporate device pre-registration (zero-touch CORP allowlist).
--
-- THE GAP THIS CLOSES: jess Path A (deviceattest/verifier_chain.go) grants
-- TIER_CORP whenever a TPM EK certificate chains to a pinned manufacturer
-- root — i.e. on hardware GENUINENESS alone. That proves "a real, untampered
-- TPM from a trusted vendor", NOT "one of OUR devices": any genuine TPM (incl.
-- an employee's personal laptop) chains to the same public vendor roots. The
-- industry splits these into two layers (Autopilot hardware-hash / Intune
-- Corporate Device Identifiers / TPM EK-pubkey allowlist); this table is the
-- second layer — the corporate-asset allowlist keyed on the device's TPM EK
-- pubkey hash (and/or serial).
--
-- An admin bulk-imports the fleet's EK-pubkey hashes (or serials) — harvested
-- from an OEM hardware-hash CSV at purchase, or during imaging. At attest time
-- jess consults this allowlist (GET /internal/v1/iam-devices/corp-asset/by-ek-hash)
-- and DOWNGRADES CORP -> BYOD for any genuine-TPM device that is NOT a known
-- corporate asset. Result: pre-registered fleet -> CORP (zero-touch, scales to
-- thousands); everything else -> BYOD -> posture-only -> no Eyrie management.
--
-- This is deliberately a SEPARATE table from iam_devices (the attested-device
-- registry). A pre-registration exists BEFORE first attestation and has no
-- device_uuid/platform/tier; folding it into iam_devices would break the jess
-- TOFU first-vs-returning lookup (GetByEKPubkeyHash treats any non-empty row as
-- a returning device).
--
-- NOTE (parity with phase-2b): the embedded golang-migrate runner was retired
-- (cmd/services.go). On a real/fresh/DR DB the authoritative creator is the
-- Keystone bundle migration-bundles/falcon-id-v0.232.259.yaml (mirrors this DDL
-- + adds the GRANT — SchemaDefinition has no privileges field). This file is the
-- canonical DDL reference + local-dev (applied by hand). IF NOT EXISTS = both
-- paths idempotent.

SET LOCAL statement_timeout = '30s';

-- One row per pre-registered corporate device. At least one identifier
-- (ek_pubkey_hash OR serial_number) must be present; ek_pubkey_hash is the
-- canonical attestation-time key (sha256 of the EK pubkey PEM, 32 bytes).
CREATE TABLE IF NOT EXISTS iam_device_preregistrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Owning tenant — the corporate asset belongs to exactly one tenant.
    tenant_id       UUID NOT NULL,
    -- sha256(EK pubkey PEM), 32 bytes raw (hex-encoded 64 chars in JSON/HTTP).
    -- Hardware is globally unique, so the uniqueness is global (a given TPM can
    -- be claimed by at most one tenant) — enforced by the partial index below.
    ek_pubkey_hash  BYTEA,
    -- OEM serial (Autopilot/Intune-style identifier). Scoped unique per tenant.
    serial_number   TEXT,
    -- Optional human-facing inventory metadata.
    asset_tag       TEXT,
    model           TEXT,
    note            TEXT,
    -- Falcon-ID sub of the admin who imported this entry (audit).
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT iam_device_prereg_identifier_present
        CHECK (ek_pubkey_hash IS NOT NULL OR serial_number IS NOT NULL)
);

-- Global uniqueness of the hardware EK (prevents two tenants pre-registering
-- the same physical TPM). Partial: rows identified only by serial are exempt.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iam_device_prereg_ek_pubkey_hash
    ON iam_device_preregistrations (ek_pubkey_hash)
    WHERE ek_pubkey_hash IS NOT NULL;

-- Per-tenant uniqueness of serial (serials can collide across vendors).
CREATE UNIQUE INDEX IF NOT EXISTS uq_iam_device_prereg_tenant_serial
    ON iam_device_preregistrations (tenant_id, serial_number)
    WHERE serial_number IS NOT NULL;

-- Tenant-scoped listing for the admin console.
CREATE INDEX IF NOT EXISTS idx_iam_device_prereg_tenant
    ON iam_device_preregistrations (tenant_id, created_at DESC);
