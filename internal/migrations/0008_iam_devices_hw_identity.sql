-- 0008_iam_devices_hw_identity.sql
-- Hardware-identity persistence for the device registry.
--
-- THE GAP THIS CLOSES: iam_devices (migration 0004) records the attestation
-- substrate (platform, EK pubkey hash, TPM manufacturer/kind) but NOT the
-- human-facing hardware identity of the physical machine — its OEM serial
-- number, product model, and manufacturer. The hexxlock-access enrollment
-- agent now collects these (SMBIOS/DMI on Linux/Windows) and sends them at
-- enrollment; the jess admin "Approve as corporate asset" UI reads them back
-- from this table (via GET /internal/v1/iam-devices/by-ek-hash/:hash and
-- /by-uuid/:uuid). Without these columns that UI renders serial / model /
-- manufacturer as "—".
--
-- Cross-repo contract (snake_case, optional, may be empty):
--   serial_number, model, manufacturer.
-- The hexxlock-access agent writes them at enrollment; the jess agent reads
-- them. The exact field names above are shared across all three repos.
--
-- Additive + non-breaking: ADD COLUMN IF NOT EXISTS … NOT NULL DEFAULT ''.
-- Existing rows backfill to '' via the DEFAULT; existing INSERTs that omit the
-- columns still succeed (the DEFAULT applies). Empty string is the canonical
-- "absent" value — there are no NULLs to scan.
--
-- NOTE (parity with 0004/0007): the embedded golang-migrate runner was retired
-- (cmd/services.go). On a real/fresh/DR DB the AUTHORITATIVE applier is the
-- Keystone MigrationBundle in the GitOps repository
-- (platform/keystone/resources/falcon-id/migration-bundles/falcon-id-vX.Y.Z.yaml),
-- generated from this file via hack/render-migration-bundle.sh and applied
-- transactionally by the Keystone operator. This file is the canonical DDL
-- reference + local-dev (applied by hand). IF NOT EXISTS = both paths idempotent.

SET LOCAL statement_timeout = '30s';

ALTER TABLE iam_devices
    ADD COLUMN IF NOT EXISTS serial_number TEXT NOT NULL DEFAULT '';

ALTER TABLE iam_devices
    ADD COLUMN IF NOT EXISTS model TEXT NOT NULL DEFAULT '';

ALTER TABLE iam_devices
    ADD COLUMN IF NOT EXISTS manufacturer TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN iam_devices.serial_number IS
    'OEM hardware serial (SMBIOS System Serial Number / DMI). Captured at enrollment by the hexxlock-access agent and surfaced in the jess corporate-asset UI. Empty string when the agent could not read it.';

COMMENT ON COLUMN iam_devices.model IS
    'OEM product/model name (SMBIOS System Product Name). Empty string when absent.';

COMMENT ON COLUMN iam_devices.manufacturer IS
    'OEM manufacturer/vendor (SMBIOS System Manufacturer). Empty string when absent.';
