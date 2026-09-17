-- ZTNA Phase 3 — device-cert enrollment registry.
--
-- ADR cross-refs: Talon ADR 0040 (ZTNA Platform) Phase 3; jess
-- ADR 0043 (device-cert profile, Q5 + §3.c.0). The Path B (TOFU)
-- enrollment store interface defined in jess
-- internal/deviceattest/tpm2/verifier_tofu.go persists rows here.
--
-- Why a Falcon-ID-owned registry:
--   Per ADR 0043 Q5 the device registry is account-scoped (every
--   device belongs to a user_sub). Falcon-ID is the system-of-record
--   for user identity; jess queries this table at /device-cert mint
--   time. SOC tools also need a single pane for "all devices owned
--   by user X" — that lookup is fast against this table without a
--   cross-service join.
--
-- Idempotency: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.
-- Safe to apply against a live DB that already has the table.
--
-- GRANTs: the matching keystone bundle issues GRANT SELECT, INSERT,
-- UPDATE, DELETE on this table to falcon_id_app.
--
-- Privacy:
--   - user_sub is the Falcon-ID pairwise identifier (RFC 9493) — not
--     directly PII but linkable.
--   - hostname + mac_addrs + platform_uuid are device-identifying. SOC2
--     CC6.7 (device inventory) requires retention; deletion happens on
--     re-enrollment (revoked_at set, row preserved for audit).
--   - ek_pubkey_hash is sha256 — never the EK private key (which never
--     leaves the TPM).

SET LOCAL statement_timeout = '30s';

CREATE TABLE IF NOT EXISTS iam_devices (
    id                      uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,

    -- Canonical UUIDv4 bound to the attestation key (TPM AK, Apple
    -- SE key, Android StrongBox key). Used as the device-cert SAN:
    -- spiffe://hexxlock.com/device/<device_uuid> (ADR 0040 D-005).
    -- Unique cluster-wide; collision = bug (caller-side).
    device_uuid             uuid        NOT NULL UNIQUE,

    -- Falcon-ID sub of the user who owns this device. NOT a FK — the
    -- sub is the cross-service stable identifier (RFC 9493 iss_sub),
    -- iam_users has tenant-scoped IDs that aren't 1:1 with sub.
    user_sub                text        NOT NULL,

    -- ZTNA Phase 3 hardware-attestation discriminators per ADR 0043.
    platform                text        NOT NULL
                                        CHECK (platform IN (
                                            'tpm2-linux',
                                            'tpm2-windows',
                                            'android-strongbox',
                                            'apple-app-attest',
                                            'macos-mdm'
                                        )),

    -- A_chain = EK cert chained to pinned manufacturer root → TIER_CORP
    -- B_tofu  = EK pubkey trust-on-first-use + enrollment witness →
    --           TIER_BYOD ceiling (AMD consumer fTPM + unprovisioned)
    attestation_path        text        NOT NULL
                                        CHECK (attestation_path IN ('A_chain','B_tofu')),

    -- Tier ceiling per ADR 0040 D-006. Talon Rego (Phase 5 baseline)
    -- gates high-sensitivity routes on tier=TIER_CORP.
    tier                    text        NOT NULL
                                        CHECK (tier IN ('TIER_CORP','TIER_BYOD','TIER_BREAKGLASS')),

    -- TOFU anchor — sha256(EK pubkey PEM). Unique BY DESIGN: two
    -- enrollments with the same EK pubkey mean either the same physical
    -- TPM (rotation should reuse the row) or a TOFU collision attempt
    -- (rejected at the verifier boundary).
    ek_pubkey_hash          bytea       NOT NULL UNIQUE,

    -- TPM 2.0 extras (NULL for non-TPM platforms). Recorded from
    -- TPM2_PT_MANUFACTURER + classifier output at enrollment time.
    tpm_manufacturer        text,
    tpm_kind                text,

    -- Path B enrollment witness fields. NULL for Path A.
    witness_admin_sub       text,
    witness_signed_at       timestamptz,

    -- Device-identifying claims captured at enrollment. Bookkeeping for
    -- ops triage + SOC2 CC6.7 device inventory. Hostname + platform_uuid
    -- are updated on each successful attestation; mac_addrs is captured
    -- at enrollment only (NIC swaps don't rotate the device row).
    hostname                text,
    platform_uuid           text,
    mac_addrs               text[],

    -- Latest attestation fingerprint (sha256 of the verifier input blob).
    -- Used by the audit layer for replay detection — a re-presented
    -- blob with identical fingerprint within a short window is
    -- flagged.
    last_attestation_fingerprint  bytea,

    enrolled_at             timestamptz NOT NULL DEFAULT now(),
    last_seen_at            timestamptz NOT NULL DEFAULT now(),

    -- Revocation. Set when the user removes the device via account
    -- UI or admin revokes via SOC tool. Row is retained for audit;
    -- the device-cert CRL is built off `revoked_at IS NOT NULL`.
    revoked_at              timestamptz,
    revoked_reason          text
);

-- TOFU lookup hot-path: jess Path B verifier reads by EK pubkey hash.
-- Index is implicit via UNIQUE constraint but stating explicitly so
-- future schema refactors don't accidentally drop it.

-- User devices UI: "show me all devices owned by user X, newest first".
CREATE INDEX IF NOT EXISTS idx_iam_devices_user_enrolled
    ON iam_devices (user_sub, enrolled_at DESC);

-- CRL builder: select active revocations for the device-cert CRL.
CREATE INDEX IF NOT EXISTS idx_iam_devices_revoked
    ON iam_devices (revoked_at)
    WHERE revoked_at IS NOT NULL;

-- Tier + platform breakdown for ops dashboards (Phase 8).
CREATE INDEX IF NOT EXISTS idx_iam_devices_tier_platform
    ON iam_devices (tier, platform);

-- Last-seen recency for "stale device" alerts.
CREATE INDEX IF NOT EXISTS idx_iam_devices_last_seen
    ON iam_devices (last_seen_at);

COMMENT ON TABLE iam_devices IS
    'ZTNA Phase 3 device-cert enrollment registry. One row per physical hardware device (TPM/SE/StrongBox/MDM). Owned by Falcon-ID; consumed by jess /device-cert at mint time and Talon Rego at request time.';

COMMENT ON COLUMN iam_devices.attestation_path IS
    'A_chain = EK cert chains to pinned manufacturer root (TIER_CORP eligible). B_tofu = EK pubkey TOFU + WebAuthn-signed enrollment witness (TIER_BYOD ceiling, required for AMD consumer fTPM per ADR 0043 §3.c.0).';

COMMENT ON COLUMN iam_devices.ek_pubkey_hash IS
    'sha256(EK pubkey PEM). Unique. The Path B trust anchor — subsequent attestations match against this. EK private key never leaves the TPM.';

COMMENT ON COLUMN iam_devices.witness_admin_sub IS
    'Path B only: Falcon-ID sub of the operator who WebAuthn-signed the enrollment witness. NULL for Path A.';
