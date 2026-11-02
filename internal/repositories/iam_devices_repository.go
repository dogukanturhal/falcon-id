// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lib/pq"
)

// IAMDeviceRow mirrors every column in the iam_devices table introduced by
// migration 0004_iam_devices.sql (ZTNA Phase 3, ADR 0043).
//
// Nullable columns use pointer types so that a nil Go value maps cleanly to a
// SQL NULL without an extra pgtype wrapper. mac_addrs is a text[] column; it
// is represented as []string and transmitted via pq.Array for pgx compatibility.
//
// Invariants enforced by the repository (not the DB CHECK constraints) are
// documented on the write methods below. The DB constraints are the ultimate
// source of truth; the repository layer adds early-return validation so
// callers get a descriptive error rather than a pgconn.PgError.
type IAMDeviceRow struct {
	// Internal surrogate PK — gen_random_uuid() on INSERT; never set by
	// the caller.
	ID uuid.UUID

	// DeviceUUID is the UUIDv4 bound to the attestation key (TPM AK, Apple
	// SE key, Android StrongBox key). Used as the device-cert SAN per ADR
	// 0040 D-005: spiffe://hexxlock.com/device/<device_uuid>.
	DeviceUUID uuid.UUID

	// UserSub is the Falcon-ID sub of the owning user (RFC 9493 iss_sub).
	UserSub string

	// Platform discriminates the hardware attestation substrate.
	// Allowed values: tpm2-linux, tpm2-windows, android-strongbox,
	// apple-app-attest, macos-mdm.
	Platform string

	// AttestationPath is either "A_chain" (EK cert chains to a pinned
	// manufacturer root → TIER_CORP eligible) or "B_tofu" (EK pubkey
	// trust-on-first-use + WebAuthn-signed witness → TIER_BYOD ceiling).
	// Per ADR 0043 §3.c.0.
	AttestationPath string

	// Tier is the access-tier ceiling per ADR 0040 D-006.
	// Allowed values: TIER_CORP, TIER_BYOD, TIER_BREAKGLASS.
	Tier string

	// EKPubkeyHash is sha256(EK pubkey PEM), hex-encoded (64 chars).
	// The UNIQUE constraint on this column is the TOFU anchor for Path B.
	EKPubkeyHash []byte

	// TPMManufacturer and TPMKind are populated from TPM2_PT_MANUFACTURER
	// and the classifier output at enrollment time. NULL for non-TPM platforms.
	TPMManufacturer *string
	TPMKind         *string

	// WitnessAdminSub and WitnessSignedAt are Path B only: the Falcon-ID
	// sub of the operator who WebAuthn-signed the enrollment witness and
	// when they signed it. Both are NULL for Path A.
	WitnessAdminSub *string
	WitnessSignedAt *time.Time

	// Hostname, PlatformUUID, and MACAddrs are device-identifying claims
	// captured at enrollment for SOC2 CC6.7 device inventory.
	Hostname     *string
	PlatformUUID *string
	MACAddrs     []string

	// SerialNumber, Model, and Manufacturer are the human-facing hardware
	// identity (OEM SMBIOS/DMI fields) captured at enrollment by the
	// device-agent agent and surfaced in the jess corporate-asset UI.
	// Backed by NOT NULL DEFAULT '' columns (migration 0008) — empty string
	// is the canonical "absent" value (no NULLs), so plain string types are
	// used rather than pointers.
	SerialNumber string
	Model        string
	Manufacturer string

	// WitnessMethod records how the enrollment was witnessed: "passkey",
	// "otp", or "" for legacy rows (migration 0039).
	WitnessMethod string

	// LastAttestationFingerprint is sha256 of the verifier input blob,
	// used by the audit layer for replay detection.
	LastAttestationFingerprint []byte

	EnrolledAt    time.Time
	LastSeenAt    time.Time
	RevokedAt     *time.Time
	RevokedBy     *string
	RevokedReason *string
}

// validPlatforms is the set of allowed platform values, mirroring the DB CHECK
// constraint so callers get an early descriptive error.
var validPlatforms = map[string]struct{}{
	"tpm2-linux":        {},
	"tpm2-windows":      {},
	"android-strongbox": {},
	"apple-app-attest":  {},
	"macos-mdm":         {},
}

// validAttestationPaths mirrors the DB CHECK constraint on attestation_path.
var validAttestationPaths = map[string]struct{}{
	"A_chain": {},
	"B_tofu":  {},
}

// validTiers mirrors the DB CHECK constraint on tier.
var validTiers = map[string]struct{}{
	"TIER_CORP":       {},
	"TIER_BYOD":       {},
	"TIER_BREAKGLASS": {},
}

// ErrIAMDeviceEKConflict is returned by RegisterDevice when a row with the
// same ek_pubkey_hash already exists (SQLSTATE 23505 on the UNIQUE constraint).
// Callers SHOULD treat this as a re-enrollment signal and call GetByEKPubkeyHash
// to retrieve the existing row.
var ErrIAMDeviceEKConflict = errors.New("iam_devices: ek_pubkey_hash already registered")

// ErrIAMDeviceUUIDConflict is returned by RegisterDevice when a row with the
// same device_uuid already exists. This indicates a caller-side bug (UUID
// collision), not a benign retry.
var ErrIAMDeviceUUIDConflict = errors.New("iam_devices: device_uuid already registered")

// IAMDevicesRepository is the canonical accessor for the iam_devices table
// (ZTNA Phase 3 device-cert enrollment registry). It is the Falcon-ID-side
// counterpart to the jess EnrollmentStore interface described in ADR 0043.
//
// Concurrency notes:
//   - RegisterDevice is called from the enrollment hot path; it is a single
//     round-trip INSERT.
//   - UpdateLastSeen is called on every successful device-cert attestation
//     (heartbeat path); it is a single round-trip UPDATE.
//   - All read methods are safe for concurrent use. The underlying DBTX pool
//     handles connection multiplexing.
//   - Revoke is idempotent: a second revocation of an already-revoked device
//     is a no-op (the existing revoked_at / revoked_reason are preserved).
type IAMDevicesRepository struct {
	pool DBTX
}

// NewIAMDevicesRepository constructs a repository against the supplied pool.
// The pool must not be nil; pass a *pgxpool.Pool in production and a
// pgxmock.PgxPoolIface in tests.
func NewIAMDevicesRepository(pool DBTX) *IAMDevicesRepository {
	return &IAMDevicesRepository{pool: pool}
}

// validateDeviceUUID checks that s is a valid UUIDv4 string.
func validateDeviceUUID(s string) error {
	u, err := uuid.Parse(s)
	if err != nil {
		return fmt.Errorf("device_uuid is not a valid UUID: %w", err)
	}
	if u.Version() != 4 {
		return fmt.Errorf("device_uuid must be UUIDv4, got v%d", u.Version())
	}
	return nil
}

// validateEKPubkeyHash checks that b is a 32-byte SHA-256 value (stored as
// bytea). The hex-encoded form is 64 chars; callers must decode before passing.
func validateEKPubkeyHash(b []byte) error {
	if len(b) != 32 {
		return fmt.Errorf("ek_pubkey_hash must be 32 bytes (SHA-256), got %d", len(b))
	}
	return nil
}

// validateWriteFields performs all field-level validation that applies to
// write methods (RegisterDevice, UpdateLastSeen, Revoke). It returns the first
// validation error encountered.
func validateWriteFields(deviceUUID, platform, attestationPath, tier string, ekPubkeyHash []byte) error {
	if err := validateDeviceUUID(deviceUUID); err != nil {
		return err
	}
	if _, ok := validPlatforms[platform]; !ok {
		return fmt.Errorf("platform %q is not one of: %s",
			platform, strings.Join(platformKeys(), ", "))
	}
	if _, ok := validAttestationPaths[attestationPath]; !ok {
		return fmt.Errorf("attestation_path %q must be one of: A_chain, B_tofu", attestationPath)
	}
	if _, ok := validTiers[tier]; !ok {
		return fmt.Errorf("tier %q must be one of: TIER_CORP, TIER_BYOD, TIER_BREAKGLASS", tier)
	}
	if err := validateEKPubkeyHash(ekPubkeyHash); err != nil {
		return err
	}
	return nil
}

// platformKeys returns the sorted list of valid platform strings for error
// messages.
func platformKeys() []string {
	keys := make([]string, 0, len(validPlatforms))
	for k := range validPlatforms {
		keys = append(keys, k)
	}
	return keys
}

// pgUniqueViolation returns true if err is a PostgreSQL SQLSTATE 23505
// (unique_violation).
func pgUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// pgConstraintName extracts the constraint name from a PgError, or returns
// an empty string if err is not a *pgconn.PgError.
func pgConstraintName(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}

// iamDeviceCols is the canonical column list for SELECT queries, matching the
// table definition in migration 0004_iam_devices.sql (plus the hardware-identity
// columns added by migration 0008_iam_devices_hw_identity.sql) exactly.
const iamDeviceCols = `
    id, device_uuid, user_sub, platform, attestation_path, tier,
    ek_pubkey_hash, tpm_manufacturer, tpm_kind,
    witness_admin_sub, witness_signed_at,
    hostname, platform_uuid, mac_addrs,
    last_attestation_fingerprint,
    enrolled_at, last_seen_at,
    revoked_at, revoked_reason, revoked_by_sub,
    serial_number, model, manufacturer, witness_method`

// scanIAMDeviceRow scans one row from the result of a query that selects
// iamDeviceCols in order.
func scanIAMDeviceRow(rows pgx.Rows) (IAMDeviceRow, error) {
	var row IAMDeviceRow
	var deviceUUIDStr string
	var macAddrs pq.StringArray
	err := rows.Scan(
		&row.ID,
		&deviceUUIDStr,
		&row.UserSub,
		&row.Platform,
		&row.AttestationPath,
		&row.Tier,
		&row.EKPubkeyHash,
		&row.TPMManufacturer,
		&row.TPMKind,
		&row.WitnessAdminSub,
		&row.WitnessSignedAt,
		&row.Hostname,
		&row.PlatformUUID,
		&macAddrs,
		&row.LastAttestationFingerprint,
		&row.EnrolledAt,
		&row.LastSeenAt,
		&row.RevokedAt,
		&row.RevokedReason,
		&row.RevokedBy,
		&row.SerialNumber,
		&row.Model,
		&row.Manufacturer,
		&row.WitnessMethod,
	)
	if err != nil {
		return IAMDeviceRow{}, err
	}
	row.DeviceUUID, _ = uuid.Parse(deviceUUIDStr)
	if macAddrs != nil {
		row.MACAddrs = []string(macAddrs)
	}
	return row, nil
}

// scanIAMDeviceRowSingle scans a single-row result set (QueryRow path).
func scanIAMDeviceRowSingle(row pgx.Row) (IAMDeviceRow, error) {
	var r IAMDeviceRow
	var deviceUUIDStr string
	var macAddrs pq.StringArray
	err := row.Scan(
		&r.ID,
		&deviceUUIDStr,
		&r.UserSub,
		&r.Platform,
		&r.AttestationPath,
		&r.Tier,
		&r.EKPubkeyHash,
		&r.TPMManufacturer,
		&r.TPMKind,
		&r.WitnessAdminSub,
		&r.WitnessSignedAt,
		&r.Hostname,
		&r.PlatformUUID,
		&macAddrs,
		&r.LastAttestationFingerprint,
		&r.EnrolledAt,
		&r.LastSeenAt,
		&r.RevokedAt,
		&r.RevokedReason,
		&r.RevokedBy,
		&r.SerialNumber,
		&r.Model,
		&r.Manufacturer,
		&r.WitnessMethod,
	)
	if err != nil {
		return IAMDeviceRow{}, err
	}
	r.DeviceUUID, _ = uuid.Parse(deviceUUIDStr)
	if macAddrs != nil {
		r.MACAddrs = []string(macAddrs)
	}
	return r, nil
}

// RegisterDevice inserts a new device enrollment row. It is the primary entry
// point for both Path A (EK cert chain) and Path B (TOFU) enrollments from the
// jess device-cert minting endpoint.
//
// Validation (pre-flight, before the round-trip):
//   - device_uuid must be a valid UUIDv4.
//   - platform must be one of the five allowed values.
//   - attestation_path must be "A_chain" or "B_tofu".
//   - tier must be "TIER_CORP", "TIER_BYOD", or "TIER_BREAKGLASS".
//   - ek_pubkey_hash must be exactly 32 bytes (SHA-256 raw digest).
//
// Returns ErrIAMDeviceEKConflict on UNIQUE(ek_pubkey_hash) violation and
// ErrIAMDeviceUUIDConflict on UNIQUE(device_uuid) violation. All other errors
// are wrapped under "iam_devices: register_device: …".
func (r *IAMDevicesRepository) RegisterDevice(ctx context.Context, row IAMDeviceRow) error {
	if err := validateWriteFields(
		row.DeviceUUID.String(), row.Platform, row.AttestationPath, row.Tier, row.EKPubkeyHash,
	); err != nil {
		return fmt.Errorf("iam_devices: register_device: %w", err)
	}

	const q = `
INSERT INTO iam_devices (
    device_uuid, user_sub, platform, attestation_path, tier,
    ek_pubkey_hash, tpm_manufacturer, tpm_kind,
    witness_admin_sub, witness_signed_at,
    hostname, platform_uuid, mac_addrs,
    last_attestation_fingerprint,
    enrolled_at, last_seen_at,
    serial_number, model, manufacturer, witness_method
) VALUES (
    $1,  $2,  $3,  $4,  $5,
    $6,  $7,  $8,
    $9,  $10,
    $11, $12, $13,
    $14,
    $15, $16,
    $17, $18, $19, $20
)`

	now := time.Now().UTC()
	if row.EnrolledAt.IsZero() {
		row.EnrolledAt = now
	}
	if row.LastSeenAt.IsZero() {
		row.LastSeenAt = now
	}

	_, err := r.pool.Exec(ctx, q,
		row.DeviceUUID.String(), row.UserSub, row.Platform, row.AttestationPath, row.Tier,
		row.EKPubkeyHash, row.TPMManufacturer, row.TPMKind,
		row.WitnessAdminSub, row.WitnessSignedAt,
		row.Hostname, row.PlatformUUID, pq.Array(row.MACAddrs),
		row.LastAttestationFingerprint,
		row.EnrolledAt, row.LastSeenAt,
		row.SerialNumber, row.Model, row.Manufacturer, row.WitnessMethod,
	)
	if err != nil {
		if pgUniqueViolation(err) {
			switch pgConstraintName(err) {
			case "iam_devices_ek_pubkey_hash_key":
				return ErrIAMDeviceEKConflict
			case "iam_devices_device_uuid_key":
				return ErrIAMDeviceUUIDConflict
			default:
				// Fallthrough to generic unique-violation — surface as EK conflict
				// because ek_pubkey_hash is the more semantically important anchor.
				if strings.Contains(err.Error(), "ek_pubkey_hash") {
					return ErrIAMDeviceEKConflict
				}
				if strings.Contains(err.Error(), "device_uuid") {
					return ErrIAMDeviceUUIDConflict
				}
			}
		}
		return fmt.Errorf("iam_devices: register_device: %w", err)
	}
	return nil
}

// GetByUUID fetches a single device row by its device_uuid SAN identifier.
// Returns pgx.ErrNoRows (wrapped) if no row matches, so callers can use
// errors.Is(err, pgx.ErrNoRows).
//
// deviceUUID must be a parseable UUID string; the method returns an error
// immediately if it is not.
func (r *IAMDevicesRepository) GetByUUID(ctx context.Context, deviceUUID string) (IAMDeviceRow, error) {
	if _, err := uuid.Parse(deviceUUID); err != nil {
		return IAMDeviceRow{}, fmt.Errorf("iam_devices: get_by_uuid: device_uuid is not a valid UUID: %w", err)
	}

	q := `SELECT ` + iamDeviceCols + `
  FROM iam_devices
 WHERE device_uuid = $1`

	row := r.pool.QueryRow(ctx, q, deviceUUID)
	result, err := scanIAMDeviceRowSingle(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return IAMDeviceRow{}, fmt.Errorf("iam_devices: get_by_uuid: %w", pgx.ErrNoRows)
		}
		return IAMDeviceRow{}, fmt.Errorf("iam_devices: get_by_uuid: %w", err)
	}
	return result, nil
}

// GetByEKPubkeyHash fetches a device row by its EK pubkey hash. This is the
// Path B TOFU lookup anchor — the jess verifier calls this to determine whether
// a presented EK pubkey has been enrolled before.
//
// hash must be a 64-char lowercase hex string (the hex encoding of a SHA-256
// digest). Returns pgx.ErrNoRows (wrapped) if no row matches.
func (r *IAMDevicesRepository) GetByEKPubkeyHash(ctx context.Context, hash string) (IAMDeviceRow, error) {
	if len(hash) != 64 {
		return IAMDeviceRow{}, fmt.Errorf("iam_devices: get_by_ek_pubkey_hash: hash must be 64 hex chars, got %d", len(hash))
	}
	b, err := hex.DecodeString(hash)
	if err != nil {
		return IAMDeviceRow{}, fmt.Errorf("iam_devices: get_by_ek_pubkey_hash: hash is not valid hex: %w", err)
	}

	q := `SELECT ` + iamDeviceCols + `
  FROM iam_devices
 WHERE ek_pubkey_hash = $1`

	row := r.pool.QueryRow(ctx, q, b)
	result, err := scanIAMDeviceRowSingle(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return IAMDeviceRow{}, fmt.Errorf("iam_devices: get_by_ek_pubkey_hash: %w", pgx.ErrNoRows)
		}
		return IAMDeviceRow{}, fmt.Errorf("iam_devices: get_by_ek_pubkey_hash: %w", err)
	}
	return result, nil
}

// ListByUserSub returns all device rows owned by the given user, ordered by
// enrolled_at DESC (newest first). The query uses the composite index
// idx_iam_devices_user_enrolled.
//
// An empty slice (not nil) is returned when the user has no devices.
func (r *IAMDevicesRepository) ListByUserSub(ctx context.Context, userSub string) ([]IAMDeviceRow, error) {
	if userSub == "" {
		return nil, fmt.Errorf("iam_devices: list_by_user_sub: userSub must not be empty")
	}

	q := `SELECT ` + iamDeviceCols + `
  FROM iam_devices
 WHERE user_sub = $1
 ORDER BY enrolled_at DESC`

	rows, err := r.pool.Query(ctx, q, userSub)
	if err != nil {
		return nil, fmt.Errorf("iam_devices: list_by_user_sub: %w", err)
	}
	defer rows.Close()

	return collectIAMDeviceRows(rows, "list_by_user_sub")
}

// UpdateLastSeen updates the heartbeat fields for a device. It is called on
// every successful attestation by the jess device-cert minting endpoint.
//
// The update writes:
//   - last_seen_at = lastSeenAt
//   - last_attestation_fingerprint = lastAttestationNonce (replay-detection anchor)
//
// Validation:
//   - deviceUUID must be a valid UUIDv4.
//   - lastSeenAt must not be zero.
func (r *IAMDevicesRepository) UpdateLastSeen(ctx context.Context, deviceUUID string, lastSeenAt time.Time, lastAttestationAt time.Time, lastAttestationNonce []byte) error {
	if err := validateDeviceUUID(deviceUUID); err != nil {
		return fmt.Errorf("iam_devices: update_last_seen: %w", err)
	}
	if lastSeenAt.IsZero() {
		return fmt.Errorf("iam_devices: update_last_seen: lastSeenAt must not be zero")
	}

	const q = `
UPDATE iam_devices
   SET last_seen_at                  = $2,
       last_attestation_fingerprint  = $3
 WHERE device_uuid = $1`

	_, err := r.pool.Exec(ctx, q, deviceUUID, lastSeenAt.UTC(), lastAttestationNonce)
	if err != nil {
		return fmt.Errorf("iam_devices: update_last_seen: %w", err)
	}
	return nil
}

// Revoke marks a device as revoked. The row is preserved (not deleted) to
// satisfy the SOC2 CC6.7 audit-retention requirement and the device-cert CRL
// build process. A second revocation of an already-revoked device is silently
// accepted (idempotent by design — the first revoked_at / revoked_reason are
// preserved via the COALESCE guard).
//
// revokedBy is the Falcon-ID sub of the operator or user who initiated the
// revocation. reason is a human-readable string (e.g., "user_self_removed",
// "admin_policy_violation"). revokedAt must not be zero.
func (r *IAMDevicesRepository) Revoke(ctx context.Context, deviceUUID string, reason string, revokedBy string, revokedAt time.Time) error {
	if err := validateDeviceUUID(deviceUUID); err != nil {
		return fmt.Errorf("iam_devices: revoke: %w", err)
	}
	if reason == "" {
		return fmt.Errorf("iam_devices: revoke: reason must not be empty")
	}
	if revokedBy == "" {
		return fmt.Errorf("iam_devices: revoke: revokedBy must not be empty")
	}
	if revokedAt.IsZero() {
		return fmt.Errorf("iam_devices: revoke: revokedAt must not be zero")
	}

	// COALESCE ensures idempotency: if the row is already revoked, the
	// existing revoked_at and revoked_reason are preserved.
	const q = `
UPDATE iam_devices
   SET revoked_at     = COALESCE(revoked_at, $2),
       revoked_reason = COALESCE(revoked_reason, $3),
       revoked_by_sub = COALESCE(revoked_by_sub, $4)
 WHERE device_uuid = $1`

	_, err := r.pool.Exec(ctx, q, deviceUUID, revokedAt.UTC(), reason, revokedBy)
	if err != nil {
		return fmt.Errorf("iam_devices: revoke: %w", err)
	}
	return nil
}

// ListRevoked returns all rows where revoked_at IS NOT NULL and revoked_at >=
// sinceRevokedAt. This is the CRL builder source — the jess CRL generator
// calls this periodically to build the device-cert CRL.
//
// The partial index idx_iam_devices_revoked (WHERE revoked_at IS NOT NULL)
// makes this query cheap even on large tables.
func (r *IAMDevicesRepository) ListRevoked(ctx context.Context, sinceRevokedAt time.Time) ([]IAMDeviceRow, error) {
	q := `SELECT ` + iamDeviceCols + `
  FROM iam_devices
 WHERE revoked_at IS NOT NULL
   AND revoked_at >= $1
 ORDER BY revoked_at DESC`

	rows, err := r.pool.Query(ctx, q, sinceRevokedAt.UTC())
	if err != nil {
		return nil, fmt.Errorf("iam_devices: list_revoked: %w", err)
	}
	defer rows.Close()

	return collectIAMDeviceRows(rows, "list_revoked")
}

// ListByTier returns all device rows with the given tier value, ordered by
// enrolled_at DESC. Used by the ops dashboard (Phase 8) and the Talon Rego
// tier-projection health check. The index idx_iam_devices_tier_platform
// supports this query.
//
// tier must be one of TIER_CORP, TIER_BYOD, TIER_BREAKGLASS.
func (r *IAMDevicesRepository) ListByTier(ctx context.Context, tier string) ([]IAMDeviceRow, error) {
	if _, ok := validTiers[tier]; !ok {
		return nil, fmt.Errorf("iam_devices: list_by_tier: tier %q must be one of: TIER_CORP, TIER_BYOD, TIER_BREAKGLASS", tier)
	}

	q := `SELECT ` + iamDeviceCols + `
  FROM iam_devices
 WHERE tier = $1
 ORDER BY enrolled_at DESC`

	rows, err := r.pool.Query(ctx, q, tier)
	if err != nil {
		return nil, fmt.Errorf("iam_devices: list_by_tier: %w", err)
	}
	defer rows.Close()

	return collectIAMDeviceRows(rows, "list_by_tier")
}

// ListStale returns device rows where last_seen_at < threshold AND revoked_at
// IS NULL. Used by the stale-device alert job to identify devices that have
// not checked in since the given threshold. Only active (non-revoked) devices
// are returned — revoked rows are irrelevant for this alert.
//
// threshold must not be zero. The index idx_iam_devices_last_seen supports this
// query.
func (r *IAMDevicesRepository) ListStale(ctx context.Context, threshold time.Time) ([]IAMDeviceRow, error) {
	if threshold.IsZero() {
		return nil, fmt.Errorf("iam_devices: list_stale: threshold must not be zero")
	}

	q := `SELECT ` + iamDeviceCols + `
  FROM iam_devices
 WHERE last_seen_at < $1
   AND revoked_at IS NULL
 ORDER BY last_seen_at ASC`

	rows, err := r.pool.Query(ctx, q, threshold.UTC())
	if err != nil {
		return nil, fmt.Errorf("iam_devices: list_stale: %w", err)
	}
	defer rows.Close()

	return collectIAMDeviceRows(rows, "list_stale")
}

// collectIAMDeviceRows drains a pgx.Rows cursor into a slice. It always
// returns a non-nil slice on success so callers can range safely.
func collectIAMDeviceRows(rows pgx.Rows, method string) ([]IAMDeviceRow, error) {
	var out []IAMDeviceRow
	for rows.Next() {
		row, err := scanIAMDeviceRow(rows)
		if err != nil {
			return nil, fmt.Errorf("iam_devices: %s: scan: %w", method, err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iam_devices: %s: iterate: %w", method, err)
	}
	if out == nil {
		out = []IAMDeviceRow{}
	}
	return out, nil
}
