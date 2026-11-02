// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lib/pq"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newIAMDevicesMock creates a pgxmock pool and a repository wired to it.
func newIAMDevicesMock(t *testing.T) (pgxmock.PgxPoolIface, *IAMDevicesRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, &IAMDevicesRepository{pool: mock}
}

// sampleDeviceRow returns a fully-populated IAMDeviceRow suitable for happy-path
// tests. All nullable pointer fields are populated so that constraint tests can
// nil them selectively.
func sampleDeviceRow(t *testing.T) IAMDeviceRow {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	deviceUUID := uuid.New()
	tpmMfr := "Infineon"
	tpmKind := "discrete"
	witnessAdmin := "sub-admin-00000000"
	hostname := "dev-box-01.corp.example.com"
	platformUUID := "deadbeef-0000-4000-8000-000000000001"
	ekHash := make([]byte, 32)
	for i := range ekHash {
		ekHash[i] = byte(i + 1)
	}

	return IAMDeviceRow{
		DeviceUUID:                 deviceUUID,
		UserSub:                    "sub-user-00000000",
		Platform:                   "tpm2-linux",
		AttestationPath:            "A_chain",
		Tier:                       "TIER_CORP",
		EKPubkeyHash:               ekHash,
		TPMManufacturer:            &tpmMfr,
		TPMKind:                    &tpmKind,
		WitnessAdminSub:            &witnessAdmin,
		WitnessSignedAt:            &now,
		Hostname:                   &hostname,
		PlatformUUID:               &platformUUID,
		MACAddrs:                   []string{"aa:bb:cc:dd:ee:ff"},
		LastAttestationFingerprint: []byte{0xde, 0xad, 0xbe, 0xef},
		EnrolledAt:                 now,
		LastSeenAt:                 now,
	}
}

// iamDeviceSelectCols returns the same column list used by the repo SELECT
// queries, so mock.NewRows(iamDeviceSelectCols) stays in sync.
func iamDeviceSelectCols() []string {
	return []string{
		"id", "device_uuid", "user_sub", "platform", "attestation_path", "tier",
		"ek_pubkey_hash", "tpm_manufacturer", "tpm_kind",
		"witness_admin_sub", "witness_signed_at",
		"hostname", "platform_uuid", "mac_addrs",
		"last_attestation_fingerprint",
		"enrolled_at", "last_seen_at",
		"revoked_at", "revoked_reason", "revoked_by_sub",
		"serial_number", "model", "manufacturer", "witness_method",
	}
}

// addDeviceRow appends a single IAMDeviceRow to a pgxmock Rows value.
// MACAddrs is passed as a pq.StringArray value so that pgxmock can convert it
// to the pq.StringArray scan target in the repository.
func addDeviceRow(rows *pgxmock.Rows, id uuid.UUID, row IAMDeviceRow) *pgxmock.Rows {
	macAddrs := pq.StringArray(row.MACAddrs)
	return rows.AddRow(
		id,
		row.DeviceUUID.String(),
		row.UserSub,
		row.Platform,
		row.AttestationPath,
		row.Tier,
		row.EKPubkeyHash,
		row.TPMManufacturer,
		row.TPMKind,
		row.WitnessAdminSub,
		row.WitnessSignedAt,
		row.Hostname,
		row.PlatformUUID,
		macAddrs,
		row.LastAttestationFingerprint,
		row.EnrolledAt,
		row.LastSeenAt,
		row.RevokedAt,
		row.RevokedReason,
		row.RevokedBy,
		row.SerialNumber,
		row.Model,
		row.Manufacturer,
		row.WitnessMethod,
	)
}

// ---------------------------------------------------------------------------
// RegisterDevice tests
// ---------------------------------------------------------------------------

func TestIAMDevicesRepository_RegisterDevice_Success(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)
	mock.ExpectExec("INSERT INTO iam_devices").
		WithArgs(anyArgs(20)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := repo.RegisterDevice(context.Background(), row)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIAMDevicesRepository_RegisterDevice_EnrolledAtDefaultsToNow(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)
	row.EnrolledAt = time.Time{} // zero — should be defaulted
	row.LastSeenAt = time.Time{}

	mock.ExpectExec("INSERT INTO iam_devices").
		WithArgs(anyArgs(20)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := repo.RegisterDevice(context.Background(), row)
	require.NoError(t, err)
}

func TestIAMDevicesRepository_RegisterDevice_EKConflict(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)
	mock.ExpectExec("INSERT INTO iam_devices").
		WithArgs(anyArgs(20)...).
		WillReturnError(&pgconn.PgError{
			Code:           "23505",
			Message:        "duplicate key value violates unique constraint",
			ConstraintName: "iam_devices_ek_pubkey_hash_key",
		})

	err := repo.RegisterDevice(context.Background(), row)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrIAMDeviceEKConflict),
		"ek_pubkey_hash unique violation must return ErrIAMDeviceEKConflict; got %v", err)
}

func TestIAMDevicesRepository_RegisterDevice_UUIDConflict(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)
	mock.ExpectExec("INSERT INTO iam_devices").
		WithArgs(anyArgs(20)...).
		WillReturnError(&pgconn.PgError{
			Code:           "23505",
			Message:        "duplicate key value violates unique constraint",
			ConstraintName: "iam_devices_device_uuid_key",
		})

	err := repo.RegisterDevice(context.Background(), row)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrIAMDeviceUUIDConflict),
		"device_uuid unique violation must return ErrIAMDeviceUUIDConflict; got %v", err)
}

func TestIAMDevicesRepository_RegisterDevice_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*IAMDeviceRow)
		wantErr string
	}{
		{
			name:    "invalid uuid",
			mutate:  func(r *IAMDeviceRow) { r.DeviceUUID = uuid.UUID{} },
			wantErr: "UUIDv4",
		},
		{
			name:    "invalid platform",
			mutate:  func(r *IAMDeviceRow) { r.Platform = "windows-hello" },
			wantErr: "platform",
		},
		{
			name:    "invalid attestation_path",
			mutate:  func(r *IAMDeviceRow) { r.AttestationPath = "C_magic" },
			wantErr: "attestation_path",
		},
		{
			name:    "invalid tier",
			mutate:  func(r *IAMDeviceRow) { r.Tier = "TIER_GOLD" },
			wantErr: "tier",
		},
		{
			name:    "ek_pubkey_hash too short",
			mutate:  func(r *IAMDeviceRow) { r.EKPubkeyHash = make([]byte, 16) },
			wantErr: "ek_pubkey_hash",
		},
		{
			name:    "ek_pubkey_hash too long",
			mutate:  func(r *IAMDeviceRow) { r.EKPubkeyHash = make([]byte, 48) },
			wantErr: "ek_pubkey_hash",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, repo := newIAMDevicesMock(t)
			row := sampleDeviceRow(t)
			tc.mutate(&row)
			err := repo.RegisterDevice(context.Background(), row)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr,
				"error message should mention the offending field")
		})
	}
}

func TestIAMDevicesRepository_RegisterDevice_AllPlatforms(t *testing.T) {
	platforms := []string{
		"tpm2-linux", "tpm2-windows", "android-strongbox",
		"apple-app-attest", "macos-mdm",
	}
	for _, platform := range platforms {
		t.Run(platform, func(t *testing.T) {
			mock, repo := newIAMDevicesMock(t)
			defer mock.Close()

			row := sampleDeviceRow(t)
			row.Platform = platform
			mock.ExpectExec("INSERT INTO iam_devices").
				WithArgs(anyArgs(20)...).
				WillReturnResult(pgxmock.NewResult("INSERT", 1))

			err := repo.RegisterDevice(context.Background(), row)
			require.NoError(t, err)
		})
	}
}

// TestIAMDevicesRepository_RegisterDevice_Concurrent verifies that when two
// goroutines concurrently attempt to register a device with the same
// ek_pubkey_hash, exactly one succeeds and the other receives
// ErrIAMDeviceEKConflict. We simulate this with two sequential mock
// expectations: first succeeds, second returns 23505.
func TestIAMDevicesRepository_RegisterDevice_Concurrent(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)

	// First INSERT succeeds.
	mock.ExpectExec("INSERT INTO iam_devices").
		WithArgs(anyArgs(20)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	// Second INSERT returns UNIQUE violation on ek_pubkey_hash.
	mock.ExpectExec("INSERT INTO iam_devices").
		WithArgs(anyArgs(20)...).
		WillReturnError(&pgconn.PgError{
			Code:           "23505",
			ConstraintName: "iam_devices_ek_pubkey_hash_key",
		})

	err1 := repo.RegisterDevice(context.Background(), row)
	err2 := repo.RegisterDevice(context.Background(), row)

	require.NoError(t, err1, "first registration must succeed")
	require.Error(t, err2, "second registration must fail")
	assert.True(t, errors.Is(err2, ErrIAMDeviceEKConflict))
	require.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// GetByUUID tests
// ---------------------------------------------------------------------------

func TestIAMDevicesRepository_GetByUUID_Found(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)
	id := uuid.New()

	rows := mock.NewRows(iamDeviceSelectCols())
	addDeviceRow(rows, id, row)

	mock.ExpectQuery("SELECT").
		WithArgs(row.DeviceUUID.String()).
		WillReturnRows(rows)

	got, err := repo.GetByUUID(context.Background(), row.DeviceUUID.String())
	require.NoError(t, err)
	assert.Equal(t, row.DeviceUUID, got.DeviceUUID)
	assert.Equal(t, row.UserSub, got.UserSub)
	assert.Equal(t, row.Platform, got.Platform)
	assert.Equal(t, row.Tier, got.Tier)
	assert.Equal(t, row.AttestationPath, got.AttestationPath)
	assert.Equal(t, row.EKPubkeyHash, got.EKPubkeyHash)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIAMDevicesRepository_GetByUUID_NotFound(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	uid := uuid.New()
	mock.ExpectQuery("SELECT").
		WithArgs(uid.String()).
		WillReturnError(pgx.ErrNoRows)

	_, err := repo.GetByUUID(context.Background(), uid.String())
	require.Error(t, err)
	assert.True(t, errors.Is(err, pgx.ErrNoRows),
		"GetByUUID must wrap pgx.ErrNoRows; got %v", err)
}

func TestIAMDevicesRepository_GetByUUID_InvalidUUID(t *testing.T) {
	_, repo := newIAMDevicesMock(t)
	_, err := repo.GetByUUID(context.Background(), "not-a-uuid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid UUID")
}

func TestIAMDevicesRepository_GetByUUID_DBError(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	uid := uuid.New()
	mock.ExpectQuery("SELECT").
		WithArgs(uid.String()).
		WillReturnError(&pgconn.PgError{Code: "08006", Message: "connection failure"})

	_, err := repo.GetByUUID(context.Background(), uid.String())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get_by_uuid")
	assert.False(t, errors.Is(err, pgx.ErrNoRows))
}

// ---------------------------------------------------------------------------
// GetByEKPubkeyHash tests
// ---------------------------------------------------------------------------

func TestIAMDevicesRepository_GetByEKPubkeyHash_Found(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)
	id := uuid.New()
	hashHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	rows := mock.NewRows(iamDeviceSelectCols())
	addDeviceRow(rows, id, row)

	mock.ExpectQuery("SELECT").
		WithArgs(anyArgs(1)...).
		WillReturnRows(rows)

	got, err := repo.GetByEKPubkeyHash(context.Background(), hashHex)
	require.NoError(t, err)
	assert.Equal(t, row.DeviceUUID, got.DeviceUUID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIAMDevicesRepository_GetByEKPubkeyHash_NotFound(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	hashHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	mock.ExpectQuery("SELECT").
		WithArgs(anyArgs(1)...).
		WillReturnError(pgx.ErrNoRows)

	_, err := repo.GetByEKPubkeyHash(context.Background(), hashHex)
	require.Error(t, err)
	assert.True(t, errors.Is(err, pgx.ErrNoRows))
}

func TestIAMDevicesRepository_GetByEKPubkeyHash_InvalidHex(t *testing.T) {
	_, repo := newIAMDevicesMock(t)
	_, err := repo.GetByEKPubkeyHash(context.Background(), "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid hex")
}

func TestIAMDevicesRepository_GetByEKPubkeyHash_WrongLength(t *testing.T) {
	_, repo := newIAMDevicesMock(t)
	_, err := repo.GetByEKPubkeyHash(context.Background(), "deadbeef") // only 8 hex chars
	require.Error(t, err)
	assert.Contains(t, err.Error(), "64 hex chars")
}

// ---------------------------------------------------------------------------
// ListByUserSub tests
// ---------------------------------------------------------------------------

func TestIAMDevicesRepository_ListByUserSub_MultipleRows(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row1 := sampleDeviceRow(t)
	row2 := sampleDeviceRow(t)
	row2.DeviceUUID = uuid.New()
	row2.Tier = "TIER_BYOD"
	row2.AttestationPath = "B_tofu"

	rows := mock.NewRows(iamDeviceSelectCols())
	addDeviceRow(rows, uuid.New(), row1)
	addDeviceRow(rows, uuid.New(), row2)

	mock.ExpectQuery("SELECT").
		WithArgs(row1.UserSub).
		WillReturnRows(rows)

	result, err := repo.ListByUserSub(context.Background(), row1.UserSub)
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, row1.Tier, result[0].Tier)
	assert.Equal(t, "TIER_BYOD", result[1].Tier)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIAMDevicesRepository_ListByUserSub_EmptyResult(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	rows := mock.NewRows(iamDeviceSelectCols())
	mock.ExpectQuery("SELECT").
		WithArgs("sub-nobody").
		WillReturnRows(rows)

	result, err := repo.ListByUserSub(context.Background(), "sub-nobody")
	require.NoError(t, err)
	assert.NotNil(t, result, "empty result must be non-nil slice")
	assert.Empty(t, result)
}

func TestIAMDevicesRepository_ListByUserSub_EmptySubError(t *testing.T) {
	_, repo := newIAMDevicesMock(t)
	_, err := repo.ListByUserSub(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list_by_user_sub")
}

func TestIAMDevicesRepository_ListByUserSub_DBError(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	mock.ExpectQuery("SELECT").
		WithArgs("sub-user").
		WillReturnError(&pgconn.PgError{Code: "57014", Message: "statement timeout"})

	_, err := repo.ListByUserSub(context.Background(), "sub-user")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list_by_user_sub")
}

// ---------------------------------------------------------------------------
// UpdateLastSeen tests
// ---------------------------------------------------------------------------

func TestIAMDevicesRepository_UpdateLastSeen_Success(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	uid := uuid.New().String()
	now := time.Now().UTC()
	nonce := []byte{0x01, 0x02, 0x03}

	mock.ExpectExec("UPDATE iam_devices").
		WithArgs(anyArgs(3)...).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.UpdateLastSeen(context.Background(), uid, now, now, nonce)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIAMDevicesRepository_UpdateLastSeen_InvalidUUID(t *testing.T) {
	_, repo := newIAMDevicesMock(t)
	err := repo.UpdateLastSeen(context.Background(), "bad-uuid", time.Now(), time.Now(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update_last_seen")
}

func TestIAMDevicesRepository_UpdateLastSeen_ZeroTime(t *testing.T) {
	_, repo := newIAMDevicesMock(t)
	uid := uuid.New().String()
	err := repo.UpdateLastSeen(context.Background(), uid, time.Time{}, time.Time{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lastSeenAt must not be zero")
}

func TestIAMDevicesRepository_UpdateLastSeen_DBError(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	uid := uuid.New().String()
	now := time.Now().UTC()

	mock.ExpectExec("UPDATE iam_devices").
		WithArgs(anyArgs(3)...).
		WillReturnError(&pgconn.PgError{Code: "08006", Message: "connection failure"})

	err := repo.UpdateLastSeen(context.Background(), uid, now, now, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update_last_seen")
}

// ---------------------------------------------------------------------------
// Revoke tests
// ---------------------------------------------------------------------------

func TestIAMDevicesRepository_Revoke_Success(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	uid := uuid.New().String()
	now := time.Now().UTC()

	mock.ExpectExec("UPDATE iam_devices").
		WithArgs(anyArgs(4)...).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.Revoke(context.Background(), uid, "user_self_removed", "sub-admin-01", now)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestIAMDevicesRepository_Revoke_RowPreserved verifies the audit-retention
// contract: after Revoke, GetByUUID must still return the row (row is NOT
// deleted). We simulate this by expecting both an UPDATE (Revoke) and a
// subsequent SELECT (GetByUUID) that returns the row with revoked_at set.
func TestIAMDevicesRepository_Revoke_RowPreserved(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)
	uid := row.DeviceUUID.String()
	now := time.Now().UTC()
	reason := "admin_policy_violation"
	revokedBy := "sub-admin-01"

	// 1. Revoke call
	mock.ExpectExec("UPDATE iam_devices").
		WithArgs(anyArgs(4)...).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.Revoke(context.Background(), uid, reason, revokedBy, now)
	require.NoError(t, err)

	// 2. GetByUUID must still return the row — simulate the DB returning
	// the row with revoked_at and revoked_by_sub populated.
	row.RevokedAt = &now
	row.RevokedReason = &reason
	row.RevokedBy = &revokedBy

	dbRows := mock.NewRows(iamDeviceSelectCols())
	addDeviceRow(dbRows, uuid.New(), row)

	mock.ExpectQuery("SELECT").
		WithArgs(uid).
		WillReturnRows(dbRows)

	got, err := repo.GetByUUID(context.Background(), uid)
	require.NoError(t, err, "GetByUUID must succeed after Revoke — row must be preserved")
	require.NotNil(t, got.RevokedAt, "revoked_at must be set")
	assert.Equal(t, reason, *got.RevokedReason)
	assert.Equal(t, revokedBy, *got.RevokedBy)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIAMDevicesRepository_Revoke_Idempotent(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	uid := uuid.New().String()
	now := time.Now().UTC()

	// Both calls must succeed — second call is a no-op due to COALESCE.
	mock.ExpectExec("UPDATE iam_devices").
		WithArgs(anyArgs(4)...).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectExec("UPDATE iam_devices").
		WithArgs(anyArgs(4)...).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err1 := repo.Revoke(context.Background(), uid, "reason-1", "sub-admin", now)
	err2 := repo.Revoke(context.Background(), uid, "reason-2", "sub-admin", now)
	require.NoError(t, err1)
	require.NoError(t, err2)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIAMDevicesRepository_Revoke_ValidationErrors(t *testing.T) {
	uid := uuid.New().String()
	now := time.Now().UTC()

	tests := []struct {
		name      string
		uuid      string
		reason    string
		revokedBy string
		revokedAt time.Time
		wantErr   string
	}{
		{"invalid uuid", "bad-uuid", "reason", "admin", now, "revoke"},
		{"empty reason", uid, "", "admin", now, "reason must not be empty"},
		{"empty revokedBy", uid, "reason", "", now, "revokedBy must not be empty"},
		{"zero revokedAt", uid, "reason", "admin", time.Time{}, "revokedAt must not be zero"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, repo := newIAMDevicesMock(t)
			err := repo.Revoke(context.Background(), tc.uuid, tc.reason, tc.revokedBy, tc.revokedAt)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// ---------------------------------------------------------------------------
// ListRevoked tests
// ---------------------------------------------------------------------------

func TestIAMDevicesRepository_ListRevoked_ReturnsRevokedRows(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)
	now := time.Now().UTC()
	reason := "user_self_removed"
	revokedBy := "sub-user-00000000"
	row.RevokedAt = &now
	row.RevokedReason = &reason
	row.RevokedBy = &revokedBy

	rows := mock.NewRows(iamDeviceSelectCols())
	addDeviceRow(rows, uuid.New(), row)

	since := now.Add(-24 * time.Hour)
	mock.ExpectQuery("SELECT").
		WithArgs(since).
		WillReturnRows(rows)

	result, err := repo.ListRevoked(context.Background(), since)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.NotNil(t, result[0].RevokedAt)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIAMDevicesRepository_ListRevoked_Empty(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	rows := mock.NewRows(iamDeviceSelectCols())
	mock.ExpectQuery("SELECT").
		WithArgs(anyArgs(1)...).
		WillReturnRows(rows)

	result, err := repo.ListRevoked(context.Background(), time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

func TestIAMDevicesRepository_ListRevoked_DBError(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	mock.ExpectQuery("SELECT").
		WithArgs(anyArgs(1)...).
		WillReturnError(&pgconn.PgError{Code: "57014", Message: "statement timeout"})

	_, err := repo.ListRevoked(context.Background(), time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list_revoked")
}

// ---------------------------------------------------------------------------
// ListByTier tests
// ---------------------------------------------------------------------------

func TestIAMDevicesRepository_ListByTier_ValidTiers(t *testing.T) {
	tiers := []string{"TIER_CORP", "TIER_BYOD", "TIER_BREAKGLASS"}
	for _, tier := range tiers {
		t.Run(tier, func(t *testing.T) {
			mock, repo := newIAMDevicesMock(t)
			defer mock.Close()

			row := sampleDeviceRow(t)
			row.Tier = tier

			rows := mock.NewRows(iamDeviceSelectCols())
			addDeviceRow(rows, uuid.New(), row)

			mock.ExpectQuery("SELECT").
				WithArgs(tier).
				WillReturnRows(rows)

			result, err := repo.ListByTier(context.Background(), tier)
			require.NoError(t, err)
			require.Len(t, result, 1)
			assert.Equal(t, tier, result[0].Tier)
		})
	}
}

func TestIAMDevicesRepository_ListByTier_InvalidTier(t *testing.T) {
	_, repo := newIAMDevicesMock(t)
	_, err := repo.ListByTier(context.Background(), "TIER_GOLD")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list_by_tier")
	assert.Contains(t, err.Error(), "TIER_GOLD")
}

func TestIAMDevicesRepository_ListByTier_EmptyResult(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	rows := mock.NewRows(iamDeviceSelectCols())
	mock.ExpectQuery("SELECT").
		WithArgs("TIER_BREAKGLASS").
		WillReturnRows(rows)

	result, err := repo.ListByTier(context.Background(), "TIER_BREAKGLASS")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// ListStale tests
// ---------------------------------------------------------------------------

func TestIAMDevicesRepository_ListStale_ReturnsStaleActiveDevices(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)
	row.LastSeenAt = time.Now().UTC().Add(-30 * 24 * time.Hour) // 30 days ago

	rows := mock.NewRows(iamDeviceSelectCols())
	addDeviceRow(rows, uuid.New(), row)

	threshold := time.Now().UTC().Add(-7 * 24 * time.Hour) // 7 days ago
	mock.ExpectQuery("SELECT").
		WithArgs(threshold).
		WillReturnRows(rows)

	result, err := repo.ListStale(context.Background(), threshold)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Nil(t, result[0].RevokedAt, "stale results must exclude revoked devices")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIAMDevicesRepository_ListStale_ZeroThresholdError(t *testing.T) {
	_, repo := newIAMDevicesMock(t)
	_, err := repo.ListStale(context.Background(), time.Time{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "threshold must not be zero")
}

func TestIAMDevicesRepository_ListStale_EmptyResult(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	rows := mock.NewRows(iamDeviceSelectCols())
	mock.ExpectQuery("SELECT").
		WithArgs(anyArgs(1)...).
		WillReturnRows(rows)

	threshold := time.Now().UTC()
	result, err := repo.ListStale(context.Background(), threshold)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

func TestIAMDevicesRepository_ListStale_DBError(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	mock.ExpectQuery("SELECT").
		WithArgs(anyArgs(1)...).
		WillReturnError(&pgconn.PgError{Code: "08006", Message: "connection failure"})

	_, err := repo.ListStale(context.Background(), time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list_stale")
}

// ---------------------------------------------------------------------------
// Error sentinel identity tests
// ---------------------------------------------------------------------------

func TestIAMDevicesRepository_Sentinels_AreDistinct(t *testing.T) {
	// Verify the two sentinel errors are distinct — callers must be able
	// to distinguish a re-enrollment (EK conflict) from a UUID bug.
	assert.NotEqual(t, ErrIAMDeviceEKConflict, ErrIAMDeviceUUIDConflict)
	assert.False(t, errors.Is(ErrIAMDeviceEKConflict, ErrIAMDeviceUUIDConflict))
	assert.False(t, errors.Is(ErrIAMDeviceUUIDConflict, ErrIAMDeviceEKConflict))
}

// ---------------------------------------------------------------------------
// MACAddrs nullable handling
// ---------------------------------------------------------------------------

func TestIAMDevicesRepository_GetByUUID_NilMACAddrs(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)
	row.MACAddrs = nil // device enrolled without MAC capture

	id := uuid.New()
	dbRows := mock.NewRows(iamDeviceSelectCols())
	addDeviceRow(dbRows, id, row)

	mock.ExpectQuery("SELECT").
		WithArgs(row.DeviceUUID.String()).
		WillReturnRows(dbRows)

	got, err := repo.GetByUUID(context.Background(), row.DeviceUUID.String())
	require.NoError(t, err)
	assert.Empty(t, got.MACAddrs, "nil mac_addrs must scan to empty slice")
}

// ---------------------------------------------------------------------------
// Path B (TOFU) specific tests
// ---------------------------------------------------------------------------

// TestIAMDevicesRepository_RegisterDevice_PathBFields verifies that Path B
// witness fields (witness_admin_sub, witness_signed_at) are accepted and
// persisted correctly when attestation_path=B_tofu.
func TestIAMDevicesRepository_RegisterDevice_PathBFields(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)
	row.AttestationPath = "B_tofu"
	row.Tier = "TIER_BYOD"
	// WitnessAdminSub and WitnessSignedAt are already set in sampleDeviceRow.

	mock.ExpectExec("INSERT INTO iam_devices").
		WithArgs(anyArgs(20)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := repo.RegisterDevice(context.Background(), row)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestIAMDevicesRepository_RegisterDevice_PathAFields verifies that Path A
// (EK cert chain) enrollments succeed with nil witness fields.
func TestIAMDevicesRepository_RegisterDevice_PathAFields(t *testing.T) {
	mock, repo := newIAMDevicesMock(t)
	defer mock.Close()

	row := sampleDeviceRow(t)
	row.AttestationPath = "A_chain"
	row.Tier = "TIER_CORP"
	row.WitnessAdminSub = nil
	row.WitnessSignedAt = nil

	mock.ExpectExec("INSERT INTO iam_devices").
		WithArgs(anyArgs(20)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := repo.RegisterDevice(context.Background(), row)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// EKPubkeyHash hex string helper validation (used by GetByEKPubkeyHash callers)
// ---------------------------------------------------------------------------

func TestValidateEKPubkeyHashHex_Variants(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		wantErr bool
	}{
		{
			name:    "valid 64-char lowercase hex",
			hash:    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			wantErr: false,
		},
		{
			name:    "valid 64-char uppercase hex",
			hash:    "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
			wantErr: false,
		},
		{
			name:    "too short",
			hash:    "deadbeef",
			wantErr: true,
		},
		{
			name:    "not hex",
			hash:    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantErr: true,
		},
	}

	_, repo := newIAMDevicesMock(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := repo.GetByEKPubkeyHash(context.Background(), tc.hash)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				// We expect a DB error (no mock expectation), not a validation error.
				// The method must not return a validation error for valid hex.
				// Since there is no mock expectation set, the mock will return an error
				// about unexpected call — that's fine; we only care that validation passed.
				// For valid hex inputs we cannot distinguish "no mock" from DB error at
				// this level, so just assert no "hex" / "chars" error.
				if err != nil {
					assert.NotContains(t, err.Error(), "64 hex chars",
						"should not fail hex validation for valid input")
					assert.NotContains(t, err.Error(), "not valid hex",
						"should not fail hex validation for valid input")
				}
			}
		})
	}
}
