// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	testIPLocalhost = "127.0.0.1"
)

func newDeviceMock(t *testing.T) (pgxmock.PgxPoolIface, *DeviceRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newDeviceRepositoryWithMock(mock)
}

// deviceCols lists all columns returned by device SELECT queries.
var deviceCols = []string{
	"id", "user_id", "fingerprint_hash", "device_name", "device_type",
	"browser", "os", "is_trusted", "first_seen_at", "last_seen_at",
	"last_ip", "trust_expires_at", "created_at", "updated_at",
}

func TestDeviceRepository_Create(t *testing.T) {
	now := time.Now()
	deviceID := uuid.New()
	userID := uuid.New()
	deviceName := "Chrome on macOS"
	deviceType := "desktop"
	browser := "Chrome"
	os := "macOS"
	lastIP := testIPLocalhost

	tests := []struct {
		name    string
		setup   func(mock pgxmock.PgxPoolIface, dev *models.Device)
		wantErr bool
	}{
		{
			name: "success",
			setup: func(mock pgxmock.PgxPoolIface, _ *models.Device) {
				rows := mock.NewRows([]string{"first_seen_at", "last_seen_at", "created_at", "updated_at"}).
					AddRow(now, now, now, now)
				mock.ExpectQuery(`INSERT INTO iam_user_devices`).
					WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
						pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name: "db error",
			setup: func(mock pgxmock.PgxPoolIface, _ *models.Device) {
				mock.ExpectQuery(`INSERT INTO iam_user_devices`).
					WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
						pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnError(fmt.Errorf("db connection lost"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, repo := newDeviceMock(t)
			defer mock.Close()

			dev := &models.Device{
				ID:              deviceID,
				UserID:          userID,
				FingerprintHash: "abc123",
				DeviceName:      &deviceName,
				DeviceType:      &deviceType,
				Browser:         &browser,
				OS:              &os,
				IsTrusted:       false,
				LastIP:          &lastIP,
			}

			tt.setup(mock, dev)

			err := repo.Create(context.Background(), dev)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, now, dev.FirstSeenAt)
				assert.Equal(t, now, dev.CreatedAt)
			}
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestDeviceRepository_GetByID(t *testing.T) {
	now := time.Now()
	deviceID := uuid.New()
	userID := uuid.New()
	deviceName := "Firefox"
	deviceType := "desktop"

	t.Run("found", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		rows := mock.NewRows(deviceCols).AddRow(
			deviceID, userID, "hash123", &deviceName, &deviceType,
			nil, nil, false, now, now, nil, nil, now, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(deviceID).WillReturnRows(rows)

		dev, err := repo.GetByID(context.Background(), deviceID)
		require.NoError(t, err)
		require.NotNil(t, dev)
		assert.Equal(t, deviceID, dev.ID)
		assert.Equal(t, userID, dev.UserID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		rows := mock.NewRows(deviceCols) // empty
		mock.ExpectQuery(`SELECT`).WithArgs(deviceID).WillReturnRows(rows)

		dev, err := repo.GetByID(context.Background(), deviceID)
		assert.NoError(t, err)
		assert.Nil(t, dev)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WithArgs(deviceID).WillReturnError(fmt.Errorf("timeout"))

		dev, err := repo.GetByID(context.Background(), deviceID)
		assert.Error(t, err)
		assert.Nil(t, dev)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeviceRepository_GetByFingerprint(t *testing.T) {
	now := time.Now()
	userID := uuid.New()
	deviceID := uuid.New()
	fp := "fingerprint-abc"

	t.Run("found", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		rows := mock.NewRows(deviceCols).AddRow(
			deviceID, userID, fp, nil, nil, nil, nil, false, now, now, nil, nil, now, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(userID, fp).WillReturnRows(rows)

		dev, err := repo.GetByFingerprint(context.Background(), userID, fp)
		require.NoError(t, err)
		require.NotNil(t, dev)
		assert.Equal(t, fp, dev.FingerprintHash)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		rows := mock.NewRows(deviceCols)
		mock.ExpectQuery(`SELECT`).WithArgs(userID, fp).WillReturnRows(rows)

		dev, err := repo.GetByFingerprint(context.Background(), userID, fp)
		assert.NoError(t, err)
		assert.Nil(t, dev)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeviceRepository_GetByUserID(t *testing.T) {
	now := time.Now()
	userID := uuid.New()
	deviceID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		countRows := mock.NewRows([]string{"count"}).AddRow(int64(1))
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(userID).WillReturnRows(countRows)

		listRows := mock.NewRows(deviceCols).AddRow(
			deviceID, userID, "fp1", nil, nil, nil, nil, false, now, now, nil, nil, now, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(userID, 10, 0).WillReturnRows(listRows)

		devices, total, err := repo.GetByUserID(context.Background(), userID, 1, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, devices, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("count error", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT COUNT`).WithArgs(userID).WillReturnError(fmt.Errorf("db error"))

		_, _, err := repo.GetByUserID(context.Background(), userID, 1, 10)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeviceRepository_Update(t *testing.T) {
	now := time.Now()
	deviceID := uuid.New()
	userID := uuid.New()
	deviceName := "Updated Device"
	deviceType := "mobile"

	t.Run("success", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"updated_at"}).AddRow(now)
		mock.ExpectQuery(`UPDATE iam_user_devices`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(rows)

		dev := &models.Device{
			ID:         deviceID,
			UserID:     userID,
			DeviceName: &deviceName,
			DeviceType: &deviceType,
		}
		err := repo.Update(context.Background(), dev)
		assert.NoError(t, err)
		assert.Equal(t, now, dev.UpdatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeviceRepository_TrustDevice(t *testing.T) {
	deviceID := uuid.New()
	expiry := time.Now().Add(30 * 24 * time.Hour)

	t.Run("with expiry", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_user_devices SET is_trusted = true`).
			WithArgs(deviceID, &expiry).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.TrustDevice(context.Background(), deviceID, &expiry)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("without expiry", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_user_devices SET is_trusted = true`).
			WithArgs(deviceID, (*time.Time)(nil)).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.TrustDevice(context.Background(), deviceID, nil)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_user_devices SET is_trusted = true`).
			WithArgs(deviceID, &expiry).
			WillReturnError(fmt.Errorf("constraint violation"))

		err := repo.TrustDevice(context.Background(), deviceID, &expiry)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeviceRepository_UntrustDevice(t *testing.T) {
	deviceID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_user_devices SET is_trusted = false`).
			WithArgs(deviceID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UntrustDevice(context.Background(), deviceID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeviceRepository_Delete(t *testing.T) {
	deviceID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_user_devices WHERE id`).
			WithArgs(deviceID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(context.Background(), deviceID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_user_devices WHERE id`).
			WithArgs(deviceID).
			WillReturnError(fmt.Errorf("foreign key violation"))

		err := repo.Delete(context.Background(), deviceID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeviceRepository_UpdateLastSeen(t *testing.T) {
	deviceID := uuid.New()
	ip := "192.168.1.1"

	t.Run("success", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_user_devices SET last_seen_at`).
			WithArgs(deviceID, ip).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateLastSeen(context.Background(), deviceID, ip)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeviceRepository_CountUserDevices(t *testing.T) {
	userID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"count"}).AddRow(int64(5))
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(userID).WillReturnRows(rows)

		count, err := repo.CountUserDevices(context.Background(), userID)
		assert.NoError(t, err)
		assert.Equal(t, int64(5), count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeviceRepository_IsTrustedDevice(t *testing.T) {
	userID := uuid.New()
	fp := "trusted-fingerprint"

	t.Run("trusted", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"is_trusted"}).AddRow(true)
		mock.ExpectQuery(`SELECT is_trusted`).WithArgs(userID, fp).WillReturnRows(rows)

		trusted, err := repo.IsTrustedDevice(context.Background(), userID, fp)
		assert.NoError(t, err)
		assert.True(t, trusted)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns false", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"is_trusted"})
		mock.ExpectQuery(`SELECT is_trusted`).WithArgs(userID, fp).WillReturnRows(rows)

		trusted, err := repo.IsTrustedDevice(context.Background(), userID, fp)
		assert.NoError(t, err)
		assert.False(t, trusted)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeviceRepository_CleanupExpiredTrust(t *testing.T) {
	t.Run("returns rows affected", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_user_devices SET is_trusted = false`).
			WillReturnResult(pgxmock.NewResult("UPDATE", 3))

		count, err := repo.CleanupExpiredTrust(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, int64(3), count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeviceRepository_GetTrustedDevices(t *testing.T) {
	now := time.Now()
	userID := uuid.New()
	deviceID := uuid.New()

	t.Run("returns trusted devices", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		rows := mock.NewRows(deviceCols).AddRow(
			deviceID, userID, "fp1", nil, nil, nil, nil, true, now, now, nil, nil, now, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnRows(rows)

		devices, err := repo.GetTrustedDevices(context.Background(), userID)
		require.NoError(t, err)
		assert.Len(t, devices, 1)
		assert.True(t, devices[0].IsTrusted)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty result", func(t *testing.T) {
		mock, repo := newDeviceMock(t)
		defer mock.Close()

		rows := mock.NewRows(deviceCols)
		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnRows(rows)

		devices, err := repo.GetTrustedDevices(context.Background(), userID)
		assert.NoError(t, err)
		assert.Len(t, devices, 0)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
