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

func newMagicLinkMock(t *testing.T) (pgxmock.PgxPoolIface, *MagicLinkRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newMagicLinkRepositoryWithMock(mock)
}

var magicLinkCols = []string{
	"id", "user_id", "email", "token_hash", "ip_address", "user_agent",
	"used_at", "expires_at", "created_at",
}

func sampleMagicLink() *models.MagicLink {
	ip := "192.168.1.10"
	ua := "Mozilla/5.0"
	uid := uuid.New()
	return &models.MagicLink{
		ID:        uuid.New(),
		UserID:    &uid,
		Email:     "user@example.com",
		TokenHash: "token-hash-abc123",
		IPAddress: &ip,
		UserAgent: &ua,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
}

func TestMagicLinkRepository_Create(t *testing.T) {
	now := time.Now()

	t.Run("success", func(t *testing.T) {
		mock, repo := newMagicLinkMock(t)
		defer mock.Close()

		link := sampleMagicLink()
		rows := mock.NewRows([]string{"created_at"}).AddRow(now)
		mock.ExpectQuery(`INSERT INTO iam_magic_links`).
			WithArgs(anyArgs(7)...).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), link)
		assert.NoError(t, err)
		assert.Equal(t, now, link.CreatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newMagicLinkMock(t)
		defer mock.Close()

		link := sampleMagicLink()
		mock.ExpectQuery(`INSERT INTO iam_magic_links`).
			WithArgs(anyArgs(7)...).
			WillReturnError(fmt.Errorf("duplicate key"))

		err := repo.Create(context.Background(), link)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMagicLinkRepository_GetByTokenHash(t *testing.T) {
	now := time.Now()
	link := sampleMagicLink()

	t.Run("found", func(t *testing.T) {
		mock, repo := newMagicLinkMock(t)
		defer mock.Close()

		rows := mock.NewRows(magicLinkCols).AddRow(
			link.ID, link.UserID, link.Email, link.TokenHash,
			link.IPAddress, link.UserAgent, nil, link.ExpiresAt, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(link.TokenHash).WillReturnRows(rows)

		got, err := repo.GetByTokenHash(context.Background(), link.TokenHash)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, link.TokenHash, got.TokenHash)
		assert.Equal(t, link.Email, got.Email)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newMagicLinkMock(t)
		defer mock.Close()

		rows := mock.NewRows(magicLinkCols)
		mock.ExpectQuery(`SELECT`).WithArgs(link.TokenHash).WillReturnRows(rows)

		got, err := repo.GetByTokenHash(context.Background(), link.TokenHash)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newMagicLinkMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WithArgs(link.TokenHash).WillReturnError(fmt.Errorf("timeout"))

		got, err := repo.GetByTokenHash(context.Background(), link.TokenHash)
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMagicLinkRepository_MarkAsUsed(t *testing.T) {
	linkID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newMagicLinkMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_magic_links SET used_at`).
			WithArgs(linkID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.MarkAsUsed(context.Background(), linkID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newMagicLinkMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_magic_links SET used_at`).
			WithArgs(linkID).
			WillReturnError(fmt.Errorf("constraint violation"))

		err := repo.MarkAsUsed(context.Background(), linkID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMagicLinkRepository_DeleteExpired(t *testing.T) {
	t.Run("deletes expired links", func(t *testing.T) {
		mock, repo := newMagicLinkMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_magic_links WHERE expires_at`).
			WillReturnResult(pgxmock.NewResult("DELETE", 7))

		count, err := repo.DeleteExpired(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, int64(7), count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMagicLinkRepository_DeleteByEmail(t *testing.T) {
	email := "user@example.com"

	t.Run("success", func(t *testing.T) {
		mock, repo := newMagicLinkMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_magic_links WHERE email`).
			WithArgs(email).
			WillReturnResult(pgxmock.NewResult("DELETE", 2))

		err := repo.DeleteByEmail(context.Background(), email)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMagicLinkRepository_CountRecentByEmail(t *testing.T) {
	email := "user@example.com"
	since := time.Now().Add(-1 * time.Hour)

	t.Run("returns count", func(t *testing.T) {
		mock, repo := newMagicLinkMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"count"}).AddRow(3)
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(email, since).WillReturnRows(rows)

		count, err := repo.CountRecentByEmail(context.Background(), email, since)
		assert.NoError(t, err)
		assert.Equal(t, 3, count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMagicLinkRepository_CountRecentByIP(t *testing.T) {
	ip := testImpersonationIP
	since := time.Now().Add(-1 * time.Hour)

	t.Run("returns count", func(t *testing.T) {
		mock, repo := newMagicLinkMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"count"}).AddRow(1)
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(ip, since).WillReturnRows(rows)

		count, err := repo.CountRecentByIP(context.Background(), ip, since)
		assert.NoError(t, err)
		assert.Equal(t, 1, count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
