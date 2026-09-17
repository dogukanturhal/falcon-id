// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// newInvRepoMock creates an InvitationRepository backed by pgxmock.
func newInvRepoMock(t *testing.T) (*InvitationRepository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	repo := &InvitationRepository{db: mock}
	return repo, mock
}

// invColumns are all columns selected in invitation queries.
func invColumns() []string {
	return []string{
		"id", "user_id", "tenant_id", "realm_id", "token_hash", "invitation_type",
		"invited_by_admin_id", "invited_by_user_id", "email", "email_sent_at", "email_send_count",
		"last_email_sent_at", "status", "accepted_at", "accepted_ip", "expires_at", "custom_message",
		"created_at", "updated_at",
	}
}

func newTestInvitation(tenantID uuid.UUID) *models.UserInvitation {
	userID := uuid.New()
	msg := "Welcome to Example Suite"
	return &models.UserInvitation{
		ID:             uuid.New(),
		UserID:         userID,
		TenantID:       tenantID,
		TokenHash:      "sha256hashvalue",
		InvitationType: models.InvitationTypeUserInvite,
		Email:          "user@example.com",
		Status:         models.InvitationStatusPending,
		ExpiresAt:      time.Now().Add(72 * time.Hour).UTC(),
		CustomMessage:  &msg,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
}

func invRow(inv *models.UserInvitation) []interface{} {
	return []interface{}{
		inv.ID, inv.UserID, inv.TenantID, inv.RealmID, inv.TokenHash, inv.InvitationType,
		inv.InvitedByAdminID, inv.InvitedByUserID, inv.Email, inv.EmailSentAt, inv.EmailSendCount,
		inv.LastEmailSentAt, inv.Status, inv.AcceptedAt, inv.AcceptedIP, inv.ExpiresAt, inv.CustomMessage,
		inv.CreatedAt, inv.UpdatedAt,
	}
}

// --- Create ------------------------------------------------------------------

func TestInvitationRepository_Create(t *testing.T) {
	t.Run("success with provided ID", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		inv := newTestInvitation(tenantID)
		now := time.Now().UTC()

		mock.ExpectQuery(`INSERT INTO iam_user_invitations`).
			WithArgs(
				inv.ID, inv.UserID, inv.TenantID, inv.RealmID, inv.TokenHash, inv.InvitationType,
				inv.InvitedByAdminID, inv.InvitedByUserID, inv.Email, inv.ExpiresAt, inv.CustomMessage,
			).
			WillReturnRows(pgxmock.NewRows([]string{"created_at", "updated_at"}).
				AddRow(now, now))

		err := repo.Create(ctx, inv)
		require.NoError(t, err)
		assert.Equal(t, now, inv.CreatedAt)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("generates UUID when nil", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		inv := newTestInvitation(tenantID)
		inv.ID = uuid.Nil
		now := time.Now().UTC()

		// The repo generates a new UUID before inserting, so use AnyArg for the ID.
		mock.ExpectQuery(`INSERT INTO iam_user_invitations`).
			WithArgs(
				pgxmock.AnyArg(), // generated UUID replaces uuid.Nil
				inv.UserID, inv.TenantID, inv.RealmID, inv.TokenHash, inv.InvitationType,
				inv.InvitedByAdminID, inv.InvitedByUserID, inv.Email, inv.ExpiresAt, inv.CustomMessage,
			).
			WillReturnRows(pgxmock.NewRows([]string{"created_at", "updated_at"}).
				AddRow(now, now))

		err := repo.Create(ctx, inv)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, inv.ID)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		inv := newTestInvitation(uuid.New())
		mock.ExpectQuery(`INSERT INTO iam_user_invitations`).
			WithArgs(
				inv.ID, inv.UserID, inv.TenantID, inv.RealmID, inv.TokenHash, inv.InvitationType,
				inv.InvitedByAdminID, inv.InvitedByUserID, inv.Email, inv.ExpiresAt, inv.CustomMessage,
			).
			WillReturnError(errors.New("constraint violation"))

		err := repo.Create(ctx, inv)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// --- GetByID -----------------------------------------------------------------

func TestInvitationRepository_GetByID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		inv := newTestInvitation(uuid.New())
		rows := pgxmock.NewRows(invColumns()).AddRow(invRow(inv)...)

		mock.ExpectQuery(`SELECT .+ FROM iam_user_invitations\s+WHERE id = \$1`).
			WithArgs(inv.ID).
			WillReturnRows(rows)

		got, err := repo.GetByID(ctx, inv.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, inv.ID, got.ID)
		assert.Equal(t, inv.Email, got.Email)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_user_invitations\s+WHERE id = \$1`).
			WithArgs(id).
			WillReturnRows(pgxmock.NewRows(invColumns()))

		got, err := repo.GetByID(ctx, id)
		require.NoError(t, err)
		assert.Nil(t, got)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_user_invitations\s+WHERE id = \$1`).
			WithArgs(id).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetByID(ctx, id)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// --- GetByTokenHash ----------------------------------------------------------

func TestInvitationRepository_GetByTokenHash(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		inv := newTestInvitation(uuid.New())
		rows := pgxmock.NewRows(invColumns()).AddRow(invRow(inv)...)

		mock.ExpectQuery(`SELECT .+ FROM iam_user_invitations\s+WHERE token_hash = \$1`).
			WithArgs(inv.TokenHash).
			WillReturnRows(rows)

		got, err := repo.GetByTokenHash(ctx, inv.TokenHash)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, inv.TokenHash, got.TokenHash)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		mock.ExpectQuery(`SELECT .+ FROM iam_user_invitations\s+WHERE token_hash = \$1`).
			WithArgs("nonexistent-hash").
			WillReturnRows(pgxmock.NewRows(invColumns()))

		got, err := repo.GetByTokenHash(ctx, "nonexistent-hash")
		require.NoError(t, err)
		assert.Nil(t, got)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// --- UpdateStatus ------------------------------------------------------------

func TestInvitationRepository_UpdateStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		status := models.InvitationStatusAccepted

		mock.ExpectExec(`UPDATE iam_user_invitations SET status = \$1`).
			WithArgs(status, id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateStatus(ctx, id, status)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		status := models.InvitationStatusRevoked
		mock.ExpectExec(`UPDATE iam_user_invitations SET status`).
			WithArgs(status, id).
			WillReturnError(errors.New("db error"))

		err := repo.UpdateStatus(ctx, id, status)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// --- MarkAsAccepted ----------------------------------------------------------

func TestInvitationRepository_MarkAsAccepted(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		ip := "192.168.1.100"

		mock.ExpectExec(`UPDATE iam_user_invitations SET status = 'accepted'`).
			WithArgs(ip, id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.MarkAsAccepted(ctx, id, ip)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		ip := testImpersonationIP
		mock.ExpectExec(`UPDATE iam_user_invitations SET status = 'accepted'`).
			WithArgs(ip, id).
			WillReturnError(errors.New("db error"))

		err := repo.MarkAsAccepted(ctx, id, ip)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// --- MarkAsRevoked -----------------------------------------------------------

func TestInvitationRepository_MarkAsRevoked(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()

		mock.ExpectExec(`UPDATE iam_user_invitations SET status = 'revoked'`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.MarkAsRevoked(ctx, id)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_user_invitations SET status = 'revoked'`).
			WithArgs(id).
			WillReturnError(errors.New("db error"))

		err := repo.MarkAsRevoked(ctx, id)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// --- ListByTenantID ----------------------------------------------------------

func TestInvitationRepository_ListByTenantID(t *testing.T) {
	t.Run("returns all invitations without status filter", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		inv1 := newTestInvitation(tenantID)
		inv2 := newTestInvitation(tenantID)
		inv2.Status = models.InvitationStatusAccepted

		rows := pgxmock.NewRows(invColumns()).
			AddRow(invRow(inv1)...).
			AddRow(invRow(inv2)...)

		mock.ExpectQuery(`SELECT .+ FROM iam_user_invitations\s+WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnRows(rows)

		invitations, err := repo.ListByTenantID(ctx, tenantID, nil)
		require.NoError(t, err)
		assert.Len(t, invitations, 2)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("filters by status when provided", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		inv := newTestInvitation(tenantID)
		pending := models.InvitationStatusPending

		rows := pgxmock.NewRows(invColumns()).AddRow(invRow(inv)...)

		mock.ExpectQuery(`SELECT .+ FROM iam_user_invitations\s+WHERE tenant_id = \$1`).
			WithArgs(tenantID, pending).
			WillReturnRows(rows)

		invitations, err := repo.ListByTenantID(ctx, tenantID, &pending)
		require.NoError(t, err)
		assert.Len(t, invitations, 1)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_user_invitations`).
			WithArgs(tenantID).
			WillReturnError(errors.New("db error"))

		_, err := repo.ListByTenantID(ctx, tenantID, nil)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty tenant returns empty slice", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_user_invitations`).
			WithArgs(tenantID).
			WillReturnRows(pgxmock.NewRows(invColumns()))

		invitations, err := repo.ListByTenantID(ctx, tenantID, nil)
		require.NoError(t, err)
		assert.Empty(t, invitations)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// --- ExpireOldInvitations ----------------------------------------------------

func TestInvitationRepository_ExpireOldInvitations(t *testing.T) {
	t.Run("returns count of expired invitations", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		mock.ExpectExec(`UPDATE iam_user_invitations SET status = 'expired'`).
			WillReturnResult(pgxmock.NewResult("UPDATE", 5))

		count, err := repo.ExpireOldInvitations(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(5), count)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		mock.ExpectExec(`UPDATE iam_user_invitations SET status = 'expired'`).
			WillReturnError(errors.New("db error"))

		_, err := repo.ExpireOldInvitations(ctx)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// --- RevokePendingByUserID ---------------------------------------------------

func TestInvitationRepository_RevokePendingByUserID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		mock.ExpectExec(`UPDATE iam_user_invitations SET status = 'revoked'.+ WHERE user_id = \$1`).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 2))

		err := repo.RevokePendingByUserID(ctx, userID)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		mock.ExpectExec(`UPDATE iam_user_invitations SET status = 'revoked'`).
			WithArgs(userID).
			WillReturnError(errors.New("db error"))

		err := repo.RevokePendingByUserID(ctx, userID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// --- UpdateEmailSent ---------------------------------------------------------

func TestInvitationRepository_UpdateEmailSent(t *testing.T) {
	t.Run("success increments email count", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_user_invitations`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateEmailSent(ctx, id)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_user_invitations`).
			WithArgs(id).
			WillReturnError(errors.New("db error"))

		err := repo.UpdateEmailSent(ctx, id)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// --- UpdateTokenHash ---------------------------------------------------------

func TestInvitationRepository_UpdateTokenHash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		newHash := "new-sha256-hash"
		newExpiry := time.Now().Add(24 * time.Hour).UTC()

		mock.ExpectExec(`UPDATE iam_user_invitations SET token_hash`).
			WithArgs(newHash, newExpiry, id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateTokenHash(ctx, id, newHash, newExpiry)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// --- DeleteByID --------------------------------------------------------------

func TestInvitationRepository_DeleteByID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_user_invitations WHERE id = \$1`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.DeleteByID(ctx, id)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newInvRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_user_invitations`).
			WithArgs(id).
			WillReturnError(errors.New("db error"))

		err := repo.DeleteByID(ctx, id)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}
