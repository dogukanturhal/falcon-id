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
	testImpersonationIP = "10.0.0.1"
	testImpersonationUA = "Mozilla/5.0"
)

func newImpersonationMock(t *testing.T) (pgxmock.PgxPoolIface, *ImpersonationRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newImpersonationRepositoryWithMock(mock)
}

var impersonationCols = []string{
	"id", "tenant_id", "admin_user_id", "target_user_id", "reason",
	"ip_address", "user_agent", "started_at", "ended_at",
	"original_session_id", "impersonation_session_id", "created_at",
}

func sampleImpersonationSession() *models.ImpersonationSession {
	ip := testImpersonationIP
	ua := testImpersonationUA
	origSessionID := uuid.New()
	impSessionID := uuid.New()
	return &models.ImpersonationSession{
		ID:                     uuid.New(),
		TenantID:               uuid.New(),
		AdminUserID:            uuid.New(),
		TargetUserID:           uuid.New(),
		Reason:                 "support ticket #123",
		IPAddress:              &ip,
		UserAgent:              &ua,
		StartedAt:              time.Now(),
		OriginalSessionID:      &origSessionID,
		ImpersonationSessionID: &impSessionID,
		CreatedAt:              time.Now(),
	}
}

func TestImpersonationRepository_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		session := sampleImpersonationSession()
		mock.ExpectExec(`INSERT INTO iam_impersonation_sessions`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.Create(context.Background(), session)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		session := sampleImpersonationSession()
		mock.ExpectExec(`INSERT INTO iam_impersonation_sessions`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnError(fmt.Errorf("unique constraint violation"))

		err := repo.Create(context.Background(), session)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestImpersonationRepository_GetByID(t *testing.T) {
	now := time.Now()
	session := sampleImpersonationSession()

	t.Run("found", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		rows := mock.NewRows(impersonationCols).AddRow(
			session.ID, session.TenantID, session.AdminUserID, session.TargetUserID,
			session.Reason, session.IPAddress, session.UserAgent, now, nil,
			session.OriginalSessionID, session.ImpersonationSessionID, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(session.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), session.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, session.ID, got.ID)
		assert.Equal(t, session.Reason, got.Reason)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WithArgs(session.ID).WillReturnError(fmt.Errorf("connection refused"))

		got, err := repo.GetByID(context.Background(), session.ID)
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestImpersonationRepository_GetActiveByAdminID(t *testing.T) {
	now := time.Now()
	session := sampleImpersonationSession()

	t.Run("active session found", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		rows := mock.NewRows(impersonationCols).AddRow(
			session.ID, session.TenantID, session.AdminUserID, session.TargetUserID,
			session.Reason, session.IPAddress, session.UserAgent, now, nil,
			session.OriginalSessionID, session.ImpersonationSessionID, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(session.AdminUserID).WillReturnRows(rows)

		got, err := repo.GetActiveByAdminID(context.Background(), session.AdminUserID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, session.AdminUserID, got.AdminUserID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestImpersonationRepository_EndSession(t *testing.T) {
	sessionID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_impersonation_sessions`).
			WithArgs(pgxmock.AnyArg(), sessionID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.EndSession(context.Background(), sessionID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found or already ended", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_impersonation_sessions`).
			WithArgs(pgxmock.AnyArg(), sessionID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.EndSession(context.Background(), sessionID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already ended")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_impersonation_sessions`).
			WithArgs(pgxmock.AnyArg(), sessionID).
			WillReturnError(fmt.Errorf("deadlock"))

		err := repo.EndSession(context.Background(), sessionID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestImpersonationRepository_UpdateImpersonationSessionID(t *testing.T) {
	sessionID := uuid.New()
	newSessionID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_impersonation_sessions`).
			WithArgs(newSessionID, sessionID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateImpersonationSessionID(context.Background(), sessionID, newSessionID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestImpersonationRepository_MarkSessionAsImpersonation(t *testing.T) {
	sessionID := uuid.New()
	impersonatorID := uuid.New()
	impersonationSessionID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_sessions`).
			WithArgs(impersonatorID, impersonationSessionID, sessionID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.MarkSessionAsImpersonation(context.Background(), sessionID, impersonatorID, impersonationSessionID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestImpersonationRepository_ClearSessionImpersonation(t *testing.T) {
	sessionID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_sessions`).
			WithArgs(sessionID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.ClearSessionImpersonation(context.Background(), sessionID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestImpersonationRepository_GetSessionImpersonationStatus(t *testing.T) {
	sessionID := uuid.New()
	impersonatorID := uuid.New()
	impersonationSessionID := uuid.New()

	t.Run("has impersonation", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"impersonator_id", "impersonation_session_id"}).
			AddRow(&impersonatorID, &impersonationSessionID)
		mock.ExpectQuery(`SELECT impersonator_id`).WithArgs(sessionID).WillReturnRows(rows)

		gotImpersonatorID, gotImpSessionID, err := repo.GetSessionImpersonationStatus(context.Background(), sessionID)
		require.NoError(t, err)
		require.NotNil(t, gotImpersonatorID)
		require.NotNil(t, gotImpSessionID)
		assert.Equal(t, impersonatorID, *gotImpersonatorID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no impersonation (nulls)", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"impersonator_id", "impersonation_session_id"}).
			AddRow(nil, nil)
		mock.ExpectQuery(`SELECT impersonator_id`).WithArgs(sessionID).WillReturnRows(rows)

		gotImpersonatorID, gotImpSessionID, err := repo.GetSessionImpersonationStatus(context.Background(), sessionID)
		require.NoError(t, err)
		assert.Nil(t, gotImpersonatorID)
		assert.Nil(t, gotImpSessionID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestImpersonationRepository_List(t *testing.T) {
	now := time.Now()
	tenantID := uuid.New()
	session := sampleImpersonationSession()
	session.TenantID = tenantID

	t.Run("list without filters", func(t *testing.T) {
		mock, repo := newImpersonationMock(t)
		defer mock.Close()

		// Expect count query
		countRows := mock.NewRows([]string{"count"}).AddRow(1)
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(tenantID).WillReturnRows(countRows)

		// Expect list query
		listRows := mock.NewRows(impersonationCols).AddRow(
			session.ID, tenantID, session.AdminUserID, session.TargetUserID,
			session.Reason, session.IPAddress, session.UserAgent, now, nil,
			session.OriginalSessionID, session.ImpersonationSessionID, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID, 10, 0).WillReturnRows(listRows)

		sessions, total, err := repo.List(context.Background(), tenantID, 1, 10, nil, nil, false)
		require.NoError(t, err)
		assert.Equal(t, 1, total)
		assert.Len(t, sessions, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
