// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build future_session_repo

package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ──────────────────────────────────────────────────────────────────────────────
// Helper
// ──────────────────────────────────────────────────────────────────────────────

// newSessionRepo creates a SessionRepository backed by a pgxmock pool using
// regexp query matching.
func newSessionRepo(t *testing.T) (*SessionRepository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := NewSessionRepository(mock)
	t.Cleanup(func() { mock.Close() })
	return repo, mock
}

// testSessionColumns mirrors the sessionColumns const so that row slices can
// be built without duplicating the string.
var testSessionColumns = []string{
	"id", "user_id", "session_token_hash",
	"device_info", "ip_address", "user_agent", "location",
	"is_active", "created_at", "last_activity_at", "expires_at",
	"max_expires_at", "ended_at", "end_reason",
	"saml_provider_id", "saml_name_id", "saml_session_index",
}

// sampleSession returns a deterministic test session.
func sampleSession(userID uuid.UUID) *models.Session {
	now := time.Now().UTC().Truncate(time.Second)
	deviceInfo := "Chrome/Linux"
	ip := "127.0.0.1"
	ua := "Mozilla/5.0"
	return &models.Session{
		ID:               uuid.New(),
		UserID:           userID,
		SessionTokenHash: "sessionhash123",
		DeviceInfo:       &deviceInfo,
		IPAddress:        &ip,
		UserAgent:        &ua,
		IsActive:         true,
		CreatedAt:        now,
		LastActivityAt:   now,
		ExpiresAt:        now.Add(24 * time.Hour),
		MaxExpiresAt:     now.Add(30 * 24 * time.Hour),
	}
}

// sessionRow returns the column values for a given session in the same order
// as testSessionColumns.
func sessionRow(s *models.Session) []interface{} {
	return []interface{}{
		s.ID, s.UserID, s.SessionTokenHash,
		s.DeviceInfo, s.IPAddress, s.UserAgent, s.Location,
		s.IsActive, s.CreatedAt, s.LastActivityAt, s.ExpiresAt,
		s.MaxExpiresAt, s.EndedAt, s.EndReason,
		s.SAMLProviderID, s.SAMLNameID, s.SAMLSessionIndex,
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Create
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_Create(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	userID := uuid.New()
	session := sampleSession(userID)

	now := session.CreatedAt

	mock.ExpectQuery(`INSERT INTO iam_sessions`).
		WithArgs(
			pgxmock.AnyArg(), // id
			session.UserID,
			session.SessionTokenHash,
			session.DeviceInfo,
			session.IPAddress,
			session.UserAgent,
			session.Location,
			session.ExpiresAt,
			pgxmock.AnyArg(), // max_expires_at (auto-set if zero)
			session.SAMLProviderID,
			session.SAMLNameID,
			session.SAMLSessionIndex,
		).
		WillReturnRows(pgxmock.NewRows([]string{"created_at", "last_activity_at"}).
			AddRow(now, now))

	err := repo.Create(ctx, session)
	require.NoError(t, err)
	assert.Equal(t, now, session.CreatedAt)
	assert.Equal(t, now, session.LastActivityAt)
	assert.NotEqual(t, uuid.Nil, session.ID)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// GetByID
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_GetByID_Found(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	userID := uuid.New()
	session := sampleSession(userID)

	mock.ExpectQuery(`SELECT .+ FROM iam_sessions WHERE id = \$1`).
		WithArgs(session.ID).
		WillReturnRows(pgxmock.NewRows(testSessionColumns).
			AddRow(sessionRow(session)...))

	got, err := repo.GetByID(ctx, session.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, session.UserID, got.UserID)
	assert.Equal(t, session.SessionTokenHash, got.SessionTokenHash)
	assert.True(t, got.IsActive)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSessionRepository_GetByID_NotFound(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	mock.ExpectQuery(`SELECT .+ FROM iam_sessions WHERE id = \$1`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(testSessionColumns))

	got, err := repo.GetByID(ctx, uuid.New())
	require.NoError(t, err)
	assert.Nil(t, got)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// GetByTokenHash
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_GetByTokenHash_Found(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	userID := uuid.New()
	session := sampleSession(userID)

	mock.ExpectQuery(`SELECT .+ FROM iam_sessions WHERE session_token_hash = \$1`).
		WithArgs(session.SessionTokenHash).
		WillReturnRows(pgxmock.NewRows(testSessionColumns).
			AddRow(sessionRow(session)...))

	got, err := repo.GetByTokenHash(ctx, session.SessionTokenHash)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, session.ID, got.ID)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSessionRepository_GetByTokenHash_NotFound(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	mock.ExpectQuery(`SELECT .+ FROM iam_sessions WHERE session_token_hash = \$1`).
		WithArgs("notarealthash").
		WillReturnRows(pgxmock.NewRows(testSessionColumns))

	got, err := repo.GetByTokenHash(ctx, "notarealthash")
	require.NoError(t, err)
	assert.Nil(t, got)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// GetActiveSessions
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_GetActiveSessions_Multiple(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	userID := uuid.New()
	s1 := sampleSession(userID)
	s2 := sampleSession(userID)

	mock.ExpectQuery(`SELECT .+ FROM iam_sessions.+WHERE user_id = \$1 AND is_active = true`).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows(testSessionColumns).
			AddRow(sessionRow(s1)...).
			AddRow(sessionRow(s2)...))

	sessions, err := repo.GetActiveSessions(ctx, userID)
	require.NoError(t, err)
	require.Len(t, sessions, 2)
	assert.Equal(t, s1.ID, sessions[0].ID)
	assert.Equal(t, s2.ID, sessions[1].ID)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSessionRepository_GetActiveSessions_Empty(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	userID := uuid.New()

	mock.ExpectQuery(`SELECT .+ FROM iam_sessions.+WHERE user_id = \$1 AND is_active = true`).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows(testSessionColumns))

	sessions, err := repo.GetActiveSessions(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, sessions)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// EndSession
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_EndSession_Success(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	sessionID := uuid.New()
	reason := "logout"

	mock.ExpectExec(`UPDATE iam_sessions SET is_active = false, ended_at = NOW\(\), end_reason`).
		WithArgs(sessionID, reason).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.EndSession(ctx, sessionID, reason)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSessionRepository_EndSession_AlreadyEnded(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	sessionID := uuid.New()
	reason := "logout"

	// RowsAffected = 0 triggers the "not found or already ended" error.
	mock.ExpectExec(`UPDATE iam_sessions SET is_active = false, ended_at = NOW\(\), end_reason`).
		WithArgs(sessionID, reason).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := repo.EndSession(ctx, sessionID, reason)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found or already ended")

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// EndAllUserSessions
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_EndAllUserSessions(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	userID := uuid.New()
	reason := "account_disabled"

	mock.ExpectExec(`UPDATE iam_sessions SET is_active = false, ended_at = NOW\(\), end_reason`).
		WithArgs(userID, reason).
		WillReturnResult(pgxmock.NewResult("UPDATE", 3))

	err := repo.EndAllUserSessions(ctx, userID, reason)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// EndAllUserSessionsExcept
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_EndAllUserSessionsExcept(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	userID := uuid.New()
	exceptID := uuid.New()
	reason := "logout_others"

	mock.ExpectExec(`UPDATE iam_sessions SET is_active = false, ended_at = NOW\(\), end_reason`).
		WithArgs(userID, exceptID, reason).
		WillReturnResult(pgxmock.NewResult("UPDATE", 2))

	err := repo.EndAllUserSessionsExcept(ctx, userID, exceptID, reason)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// UpdateLastActivity
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_UpdateLastActivity(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	sessionID := uuid.New()
	idleTimeout := 8 * time.Hour

	mock.ExpectExec(`UPDATE iam_sessions`).
		WithArgs(sessionID, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.UpdateLastActivity(ctx, sessionID, idleTimeout)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// CountActiveSessions
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_CountActiveSessions(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	userID := uuid.New()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_sessions WHERE user_id = \$1 AND is_active = true`).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(4))

	count, err := repo.CountActiveSessions(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, 4, count)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// CleanupExpiredSessions
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_CleanupExpiredSessions(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	mock.ExpectExec(`UPDATE iam_sessions`).
		WillReturnResult(pgxmock.NewResult("UPDATE", 7))

	n, err := repo.CleanupExpiredSessions(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(7), n)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// DeleteOldSessions
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_DeleteOldSessions(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)

	mock.ExpectExec(`DELETE FROM iam_sessions WHERE is_active = false AND ended_at < \$1`).
		WithArgs(cutoff).
		WillReturnResult(pgxmock.NewResult("DELETE", 50))

	n, err := repo.DeleteOldSessions(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(50), n)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// CleanupStaleSessions
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_CleanupStaleSessions(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	timeout := 30 * time.Minute

	mock.ExpectExec(`UPDATE iam_sessions.+WHERE is_active = true AND last_activity_at < \$1`).
		WithArgs(pgxmock.AnyArg()). // threshold is computed from time.Now() inside the method
		WillReturnResult(pgxmock.NewResult("UPDATE", 2))

	n, err := repo.CleanupStaleSessions(ctx, timeout)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// GetLoginHistory
// ──────────────────────────────────────────────────────────────────────────────

func TestSessionRepository_GetLoginHistory(t *testing.T) {
	ctx := context.Background()
	repo, mock := newSessionRepo(t)

	userID := uuid.New()
	s := sampleSession(userID)

	// COUNT query
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_sessions WHERE user_id = \$1`).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(1)))

	// Paginated SELECT query
	mock.ExpectQuery(`SELECT .+ FROM iam_sessions.+WHERE user_id = \$1`).
		WithArgs(userID, 10, 0).
		WillReturnRows(pgxmock.NewRows(testSessionColumns).
			AddRow(sessionRow(s)...))

	sessions, total, err := repo.GetLoginHistory(ctx, userID, 1, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, sessions, 1)
	assert.Equal(t, s.ID, sessions[0].ID)

	require.NoError(t, mock.ExpectationsWereMet())
}
