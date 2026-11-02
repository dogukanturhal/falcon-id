// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSweepSessionRepo(t *testing.T) (*SessionRepository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	t.Cleanup(mock.Close)
	return &SessionRepository{db: mock}, mock
}

// EndSession on a session that is already ended (0 rows ended) is not an error
// and still runs the token sweep for that id (idempotent retry of a logout).
func TestSessionRepository_EndSession_IdempotentStillSweeps(t *testing.T) {
	repo, mock := newSweepSessionRepo(t)
	id := uuid.New()
	mock.ExpectQuery(`(?s)WITH ended AS \(UPDATE iam_sessions.*end_reason IN \('expired'.*RETURNING id, user_id\), ids AS \(SELECT id, user_id FROM ended UNION SELECT id, user_id FROM iam_sessions WHERE id = \$1::uuid\), agg AS .*swept AS \(\s*UPDATE iam_oauth_tokens`).
		WithArgs(id, "logout").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(0)))

	require.NoError(t, repo.EndSession(context.Background(), id, "logout"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// Every bulk end path (SAML SLO and inbound back-channel logout go through
// these) sweeps the tokens in the same statement for an explicit reason...
func TestSessionRepository_BulkEnds_SweepTokensForExplicitReason(t *testing.T) {
	repo, mock := newSweepSessionRepo(t)
	user, except := uuid.New(), uuid.New()
	rows := func() *pgxmock.Rows { return pgxmock.NewRows([]string{"count"}).AddRow(int64(2)) }

	mock.ExpectQuery(`(?s)WITH ended AS .*swept AS \(\s*UPDATE iam_oauth_tokens`).WithArgs(user, "backchannel_logout").WillReturnRows(rows())
	require.NoError(t, repo.EndAllUserSessions(context.Background(), user, "backchannel_logout"))

	mock.ExpectQuery(`(?s)WITH ended AS .*swept AS \(\s*UPDATE iam_oauth_tokens`).WithArgs(user, except, "password_change").WillReturnRows(rows())
	require.NoError(t, repo.EndAllUserSessionsExcept(context.Background(), user, except, "password_change"))

	tenant := uuid.New()
	mock.ExpectQuery(`(?s)WITH ended AS .*swept AS \(\s*UPDATE iam_oauth_tokens`).WithArgs(user, tenant, "revoked").WillReturnRows(rows())
	n, err := repo.RevokeTenantSessions(context.Background(), user, tenant, "revoked")
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ...and never for a lapse (idle/absolute expiry keeps refresh tokens alive).
func TestSessionRepository_LapseDoesNotSweepTokens(t *testing.T) {
	repo, mock := newSweepSessionRepo(t)
	user := uuid.New()
	mock.ExpectQuery(`^WITH ended AS \(UPDATE iam_sessions [^;]*\) SELECT count\(\*\) FROM ended$`).
		WithArgs(user, "inactivity_timeout").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(1)))
	require.NoError(t, repo.EndAllUserSessions(context.Background(), user, "inactivity_timeout"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOAuthClientRepository_RevokeTokensBySession_NilUUIDIsNoop(t *testing.T) {
	mock, repo := newOAuthClientMock(t)
	defer mock.Close()
	n, err := repo.RevokeTokensBySession(context.Background(), uuid.Nil, uuid.New())
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.NoError(t, mock.ExpectationsWereMet())
}
