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

// ─── MarkAuthorizationCodeUsedCAS ────────────────────────────────────────────
// The compare-and-swap that guarantees single-use while remaining rollback-able
// (2026-07-21 OAuth migration-gap remediation, Fix B).

func TestOAuthClientRepository_MarkAuthorizationCodeUsedCAS(t *testing.T) {
	t.Run("wins when the row is still unused (1 row affected)", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()
		id := uuid.New()

		mock.ExpectExec("UPDATE iam_oauth_authorization_codes SET is_used = true").
			WithArgs(pgxmock.AnyArg(), id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		won, err := repo.MarkAuthorizationCodeUsedCAS(context.Background(), id)
		require.NoError(t, err)
		assert.True(t, won, "the caller that flips is_used false→true wins the CAS")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("loses when the row is already used (0 rows affected)", func(t *testing.T) {
		mock, repo := newOAuthClientMock(t)
		defer mock.Close()
		id := uuid.New()

		mock.ExpectExec("UPDATE iam_oauth_authorization_codes SET is_used = true").
			WithArgs(pgxmock.AnyArg(), id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		won, err := repo.MarkAuthorizationCodeUsedCAS(context.Background(), id)
		require.NoError(t, err)
		assert.False(t, won, "a concurrent redemption that already consumed the code loses the CAS")
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── BeginTx rollback ────────────────────────────────────────────────────────
// A CAS-marked code inside a transaction that is rolled back (the token write
// failed downstream) must never reach COMMIT — so the mark-used is discarded and
// the code stays usable.

func TestOAuthClientRepository_BeginTx_RollbackDiscardsMarkUsed(t *testing.T) {
	mock, repo := newOAuthClientMock(t)
	defer mock.Close()
	id := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE iam_oauth_authorization_codes SET is_used = true").
		WithArgs(pgxmock.AnyArg(), id).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectRollback()

	tx, err := repo.BeginTx(context.Background())
	require.NoError(t, err)

	won, err := tx.MarkAuthorizationCodeUsedCAS(context.Background(), id)
	require.NoError(t, err)
	assert.True(t, won)

	// Simulate a downstream token-generation failure: roll back rather than
	// commit. No COMMIT is ever issued, so the mark-used never lands.
	require.NoError(t, tx.Rollback(context.Background()))
	require.NoError(t, mock.ExpectationsWereMet())
}
