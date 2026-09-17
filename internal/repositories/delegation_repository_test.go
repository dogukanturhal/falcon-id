// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func newDelegationMock(t *testing.T) (pgxmock.PgxPoolIface, *DelegationRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newDelegationRepositoryWithMock(mock)
}

var delegationCols = []string{
	"id", "tenant_id", "delegator_id", "delegatee_id", "permissions",
	"resource_type", "resource_id", "expires_at", "reason",
	"revoked_at", "revoked_by", "created_at", "updated_at",
}

func sampleDelegation() *models.Delegation {
	reason := "vacation cover"
	resourceType := "reports"
	return &models.Delegation{
		ID:           uuid.New(),
		TenantID:     uuid.New(),
		DelegatorID:  uuid.New(),
		DelegateeID:  uuid.New(),
		Permissions:  pq.StringArray{"read", "write"},
		ResourceType: &resourceType,
		Reason:       &reason,
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}
}

func TestDelegationRepository_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		d := sampleDelegation()
		mock.ExpectExec(`INSERT INTO iam_delegations`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.Create(context.Background(), d)
		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, d.ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		d := sampleDelegation()
		mock.ExpectExec(`INSERT INTO iam_delegations`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnError(fmt.Errorf("unique constraint violated"))

		err := repo.Create(context.Background(), d)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDelegationRepository_GetByID(t *testing.T) {
	now := time.Now()
	d := sampleDelegation()

	t.Run("found", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		rows := mock.NewRows(delegationCols).AddRow(
			d.ID, d.TenantID, d.DelegatorID, d.DelegateeID, d.Permissions,
			d.ResourceType, d.ResourceID, d.ExpiresAt, d.Reason,
			nil, nil, now, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(d.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), d.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, d.ID, got.ID)
		assert.Equal(t, d.DelegatorID, got.DelegatorID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		rows := mock.NewRows(delegationCols)
		mock.ExpectQuery(`SELECT`).WithArgs(d.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), d.ID)
		assert.Error(t, err) // returns error on not found
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDelegationRepository_Revoke(t *testing.T) {
	delegationID := uuid.New()
	revokerID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_delegations`).
			WithArgs(pgxmock.AnyArg(), revokerID, delegationID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.Revoke(context.Background(), delegationID, revokerID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found or already revoked", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_delegations`).
			WithArgs(pgxmock.AnyArg(), revokerID, delegationID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.Revoke(context.Background(), delegationID, revokerID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "revoked")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_delegations`).
			WithArgs(pgxmock.AnyArg(), revokerID, delegationID).
			WillReturnError(fmt.Errorf("lock timeout"))

		err := repo.Revoke(context.Background(), delegationID, revokerID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDelegationRepository_ListByDelegator(t *testing.T) {
	now := time.Now()
	d := sampleDelegation()

	t.Run("active only", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		rows := mock.NewRows(delegationCols).AddRow(
			d.ID, d.TenantID, d.DelegatorID, d.DelegateeID, d.Permissions,
			d.ResourceType, d.ResourceID, d.ExpiresAt, d.Reason,
			nil, nil, now, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(d.DelegatorID).WillReturnRows(rows)

		delegations, err := repo.ListByDelegator(context.Background(), d.DelegatorID, false)
		require.NoError(t, err)
		assert.Len(t, delegations, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("including revoked", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		rows := mock.NewRows(delegationCols).AddRow(
			d.ID, d.TenantID, d.DelegatorID, d.DelegateeID, d.Permissions,
			d.ResourceType, d.ResourceID, d.ExpiresAt, d.Reason,
			nil, nil, now, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(d.DelegatorID).WillReturnRows(rows)

		delegations, err := repo.ListByDelegator(context.Background(), d.DelegatorID, true)
		require.NoError(t, err)
		assert.Len(t, delegations, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDelegationRepository_ListByDelegatee(t *testing.T) {
	now := time.Now()
	d := sampleDelegation()

	t.Run("active delegations for delegatee", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		rows := mock.NewRows(delegationCols).AddRow(
			d.ID, d.TenantID, d.DelegatorID, d.DelegateeID, d.Permissions,
			d.ResourceType, d.ResourceID, d.ExpiresAt, d.Reason,
			nil, nil, now, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(d.DelegateeID).WillReturnRows(rows)

		delegations, err := repo.ListByDelegatee(context.Background(), d.DelegateeID, false)
		require.NoError(t, err)
		assert.Len(t, delegations, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDelegationRepository_GetActiveDelegationsForUser(t *testing.T) {
	now := time.Now()
	d := sampleDelegation()

	t.Run("active delegations", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		rows := mock.NewRows(delegationCols).AddRow(
			d.ID, d.TenantID, d.DelegatorID, d.DelegateeID, d.Permissions,
			d.ResourceType, d.ResourceID, d.ExpiresAt, d.Reason,
			nil, nil, now, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(d.DelegateeID).WillReturnRows(rows)

		delegations, err := repo.GetActiveDelegationsForUser(context.Background(), d.DelegateeID)
		require.NoError(t, err)
		assert.Len(t, delegations, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty result", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		rows := mock.NewRows(delegationCols)
		mock.ExpectQuery(`SELECT`).WithArgs(d.DelegateeID).WillReturnRows(rows)

		delegations, err := repo.GetActiveDelegationsForUser(context.Background(), d.DelegateeID)
		assert.NoError(t, err)
		assert.Len(t, delegations, 0)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDelegationRepository_CleanupExpired(t *testing.T) {
	t.Run("rows deleted", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_delegations`).
			WithArgs(30).
			WillReturnResult(pgxmock.NewResult("DELETE", 5))

		count, err := repo.CleanupExpired(context.Background(), 30)
		assert.NoError(t, err)
		assert.Equal(t, int64(5), count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newDelegationMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_delegations`).
			WithArgs(30).
			WillReturnError(fmt.Errorf("timeout"))

		_, err := repo.CleanupExpired(context.Background(), 30)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
