// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func newRealmMock(t *testing.T) (pgxmock.PgxPoolIface, *RealmRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newRealmRepositoryWithMock(mock)
}

var realmCols = []string{
	"id", "slug", "display_name", "type", "status",
	"database_connection_id", "schema_name", "settings", "branding", "features",
	"max_tenants", "max_users_per_tenant", "max_total_users",
	"created_at", "updated_at", "created_by", "tenant_count", "user_count",
}

func sampleRealm() *models.Realm {
	settings := json.RawMessage(`{}`)
	branding := json.RawMessage(`{}`)
	features := json.RawMessage(`{}`)
	return &models.Realm{
		ID:          uuid.New(),
		Slug:        "test-realm",
		DisplayName: "Test Realm",
		Type:        models.RealmTypeShared,
		Status:      models.RealmStatusActive,
		Settings:    settings,
		Branding:    branding,
		Features:    features,
	}
}

func TestRealmRepository_Create(t *testing.T) {
	now := time.Now()

	t.Run("success", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		realm := sampleRealm()
		rows := mock.NewRows([]string{"created_at", "updated_at"}).AddRow(now, now)
		mock.ExpectQuery(`INSERT INTO realms`).
			WithArgs(
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), realm)
		assert.NoError(t, err)
		assert.Equal(t, now, realm.CreatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("slug already exists", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		realm := sampleRealm()
		mock.ExpectQuery(`INSERT INTO realms`).
			WithArgs(
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			).
			WillReturnError(fmt.Errorf("ERROR: duplicate key value violates unique constraint \"realms_slug_key\""))

		err := repo.Create(context.Background(), realm)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRealmRepository_GetByID(t *testing.T) {
	now := time.Now()
	realm := sampleRealm()

	t.Run("found", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		rows := mock.NewRows(realmCols).AddRow(
			realm.ID, realm.Slug, realm.DisplayName, realm.Type, realm.Status,
			nil, nil, realm.Settings, realm.Branding, realm.Features,
			nil, nil, nil,
			now, now, nil, int64(0), int64(0),
		)
		mock.ExpectQuery(`SELECT`).WithArgs(realm.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), realm.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, realm.ID, got.ID)
		assert.Equal(t, realm.Slug, got.Slug)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		rows := mock.NewRows(realmCols)
		mock.ExpectQuery(`SELECT`).WithArgs(realm.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), realm.ID)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRealmRepository_GetBySlug(t *testing.T) {
	now := time.Now()
	realm := sampleRealm()

	t.Run("found", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		rows := mock.NewRows(realmCols).AddRow(
			realm.ID, realm.Slug, realm.DisplayName, realm.Type, realm.Status,
			nil, nil, realm.Settings, realm.Branding, realm.Features,
			nil, nil, nil,
			now, now, nil, int64(0), int64(0),
		)
		mock.ExpectQuery(`SELECT`).WithArgs(realm.Slug).WillReturnRows(rows)

		got, err := repo.GetBySlug(context.Background(), realm.Slug)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, realm.Slug, got.Slug)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		rows := mock.NewRows(realmCols)
		mock.ExpectQuery(`SELECT`).WithArgs(realm.Slug).WillReturnRows(rows)

		got, err := repo.GetBySlug(context.Background(), realm.Slug)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRealmRepository_Update(t *testing.T) {
	now := time.Now()
	realm := sampleRealm()

	t.Run("success", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"updated_at"}).AddRow(now)
		mock.ExpectQuery(`UPDATE realms`).
			WithArgs(
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			).
			WillReturnRows(rows)

		err := repo.Update(context.Background(), realm)
		assert.NoError(t, err)
		assert.Equal(t, now, realm.UpdatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"updated_at"})
		mock.ExpectQuery(`UPDATE realms`).
			WithArgs(
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			).
			WillReturnRows(rows)

		err := repo.Update(context.Background(), realm)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRealmRepository_UpdateStatus(t *testing.T) {
	realmID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE realms SET status`).
			WithArgs(realmID, pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateStatus(context.Background(), realmID, models.RealmStatusSuspended)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE realms SET status`).
			WithArgs(realmID, pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.UpdateStatus(context.Background(), realmID, models.RealmStatusSuspended)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "realm not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRealmRepository_Delete(t *testing.T) {
	realmID := uuid.New()

	t.Run("archives realm", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE realms SET status`).
			WithArgs(realmID, pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.Delete(context.Background(), realmID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRealmRepository_List(t *testing.T) {
	now := time.Now()
	realm := sampleRealm()

	t.Run("list active realms", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		// Count query — no args when no filters applied (default WHERE excludes archived)
		countRows := mock.NewRows([]string{"count"}).AddRow(int64(1))
		mock.ExpectQuery(`SELECT COUNT`).WillReturnRows(countRows)

		// List query — args: pageSize, offset
		listRows := mock.NewRows(realmCols).AddRow(
			realm.ID, realm.Slug, realm.DisplayName, realm.Type, realm.Status,
			nil, nil, realm.Settings, realm.Branding, realm.Features,
			nil, nil, nil,
			now, now, nil, int64(0), int64(0),
		)
		mock.ExpectQuery(`SELECT`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(listRows)

		filters := RealmFilters{Page: 1, PageSize: 10}
		realms, total, err := repo.List(context.Background(), filters)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, realms, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRealmRepository_CreateSecurityPolicy(t *testing.T) {
	now := time.Now()
	policyID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		policy := &models.RealmSecurityPolicy{
			RealmID: uuid.New(),
		}

		rows := mock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(policyID, now, now)
		mock.ExpectQuery(`INSERT INTO realm_security_policies`).
			WithArgs(policy.RealmID).
			WillReturnRows(rows)

		err := repo.CreateSecurityPolicy(context.Background(), policy)
		assert.NoError(t, err)
		assert.Equal(t, policyID, policy.ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRealmRepository_DeleteIdentityProvider(t *testing.T) {
	idpID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM realm_identity_providers`).
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.DeleteIdentityProvider(context.Background(), idpID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newRealmMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM realm_identity_providers`).
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.DeleteIdentityProvider(context.Background(), idpID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
