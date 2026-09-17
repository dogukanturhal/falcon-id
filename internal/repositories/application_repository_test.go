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

// ─── helpers ─────────────────────────────────────────────────────────────────

func newApplicationRepoMock(t *testing.T) (pgxmock.PgxPoolIface, *ApplicationRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newApplicationRepositoryWithMock(mock)
}

// applicationScanCols mirrors applicationColumns exactly (35 columns).
var applicationScanCols = []string{
	"id", "display_name", "slug", "description", "logo_url", "homepage_url",
	"privacy_policy_url", "terms_of_service_url", "app_type", "publisher_type", "is_platform_app",
	"sign_in_audience", "redirect_uris", "post_logout_uris", "allowed_grant_types", "default_scopes",
	"access_token_lifetime", "refresh_token_lifetime", "id_token_lifetime",
	"is_public", "require_pkce", "preauthorized", "status", "tags", "metadata",
	"publisher_verified", "publisher_verified_at", "publisher_domain",
	"created_by", "created_at", "updated_at", "deleted_at", "purge_after",
	"stale_since", "last_sign_in_at",
}

func sampleApplication() *models.Application {
	now := time.Now()
	return &models.Application{
		ID:                   uuid.New(),
		DisplayName:          "Test Application",
		Slug:                 "test-app",
		Description:          "A test application",
		AppType:              models.ApplicationAppTypeWeb,
		PublisherType:        models.ApplicationPublisherFirstParty,
		IsPlatformApp:        false,
		SignInAudience:       "single_tenant",
		RedirectURIs:         []string{"https://example.com/callback"},
		PostLogoutURIs:       []string{"https://example.com/logout"},
		AllowedGrantTypes:    []string{"authorization_code"},
		DefaultScopes:        []string{"openid", "profile"},
		AccessTokenLifetime:  3600,
		RefreshTokenLifetime: 86400,
		IDTokenLifetime:      3600,
		IsPublic:             false,
		RequirePKCE:          true,
		Preauthorized:        false,
		Status:               models.ApplicationStatusActive,
		Tags:                 []string{"web", "saas"},
		Metadata:             []byte("{}"),
		PublisherVerified:    false,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
}

func appRow(app *models.Application) []interface{} {
	return []interface{}{
		app.ID, app.DisplayName, app.Slug, app.Description,
		app.LogoURL, app.HomepageURL, app.PrivacyPolicyURL, app.TermsOfServiceURL,
		app.AppType, app.PublisherType, app.IsPlatformApp,
		app.SignInAudience, app.RedirectURIs, app.PostLogoutURIs,
		app.AllowedGrantTypes, app.DefaultScopes,
		app.AccessTokenLifetime, app.RefreshTokenLifetime, app.IDTokenLifetime,
		app.IsPublic, app.RequirePKCE, app.Preauthorized,
		app.Status, app.Tags, app.Metadata,
		app.PublisherVerified, app.PublisherVerifiedAt, app.PublisherDomain,
		app.CreatedBy, app.CreatedAt, app.UpdatedAt,
		app.DeletedAt, app.PurgeAfter,
		app.StaleSince, app.LastSignInAt,
	}
}

// ─── Create ──────────────────────────────────────────────────────────────────

func TestApplicationRepository_Create(t *testing.T) {
	now := time.Now()

	t.Run("success assigns timestamps", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		app := sampleApplication()
		rows := mock.NewRows([]string{"created_at", "updated_at"}).AddRow(now, now)
		// INSERT has 31 positional args
		mock.ExpectQuery(`INSERT INTO iam_applications`).
			WithArgs(anyArgs(31)...).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), app)
		require.NoError(t, err)
		assert.Equal(t, now, app.CreatedAt)
		assert.Equal(t, now, app.UpdatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("auto-assigns UUID when nil", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		app := sampleApplication()
		app.ID = uuid.Nil

		rows := mock.NewRows([]string{"created_at", "updated_at"}).AddRow(now, now)
		mock.ExpectQuery(`INSERT INTO iam_applications`).
			WithArgs(anyArgs(31)...).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), app)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, app.ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		app := sampleApplication()
		mock.ExpectQuery(`INSERT INTO iam_applications`).
			WithArgs(anyArgs(31)...).
			WillReturnError(fmt.Errorf("unique violation on slug"))

		err := repo.Create(context.Background(), app)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByID ─────────────────────────────────────────────────────────────────

func TestApplicationRepository_GetByID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		app := sampleApplication()
		rows := mock.NewRows(applicationScanCols).AddRow(appRow(app)...)
		mock.ExpectQuery(`SELECT`).WithArgs(app.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), app.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, app.ID, got.ID)
		assert.Equal(t, app.DisplayName, got.DisplayName)
		assert.Equal(t, app.Slug, got.Slug)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(id).WillReturnRows(mock.NewRows(applicationScanCols))

		got, err := repo.GetByID(context.Background(), id)
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByIDIncludeDeleted ───────────────────────────────────────────────────

func TestApplicationRepository_GetByIDIncludeDeleted(t *testing.T) {
	t.Run("returns soft-deleted app", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		app := sampleApplication()
		now := time.Now()
		app.DeletedAt = &now

		rows := mock.NewRows(applicationScanCols).AddRow(appRow(app)...)
		mock.ExpectQuery(`SELECT`).WithArgs(app.ID).WillReturnRows(rows)

		got, err := repo.GetByIDIncludeDeleted(context.Background(), app.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.NotNil(t, got.DeletedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetBySlug ───────────────────────────────────────────────────────────────

func TestApplicationRepository_GetBySlug(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		app := sampleApplication()
		rows := mock.NewRows(applicationScanCols).AddRow(appRow(app)...)
		mock.ExpectQuery(`SELECT`).WithArgs(app.Slug).WillReturnRows(rows)

		got, err := repo.GetBySlug(context.Background(), app.Slug)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, app.Slug, got.Slug)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WithArgs("nonexistent-slug").WillReturnRows(mock.NewRows(applicationScanCols))

		got, err := repo.GetBySlug(context.Background(), "nonexistent-slug")
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── List ────────────────────────────────────────────────────────────────────

func TestApplicationRepository_List(t *testing.T) {
	t.Run("returns apps with total and no filters", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		app1 := sampleApplication()
		app2 := sampleApplication()
		app2.ID = uuid.New()
		app2.Slug = "test-app-2"

		// No filter args for COUNT; LIMIT + OFFSET for SELECT
		mock.ExpectQuery(`SELECT COUNT`).WillReturnRows(mock.NewRows([]string{"count"}).AddRow(int64(2)))
		rows := mock.NewRows(applicationScanCols).
			AddRow(appRow(app1)...).
			AddRow(appRow(app2)...)
		mock.ExpectQuery(`SELECT`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(rows)

		apps, total, err := repo.List(context.Background(), 1, 10, "", "", nil)
		require.NoError(t, err)
		assert.Equal(t, int64(2), total)
		assert.Len(t, apps, 2)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("filters by status", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		// COUNT query receives only the filter args (no LIMIT/OFFSET)
		mock.ExpectQuery(`SELECT COUNT`).WithArgs("active").
			WillReturnRows(mock.NewRows([]string{"count"}).AddRow(int64(1)))
		// SELECT query receives filter args + pageSize + offset
		mock.ExpectQuery(`SELECT`).WithArgs("active", pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(mock.NewRows(applicationScanCols).AddRow(appRow(sampleApplication())...))

		apps, total, err := repo.List(context.Background(), 1, 10, "active", "", nil)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, apps, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty result returns nil slice", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT COUNT`).WillReturnRows(mock.NewRows([]string{"count"}).AddRow(int64(0)))
		mock.ExpectQuery(`SELECT`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(mock.NewRows(applicationScanCols))

		apps, total, err := repo.List(context.Background(), 1, 10, "", "", nil)
		require.NoError(t, err)
		assert.Equal(t, int64(0), total)
		assert.Empty(t, apps)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("count error propagates", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT COUNT`).WillReturnError(fmt.Errorf("db down"))

		_, _, err := repo.List(context.Background(), 1, 10, "", "", nil)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Delete ──────────────────────────────────────────────────────────────────

func TestApplicationRepository_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_applications`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(context.Background(), id)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_applications`).
			WithArgs(id).
			WillReturnError(fmt.Errorf("constraint violation"))

		err := repo.Delete(context.Background(), id)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetPreauthorized ────────────────────────────────────────────────────────

func TestApplicationRepository_GetPreauthorized(t *testing.T) {
	t.Run("returns preauthorized apps", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		app := sampleApplication()
		app.Preauthorized = true
		rows := mock.NewRows(applicationScanCols).AddRow(appRow(app)...)
		mock.ExpectQuery(`SELECT`).WillReturnRows(rows)

		apps, err := repo.GetPreauthorized(context.Background())
		require.NoError(t, err)
		assert.Len(t, apps, 1)
		assert.True(t, apps[0].Preauthorized)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty returns nil slice", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WillReturnRows(mock.NewRows(applicationScanCols))

		apps, err := repo.GetPreauthorized(context.Background())
		require.NoError(t, err)
		assert.Empty(t, apps)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WillReturnError(fmt.Errorf("timeout"))

		_, err := repo.GetPreauthorized(context.Background())
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── CountServicePrincipals ──────────────────────────────────────────────────

func TestApplicationRepository_CountServicePrincipals(t *testing.T) {
	t.Run("returns count", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		appID := uuid.New()
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(appID).
			WillReturnRows(mock.NewRows([]string{"count"}).AddRow(int64(3)))

		count, err := repo.CountServicePrincipals(context.Background(), appID)
		require.NoError(t, err)
		assert.Equal(t, int64(3), count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		appID := uuid.New()
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(appID).WillReturnError(fmt.Errorf("db error"))

		_, err := repo.CountServicePrincipals(context.Background(), appID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetAppRoles ─────────────────────────────────────────────────────────────

func TestApplicationRepository_GetAppRoles(t *testing.T) {
	t.Run("returns raw json", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		appID := uuid.New()
		raw := []byte(`[{"id":"role-1","value":"Admin"}]`)
		mock.ExpectQuery(`SELECT COALESCE`).WithArgs(appID).
			WillReturnRows(mock.NewRows([]string{"app_roles"}).AddRow(raw))

		got, err := repo.GetAppRoles(context.Background(), appID)
		require.NoError(t, err)
		assert.Equal(t, raw, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── UpdatePublisherVerification ─────────────────────────────────────────────

func TestApplicationRepository_UpdatePublisherVerification(t *testing.T) {
	domain := "example.com"

	t.Run("verify with domain", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_applications SET publisher_verified`).
			WithArgs(true, &domain, id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdatePublisherVerification(context.Background(), id, true, &domain)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("unverify clears domain", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_applications SET publisher_verified`).
			WithArgs(false, (*string)(nil), id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdatePublisherVerification(context.Background(), id, false, nil)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── SoftDelete ──────────────────────────────────────────────────────────────

func TestApplicationRepository_SoftDelete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_applications`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.SoftDelete(context.Background(), id)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_applications`).
			WithArgs(id).
			WillReturnError(fmt.Errorf("db error"))

		err := repo.SoftDelete(context.Background(), id)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Restore ─────────────────────────────────────────────────────────────────

func TestApplicationRepository_Restore(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_applications`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.Restore(context.Background(), id)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found or purge elapsed returns error", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_applications`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.Restore(context.Background(), id)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── PurgeExpired ────────────────────────────────────────────────────────────

func TestApplicationRepository_PurgeExpired(t *testing.T) {
	t.Run("returns deleted count", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_applications`).
			WillReturnResult(pgxmock.NewResult("DELETE", 5))

		count, err := repo.PurgeExpired(context.Background())
		require.NoError(t, err)
		assert.Equal(t, int64(5), count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_applications`).WillReturnError(fmt.Errorf("db error"))

		_, err := repo.PurgeExpired(context.Background())
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── ListDeleted ─────────────────────────────────────────────────────────────

func TestApplicationRepository_ListDeleted(t *testing.T) {
	t.Run("returns soft-deleted apps", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		app := sampleApplication()
		now := time.Now()
		app.DeletedAt = &now
		rows := mock.NewRows(applicationScanCols).AddRow(appRow(app)...)
		mock.ExpectQuery(`SELECT`).WillReturnRows(rows)

		apps, err := repo.ListDeleted(context.Background())
		require.NoError(t, err)
		assert.Len(t, apps, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── ListActive ──────────────────────────────────────────────────────────────

func TestApplicationRepository_ListActive(t *testing.T) {
	t.Run("returns active apps", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		app := sampleApplication()
		rows := mock.NewRows(applicationScanCols).AddRow(appRow(app)...)
		mock.ExpectQuery(`SELECT`).WillReturnRows(rows)

		apps, err := repo.ListActive(context.Background())
		require.NoError(t, err)
		assert.Len(t, apps, 1)
		assert.Equal(t, models.ApplicationStatusActive, apps[0].Status)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WillReturnError(fmt.Errorf("timeout"))

		_, err := repo.ListActive(context.Background())
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── MarkStale ───────────────────────────────────────────────────────────────

func TestApplicationRepository_MarkStale(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		appID := uuid.New()
		since := time.Now()
		mock.ExpectExec(`UPDATE iam_applications SET stale_since`).
			WithArgs(since, appID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.MarkStale(context.Background(), appID, since)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── ClearStale ──────────────────────────────────────────────────────────────

func TestApplicationRepository_ClearStale(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		appID := uuid.New()
		mock.ExpectExec(`UPDATE iam_applications SET stale_since`).
			WithArgs(appID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.ClearStale(context.Background(), appID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── UpdateLastSignIn ────────────────────────────────────────────────────────

func TestApplicationRepository_UpdateLastSignIn(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		appID := uuid.New()
		signInTime := time.Now()
		mock.ExpectExec(`UPDATE iam_applications SET last_sign_in_at`).
			WithArgs(signInTime, appID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateLastSignIn(context.Background(), appID, signInTime)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetServicePrincipalCount ────────────────────────────────────────────────

func TestApplicationRepository_GetServicePrincipalCount(t *testing.T) {
	t.Run("returns active SP count", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		appID := uuid.New()
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(appID).
			WillReturnRows(mock.NewRows([]string{"count"}).AddRow(int64(7)))

		count, err := repo.GetServicePrincipalCount(context.Background(), appID)
		require.NoError(t, err)
		assert.Equal(t, int64(7), count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── SoftDeleteSP ────────────────────────────────────────────────────────────

func TestApplicationRepository_SoftDeleteSP(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		spID := uuid.New()
		mock.ExpectExec(`UPDATE iam_service_principals`).
			WithArgs(spID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.SoftDeleteSP(context.Background(), spID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── RestoreSP ───────────────────────────────────────────────────────────────

func TestApplicationRepository_RestoreSP(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		spID := uuid.New()
		mock.ExpectExec(`UPDATE iam_service_principals`).
			WithArgs(spID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.RestoreSP(context.Background(), spID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		mock, repo := newApplicationRepoMock(t)
		defer mock.Close()

		spID := uuid.New()
		mock.ExpectExec(`UPDATE iam_service_principals`).
			WithArgs(spID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.RestoreSP(context.Background(), spID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
