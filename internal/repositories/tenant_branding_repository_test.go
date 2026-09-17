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

// ─── helpers ─────────────────────────────────────────────────────────────────

func newBrandingRepoMock(t *testing.T) (*TenantBrandingRepository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return &TenantBrandingRepository{db: mock}, mock
}

func brandingCols() []string {
	return []string{
		"id", "tenant_id", "logo_url", "favicon_url", "primary_color", "background_color",
		"accent_color", "custom_css", "login_title", "login_subtitle", "login_message",
		"support_email", "support_url", "privacy_policy_url", "terms_of_service_url",
		"hide_hexxlock_branding", "created_at", "updated_at",
	}
}

func newTestBranding(tenantID uuid.UUID) *models.TenantBranding {
	now := time.Now().UTC()
	logo := "https://cdn.example.com/logo.png"
	favicon := "https://cdn.example.com/favicon.ico"
	accent := "#FF6B35"
	css := ".btn { border-radius: 4px; }"
	title := "Welcome to Acme Corp"
	subtitle := "Sign in to continue"
	msg := "Use your company credentials."
	supportEmail := "it@acme.com"
	supportURL := "https://support.acme.com"
	privacyURL := "https://acme.com/privacy"
	tosURL := "https://acme.com/tos"
	return &models.TenantBranding{
		ID:                   uuid.New(),
		TenantID:             tenantID,
		LogoURL:              &logo,
		FaviconURL:           &favicon,
		PrimaryColor:         "#0055CC",
		BackgroundColor:      "#FFFFFF",
		AccentColor:          &accent,
		CustomCSS:            &css,
		LoginTitle:           &title,
		LoginSubtitle:        &subtitle,
		LoginMessage:         &msg,
		SupportEmail:         &supportEmail,
		SupportURL:           &supportURL,
		PrivacyPolicyURL:     &privacyURL,
		TermsOfServiceURL:    &tosURL,
		HideHexxlockBranding: true,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
}

func brandingRow(b *models.TenantBranding) []interface{} {
	return []interface{}{
		b.ID, b.TenantID,
		b.LogoURL, b.FaviconURL,
		b.PrimaryColor, b.BackgroundColor, b.AccentColor,
		b.CustomCSS,
		b.LoginTitle, b.LoginSubtitle, b.LoginMessage,
		b.SupportEmail, b.SupportURL,
		b.PrivacyPolicyURL, b.TermsOfServiceURL,
		b.HideHexxlockBranding,
		b.CreatedAt, b.UpdatedAt,
	}
}

// ─── GetByTenantID ────────────────────────────────────────────────────────────

func TestTenantBranding_GetByTenantID(t *testing.T) {
	t.Run("found returns branding", func(t *testing.T) {
		repo, mock := newBrandingRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		b := newTestBranding(tenantID)

		rows := pgxmock.NewRows(brandingCols()).AddRow(brandingRow(b)...)
		mock.ExpectQuery(`SELECT .+ FROM iam_tenant_branding WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnRows(rows)

		got, err := repo.GetByTenantID(ctx, tenantID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, b.ID, got.ID)
		assert.Equal(t, tenantID, got.TenantID)
		assert.Equal(t, "#0055CC", got.PrimaryColor)
		assert.True(t, got.HideHexxlockBranding)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not configured returns nil nil", func(t *testing.T) {
		repo, mock := newBrandingRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_tenant_branding WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnRows(pgxmock.NewRows(brandingCols()))

		got, err := repo.GetByTenantID(ctx, tenantID)
		require.NoError(t, err)
		assert.Nil(t, got)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newBrandingRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_tenant_branding WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnError(errors.New("connection reset"))

		_, err := repo.GetByTenantID(ctx, tenantID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "GetByTenantID")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("nil optional fields scan correctly", func(t *testing.T) {
		repo, mock := newBrandingRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		now := time.Now().UTC()
		// Row with all optional fields nil
		rows := pgxmock.NewRows(brandingCols()).AddRow(
			uuid.New(), tenantID,
			nil, nil, // logo, favicon
			"#000000", "#FFFFFF", nil, // primary, background, accent
			nil,           // css
			nil, nil, nil, // title, subtitle, message
			nil, nil, // support email, url
			nil, nil, // privacy, tos
			false, // hide branding
			now, now,
		)
		mock.ExpectQuery(`SELECT .+ FROM iam_tenant_branding WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnRows(rows)

		got, err := repo.GetByTenantID(ctx, tenantID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Nil(t, got.LogoURL)
		assert.Nil(t, got.LoginTitle)
		assert.False(t, got.HideHexxlockBranding)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Upsert ───────────────────────────────────────────────────────────────────

func TestTenantBranding_Upsert(t *testing.T) {
	t.Run("inserts new branding", func(t *testing.T) {
		repo, mock := newBrandingRepoMock(t)
		ctx := context.Background()

		now := time.Now().UTC()
		tenantID := uuid.New()
		b := newTestBranding(tenantID)
		b.ID = uuid.Nil // force auto-generation

		mock.ExpectQuery(`INSERT INTO iam_tenant_branding`).
			WithArgs(
				pgxmock.AnyArg(), // id
				b.TenantID, b.LogoURL, b.FaviconURL,
				b.PrimaryColor, b.BackgroundColor, b.AccentColor,
				b.CustomCSS,
				b.LoginTitle, b.LoginSubtitle, b.LoginMessage,
				b.SupportEmail, b.SupportURL,
				b.PrivacyPolicyURL, b.TermsOfServiceURL,
				b.HideHexxlockBranding,
			).
			WillReturnRows(pgxmock.NewRows([]string{"created_at", "updated_at"}).
				AddRow(now, now))

		err := repo.Upsert(ctx, b)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, b.ID)
		assert.Equal(t, now.UTC().Truncate(time.Second), b.CreatedAt.UTC().Truncate(time.Second))
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("updates existing branding on conflict", func(t *testing.T) {
		repo, mock := newBrandingRepoMock(t)
		ctx := context.Background()

		now := time.Now().UTC()
		tenantID := uuid.New()
		b := newTestBranding(tenantID)

		mock.ExpectQuery(`INSERT INTO iam_tenant_branding`).
			WithArgs(
				b.ID, b.TenantID, b.LogoURL, b.FaviconURL,
				b.PrimaryColor, b.BackgroundColor, b.AccentColor,
				b.CustomCSS,
				b.LoginTitle, b.LoginSubtitle, b.LoginMessage,
				b.SupportEmail, b.SupportURL,
				b.PrivacyPolicyURL, b.TermsOfServiceURL,
				b.HideHexxlockBranding,
			).
			WillReturnRows(pgxmock.NewRows([]string{"created_at", "updated_at"}).
				AddRow(now, now))

		err := repo.Upsert(ctx, b)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newBrandingRepoMock(t)
		ctx := context.Background()

		b := newTestBranding(uuid.New())

		mock.ExpectQuery(`INSERT INTO iam_tenant_branding`).
			WithArgs(
				b.ID, b.TenantID, b.LogoURL, b.FaviconURL,
				b.PrimaryColor, b.BackgroundColor, b.AccentColor,
				b.CustomCSS,
				b.LoginTitle, b.LoginSubtitle, b.LoginMessage,
				b.SupportEmail, b.SupportURL,
				b.PrivacyPolicyURL, b.TermsOfServiceURL,
				b.HideHexxlockBranding,
			).
			WillReturnError(errors.New("db error"))

		err := repo.Upsert(ctx, b)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Delete ───────────────────────────────────────────────────────────────────

func TestTenantBranding_Delete(t *testing.T) {
	t.Run("deletes branding", func(t *testing.T) {
		repo, mock := newBrandingRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_tenant_branding WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(ctx, tenantID)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("deleting non-existent branding is not an error", func(t *testing.T) {
		repo, mock := newBrandingRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_tenant_branding WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.Delete(ctx, tenantID)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newBrandingRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_tenant_branding WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnError(errors.New("db error"))

		err := repo.Delete(ctx, tenantID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Delete")
		require.NoError(t, mock.ExpectationsWereMet())
	})
}
