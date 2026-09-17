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

// newConsentRepoMock creates a ConsentRepository backed by pgxmock.
func newConsentRepoMock(t *testing.T) (*ConsentRepository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	repo := &ConsentRepository{db: mock}
	return repo, mock
}

// consentTypeColumns are the columns returned by consent type queries.
func consentTypeColumns() []string {
	return []string{
		"id", "tenant_id", "name", "display_name", "description", "category",
		"is_required", "is_active", "version", "legal_basis",
		"data_retention_days", "external_policy_url", "created_at", "updated_at",
	}
}

// userConsentColumns are the columns returned by user consent queries.
func userConsentColumns() []string {
	return []string{
		"id", "user_id", "consent_type_id", "granted", "consent_version",
		"granted_at", "revoked_at", "ip_address", "user_agent",
		"created_at", "updated_at",
	}
}

// userConsentWithTypeColumns combines user consent and consent type columns.
func userConsentWithTypeColumns() []string {
	uc := []string{
		"uc.id", "uc.user_id", "uc.consent_type_id", "uc.granted", "uc.consent_version",
		"uc.granted_at", "uc.revoked_at", "uc.ip_address", "uc.user_agent",
		"uc.created_at", "uc.updated_at",
	}
	ct := []string{
		"ct.id", "ct.tenant_id", "ct.name", "ct.display_name", "ct.description", "ct.category",
		"ct.is_required", "ct.is_active", "ct.version", "ct.legal_basis",
		"ct.data_retention_days", "ct.external_policy_url", "ct.created_at", "ct.updated_at",
	}
	return append(uc, ct...)
}

// consentHistoryWithTypeColumns combines consent history and consent type columns.
func consentHistoryWithTypeColumns() []string {
	ch := []string{
		"ch.id", "ch.user_id", "ch.consent_type_id", "ch.action", "ch.consent_version",
		"ch.ip_address", "ch.user_agent", "ch.created_at",
	}
	ct := []string{
		"ct.id", "ct.tenant_id", "ct.name", "ct.display_name", "ct.description", "ct.category",
		"ct.is_required", "ct.is_active", "ct.version", "ct.legal_basis",
		"ct.data_retention_days", "ct.external_policy_url", "ct.created_at", "ct.updated_at",
	}
	return append(ch, ct...)
}

func newTestConsentType(tenantID uuid.UUID) *models.ConsentType {
	desc := "Privacy policy consent"
	basis := string(models.LegalBasisConsent)
	days := 365
	url := "https://example.com/privacy"
	return &models.ConsentType{
		ID:                uuid.New(),
		TenantID:          tenantID,
		Name:              "privacy_policy",
		DisplayName:       "Privacy Policy",
		Description:       &desc,
		Category:          "required",
		IsRequired:        true,
		IsActive:          true,
		Version:           1,
		LegalBasis:        &basis,
		DataRetentionDays: &days,
		ExternalPolicyURL: &url,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
}

func consentTypeRow(ct *models.ConsentType) []interface{} {
	return []interface{}{
		ct.ID, ct.TenantID, ct.Name, ct.DisplayName, ct.Description, ct.Category,
		ct.IsRequired, ct.IsActive, ct.Version, ct.LegalBasis,
		ct.DataRetentionDays, ct.ExternalPolicyURL, ct.CreatedAt, ct.UpdatedAt,
	}
}

func newTestUserConsent(userID, consentTypeID uuid.UUID) *models.UserConsent {
	now := time.Now().UTC()
	ip := testImpersonationIP
	ua := testImpersonationUA
	return &models.UserConsent{
		ID:             uuid.New(),
		UserID:         userID,
		ConsentTypeID:  consentTypeID,
		Granted:        true,
		ConsentVersion: 1,
		GrantedAt:      &now,
		IPAddress:      &ip,
		UserAgent:      &ua,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func userConsentRow(uc *models.UserConsent) []interface{} {
	return []interface{}{
		uc.ID, uc.UserID, uc.ConsentTypeID, uc.Granted, uc.ConsentVersion,
		uc.GrantedAt, uc.RevokedAt, uc.IPAddress, uc.UserAgent,
		uc.CreatedAt, uc.UpdatedAt,
	}
}

func userConsentWithTypeRow(uc *models.UserConsent, ct *models.ConsentType) []interface{} {
	ucFields := []interface{}{
		uc.ID, uc.UserID, uc.ConsentTypeID, uc.Granted, uc.ConsentVersion,
		uc.GrantedAt, uc.RevokedAt, uc.IPAddress, uc.UserAgent,
		uc.CreatedAt, uc.UpdatedAt,
	}
	ctFields := consentTypeRow(ct)
	return append(ucFields, ctFields...)
}

// ─── GetConsentTypes ─────────────────────────────────────────────────────────

func TestConsentRepository_GetConsentTypes(t *testing.T) {
	t.Run("returns active consent types for tenant", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		ct := newTestConsentType(tenantID)

		rows := pgxmock.NewRows(consentTypeColumns()).AddRow(consentTypeRow(ct)...)

		mock.ExpectQuery(`SELECT .+ FROM iam_consent_types\s+WHERE tenant_id = \$1 AND is_active = true`).
			WithArgs(tenantID).
			WillReturnRows(rows)

		types, err := repo.GetConsentTypes(ctx, tenantID)
		require.NoError(t, err)
		assert.Len(t, types, 1)
		assert.Equal(t, "privacy_policy", types[0].Name)
		assert.True(t, types[0].IsActive)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no active types returns empty", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_consent_types`).
			WithArgs(tenantID).
			WillReturnRows(pgxmock.NewRows(consentTypeColumns()))

		types, err := repo.GetConsentTypes(ctx, tenantID)
		require.NoError(t, err)
		assert.Empty(t, types)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_consent_types`).
			WithArgs(tenantID).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetConsentTypes(ctx, tenantID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetConsentTypeByID ──────────────────────────────────────────────────────

func TestConsentRepository_GetConsentTypeByID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		ct := newTestConsentType(tenantID)
		rows := pgxmock.NewRows(consentTypeColumns()).AddRow(consentTypeRow(ct)...)

		mock.ExpectQuery(`SELECT .+ FROM iam_consent_types WHERE id = \$1`).
			WithArgs(ct.ID).
			WillReturnRows(rows)

		got, err := repo.GetConsentTypeByID(ctx, ct.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, ct.ID, got.ID)
		assert.Equal(t, "privacy_policy", got.Name)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_consent_types WHERE id = \$1`).
			WithArgs(id).
			WillReturnRows(pgxmock.NewRows(consentTypeColumns()))

		got, err := repo.GetConsentTypeByID(ctx, id)
		require.NoError(t, err)
		assert.Nil(t, got)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		anyID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_consent_types WHERE id = \$1`).
			WithArgs(anyID).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetConsentTypeByID(ctx, anyID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetConsentTypeByName ────────────────────────────────────────────────────

func TestConsentRepository_GetConsentTypeByName(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		ct := newTestConsentType(tenantID)
		rows := pgxmock.NewRows(consentTypeColumns()).AddRow(consentTypeRow(ct)...)

		mock.ExpectQuery(`SELECT .+ FROM iam_consent_types WHERE tenant_id = \$1 AND name = \$2`).
			WithArgs(tenantID, "privacy_policy").
			WillReturnRows(rows)

		got, err := repo.GetConsentTypeByName(ctx, tenantID, "privacy_policy")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "privacy_policy", got.Name)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_consent_types WHERE tenant_id = \$1 AND name = \$2`).
			WithArgs(tenantID, "nonexistent").
			WillReturnRows(pgxmock.NewRows(consentTypeColumns()))

		got, err := repo.GetConsentTypeByName(ctx, tenantID, "nonexistent")
		require.NoError(t, err)
		assert.Nil(t, got)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetUserConsents ─────────────────────────────────────────────────────────

func TestConsentRepository_GetUserConsents(t *testing.T) {
	t.Run("returns consents with type data", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		ct := newTestConsentType(tenantID)
		uc := newTestUserConsent(userID, ct.ID)

		rows := pgxmock.NewRows(userConsentWithTypeColumns()).
			AddRow(userConsentWithTypeRow(uc, ct)...)

		mock.ExpectQuery(`SELECT uc\.id.+ FROM iam_user_consents uc\s+JOIN iam_consent_types ct`).
			WithArgs(userID, tenantID).
			WillReturnRows(rows)

		consents, err := repo.GetUserConsents(ctx, userID, tenantID)
		require.NoError(t, err)
		assert.Len(t, consents, 1)
		assert.Equal(t, uc.ID, consents[0].ID)
		assert.True(t, consents[0].Granted)
		assert.Equal(t, ct.Name, consents[0].ConsentType.Name)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no consents returns empty", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()

		mock.ExpectQuery(`SELECT uc\.id.+`).
			WithArgs(userID, tenantID).
			WillReturnRows(pgxmock.NewRows(userConsentWithTypeColumns()))

		consents, err := repo.GetUserConsents(ctx, userID, tenantID)
		require.NoError(t, err)
		assert.Empty(t, consents)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		anyUserID := uuid.New()
		anyTenantID := uuid.New()
		mock.ExpectQuery(`SELECT uc\.id.+`).
			WithArgs(anyUserID, anyTenantID).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetUserConsents(ctx, anyUserID, anyTenantID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetUserConsent ──────────────────────────────────────────────────────────

func TestConsentRepository_GetUserConsent(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		consentTypeID := uuid.New()
		uc := newTestUserConsent(userID, consentTypeID)

		rows := pgxmock.NewRows(userConsentColumns()).AddRow(userConsentRow(uc)...)

		mock.ExpectQuery(`SELECT .+ FROM iam_user_consents\s+WHERE user_id = \$1 AND consent_type_id = \$2`).
			WithArgs(userID, consentTypeID).
			WillReturnRows(rows)

		got, err := repo.GetUserConsent(ctx, userID, consentTypeID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, uc.ID, got.ID)
		assert.True(t, got.Granted)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		consentTypeID := uuid.New()

		mock.ExpectQuery(`SELECT .+ FROM iam_user_consents\s+WHERE user_id = \$1 AND consent_type_id = \$2`).
			WithArgs(userID, consentTypeID).
			WillReturnRows(pgxmock.NewRows(userConsentColumns()))

		got, err := repo.GetUserConsent(ctx, userID, consentTypeID)
		require.NoError(t, err)
		assert.Nil(t, got)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		anyUserID := uuid.New()
		anyConsentTypeID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_user_consents`).
			WithArgs(anyUserID, anyConsentTypeID).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetUserConsent(ctx, anyUserID, anyConsentTypeID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── UpsertConsent ───────────────────────────────────────────────────────────

func TestConsentRepository_UpsertConsent(t *testing.T) {
	t.Run("creates new consent", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		consentTypeID := uuid.New()
		uc := newTestUserConsent(userID, consentTypeID)
		uc.ID = uuid.Nil // will be auto-generated
		now := time.Now().UTC()
		newID := uuid.New()

		mock.ExpectQuery(`INSERT INTO iam_user_consents`).
			WithArgs(pgxmock.AnyArg(), uc.UserID, uc.ConsentTypeID, uc.Granted,
				uc.ConsentVersion, uc.GrantedAt, uc.RevokedAt, uc.IPAddress, uc.UserAgent).
			WillReturnRows(pgxmock.NewRows([]string{"id", "created_at", "updated_at"}).
				AddRow(newID, now, now))

		err := repo.UpsertConsent(ctx, uc)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, uc.ID)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("updates existing consent", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		consentTypeID := uuid.New()
		uc := newTestUserConsent(userID, consentTypeID)
		now := time.Now().UTC()

		mock.ExpectQuery(`INSERT INTO iam_user_consents`).
			WithArgs(
				uc.ID, uc.UserID, uc.ConsentTypeID, uc.Granted,
				uc.ConsentVersion, uc.GrantedAt, uc.RevokedAt,
				uc.IPAddress, uc.UserAgent,
			).
			WillReturnRows(pgxmock.NewRows([]string{"id", "created_at", "updated_at"}).
				AddRow(uc.ID, now, now))

		err := repo.UpsertConsent(ctx, uc)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("revoke consent (granted=false)", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		consentTypeID := uuid.New()
		uc := newTestUserConsent(userID, consentTypeID)
		uc.Granted = false
		revokedAt := time.Now().UTC()
		uc.RevokedAt = &revokedAt
		uc.GrantedAt = nil
		now := time.Now().UTC()

		mock.ExpectQuery(`INSERT INTO iam_user_consents`).
			WithArgs(uc.ID, uc.UserID, uc.ConsentTypeID, uc.Granted,
				uc.ConsentVersion, uc.GrantedAt, uc.RevokedAt, uc.IPAddress, uc.UserAgent).
			WillReturnRows(pgxmock.NewRows([]string{"id", "created_at", "updated_at"}).
				AddRow(uc.ID, now, now))

		err := repo.UpsertConsent(ctx, uc)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		uc := newTestUserConsent(uuid.New(), uuid.New())
		mock.ExpectQuery(`INSERT INTO iam_user_consents`).
			WithArgs(uc.ID, uc.UserID, uc.ConsentTypeID, uc.Granted,
				uc.ConsentVersion, uc.GrantedAt, uc.RevokedAt, uc.IPAddress, uc.UserAgent).
			WillReturnError(errors.New("constraint violation"))

		err := repo.UpsertConsent(ctx, uc)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetRequiredConsentTypes ─────────────────────────────────────────────────

func TestConsentRepository_GetRequiredConsentTypes(t *testing.T) {
	t.Run("returns only required consent types", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		ct := newTestConsentType(tenantID)
		ct.IsRequired = true

		rows := pgxmock.NewRows(consentTypeColumns()).AddRow(consentTypeRow(ct)...)

		mock.ExpectQuery(`SELECT .+ FROM iam_consent_types\s+WHERE tenant_id = \$1 AND is_active = true AND is_required = true`).
			WithArgs(tenantID).
			WillReturnRows(rows)

		types, err := repo.GetRequiredConsentTypes(ctx, tenantID)
		require.NoError(t, err)
		assert.Len(t, types, 1)
		assert.True(t, types[0].IsRequired)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		anyTenantID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_consent_types`).
			WithArgs(anyTenantID).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetRequiredConsentTypes(ctx, anyTenantID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetPendingRequiredConsents ──────────────────────────────────────────────

func TestConsentRepository_GetPendingRequiredConsents(t *testing.T) {
	t.Run("returns consent types not yet granted", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		ct := newTestConsentType(tenantID)

		rows := pgxmock.NewRows(consentTypeColumns()).AddRow(consentTypeRow(ct)...)

		mock.ExpectQuery(`SELECT ct\.id.+ FROM iam_consent_types ct\s+LEFT JOIN iam_user_consents uc`).
			WithArgs(userID, tenantID).
			WillReturnRows(rows)

		types, err := repo.GetPendingRequiredConsents(ctx, userID, tenantID)
		require.NoError(t, err)
		assert.Len(t, types, 1)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("all required consents granted returns empty", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()

		mock.ExpectQuery(`SELECT ct\.id.+`).
			WithArgs(userID, tenantID).
			WillReturnRows(pgxmock.NewRows(consentTypeColumns()))

		types, err := repo.GetPendingRequiredConsents(ctx, userID, tenantID)
		require.NoError(t, err)
		assert.Empty(t, types)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		anyUserID := uuid.New()
		anyTenantID := uuid.New()
		mock.ExpectQuery(`SELECT ct\.id.+`).
			WithArgs(anyUserID, anyTenantID).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetPendingRequiredConsents(ctx, anyUserID, anyTenantID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── HasGrantedAllRequired ───────────────────────────────────────────────────

func TestConsentRepository_HasGrantedAllRequired(t *testing.T) {
	t.Run("all granted returns true", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()

		// Delegates to GetPendingRequiredConsents
		mock.ExpectQuery(`SELECT ct\.id.+`).
			WithArgs(userID, tenantID).
			WillReturnRows(pgxmock.NewRows(consentTypeColumns()))

		ok, err := repo.HasGrantedAllRequired(ctx, userID, tenantID)
		require.NoError(t, err)
		assert.True(t, ok)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("pending consents returns false", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		ct := newTestConsentType(tenantID)

		mock.ExpectQuery(`SELECT ct\.id.+`).
			WithArgs(userID, tenantID).
			WillReturnRows(pgxmock.NewRows(consentTypeColumns()).AddRow(consentTypeRow(ct)...))

		ok, err := repo.HasGrantedAllRequired(ctx, userID, tenantID)
		require.NoError(t, err)
		assert.False(t, ok)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── DeleteUserConsents ──────────────────────────────────────────────────────

func TestConsentRepository_DeleteUserConsents(t *testing.T) {
	t.Run("deletes all consents for user", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_user_consents WHERE user_id = \$1`).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 3))

		err := repo.DeleteUserConsents(ctx, userID)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no consents is not an error", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_user_consents WHERE user_id = \$1`).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.DeleteUserConsents(ctx, userID)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		anyUserID := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_user_consents`).
			WithArgs(anyUserID).
			WillReturnError(errors.New("db error"))

		err := repo.DeleteUserConsents(ctx, anyUserID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetConsentHistory ───────────────────────────────────────────────────────

func TestConsentRepository_GetConsentHistory(t *testing.T) {
	t.Run("returns consent history since date", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		since := time.Now().Add(-30 * 24 * time.Hour).UTC()
		ct := newTestConsentType(tenantID)
		uc := newTestUserConsent(userID, ct.ID)

		rows := pgxmock.NewRows(userConsentWithTypeColumns()).
			AddRow(userConsentWithTypeRow(uc, ct)...)

		mock.ExpectQuery(`SELECT uc\.id.+ FROM iam_user_consents uc\s+JOIN iam_consent_types ct`).
			WithArgs(userID, since).
			WillReturnRows(rows)

		history, err := repo.GetConsentHistory(ctx, userID, since)
		require.NoError(t, err)
		assert.Len(t, history, 1)
		assert.Equal(t, uc.ID, history[0].ID)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no history returns empty", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		since := time.Now().Add(-7 * 24 * time.Hour)

		mock.ExpectQuery(`SELECT uc\.id.+`).
			WithArgs(userID, since).
			WillReturnRows(pgxmock.NewRows(userConsentWithTypeColumns()))

		history, err := repo.GetConsentHistory(ctx, userID, since)
		require.NoError(t, err)
		assert.Empty(t, history)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		anyUserID := uuid.New()
		anySince := time.Now()
		mock.ExpectQuery(`SELECT uc\.id.+`).
			WithArgs(anyUserID, anySince).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetConsentHistory(ctx, anyUserID, anySince)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetConsentHistoryDetailed ───────────────────────────────────────────────

func TestConsentRepository_GetConsentHistoryDetailed(t *testing.T) {
	t.Run("returns paginated history with type info", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		ct := newTestConsentType(tenantID)
		histID := uuid.New()
		ip := testImpersonationIP
		ua := "curl/7.0"
		now := time.Now().UTC()

		cols := consentHistoryWithTypeColumns()
		row := []interface{}{
			histID, userID, ct.ID, "granted", 1,
			&ip, &ua, now,
			// ct fields
			ct.ID, ct.TenantID, ct.Name, ct.DisplayName, ct.Description, ct.Category,
			ct.IsRequired, ct.IsActive, ct.Version, ct.LegalBasis,
			ct.DataRetentionDays, ct.ExternalPolicyURL, ct.CreatedAt, ct.UpdatedAt,
		}

		rows := pgxmock.NewRows(cols).AddRow(row...)

		mock.ExpectQuery(`SELECT ch\.id.+ FROM iam_consent_history ch\s+JOIN iam_consent_types ct`).
			WithArgs(userID, tenantID, 10).
			WillReturnRows(rows)

		history, err := repo.GetConsentHistoryDetailed(ctx, userID, tenantID, 10)
		require.NoError(t, err)
		assert.Len(t, history, 1)
		assert.Equal(t, histID, history[0].ID)
		assert.Equal(t, "granted", history[0].Action)
		assert.Equal(t, ct.Name, history[0].ConsentType.Name)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty history returns empty slice", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()

		mock.ExpectQuery(`SELECT ch\.id.+`).
			WithArgs(userID, tenantID, 50).
			WillReturnRows(pgxmock.NewRows(consentHistoryWithTypeColumns()))

		history, err := repo.GetConsentHistoryDetailed(ctx, userID, tenantID, 50)
		require.NoError(t, err)
		assert.Empty(t, history)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newConsentRepoMock(t)
		ctx := context.Background()

		anyUserID := uuid.New()
		anyTenantID := uuid.New()
		mock.ExpectQuery(`SELECT ch\.id.+`).
			WithArgs(anyUserID, anyTenantID, 10).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetConsentHistoryDetailed(ctx, anyUserID, anyTenantID, 10)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}
