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
	testIDPTypeLDAP = "ldap"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func newIDPRepoMock(t *testing.T) (pgxmock.PgxPoolIface, *IdentityProviderRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newIdentityProviderRepositoryWithMock(mock)
}

// providerCols matches providerSelectCols used by full SELECT queries.
var providerCols = []string{
	"id", "tenant_id", "realm_id", "scope", "provider_type", "provider_name", "display_name",
	"client_id", "client_secret_encrypted", "authorization_url", "token_url", "userinfo_url",
	"scopes", "ldap_config", "attribute_mapping", "auto_provision_users", "default_role_ids",
	"is_active", "is_default", "priority", "created_at", "updated_at", "created_by",
	"saml_sp_config", "apple_config",
}

func sampleProvider() *models.IdentityProvider {
	now := time.Now()
	tenantID := uuid.New()
	return &models.IdentityProvider{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Type:        "oidc",
		Name:        "google-sso",
		DisplayName: "Google SSO",
		Scope:       "tenant",
		IsEnabled:   true,
		IsDefault:   false,
		Priority:    100,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// providerRow returns values for providerCols, using nil for all JSON/nullable columns.
func providerRow(p *models.IdentityProvider) []interface{} {
	var tenantIDPtr *uuid.UUID
	if p.TenantID != uuid.Nil {
		tid := p.TenantID
		tenantIDPtr = &tid
	}
	return []interface{}{
		p.ID, tenantIDPtr, p.RealmID, p.Scope,
		p.Type, p.Name, p.DisplayName,
		p.ClientID, p.ClientSecretEncrypted, p.AuthorizationURL, p.TokenURL, p.UserInfoURL,
		p.Scopes, nil, nil, p.AutoProvisionUsers, p.DefaultRoleIDs,
		p.IsEnabled, p.IsDefault, p.Priority, p.CreatedAt, p.UpdatedAt, p.CreatedBy,
		nil, nil,
	}
}

// ─── Create ──────────────────────────────────────────────────────────────────

func TestIdentityProviderRepository_Create(t *testing.T) {
	t.Run("success with tenant scope", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		now := time.Now()
		provider := sampleProvider()

		rows := mock.NewRows([]string{"created_at", "updated_at"}).AddRow(now, now)
		// 23 args for the INSERT
		mock.ExpectQuery(`INSERT INTO iam_identity_providers`).
			WithArgs(anyArgs(23)...).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), provider)
		require.NoError(t, err)
		assert.Equal(t, now, provider.CreatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("auto-assigns ID when nil", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		now := time.Now()
		provider := sampleProvider()
		provider.ID = uuid.Nil

		rows := mock.NewRows([]string{"created_at", "updated_at"}).AddRow(now, now)
		mock.ExpectQuery(`INSERT INTO iam_identity_providers`).
			WithArgs(anyArgs(23)...).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), provider)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, provider.ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("sets default scope to tenant when empty", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		now := time.Now()
		provider := sampleProvider()
		provider.Scope = ""

		rows := mock.NewRows([]string{"created_at", "updated_at"}).AddRow(now, now)
		mock.ExpectQuery(`INSERT INTO iam_identity_providers`).
			WithArgs(anyArgs(23)...).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), provider)
		require.NoError(t, err)
		assert.Equal(t, "tenant", provider.Scope)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		provider := sampleProvider()
		mock.ExpectQuery(`INSERT INTO iam_identity_providers`).
			WithArgs(anyArgs(23)...).
			WillReturnError(fmt.Errorf("duplicate provider name"))

		err := repo.Create(context.Background(), provider)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByID ─────────────────────────────────────────────────────────────────

func TestIdentityProviderRepository_GetByID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		provider := sampleProvider()
		rows := mock.NewRows(providerCols).AddRow(providerRow(provider)...)
		mock.ExpectQuery(`SELECT`).WithArgs(provider.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), provider.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, provider.ID, got.ID)
		assert.Equal(t, provider.Type, got.Type)
		assert.Equal(t, provider.Name, got.Name)
		assert.Equal(t, provider.TenantID, got.TenantID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil (no error)", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(id).WillReturnRows(mock.NewRows(providerCols))

		got, err := repo.GetByID(context.Background(), id)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(id).WillReturnError(fmt.Errorf("db down"))

		got, err := repo.GetByID(context.Background(), id)
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("realm-scoped provider has nil tenant_id set correctly", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		realmID := uuid.New()
		provider := sampleProvider()
		provider.TenantID = uuid.Nil
		provider.Scope = idpScopeRealm
		provider.RealmID = &realmID

		row := providerRow(provider) // tenant_id pointer will be nil
		rows := mock.NewRows(providerCols).AddRow(row...)
		mock.ExpectQuery(`SELECT`).WithArgs(provider.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), provider.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, uuid.Nil, got.TenantID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByTenantAndType ──────────────────────────────────────────────────────

func TestIdentityProviderRepository_GetByTenantAndType(t *testing.T) {
	t.Run("returns matching providers", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		provider := sampleProvider()
		rows := mock.NewRows(providerCols).AddRow(providerRow(provider)...)
		mock.ExpectQuery(`SELECT`).WithArgs(provider.TenantID, "oidc").WillReturnRows(rows)

		providers, err := repo.GetByTenantAndType(context.Background(), provider.TenantID, "oidc")
		require.NoError(t, err)
		assert.Len(t, providers, 1)
		assert.Equal(t, provider.ID, providers[0].ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no matching providers returns empty slice", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID, testIDPTypeLDAP).WillReturnRows(mock.NewRows(providerCols))

		providers, err := repo.GetByTenantAndType(context.Background(), tenantID, testIDPTypeLDAP)
		require.NoError(t, err)
		assert.Empty(t, providers)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── List ────────────────────────────────────────────────────────────────────

func TestIdentityProviderRepository_List(t *testing.T) {
	t.Run("returns all providers for tenant", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		provider1 := sampleProvider()
		provider2 := sampleProvider()
		provider2.ID = uuid.New()
		provider2.Type = testIDPTypeLDAP

		rows := mock.NewRows(providerCols).
			AddRow(providerRow(provider1)...).
			AddRow(providerRow(provider2)...)
		mock.ExpectQuery(`SELECT`).WithArgs(provider1.TenantID).WillReturnRows(rows)

		providers, err := repo.List(context.Background(), provider1.TenantID)
		require.NoError(t, err)
		assert.Len(t, providers, 2)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty tenant returns empty slice", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID).WillReturnRows(mock.NewRows(providerCols))

		providers, err := repo.List(context.Background(), tenantID)
		require.NoError(t, err)
		assert.Empty(t, providers)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID).WillReturnError(fmt.Errorf("connection error"))

		_, err := repo.List(context.Background(), tenantID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── ListByRealm ─────────────────────────────────────────────────────────────

func TestIdentityProviderRepository_ListByRealm(t *testing.T) {
	t.Run("returns realm-scoped providers", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		realmID := uuid.New()
		provider := sampleProvider()
		provider.Scope = idpScopeRealm
		provider.RealmID = &realmID
		provider.TenantID = uuid.Nil

		rows := mock.NewRows(providerCols).AddRow(providerRow(provider)...)
		mock.ExpectQuery(`SELECT`).WithArgs(realmID).WillReturnRows(rows)

		providers, err := repo.ListByRealm(context.Background(), realmID)
		require.NoError(t, err)
		assert.Len(t, providers, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Delete ──────────────────────────────────────────────────────────────────

func TestIdentityProviderRepository_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_identity_providers`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(context.Background(), id)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_identity_providers`).
			WithArgs(id).
			WillReturnError(fmt.Errorf("foreign key constraint"))

		err := repo.Delete(context.Background(), id)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetAllByType ────────────────────────────────────────────────────────────

func TestIdentityProviderRepository_GetAllByType(t *testing.T) {
	t.Run("returns all providers of type ldap", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		p1 := sampleProvider()
		p1.Type = testIDPTypeLDAP
		p2 := sampleProvider()
		p2.ID = uuid.New()
		p2.Type = testIDPTypeLDAP

		rows := mock.NewRows(providerCols).
			AddRow(providerRow(p1)...).
			AddRow(providerRow(p2)...)
		mock.ExpectQuery(`SELECT`).WithArgs(testIDPTypeLDAP).WillReturnRows(rows)

		providers, err := repo.GetAllByType(context.Background(), testIDPTypeLDAP)
		require.NoError(t, err)
		assert.Len(t, providers, 2)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("unknown type returns empty slice", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WithArgs("nonexistent").WillReturnRows(mock.NewRows(providerCols))

		providers, err := repo.GetAllByType(context.Background(), "nonexistent")
		require.NoError(t, err)
		assert.Empty(t, providers)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetEnabledLoginProviders ────────────────────────────────────────────────

var enabledLoginProviderCols = []string{
	"id", "tenant_id", "realm_id", "scope", "provider_type", "provider_name", "display_name",
	"client_id", "authorization_url",
	"ldap_config",
	"is_active", "is_default", "priority", "created_at", "updated_at",
}

func TestIdentityProviderRepository_GetEnabledLoginProviders(t *testing.T) {
	now := time.Now()

	t.Run("returns enabled providers for tenant and realm", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		tenantID := uuid.New()
		realmID := uuid.New()

		// The oidc row carries real credentials: a provider without them cannot
		// start a login and is now filtered out (see the subtest below), so an
		// uncredentialed fixture would be testing the filter rather than the scan.
		clientID := "google-client-id"
		authURL := "https://accounts.google.com/o/oauth2/v2/auth"
		rows := mock.NewRows(enabledLoginProviderCols).
			AddRow(uuid.New(), &tenantID, nil, "tenant", "oidc", "google", "Google", &clientID, &authURL, nil, true, false, 100, now, now).
			AddRow(uuid.New(), nil, &realmID, idpScopeRealm, "saml", "corp-saml", "Corp SAML", nil, nil, nil, true, false, 50, now, now)
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID, realmID).WillReturnRows(rows)

		providers, err := repo.GetEnabledLoginProviders(context.Background(), tenantID, realmID)
		require.NoError(t, err)
		assert.Len(t, providers, 2, "a credentialed oidc provider and a saml provider are both offerable")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("does not offer a provider that cannot start a login", func(t *testing.T) {
		// CONTROL: an enabled-but-uncredentialed OAuth row must not render a
		// login button. Previously it did, and clicking it sent the user to the
		// IdP with client_id= empty, so the failure surfaced on the IdP's
		// property after the button looked fine.
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		tenantID := uuid.New()
		realmID := uuid.New()

		rows := mock.NewRows(enabledLoginProviderCols).
			// enabled, but no client_id and no authorization_url
			AddRow(uuid.New(), &tenantID, nil, "tenant", "oidc", "google", "Google", nil, nil, nil, true, false, 100, now, now).
			// SAML keeps its credentials elsewhere and must still be offered
			AddRow(uuid.New(), nil, &realmID, idpScopeRealm, "saml", "corp-saml", "Corp SAML", nil, nil, nil, true, false, 50, now, now)
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID, realmID).WillReturnRows(rows)

		providers, err := repo.GetEnabledLoginProviders(context.Background(), tenantID, realmID)
		require.NoError(t, err)
		require.Len(t, providers, 1, "the uncredentialed oidc provider must be filtered out")
		assert.Equal(t, "corp-saml", providers[0].Name, "SAML must NOT be swept up by an OAuth credential rule")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty returns nil", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		tenantID := uuid.New()
		realmID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID, realmID).WillReturnRows(mock.NewRows(enabledLoginProviderCols))

		providers, err := repo.GetEnabledLoginProviders(context.Background(), tenantID, realmID)
		require.NoError(t, err)
		assert.Empty(t, providers)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		tenantID := uuid.New()
		realmID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID, realmID).WillReturnError(fmt.Errorf("db error"))

		_, err := repo.GetEnabledLoginProviders(context.Background(), tenantID, realmID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetEnabledSocialProviders ───────────────────────────────────────────────

var enabledSocialProviderCols = []string{
	"id", "tenant_id", "realm_id", "scope", "provider_type", "provider_name", "display_name",
	"client_id", "authorization_url",
	"is_active", "is_default", "priority", "created_at", "updated_at",
}

func TestIdentityProviderRepository_GetEnabledSocialProviders(t *testing.T) {
	now := time.Now()

	t.Run("returns social providers", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		tenantID := uuid.New()
		realmID := uuid.New()

		rows := mock.NewRows(enabledSocialProviderCols).
			AddRow(uuid.New(), &tenantID, nil, "tenant", "google", "google-oauth", "Google", nil, nil, true, false, 100, now, now)
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID, realmID).WillReturnRows(rows)

		providers, err := repo.GetEnabledSocialProviders(context.Background(), tenantID, realmID)
		require.NoError(t, err)
		assert.Len(t, providers, 1)
		assert.Equal(t, "google", providers[0].Type)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty returns nil", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		tenantID := uuid.New()
		realmID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID, realmID).WillReturnRows(mock.NewRows(enabledSocialProviderCols))

		providers, err := repo.GetEnabledSocialProviders(context.Background(), tenantID, realmID)
		require.NoError(t, err)
		assert.Empty(t, providers)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Update (immutability guard behavior via mock) ───────────────────────────

func TestIdentityProviderRepository_Update(t *testing.T) {
	t.Run("rejects scope change", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		existing := sampleProvider()
		existing.Scope = "tenant"

		// GetByID called inside Update for immutability check
		rows := mock.NewRows(providerCols).AddRow(providerRow(existing)...)
		mock.ExpectQuery(`SELECT`).WithArgs(existing.ID).WillReturnRows(rows)

		// Now try to update with different scope
		mutated := *existing
		mutated.Scope = idpScopeRealm

		err := repo.Update(context.Background(), &mutated)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SECURITY")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("provider not found returns error", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		provider := sampleProvider()
		// GetByID returns no rows
		mock.ExpectQuery(`SELECT`).WithArgs(provider.ID).WillReturnRows(mock.NewRows(providerCols))

		err := repo.Update(context.Background(), provider)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("success updates mutable fields", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		now := time.Now()
		provider := sampleProvider()

		// GetByID for immutability check
		rows := mock.NewRows(providerCols).AddRow(providerRow(provider)...)
		mock.ExpectQuery(`SELECT`).WithArgs(provider.ID).WillReturnRows(rows)

		// UPDATE RETURNING updated_at
		mock.ExpectQuery(`UPDATE iam_identity_providers SET`).
			WithArgs(anyArgs(15)...).
			WillReturnRows(mock.NewRows([]string{"updated_at"}).AddRow(now))

		err := repo.Update(context.Background(), provider)
		require.NoError(t, err)
		assert.Equal(t, now, provider.UpdatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── CreateRealmProvider ─────────────────────────────────────────────────────

func TestIdentityProviderRepository_CreateRealmProvider(t *testing.T) {
	t.Run("sets scope to realm and tenant_id to nil", func(t *testing.T) {
		mock, repo := newIDPRepoMock(t)
		defer mock.Close()

		now := time.Now()
		provider := sampleProvider()
		provider.Scope = "tenant" // should be overwritten

		rows := mock.NewRows([]string{"created_at", "updated_at"}).AddRow(now, now)
		mock.ExpectQuery(`INSERT INTO iam_identity_providers`).
			WithArgs(anyArgs(23)...).
			WillReturnRows(rows)

		err := repo.CreateRealmProvider(context.Background(), provider)
		require.NoError(t, err)
		assert.Equal(t, idpScopeRealm, provider.Scope)
		assert.Equal(t, uuid.Nil, provider.TenantID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
