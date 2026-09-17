// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// IdentityProviderRepository is an exported type.
type IdentityProviderRepository struct {
	db DBTX
}

// NewIdentityProviderRepository is an exported function.
func NewIdentityProviderRepository(db *pgxpool.Pool) *IdentityProviderRepository {
	return &IdentityProviderRepository{db: db}
}

// marshalProviderJSON marshals the JSONB config columns for INSERT/UPDATE.
func (r *IdentityProviderRepository) marshalProviderJSON(provider *models.IdentityProvider) (ldap, attr, samlSP, apple []byte, err error) {
	if provider.LDAPConfig != nil {
		ldap, err = json.Marshal(provider.LDAPConfig)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to marshal ldap config: %w", err)
		}
	}
	if provider.AttributeMapping != nil {
		attr, err = json.Marshal(provider.AttributeMapping)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to marshal attribute mapping: %w", err)
		}
	}
	if provider.SAMLSPConfig != nil {
		samlSP, err = json.Marshal(provider.SAMLSPConfig)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to marshal saml sp config: %w", err)
		}
	}
	if provider.AppleConfig != nil {
		apple, err = json.Marshal(provider.AppleConfig)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to marshal apple config: %w", err)
		}
	}
	return ldap, attr, samlSP, apple, nil
}

// tenantIDForInsert returns nil when TenantID is uuid.Nil (realm-scoped providers).
func tenantIDForInsert(tid uuid.UUID) interface{} {
	if tid == uuid.Nil {
		return nil
	}
	return tid
}

// Create is an exported function.
func (r *IdentityProviderRepository) Create(ctx context.Context, provider *models.IdentityProvider) error {
	ldapConfigJSON, attrMappingJSON, samlSPConfigJSON, appleConfigJSON, err := r.marshalProviderJSON(provider)
	if err != nil {
		return err
	}

	if provider.Scope == "" {
		provider.Scope = idpScopeTenant
	}

	query := `
		INSERT INTO iam_identity_providers (
			id, tenant_id, realm_id, scope, provider_type, provider_name, display_name,
			client_id, client_secret_encrypted, authorization_url, token_url, userinfo_url,
			scopes, ldap_config, attribute_mapping, auto_provision_users, default_role_ids,
			is_active, is_default, priority, created_by, saml_sp_config, apple_config
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
		) RETURNING created_at, updated_at`

	if provider.ID == uuid.Nil {
		provider.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		provider.ID, tenantIDForInsert(provider.TenantID), provider.RealmID, provider.Scope,
		provider.Type, provider.Name, provider.DisplayName,
		provider.ClientID, provider.ClientSecretEncrypted, provider.AuthorizationURL, provider.TokenURL, provider.UserInfoURL,
		provider.Scopes, ldapConfigJSON, attrMappingJSON, provider.AutoProvisionUsers, provider.DefaultRoleIDs,
		provider.IsEnabled, provider.IsDefault, provider.Priority, provider.CreatedBy,
		samlSPConfigJSON, appleConfigJSON,
	).Scan(&provider.CreatedAt, &provider.UpdatedAt)
}

const (
	idpScopeTenant = "tenant"
	idpScopeRealm  = "realm"
)

// providerSelectCols is the standard column list for full provider queries.
const providerSelectCols = `id, tenant_id, realm_id, scope, provider_type, provider_name, display_name,
	client_id, client_secret_encrypted, authorization_url, token_url, userinfo_url,
	scopes, ldap_config, attribute_mapping, auto_provision_users, default_role_ids,
	is_active, is_default, priority, created_at, updated_at, created_by,
	saml_sp_config, apple_config`

// scanFullProvider scans a single row into a provider, handling nullable tenant_id.
func (r *IdentityProviderRepository) scanFullProvider(scanner interface {
	Scan(dest ...interface{}) error
}, provider *models.IdentityProvider,
) (ldap, attr, samlSP, apple []byte, err error) {
	var tenantID *uuid.UUID
	var ldapConfigJSON, attrMappingJSON, samlSPConfigJSON, appleConfigJSON []byte

	err = scanner.Scan(
		&provider.ID, &tenantID, &provider.RealmID, &provider.Scope,
		&provider.Type, &provider.Name, &provider.DisplayName,
		&provider.ClientID, &provider.ClientSecretEncrypted, &provider.AuthorizationURL, &provider.TokenURL, &provider.UserInfoURL,
		&provider.Scopes, &ldapConfigJSON, &attrMappingJSON, &provider.AutoProvisionUsers, &provider.DefaultRoleIDs,
		&provider.IsEnabled, &provider.IsDefault, &provider.Priority, &provider.CreatedAt, &provider.UpdatedAt, &provider.CreatedBy,
		&samlSPConfigJSON, &appleConfigJSON,
	)
	if tenantID != nil {
		provider.TenantID = *tenantID
	}
	return ldapConfigJSON, attrMappingJSON, samlSPConfigJSON, appleConfigJSON, err
}

// GetByID is an exported function.
func (r *IdentityProviderRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.IdentityProvider, error) {
	provider := &models.IdentityProvider{}

	query := `SELECT ` + providerSelectCols + ` FROM iam_identity_providers WHERE id = $1`

	ldapJSON, attrJSON, samlSPJSON, appleJSON, err := r.scanFullProvider(
		r.db.QueryRow(ctx, query, id), provider,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}

	if err := r.unmarshalProviderJSON(provider, ldapJSON, attrJSON, samlSPJSON, appleJSON); err != nil {
		return nil, err
	}

	return provider, nil
}

// unmarshalProviderJSON unmarshals JSON config columns into provider struct fields
func (r *IdentityProviderRepository) unmarshalProviderJSON(provider *models.IdentityProvider, ldapJSON, attrJSON, samlSPJSON, appleJSON []byte) error {
	if ldapJSON != nil {
		provider.LDAPConfig = &models.LDAPConfig{}
		if err := json.Unmarshal(ldapJSON, provider.LDAPConfig); err != nil {
			return fmt.Errorf("failed to unmarshal ldap config: %w", err)
		}
	}
	if attrJSON != nil {
		provider.AttributeMapping = make(map[string]string)
		if err := json.Unmarshal(attrJSON, &provider.AttributeMapping); err != nil {
			return fmt.Errorf("failed to unmarshal attribute mapping: %w", err)
		}
	}
	if samlSPJSON != nil {
		provider.SAMLSPConfig = &models.SAMLSPConfig{}
		if err := json.Unmarshal(samlSPJSON, provider.SAMLSPConfig); err != nil {
			return fmt.Errorf("failed to unmarshal saml sp config: %w", err)
		}
	}
	if appleJSON != nil {
		provider.AppleConfig = &models.AppleConfig{}
		if err := json.Unmarshal(appleJSON, provider.AppleConfig); err != nil {
			return fmt.Errorf("failed to unmarshal apple config: %w", err)
		}
	}
	return nil
}

// GetByTenantAndType returns every IDP of the given type for the tenant,
// regardless of whether the IDP is currently active.
//
// The query intentionally does NOT filter on `is_active`. Callers
// (LDAPService.GetActiveLDAPProviders / SocialAuthService.
// resolveOAuthProvider / SAMLSPService.resolveProvider) inspect the
// returned `IsEnabled` field and decide — pre-2026-05-21 the repo
// filtered directly, hiding "IDP was deactivated by tenant admin"
// from the SOC + masking the operational state from
// support tooling. See
// docs/audits/2026-05-21-repo-state-filter-audit.md.
//
// The list is ordered by priority DESC then name ASC so callers that
// "first match wins" (resolveOAuthProvider, resolveProvider) keep
// the highest-priority active IDP at the head when they filter
// inline.
func (r *IdentityProviderRepository) GetByTenantAndType(ctx context.Context, tenantID uuid.UUID, providerType string) ([]*models.IdentityProvider, error) {
	query := `SELECT ` + providerSelectCols + `
		FROM iam_identity_providers
		WHERE tenant_id = $1 AND provider_type = $2
		ORDER BY priority DESC, provider_name ASC`

	return r.scanProviderRows(ctx, query, tenantID, providerType)
}

// scanProviderRows is a helper to scan multiple provider rows with all columns
func (r *IdentityProviderRepository) scanProviderRows(ctx context.Context, query string, args ...interface{}) ([]*models.IdentityProvider, error) {
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("scanProviderRows: %w", err)
	}
	defer rows.Close()

	var providers []*models.IdentityProvider
	for rows.Next() {
		provider := &models.IdentityProvider{}

		ldapJSON, attrJSON, samlSPJSON, appleJSON, err := r.scanFullProvider(rows, provider)
		if err != nil {
			return nil, fmt.Errorf("scanProviderRows scan: %w", err)
		}

		if err := r.unmarshalProviderJSON(provider, ldapJSON, attrJSON, samlSPJSON, appleJSON); err != nil {
			return nil, err
		}

		providers = append(providers, provider)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanProviderRows iteration: %w", err)
	}

	return providers, nil
}

// List is an exported function.
func (r *IdentityProviderRepository) List(ctx context.Context, tenantID uuid.UUID) ([]*models.IdentityProvider, error) {
	query := `SELECT ` + providerSelectCols + `
		FROM iam_identity_providers WHERE tenant_id = $1
		ORDER BY priority DESC, provider_name ASC`

	return r.scanProviderRows(ctx, query, tenantID)
}

// ListByRealm returns realm-scoped providers for a realm.
func (r *IdentityProviderRepository) ListByRealm(ctx context.Context, realmID uuid.UUID) ([]*models.IdentityProvider, error) {
	query := `SELECT ` + providerSelectCols + `
		FROM iam_identity_providers
		WHERE realm_id = $1 AND scope = 'realm'
		ORDER BY priority DESC, provider_name ASC`

	return r.scanProviderRows(ctx, query, realmID)
}

// ListTenantProviderSummaries returns tenant-scoped IDPs for the given tenant IDs,
// joined with iam_tenants to include tenant name/slug. Used by the realm service
// to show all tenant IDPs across a realm (cross-DB: tenant IDs come from control plane).
func (r *IdentityProviderRepository) ListTenantProviderSummaries(ctx context.Context, tenantIDs []uuid.UUID) ([]models.TenantIdentityProviderSummary, error) {
	if len(tenantIDs) == 0 {
		return nil, nil
	}

	query := `
		SELECT ip.id, ip.tenant_id, t.name, t.slug,
		       ip.provider_type, ip.provider_name, ip.display_name,
		       ip.is_active, ip.priority, ip.created_at, ip.updated_at
		FROM iam_identity_providers ip
		JOIN iam_tenants t ON ip.tenant_id = t.id
		WHERE ip.tenant_id = ANY($1) AND ip.scope = 'tenant'
		ORDER BY t.name ASC, ip.priority DESC, ip.provider_name ASC
	`

	rows, err := r.db.Query(ctx, query, tenantIDs)
	if err != nil {
		return nil, fmt.Errorf("ListTenantProviderSummaries: %w", err)
	}
	defer rows.Close()

	var providers []models.TenantIdentityProviderSummary
	for rows.Next() {
		var p models.TenantIdentityProviderSummary
		if err := rows.Scan(
			&p.ID, &p.TenantID, &p.TenantName, &p.TenantSlug,
			&p.Type, &p.Name, &p.DisplayName,
			&p.IsEnabled, &p.Priority, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("ListTenantProviderSummaries: scan: %w", err)
		}
		providers = append(providers, p)
	}
	return providers, rows.Err()
}

// CreateRealmProvider creates a realm-scoped identity provider (scope='realm', tenant_id=NULL).
func (r *IdentityProviderRepository) CreateRealmProvider(ctx context.Context, provider *models.IdentityProvider) error {
	provider.Scope = idpScopeRealm
	provider.TenantID = uuid.Nil
	return r.Create(ctx, provider)
}

// Update modifies an existing identity provider's mutable fields.
// SECURITY: scope, realm_id, and tenant_id are immutable after creation.
// The database trigger (migration 123) enforces this at the storage layer,
// but we also enforce it here for defense-in-depth and clearer error messages.
func (r *IdentityProviderRepository) Update(ctx context.Context, provider *models.IdentityProvider) error {
	// SECURITY: Defense-in-depth — verify scope/tenant/realm are not being changed.
	// The DB trigger will also block this, but catching it here gives a better error.
	existing, err := r.GetByID(ctx, provider.ID)
	if err != nil {
		return fmt.Errorf("Update: failed to fetch existing provider for immutability check: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("Update: identity provider not found: %s", provider.ID)
	}

	if existing.Scope != provider.Scope && provider.Scope != "" {
		return fmt.Errorf("SECURITY: cannot change identity provider scope from %q to %q after creation. "+
			"Delete this provider and recreate it with the desired scope", existing.Scope, provider.Scope)
	}
	if existing.TenantID != provider.TenantID && provider.TenantID != existing.TenantID {
		return fmt.Errorf("SECURITY: cannot change identity provider tenant_id after creation")
	}
	if (existing.RealmID == nil) != (provider.RealmID == nil) ||
		(existing.RealmID != nil && provider.RealmID != nil && *existing.RealmID != *provider.RealmID) {
		return fmt.Errorf("SECURITY: cannot change identity provider realm_id after creation")
	}

	var ldapConfigJSON []byte
	if provider.LDAPConfig != nil {
		ldapConfigJSON, err = json.Marshal(provider.LDAPConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal ldap config: %w", err)
		}
	}

	var attrMappingJSON []byte
	if provider.AttributeMapping != nil {
		attrMappingJSON, err = json.Marshal(provider.AttributeMapping)
		if err != nil {
			return fmt.Errorf("failed to marshal attribute mapping: %w", err)
		}
	}

	query := `
		UPDATE iam_identity_providers SET
			display_name = $2, client_id = $3, client_secret_encrypted = $4,
			authorization_url = $5, token_url = $6, userinfo_url = $7,
			scopes = $8, ldap_config = $9, attribute_mapping = $10,
			auto_provision_users = $11, default_role_ids = $12,
			is_active = $13, is_default = $14, priority = $15, updated_at = now()
		WHERE id = $1
		RETURNING updated_at`

	return r.db.QueryRow(ctx, query,
		provider.ID, provider.DisplayName, provider.ClientID, provider.ClientSecretEncrypted,
		provider.AuthorizationURL, provider.TokenURL, provider.UserInfoURL,
		provider.Scopes, ldapConfigJSON, attrMappingJSON,
		provider.AutoProvisionUsers, provider.DefaultRoleIDs,
		provider.IsEnabled, provider.IsDefault, provider.Priority,
	).Scan(&provider.UpdatedAt)
}

// Delete is an exported function.
func (r *IdentityProviderRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, "DELETE FROM iam_identity_providers WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	return nil
}

// GetAllByType returns all providers of a specific type across all tenants
// Used by AD sync scheduler to find all LDAP providers
func (r *IdentityProviderRepository) GetAllByType(ctx context.Context, providerType string) ([]*models.IdentityProvider, error) {
	query := `SELECT ` + providerSelectCols + `
		FROM iam_identity_providers
		WHERE provider_type = $1
		ORDER BY tenant_id, priority DESC, provider_name ASC`

	return r.scanProviderRows(ctx, query, providerType)
}

// GetEnabledLoginProviders returns ALL enabled identity providers for a tenant and its realm.
// Used by the login page to discover available authentication methods.
// Tenant-scoped providers are returned first, then realm-scoped providers.
func (r *IdentityProviderRepository) GetEnabledLoginProviders(ctx context.Context, tenantID uuid.UUID, realmID uuid.UUID) ([]*models.IdentityProvider, error) {
	query := `
		SELECT id, tenant_id, realm_id, scope, provider_type, provider_name, display_name,
			   client_id, authorization_url,
			   ldap_config,
			   is_active, is_default, priority, created_at, updated_at
		FROM iam_identity_providers
		WHERE ((tenant_id = $1 AND scope = 'tenant')
		    OR (realm_id = $2 AND scope = 'realm'))
		  AND is_active = true
		ORDER BY CASE WHEN scope = 'tenant' THEN 0 ELSE 1 END, priority DESC, provider_name ASC`

	rows, err := r.db.Query(ctx, query, tenantID, realmID)
	if err != nil {
		return nil, fmt.Errorf("GetEnabledLoginProviders: %w", err)
	}
	defer rows.Close()

	var providers []*models.IdentityProvider
	for rows.Next() {
		provider := &models.IdentityProvider{}
		var tenantIDPtr *uuid.UUID
		var ldapConfigJSON []byte
		err := rows.Scan(
			&provider.ID, &tenantIDPtr, &provider.RealmID, &provider.Scope,
			&provider.Type, &provider.Name, &provider.DisplayName,
			&provider.ClientID, &provider.AuthorizationURL,
			&ldapConfigJSON,
			&provider.IsEnabled, &provider.IsDefault, &provider.Priority, &provider.CreatedAt, &provider.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetEnabledLoginProviders scan: %w", err)
		}
		if tenantIDPtr != nil {
			provider.TenantID = *tenantIDPtr
		}

		if ldapConfigJSON != nil {
			provider.LDAPConfig = &models.LDAPConfig{}
			if unmarshalErr := json.Unmarshal(ldapConfigJSON, provider.LDAPConfig); unmarshalErr != nil {
				return nil, fmt.Errorf("GetEnabledLoginProviders unmarshal ldap config: %w", unmarshalErr)
			}
		}

		// SURFACE FILTER: do not offer a login button for a provider that cannot
		// start a login. This is the login/discovery list, not the admin listing,
		// so an incompletely configured provider stays visible to administrators
		// who need to finish configuring it -- it just stops being offered to users.
		if !provider.IsLoginReady() {
			continue
		}

		providers = append(providers, provider)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetEnabledLoginProviders iteration: %w", err)
	}

	return providers, nil
}

// GetEnabledSocialProviders returns enabled social login providers (OAuth-based) for a tenant and its realm.
// These are used for the login screen to show available social login options.
func (r *IdentityProviderRepository) GetEnabledSocialProviders(ctx context.Context, tenantID uuid.UUID, realmID uuid.UUID) ([]*models.IdentityProvider, error) {
	query := `
		SELECT id, tenant_id, realm_id, scope, provider_type, provider_name, display_name,
			   client_id, authorization_url,
			   is_active, is_default, priority, created_at, updated_at
		FROM iam_identity_providers
		WHERE ((tenant_id = $1 AND scope = 'tenant')
		    OR (realm_id = $2 AND scope = 'realm'))
		  AND is_active = true
		  AND provider_type IN ('google', 'microsoft', 'github', 'oauth', 'oidc', 'apple', 'oauth2')
		ORDER BY CASE WHEN scope = 'tenant' THEN 0 ELSE 1 END, priority DESC, provider_name ASC`

	rows, err := r.db.Query(ctx, query, tenantID, realmID)
	if err != nil {
		return nil, fmt.Errorf("GetEnabledSocialProviders: %w", err)
	}
	defer rows.Close()

	var providers []*models.IdentityProvider
	for rows.Next() {
		provider := &models.IdentityProvider{}
		var tenantIDPtr *uuid.UUID
		err := rows.Scan(
			&provider.ID, &tenantIDPtr, &provider.RealmID, &provider.Scope,
			&provider.Type, &provider.Name, &provider.DisplayName,
			&provider.ClientID, &provider.AuthorizationURL,
			&provider.IsEnabled, &provider.IsDefault, &provider.Priority, &provider.CreatedAt, &provider.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetEnabledSocialProviders: %w", err)
		}
		if tenantIDPtr != nil {
			provider.TenantID = *tenantIDPtr
		}
		providers = append(providers, provider)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetEnabledSocialProviders: rows iteration: %w", err)
	}

	return providers, nil
}
