// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ServicePrincipalRepository handles service principal database operations.
type ServicePrincipalRepository struct {
	pool *pgxpool.Pool
}

// NewServicePrincipalRepository creates a new ServicePrincipalRepository.
func NewServicePrincipalRepository(pool *pgxpool.Pool) *ServicePrincipalRepository {
	return &ServicePrincipalRepository{pool: pool}
}

const spSelectColumns = `id, product_id, name, slug, description, public_key_pem, key_id,
	allowed_scopes, ip_allowlist::text[], status, last_authenticated_at, created_at, updated_at,
	type, application_id, tenant_id, display_name_override, oauth_client_id, installation_status`

func scanSP(scanner interface {
	Scan(dest ...interface{}) error
},
) (*models.ServicePrincipal, error) {
	sp := &models.ServicePrincipal{}
	err := scanner.Scan(
		&sp.ID, &sp.ProductID, &sp.Name, &sp.Slug, &sp.Description,
		&sp.PublicKeyPEM, &sp.KeyID, &sp.AllowedScopes, &sp.IPAllowlist,
		&sp.Status, &sp.LastAuthenticatedAt, &sp.CreatedAt, &sp.UpdatedAt,
		&sp.Type, &sp.ApplicationID, &sp.TenantID,
		&sp.DisplayNameOverride, &sp.OAuthClientID, &sp.InstallationStatus,
	)
	if err != nil {
		return nil, err
	}
	return sp, nil
}

// Create creates a new service principal.
func (r *ServicePrincipalRepository) Create(ctx context.Context, sp *models.ServicePrincipal) error {
	if sp.Type == "" {
		sp.Type = models.SPTypeLegacy
	}
	if sp.InstallationStatus == "" {
		sp.InstallationStatus = models.SPInstallStatusEnabled
	}

	_, err := r.pool.Exec(ctx,
		`INSERT INTO iam_service_principals (id, product_id, name, slug, description, public_key_pem, key_id, allowed_scopes, ip_allowlist, status, created_at, updated_at, type, application_id, tenant_id, display_name_override, oauth_client_id, installation_status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
		sp.ID, sp.ProductID, sp.Name, sp.Slug, sp.Description, sp.PublicKeyPEM, sp.KeyID, sp.AllowedScopes, sp.IPAllowlist, sp.Status, sp.CreatedAt, sp.UpdatedAt,
		sp.Type, sp.ApplicationID, sp.TenantID, sp.DisplayNameOverride, sp.OAuthClientID, sp.InstallationStatus,
	)
	if err != nil {
		return fmt.Errorf("failed to create service principal: %w", err)
	}
	return nil
}

// GetByID retrieves a service principal by ID.
func (r *ServicePrincipalRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ServicePrincipal, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_service_principals WHERE id = $1`, spSelectColumns)
	sp, err := scanSP(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("failed to get service principal: %w", err)
	}
	return sp, nil
}

// GetBySlug retrieves a service principal by slug.
func (r *ServicePrincipalRepository) GetBySlug(ctx context.Context, slug string) (*models.ServicePrincipal, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_service_principals WHERE slug = $1`, spSelectColumns)
	sp, err := scanSP(r.pool.QueryRow(ctx, query, slug))
	if err != nil {
		return nil, fmt.Errorf("failed to get service principal by slug: %w", err)
	}
	return sp, nil
}

// GetByKeyID retrieves a service principal by key ID (for JWT kid lookup).
func (r *ServicePrincipalRepository) GetByKeyID(ctx context.Context, keyID string) (*models.ServicePrincipal, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_service_principals WHERE key_id = $1 AND status = 'active'`, spSelectColumns)
	sp, err := scanSP(r.pool.QueryRow(ctx, query, keyID))
	if err != nil {
		return nil, fmt.Errorf("failed to get service principal by key_id: %w", err)
	}
	return sp, nil
}

// List lists all service principals.
func (r *ServicePrincipalRepository) List(ctx context.Context) ([]models.ServicePrincipal, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_service_principals ORDER BY created_at DESC`, spSelectColumns)
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list service principals: %w", err)
	}
	defer rows.Close()

	var result []models.ServicePrincipal
	for rows.Next() {
		sp, err := scanSP(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan service principal: %w", err)
		}
		result = append(result, *sp)
	}
	return result, rows.Err()
}

// GetByApplicationAndTenant retrieves the SP for a given (application_id, tenant_id) pair.
func (r *ServicePrincipalRepository) GetByApplicationAndTenant(ctx context.Context, appID, tenantID uuid.UUID) (*models.ServicePrincipal, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_service_principals WHERE application_id = $1 AND tenant_id = $2`, spSelectColumns)
	sp, err := scanSP(r.pool.QueryRow(ctx, query, appID, tenantID))
	if err != nil {
		return nil, fmt.Errorf("failed to get SP by app+tenant: %w", err)
	}
	return sp, nil
}

// ListByTenant lists all service principals for a tenant.
func (r *ServicePrincipalRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ServicePrincipal, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_service_principals WHERE tenant_id = $1 ORDER BY created_at DESC`, spSelectColumns)
	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list SPs by tenant: %w", err)
	}
	defer rows.Close()

	var result []models.ServicePrincipal
	for rows.Next() {
		sp, err := scanSP(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SP: %w", err)
		}
		result = append(result, *sp)
	}
	return result, rows.Err()
}

// ListTenantInventory returns a credential-free tenant-scoped projection.
// The global List method remains the platform administration surface.
//
// Tenant API keys (iam_api_keys, kind 'tenant') are machine principals too:
// they are listed alongside service principals with the display name
// "API anahtarı: <name>" and kind "api_key".
func (r *ServicePrincipalRepository) ListTenantInventory(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]models.TenantMachinePrincipal, int64, error) {
	const union = `
		SELECT id, name, status, created_at, 'service_principal' AS kind, 'iam_service_principals' AS source
		FROM iam_service_principals WHERE tenant_id = $1
		UNION ALL
		SELECT id, 'API anahtarı: ' || name,
		       CASE WHEN revoked_at IS NOT NULL OR NOT COALESCE(is_active, TRUE) THEN 'revoked'
		            WHEN expires_at IS NOT NULL AND expires_at <= NOW() THEN 'expired'
		            ELSE 'active' END,
		       created_at, 'api_key', 'iam_api_keys'
		FROM iam_api_keys WHERE tenant_id = $1 AND kind = 'tenant'`
	var total int64
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM (`+union+`) m`, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count tenant service principals: %w", err)
	}
	rows, err := r.pool.Query(ctx, `SELECT id, name, status, created_at, kind, source FROM (`+union+`) m
		ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`, tenantID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("list tenant service principals: %w", err)
	}
	defer rows.Close()
	items := make([]models.TenantMachinePrincipal, 0)
	for rows.Next() {
		var item models.TenantMachinePrincipal
		if err := rows.Scan(&item.ID, &item.Name, &item.Status, &item.CreatedAt, &item.Kind, &item.Source); err != nil {
			return nil, 0, fmt.Errorf("scan tenant service principal: %w", err)
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

// ListByApplication lists all service principals for an application.
func (r *ServicePrincipalRepository) ListByApplication(ctx context.Context, appID uuid.UUID) ([]models.ServicePrincipal, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_service_principals WHERE application_id = $1 ORDER BY created_at DESC`, spSelectColumns)
	rows, err := r.pool.Query(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to list SPs by application: %w", err)
	}
	defer rows.Close()

	var result []models.ServicePrincipal
	for rows.Next() {
		sp, err := scanSP(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SP: %w", err)
		}
		result = append(result, *sp)
	}
	return result, rows.Err()
}

// Update updates a service principal.
func (r *ServicePrincipalRepository) Update(ctx context.Context, sp *models.ServicePrincipal) error {
	sp.UpdatedAt = time.Now()
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_service_principals SET name = $1, description = $2, allowed_scopes = $3, ip_allowlist = $4, status = $5, updated_at = $6, display_name_override = $7, installation_status = $8 WHERE id = $9`,
		sp.Name, sp.Description, sp.AllowedScopes, sp.IPAllowlist, sp.Status, sp.UpdatedAt, sp.DisplayNameOverride, sp.InstallationStatus, sp.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update service principal: %w", err)
	}
	return nil
}

// RotateKey updates the public key and key ID for a service principal.
func (r *ServicePrincipalRepository) RotateKey(ctx context.Context, id uuid.UUID, publicKeyPEM, keyID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_service_principals SET public_key_pem = $1, key_id = $2, updated_at = NOW() WHERE id = $3`,
		publicKeyPEM, keyID, id,
	)
	if err != nil {
		return fmt.Errorf("failed to rotate service principal key: %w", err)
	}
	return nil
}

// UpdateLastAuthenticated updates the last authentication timestamp.
func (r *ServicePrincipalRepository) UpdateLastAuthenticated(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_service_principals SET last_authenticated_at = NOW() WHERE id = $1`, id,
	)
	return err
}

// Delete deletes a service principal.
func (r *ServicePrincipalRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM iam_service_principals WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete service principal: %w", err)
	}
	return nil
}

// RegisterEndpoints registers service endpoints.
func (r *ServicePrincipalRepository) RegisterEndpoints(ctx context.Context, spID uuid.UUID, endpoints []models.ServiceEndpoint) error {
	// Delete existing endpoints for this service
	_, err := r.pool.Exec(ctx, `DELETE FROM iam_service_endpoints WHERE service_principal_id = $1`, spID)
	if err != nil {
		return fmt.Errorf("failed to clear endpoints: %w", err)
	}

	for _, ep := range endpoints {
		_, err := r.pool.Exec(ctx,
			`INSERT INTO iam_service_endpoints (id, service_principal_id, path, method, required_permissions, description, is_internal, rate_limit_rps)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			uuid.New(), spID, ep.Path, ep.Method, ep.RequiredPermissions, ep.Description, ep.IsInternal, ep.RateLimitRPS,
		)
		if err != nil {
			return fmt.Errorf("failed to register endpoint: %w", err)
		}
	}
	return nil
}

// RegisterEvents registers service events.
func (r *ServicePrincipalRepository) RegisterEvents(ctx context.Context, spID uuid.UUID, events []models.ServiceEvent) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM iam_service_events WHERE service_principal_id = $1`, spID)
	if err != nil {
		return fmt.Errorf("failed to clear events: %w", err)
	}

	for _, ev := range events {
		_, err := r.pool.Exec(ctx,
			`INSERT INTO iam_service_events (id, service_principal_id, event_type, schema_version, payload_schema, description)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			uuid.New(), spID, ev.EventType, ev.SchemaVersion, ev.PayloadSchema, ev.Description,
		)
		if err != nil {
			return fmt.Errorf("failed to register event: %w", err)
		}
	}
	return nil
}
