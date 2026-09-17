// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const msgSAMLServiceProviderNotFound = "SAML service provider not found"

// SAMLRepository handles SAML service provider database operations
type SAMLRepository struct {
	pool *pgxpool.Pool
}

// NewSAMLRepository creates a new SAMLRepository
func NewSAMLRepository(pool *pgxpool.Pool) *SAMLRepository {
	return &SAMLRepository{pool: pool}
}

// ==================== Service Provider Operations ====================

// GetByID retrieves a SAML service provider by its UUID
func (r *SAMLRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.SAMLServiceProvider, error) {
	query := `
		SELECT id, tenant_id, name, entity_id, acs_url, slo_url, metadata_url,
		       certificate, name_id_format, sign_assertions, encrypt_assertions,
		       attribute_mapping, allowed_attributes, is_active,
		       created_at, updated_at, created_by
		FROM iam_saml_service_providers
		WHERE id = $1`

	sp := &models.SAMLServiceProvider{}
	var allowedAttrs []string
	var attrMapping []byte

	err := r.pool.QueryRow(ctx, query, id).Scan(
		&sp.ID, &sp.TenantID, &sp.Name, &sp.EntityID, &sp.ACSURL, &sp.SLOURL,
		&sp.MetadataURL, &sp.Certificate, &sp.NameIDFormat, &sp.SignAssertions,
		&sp.EncryptAssertions, &attrMapping, &allowedAttrs, &sp.IsActive,
		&sp.CreatedAt, &sp.UpdatedAt, &sp.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgSAMLServiceProviderNotFound)
		}
		return nil, fmt.Errorf("failed to get SAML service provider: %w", err)
	}

	sp.AllowedAttributes = allowedAttrs
	if len(attrMapping) > 0 {
		_ = json.Unmarshal(attrMapping, &sp.AttributeMapping)
	}

	return sp, nil
}

// GetByEntityID retrieves a SAML service provider by its entity ID
func (r *SAMLRepository) GetByEntityID(ctx context.Context, tenantID uuid.UUID, entityID string) (*models.SAMLServiceProvider, error) {
	query := `
		SELECT id, tenant_id, name, entity_id, acs_url, slo_url, metadata_url,
		       certificate, name_id_format, sign_assertions, encrypt_assertions,
		       attribute_mapping, allowed_attributes, is_active,
		       created_at, updated_at, created_by
		FROM iam_saml_service_providers
		WHERE tenant_id = $1 AND entity_id = $2`

	sp := &models.SAMLServiceProvider{}
	var allowedAttrs []string
	var attrMapping []byte

	err := r.pool.QueryRow(ctx, query, tenantID, entityID).Scan(
		&sp.ID, &sp.TenantID, &sp.Name, &sp.EntityID, &sp.ACSURL, &sp.SLOURL,
		&sp.MetadataURL, &sp.Certificate, &sp.NameIDFormat, &sp.SignAssertions,
		&sp.EncryptAssertions, &attrMapping, &allowedAttrs, &sp.IsActive,
		&sp.CreatedAt, &sp.UpdatedAt, &sp.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgSAMLServiceProviderNotFound)
		}
		return nil, fmt.Errorf("failed to get SAML service provider: %w", err)
	}

	sp.AllowedAttributes = allowedAttrs
	if len(attrMapping) > 0 {
		_ = json.Unmarshal(attrMapping, &sp.AttributeMapping)
	}

	return sp, nil
}

// GetByTenantID retrieves all SAML service providers for a tenant
func (r *SAMLRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.SAMLServiceProvider, error) {
	query := `
		SELECT id, tenant_id, name, entity_id, acs_url, slo_url, metadata_url,
		       certificate, name_id_format, sign_assertions, encrypt_assertions,
		       attribute_mapping, allowed_attributes, is_active,
		       created_at, updated_at, created_by
		FROM iam_saml_service_providers
		WHERE tenant_id = $1
		ORDER BY name`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list SAML service providers: %w", err)
	}
	defer rows.Close()

	var providers []*models.SAMLServiceProvider
	for rows.Next() {
		sp := &models.SAMLServiceProvider{}
		var allowedAttrs []string
		var attrMapping []byte

		err := rows.Scan(
			&sp.ID, &sp.TenantID, &sp.Name, &sp.EntityID, &sp.ACSURL, &sp.SLOURL,
			&sp.MetadataURL, &sp.Certificate, &sp.NameIDFormat, &sp.SignAssertions,
			&sp.EncryptAssertions, &attrMapping, &allowedAttrs, &sp.IsActive,
			&sp.CreatedAt, &sp.UpdatedAt, &sp.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SAML service provider: %w", err)
		}

		sp.AllowedAttributes = allowedAttrs
		if len(attrMapping) > 0 {
			_ = json.Unmarshal(attrMapping, &sp.AttributeMapping)
		}

		providers = append(providers, sp)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetByTenantID: rows iteration: %w", err)
	}

	return providers, nil
}

// Create creates a new SAML service provider
func (r *SAMLRepository) Create(ctx context.Context, sp *models.SAMLServiceProvider) error {
	attrMapping, _ := json.Marshal(sp.AttributeMapping)

	query := `
		INSERT INTO iam_saml_service_providers (
			id, tenant_id, name, entity_id, acs_url, slo_url, metadata_url,
			certificate, name_id_format, sign_assertions, encrypt_assertions,
			attribute_mapping, allowed_attributes, is_active,
			created_at, updated_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)`

	_, err := r.pool.Exec(ctx, query,
		sp.ID, sp.TenantID, sp.Name, sp.EntityID, sp.ACSURL, sp.SLOURL,
		sp.MetadataURL, sp.Certificate, sp.NameIDFormat, sp.SignAssertions,
		sp.EncryptAssertions, attrMapping, sp.AllowedAttributes,
		sp.IsActive, sp.CreatedAt, sp.UpdatedAt, sp.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create SAML service provider: %w", err)
	}

	return nil
}

// Update updates a SAML service provider
func (r *SAMLRepository) Update(ctx context.Context, sp *models.SAMLServiceProvider) error {
	attrMapping, _ := json.Marshal(sp.AttributeMapping)

	query := `
		UPDATE iam_saml_service_providers SET
			name = $1, entity_id = $2, acs_url = $3, slo_url = $4, metadata_url = $5,
			certificate = $6, name_id_format = $7, sign_assertions = $8,
			encrypt_assertions = $9, attribute_mapping = $10, allowed_attributes = $11,
			is_active = $12, updated_at = $13
		WHERE id = $14`

	result, err := r.pool.Exec(ctx, query,
		sp.Name, sp.EntityID, sp.ACSURL, sp.SLOURL, sp.MetadataURL,
		sp.Certificate, sp.NameIDFormat, sp.SignAssertions,
		sp.EncryptAssertions, attrMapping, sp.AllowedAttributes,
		sp.IsActive, sp.UpdatedAt, sp.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update SAML service provider: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgSAMLServiceProviderNotFound)
	}

	return nil
}

// Delete deletes a SAML service provider
func (r *SAMLRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM iam_saml_service_providers WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete SAML service provider: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgSAMLServiceProviderNotFound)
	}

	return nil
}

// ==================== Assertion Log Operations ====================

// CreateAssertionLog creates a new assertion log entry
func (r *SAMLRepository) CreateAssertionLog(ctx context.Context, log *models.SAMLAssertionLog) error {
	query := `
		INSERT INTO iam_saml_assertion_logs (
			id, sp_id, user_id, assertion_id, name_id, ip_address,
			user_agent, status, error_message, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.pool.Exec(ctx, query,
		log.ID, log.SPID, log.UserID, log.AssertionID, log.NameID,
		log.IPAddress, log.UserAgent, log.Status, log.ErrorMessage, log.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create assertion log: %w", err)
	}

	return nil
}

// GetAssertionLogs retrieves assertion logs for a service provider
func (r *SAMLRepository) GetAssertionLogs(ctx context.Context, spID uuid.UUID, limit int) ([]*models.SAMLAssertionLog, error) {
	query := `
		SELECT id, sp_id, user_id, assertion_id, name_id, ip_address,
		       user_agent, status, error_message, created_at
		FROM iam_saml_assertion_logs
		WHERE sp_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.pool.Query(ctx, query, spID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list assertion logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.SAMLAssertionLog
	for rows.Next() {
		log := &models.SAMLAssertionLog{}
		err := rows.Scan(
			&log.ID, &log.SPID, &log.UserID, &log.AssertionID, &log.NameID,
			&log.IPAddress, &log.UserAgent, &log.Status, &log.ErrorMessage, &log.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan assertion log: %w", err)
		}
		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetAssertionLogs: rows iteration: %w", err)
	}

	return logs, nil
}

// CleanupOldLogs removes logs older than the specified duration
func (r *SAMLRepository) CleanupOldLogs(ctx context.Context, olderThan time.Duration) error {
	query := `DELETE FROM iam_saml_assertion_logs WHERE created_at < $1`
	_, err := r.pool.Exec(ctx, query, time.Now().Add(-olderThan))
	if err != nil {
		return fmt.Errorf("failed to cleanup old logs: %w", err)
	}
	return nil
}

// ==================== Metadata Discovery Operations ====================

// GetSPsForMetadataRefresh returns SPs that have auto-refresh enabled and are due for refresh
func (r *SAMLRepository) GetSPsForMetadataRefresh(ctx context.Context) ([]*models.SAMLServiceProvider, error) {
	query := `
		SELECT id, tenant_id, name, entity_id, acs_url, slo_url, metadata_url,
		       certificate, name_id_format, sign_assertions, encrypt_assertions,
		       attribute_mapping, allowed_attributes, is_active,
		       raw_metadata_xml, metadata_last_fetched, metadata_auto_refresh,
		       metadata_refresh_interval_hours, detected_idp_type, organization_name,
		       certificate_expiry, metadata_import_source,
		       created_at, updated_at, created_by
		FROM iam_saml_service_providers
		WHERE metadata_auto_refresh = true
		  AND is_active = true
		  AND metadata_url IS NOT NULL
		  AND (metadata_last_fetched IS NULL
		       OR metadata_last_fetched < now() - (metadata_refresh_interval_hours || ' hours')::interval)`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("GetSPsForMetadataRefresh: %w", err)
	}
	defer rows.Close()

	var providers []*models.SAMLServiceProvider
	for rows.Next() {
		sp := &models.SAMLServiceProvider{}
		var allowedAttrs []string
		var attrMapping []byte

		err := rows.Scan(
			&sp.ID, &sp.TenantID, &sp.Name, &sp.EntityID, &sp.ACSURL, &sp.SLOURL,
			&sp.MetadataURL, &sp.Certificate, &sp.NameIDFormat, &sp.SignAssertions,
			&sp.EncryptAssertions, &attrMapping, &allowedAttrs, &sp.IsActive,
			&sp.RawMetadataXML, &sp.MetadataLastFetched, &sp.MetadataAutoRefresh,
			&sp.MetadataRefreshIntervalHrs, &sp.DetectedIDPType, &sp.OrganizationName,
			&sp.CertificateExpiry, &sp.MetadataImportSource,
			&sp.CreatedAt, &sp.UpdatedAt, &sp.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("GetSPsForMetadataRefresh scan: %w", err)
		}
		sp.AllowedAttributes = allowedAttrs
		if len(attrMapping) > 0 {
			_ = json.Unmarshal(attrMapping, &sp.AttributeMapping)
		}
		providers = append(providers, sp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetSPsForMetadataRefresh iteration: %w", err)
	}
	return providers, nil
}

// UpdateMetadataFields updates metadata-specific fields after a refresh
func (r *SAMLRepository) UpdateMetadataFields(ctx context.Context, sp *models.SAMLServiceProvider) error {
	query := `
		UPDATE iam_saml_service_providers SET
			certificate = $1, raw_metadata_xml = $2, metadata_last_fetched = $3,
			detected_idp_type = $4, organization_name = $5, certificate_expiry = $6,
			updated_at = now()
		WHERE id = $7`

	_, err := r.pool.Exec(ctx, query,
		sp.Certificate, sp.RawMetadataXML, sp.MetadataLastFetched,
		sp.DetectedIDPType, sp.OrganizationName, sp.CertificateExpiry,
		sp.ID,
	)
	if err != nil {
		return fmt.Errorf("UpdateMetadataFields: %w", err)
	}
	return nil
}

// CreateMetadataRefreshLog creates a metadata refresh log entry
func (r *SAMLRepository) CreateMetadataRefreshLog(ctx context.Context, log *models.SAMLMetadataRefreshLog) error {
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}
	log.CreatedAt = time.Now()

	var changesJSON []byte
	if log.Changes != nil {
		var err error
		changesJSON, err = json.Marshal(log.Changes)
		if err != nil {
			return fmt.Errorf("failed to marshal changes: %w", err)
		}
	}

	query := `
		INSERT INTO iam_saml_metadata_refresh_logs (
			id, sp_id, status, changes, error_message,
			cert_rotated, old_cert_expiry, new_cert_expiry, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.pool.Exec(ctx, query,
		log.ID, log.SPID, log.Status, changesJSON, log.ErrorMessage,
		log.CertRotated, log.OldCertExpiry, log.NewCertExpiry, log.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("CreateMetadataRefreshLog: %w", err)
	}
	return nil
}

// GetMetadataRefreshLogs returns refresh logs for a SP
func (r *SAMLRepository) GetMetadataRefreshLogs(ctx context.Context, spID uuid.UUID, limit int) ([]*models.SAMLMetadataRefreshLog, error) {
	query := `
		SELECT id, sp_id, status, changes, error_message,
		       cert_rotated, old_cert_expiry, new_cert_expiry, created_at
		FROM iam_saml_metadata_refresh_logs
		WHERE sp_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.pool.Query(ctx, query, spID, limit)
	if err != nil {
		return nil, fmt.Errorf("GetMetadataRefreshLogs: %w", err)
	}
	defer rows.Close()

	var logs []*models.SAMLMetadataRefreshLog
	for rows.Next() {
		log := &models.SAMLMetadataRefreshLog{}
		var changesJSON []byte
		err := rows.Scan(
			&log.ID, &log.SPID, &log.Status, &changesJSON, &log.ErrorMessage,
			&log.CertRotated, &log.OldCertExpiry, &log.NewCertExpiry, &log.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetMetadataRefreshLogs scan: %w", err)
		}
		if len(changesJSON) > 0 {
			_ = json.Unmarshal(changesJSON, &log.Changes)
		}
		logs = append(logs, log)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetMetadataRefreshLogs iteration: %w", err)
	}
	return logs, nil
}
