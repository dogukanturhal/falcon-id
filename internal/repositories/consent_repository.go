// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ConsentRepository is an exported type.
type ConsentRepository struct {
	db      DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of ConsentRepository scoped to the given realm.
func (r *ConsentRepository) WithRealmID(realmID uuid.UUID) *ConsentRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewConsentRepository is an exported function.
func NewConsentRepository(db *pgxpool.Pool) *ConsentRepository {
	return &ConsentRepository{db: db}
}

// GetConsentTypes returns all active consent types for a tenant
func (r *ConsentRepository) GetConsentTypes(ctx context.Context, tenantID uuid.UUID) ([]models.ConsentType, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, category,
			   is_required, is_active, version, legal_basis,
			   data_retention_days, external_policy_url, created_at, updated_at
		FROM iam_consent_types
		WHERE tenant_id = $1 AND is_active = true
		ORDER BY is_required DESC, category, display_name`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetConsentTypes: %w", err)
	}
	defer rows.Close()

	var types []models.ConsentType
	for rows.Next() {
		var ct models.ConsentType
		err := rows.Scan(
			&ct.ID, &ct.TenantID, &ct.Name, &ct.DisplayName, &ct.Description,
			&ct.Category, &ct.IsRequired, &ct.IsActive, &ct.Version,
			&ct.LegalBasis, &ct.DataRetentionDays, &ct.ExternalPolicyURL,
			&ct.CreatedAt, &ct.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetConsentTypes: %w", err)
		}
		types = append(types, ct)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetConsentTypes: rows iteration: %w", err)
	}

	return types, nil
}

// GetConsentTypeByID returns a consent type by ID
func (r *ConsentRepository) GetConsentTypeByID(ctx context.Context, id uuid.UUID) (*models.ConsentType, error) {
	ct := &models.ConsentType{}
	query := `
		SELECT id, tenant_id, name, display_name, description, category,
			   is_required, is_active, version, legal_basis,
			   data_retention_days, external_policy_url, created_at, updated_at
		FROM iam_consent_types WHERE id = $1`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&ct.ID, &ct.TenantID, &ct.Name, &ct.DisplayName, &ct.Description,
		&ct.Category, &ct.IsRequired, &ct.IsActive, &ct.Version,
		&ct.LegalBasis, &ct.DataRetentionDays, &ct.ExternalPolicyURL,
		&ct.CreatedAt, &ct.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetConsentTypeByID: %w", err)
	}
	return ct, nil
}

// GetConsentTypeByName returns a consent type by name
func (r *ConsentRepository) GetConsentTypeByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.ConsentType, error) {
	ct := &models.ConsentType{}
	query := `
		SELECT id, tenant_id, name, display_name, description, category,
			   is_required, is_active, version, legal_basis,
			   data_retention_days, external_policy_url, created_at, updated_at
		FROM iam_consent_types WHERE tenant_id = $1 AND name = $2`

	err := r.db.QueryRow(ctx, query, tenantID, name).Scan(
		&ct.ID, &ct.TenantID, &ct.Name, &ct.DisplayName, &ct.Description,
		&ct.Category, &ct.IsRequired, &ct.IsActive, &ct.Version,
		&ct.LegalBasis, &ct.DataRetentionDays, &ct.ExternalPolicyURL,
		&ct.CreatedAt, &ct.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetConsentTypeByName: %w", err)
	}
	return ct, nil
}

// GetUserConsents returns all consents for a user with their types
func (r *ConsentRepository) GetUserConsents(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]models.UserConsentWithType, error) {
	query := `
		SELECT uc.id, uc.user_id, uc.consent_type_id, uc.granted, uc.consent_version,
			   uc.granted_at, uc.revoked_at, uc.ip_address, uc.user_agent,
			   uc.created_at, uc.updated_at,
			   ct.id, ct.tenant_id, ct.name, ct.display_name, ct.description, ct.category,
			   ct.is_required, ct.is_active, ct.version, ct.legal_basis,
			   ct.data_retention_days, ct.external_policy_url, ct.created_at, ct.updated_at
		FROM iam_user_consents uc
		JOIN iam_consent_types ct ON uc.consent_type_id = ct.id
		WHERE uc.user_id = $1 AND ct.tenant_id = $2 AND ct.is_active = true
		ORDER BY ct.is_required DESC, ct.category, ct.display_name`

	rows, err := r.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetUserConsents: %w", err)
	}
	defer rows.Close()

	var consents []models.UserConsentWithType
	for rows.Next() {
		var uc models.UserConsentWithType
		err := rows.Scan(
			&uc.ID, &uc.UserID, &uc.ConsentTypeID, &uc.Granted, &uc.ConsentVersion,
			&uc.GrantedAt, &uc.RevokedAt, &uc.IPAddress, &uc.UserAgent,
			&uc.CreatedAt, &uc.UpdatedAt,
			&uc.ConsentType.ID, &uc.ConsentType.TenantID, &uc.ConsentType.Name,
			&uc.ConsentType.DisplayName, &uc.ConsentType.Description, &uc.ConsentType.Category,
			&uc.ConsentType.IsRequired, &uc.ConsentType.IsActive, &uc.ConsentType.Version,
			&uc.ConsentType.LegalBasis, &uc.ConsentType.DataRetentionDays,
			&uc.ConsentType.ExternalPolicyURL, &uc.ConsentType.CreatedAt, &uc.ConsentType.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetUserConsents: %w", err)
		}
		consents = append(consents, uc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserConsents: rows iteration: %w", err)
	}

	return consents, nil
}

// GetUserConsent returns a specific consent for a user
func (r *ConsentRepository) GetUserConsent(ctx context.Context, userID, consentTypeID uuid.UUID) (*models.UserConsent, error) {
	uc := &models.UserConsent{}
	query := `
		SELECT id, user_id, consent_type_id, granted, consent_version,
			   granted_at, revoked_at, ip_address, user_agent, created_at, updated_at
		FROM iam_user_consents
		WHERE user_id = $1 AND consent_type_id = $2`

	err := r.db.QueryRow(ctx, query, userID, consentTypeID).Scan(
		&uc.ID, &uc.UserID, &uc.ConsentTypeID, &uc.Granted, &uc.ConsentVersion,
		&uc.GrantedAt, &uc.RevokedAt, &uc.IPAddress, &uc.UserAgent,
		&uc.CreatedAt, &uc.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetUserConsent: %w", err)
	}
	return uc, nil
}

// UpsertConsent creates or updates a user consent
func (r *ConsentRepository) UpsertConsent(ctx context.Context, consent *models.UserConsent) error {
	query := `
		INSERT INTO iam_user_consents (
			id, user_id, consent_type_id, granted, consent_version,
			granted_at, revoked_at, ip_address, user_agent
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (user_id, consent_type_id) DO UPDATE SET
			granted = EXCLUDED.granted,
			consent_version = EXCLUDED.consent_version,
			granted_at = CASE WHEN EXCLUDED.granted THEN COALESCE(EXCLUDED.granted_at, NOW()) ELSE iam_user_consents.granted_at END,
			revoked_at = CASE WHEN NOT EXCLUDED.granted THEN COALESCE(EXCLUDED.revoked_at, NOW()) ELSE NULL END,
			ip_address = EXCLUDED.ip_address,
			user_agent = EXCLUDED.user_agent
		RETURNING id, created_at, updated_at`

	if consent.ID == uuid.Nil {
		consent.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		consent.ID, consent.UserID, consent.ConsentTypeID, consent.Granted,
		consent.ConsentVersion, consent.GrantedAt, consent.RevokedAt,
		consent.IPAddress, consent.UserAgent,
	).Scan(&consent.ID, &consent.CreatedAt, &consent.UpdatedAt)
}

// GetRequiredConsentTypes returns all required consent types for a tenant
func (r *ConsentRepository) GetRequiredConsentTypes(ctx context.Context, tenantID uuid.UUID) ([]models.ConsentType, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, category,
			   is_required, is_active, version, legal_basis,
			   data_retention_days, external_policy_url, created_at, updated_at
		FROM iam_consent_types
		WHERE tenant_id = $1 AND is_active = true AND is_required = true
		ORDER BY display_name`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetRequiredConsentTypes: %w", err)
	}
	defer rows.Close()

	var types []models.ConsentType
	for rows.Next() {
		var ct models.ConsentType
		err := rows.Scan(
			&ct.ID, &ct.TenantID, &ct.Name, &ct.DisplayName, &ct.Description,
			&ct.Category, &ct.IsRequired, &ct.IsActive, &ct.Version,
			&ct.LegalBasis, &ct.DataRetentionDays, &ct.ExternalPolicyURL,
			&ct.CreatedAt, &ct.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetRequiredConsentTypes: %w", err)
		}
		types = append(types, ct)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetRequiredConsentTypes: rows iteration: %w", err)
	}

	return types, nil
}

// GetPendingRequiredConsents returns required consents that the user hasn't granted
func (r *ConsentRepository) GetPendingRequiredConsents(ctx context.Context, userID, tenantID uuid.UUID) ([]models.ConsentType, error) {
	query := `
		SELECT ct.id, ct.tenant_id, ct.name, ct.display_name, ct.description, ct.category,
			   ct.is_required, ct.is_active, ct.version, ct.legal_basis,
			   ct.data_retention_days, ct.external_policy_url, ct.created_at, ct.updated_at
		FROM iam_consent_types ct
		LEFT JOIN iam_user_consents uc ON ct.id = uc.consent_type_id AND uc.user_id = $1
		WHERE ct.tenant_id = $2 AND ct.is_active = true AND ct.is_required = true
		  AND (uc.id IS NULL OR uc.granted = false)
		ORDER BY ct.display_name`

	rows, err := r.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetPendingRequiredConsents: %w", err)
	}
	defer rows.Close()

	var types []models.ConsentType
	for rows.Next() {
		var ct models.ConsentType
		err := rows.Scan(
			&ct.ID, &ct.TenantID, &ct.Name, &ct.DisplayName, &ct.Description,
			&ct.Category, &ct.IsRequired, &ct.IsActive, &ct.Version,
			&ct.LegalBasis, &ct.DataRetentionDays, &ct.ExternalPolicyURL,
			&ct.CreatedAt, &ct.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetPendingRequiredConsents: %w", err)
		}
		types = append(types, ct)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetPendingRequiredConsents: rows iteration: %w", err)
	}

	return types, nil
}

// HasGrantedAllRequired checks if a user has granted all required consents
func (r *ConsentRepository) HasGrantedAllRequired(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	pending, err := r.GetPendingRequiredConsents(ctx, userID, tenantID)
	if err != nil {
		return false, fmt.Errorf("HasGrantedAllRequired: GetPendingRequiredConsents failed: %w", err)
	}
	return len(pending) == 0, nil
}

// DeleteUserConsents deletes all consents for a user (for GDPR data erasure)
func (r *ConsentRepository) DeleteUserConsents(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM iam_user_consents WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("DeleteUserConsents: %w", err)
	}
	return nil
}

// GetConsentHistory returns consent history for a user (for audit)
func (r *ConsentRepository) GetConsentHistory(ctx context.Context, userID uuid.UUID, since time.Time) ([]models.UserConsentWithType, error) {
	query := `
		SELECT uc.id, uc.user_id, uc.consent_type_id, uc.granted, uc.consent_version,
			   uc.granted_at, uc.revoked_at, uc.ip_address, uc.user_agent,
			   uc.created_at, uc.updated_at,
			   ct.id, ct.tenant_id, ct.name, ct.display_name, ct.description, ct.category,
			   ct.is_required, ct.is_active, ct.version, ct.legal_basis,
			   ct.data_retention_days, ct.external_policy_url, ct.created_at, ct.updated_at
		FROM iam_user_consents uc
		JOIN iam_consent_types ct ON uc.consent_type_id = ct.id
		WHERE uc.user_id = $1 AND uc.updated_at >= $2
		ORDER BY uc.updated_at DESC`

	rows, err := r.db.Query(ctx, query, userID, since)
	if err != nil {
		return nil, fmt.Errorf("GetConsentHistory: %w", err)
	}
	defer rows.Close()

	var consents []models.UserConsentWithType
	for rows.Next() {
		var uc models.UserConsentWithType
		err := rows.Scan(
			&uc.ID, &uc.UserID, &uc.ConsentTypeID, &uc.Granted, &uc.ConsentVersion,
			&uc.GrantedAt, &uc.RevokedAt, &uc.IPAddress, &uc.UserAgent,
			&uc.CreatedAt, &uc.UpdatedAt,
			&uc.ConsentType.ID, &uc.ConsentType.TenantID, &uc.ConsentType.Name,
			&uc.ConsentType.DisplayName, &uc.ConsentType.Description, &uc.ConsentType.Category,
			&uc.ConsentType.IsRequired, &uc.ConsentType.IsActive, &uc.ConsentType.Version,
			&uc.ConsentType.LegalBasis, &uc.ConsentType.DataRetentionDays,
			&uc.ConsentType.ExternalPolicyURL, &uc.ConsentType.CreatedAt, &uc.ConsentType.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetConsentHistory: %w", err)
		}
		consents = append(consents, uc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetConsentHistory: rows iteration: %w", err)
	}

	return consents, nil
}

// GetConsentHistoryDetailed returns detailed consent history from the consent_history table
func (r *ConsentRepository) GetConsentHistoryDetailed(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, limit int) ([]models.ConsentHistoryWithType, error) {
	query := `
		SELECT ch.id, ch.user_id, ch.consent_type_id, ch.action, ch.consent_version,
		       ch.ip_address, ch.user_agent, ch.created_at,
		       ct.id, ct.tenant_id, ct.name, ct.display_name, ct.description, ct.category,
		       ct.is_required, ct.is_active, ct.version, ct.legal_basis,
		       ct.data_retention_days, ct.external_policy_url, ct.created_at, ct.updated_at
		FROM iam_consent_history ch
		JOIN iam_consent_types ct ON ch.consent_type_id = ct.id
		WHERE ch.user_id = $1 AND ct.tenant_id = $2
		ORDER BY ch.created_at DESC
		LIMIT $3`

	rows, err := r.db.Query(ctx, query, userID, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("GetConsentHistoryDetailed: %w", err)
	}
	defer rows.Close()

	var history []models.ConsentHistoryWithType
	for rows.Next() {
		var ch models.ConsentHistoryWithType
		err := rows.Scan(
			&ch.ID, &ch.UserID, &ch.ConsentTypeID, &ch.Action, &ch.ConsentVersion,
			&ch.IPAddress, &ch.UserAgent, &ch.CreatedAt,
			&ch.ConsentType.ID, &ch.ConsentType.TenantID, &ch.ConsentType.Name,
			&ch.ConsentType.DisplayName, &ch.ConsentType.Description, &ch.ConsentType.Category,
			&ch.ConsentType.IsRequired, &ch.ConsentType.IsActive, &ch.ConsentType.Version,
			&ch.ConsentType.LegalBasis, &ch.ConsentType.DataRetentionDays,
			&ch.ConsentType.ExternalPolicyURL, &ch.ConsentType.CreatedAt, &ch.ConsentType.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetConsentHistoryDetailed: %w", err)
		}
		history = append(history, ch)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetConsentHistoryDetailed: rows iteration: %w", err)
	}

	return history, nil
}
