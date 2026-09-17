// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TenantBrandingRepository handles persistence of tenant login-screen customisation.
type TenantBrandingRepository struct {
	db DBPool
}

// NewTenantBrandingRepository creates a new TenantBrandingRepository.
func NewTenantBrandingRepository(db DBPool) *TenantBrandingRepository {
	return &TenantBrandingRepository{db: db}
}

const brandingColumns = `id, tenant_id, logo_url, favicon_url, primary_color, background_color,
	accent_color, custom_css, login_title, login_subtitle, login_message,
	support_email, support_url, privacy_policy_url, terms_of_service_url,
	hide_hexxlock_branding, created_at, updated_at`

func scanBranding(row pgx.Row) (*models.TenantBranding, error) {
	b := &models.TenantBranding{}
	err := row.Scan(
		&b.ID, &b.TenantID,
		&b.LogoURL, &b.FaviconURL,
		&b.PrimaryColor, &b.BackgroundColor, &b.AccentColor,
		&b.CustomCSS,
		&b.LoginTitle, &b.LoginSubtitle, &b.LoginMessage,
		&b.SupportEmail, &b.SupportURL,
		&b.PrivacyPolicyURL, &b.TermsOfServiceURL,
		&b.HideHexxlockBranding,
		&b.CreatedAt, &b.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GetByTenantID returns branding for a tenant.
// Returns (nil, nil) when no branding has been configured (callers should apply platform defaults).
func (r *TenantBrandingRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*models.TenantBranding, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM iam_tenant_branding WHERE tenant_id = $1`,
		brandingColumns,
	)
	branding, err := scanBranding(r.db.QueryRow(ctx, query, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByTenantID: %w", err)
	}
	return branding, nil
}

// Upsert creates or updates tenant branding.
// A new UUID is assigned when branding.ID is uuid.Nil.
// On conflict (tenant_id already exists) the existing row is updated in place.
func (r *TenantBrandingRepository) Upsert(ctx context.Context, branding *models.TenantBranding) error {
	if branding.ID == uuid.Nil {
		branding.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_tenant_branding (
			id, tenant_id, logo_url, favicon_url, primary_color, background_color,
			accent_color, custom_css, login_title, login_subtitle, login_message,
			support_email, support_url, privacy_policy_url, terms_of_service_url,
			hide_hexxlock_branding
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (tenant_id) DO UPDATE SET
			logo_url              = EXCLUDED.logo_url,
			favicon_url           = EXCLUDED.favicon_url,
			primary_color         = EXCLUDED.primary_color,
			background_color      = EXCLUDED.background_color,
			accent_color          = EXCLUDED.accent_color,
			custom_css            = EXCLUDED.custom_css,
			login_title           = EXCLUDED.login_title,
			login_subtitle        = EXCLUDED.login_subtitle,
			login_message         = EXCLUDED.login_message,
			support_email         = EXCLUDED.support_email,
			support_url           = EXCLUDED.support_url,
			privacy_policy_url    = EXCLUDED.privacy_policy_url,
			terms_of_service_url  = EXCLUDED.terms_of_service_url,
			hide_hexxlock_branding = EXCLUDED.hide_hexxlock_branding,
			updated_at            = NOW()
		RETURNING created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		branding.ID, branding.TenantID,
		branding.LogoURL, branding.FaviconURL,
		branding.PrimaryColor, branding.BackgroundColor, branding.AccentColor,
		branding.CustomCSS,
		branding.LoginTitle, branding.LoginSubtitle, branding.LoginMessage,
		branding.SupportEmail, branding.SupportURL,
		branding.PrivacyPolicyURL, branding.TermsOfServiceURL,
		branding.HideHexxlockBranding,
	).Scan(&branding.CreatedAt, &branding.UpdatedAt)
}

// Delete removes branding for a tenant.
// Deleting non-existent branding is not an error.
func (r *TenantBrandingRepository) Delete(ctx context.Context, tenantID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM iam_tenant_branding WHERE tenant_id = $1`,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	return nil
}
