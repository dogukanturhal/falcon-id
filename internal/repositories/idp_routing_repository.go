// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const msgRoutingRuleNotFound = "routing rule not found"

// IDPRoutingRepository is an exported identifier.
// IDPRoutingRepository handles IDP routing rule database operations.
type IDPRoutingRepository struct {
	pool *pgxpool.Pool
}

// NewIDPRoutingRepository is an exported identifier.
// NewIDPRoutingRepository creates a new IDPRoutingRepository.
func NewIDPRoutingRepository(pool *pgxpool.Pool) *IDPRoutingRepository {
	return &IDPRoutingRepository{pool: pool}
}

// Create inserts a new IDP routing rule.
func (r *IDPRoutingRepository) Create(ctx context.Context, rule *models.IDPRoutingRule) error {
	query := `
		INSERT INTO iam_idp_routing_rules (tenant_id, identity_provider_id, rule_type, rule_value, priority, is_enabled)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at
	`
	return r.pool.QueryRow(ctx, query,
		rule.TenantID,
		rule.IdentityProviderID,
		rule.RuleType,
		rule.RuleValue,
		rule.Priority,
		rule.IsEnabled,
	).Scan(&rule.ID, &rule.CreatedAt, &rule.UpdatedAt)
}

// Update modifies an existing IDP routing rule.
func (r *IDPRoutingRepository) Update(ctx context.Context, rule *models.IDPRoutingRule) error {
	query := `
		UPDATE iam_idp_routing_rules
		SET identity_provider_id = $1, rule_type = $2, rule_value = $3,
		    priority = $4, is_enabled = $5, updated_at = now()
		WHERE id = $6 AND tenant_id = $7
		RETURNING updated_at
	`
	err := r.pool.QueryRow(ctx, query,
		rule.IdentityProviderID,
		rule.RuleType,
		rule.RuleValue,
		rule.Priority,
		rule.IsEnabled,
		rule.ID,
		rule.TenantID,
	).Scan(&rule.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New(msgRoutingRuleNotFound)
		}
		return fmt.Errorf("failed to update routing rule: %w", err)
	}
	return nil
}

// Delete removes an IDP routing rule.
func (r *IDPRoutingRepository) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	query := `DELETE FROM iam_idp_routing_rules WHERE id = $1 AND tenant_id = $2`
	tag, err := r.pool.Exec(ctx, query, id, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete routing rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(msgRoutingRuleNotFound)
	}
	return nil
}

// GetByID retrieves a single routing rule by ID.
func (r *IDPRoutingRepository) GetByID(ctx context.Context, id, tenantID uuid.UUID) (*models.IDPRoutingRule, error) {
	query := `
		SELECT r.id, r.tenant_id, r.identity_provider_id, r.rule_type, r.rule_value,
		       r.priority, r.is_enabled, r.created_at, r.updated_at,
		       ip.provider_name, ip.provider_type, ip.display_name
		FROM iam_idp_routing_rules r
		JOIN iam_identity_providers ip ON ip.id = r.identity_provider_id
		WHERE r.id = $1 AND r.tenant_id = $2
	`
	var rule models.IDPRoutingRule
	err := r.pool.QueryRow(ctx, query, id, tenantID).Scan(
		&rule.ID, &rule.TenantID, &rule.IdentityProviderID, &rule.RuleType, &rule.RuleValue,
		&rule.Priority, &rule.IsEnabled, &rule.CreatedAt, &rule.UpdatedAt,
		&rule.ProviderName, &rule.ProviderType, &rule.ProviderDisplayName,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgRoutingRuleNotFound)
		}
		return nil, fmt.Errorf("failed to get routing rule: %w", err)
	}
	return &rule, nil
}

// ListByTenant returns all routing rules for a tenant, ordered by priority.
func (r *IDPRoutingRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.IDPRoutingRule, error) {
	query := `
		SELECT r.id, r.tenant_id, r.identity_provider_id, r.rule_type, r.rule_value,
		       r.priority, r.is_enabled, r.created_at, r.updated_at,
		       ip.provider_name, ip.provider_type, ip.display_name
		FROM iam_idp_routing_rules r
		JOIN iam_identity_providers ip ON ip.id = r.identity_provider_id
		WHERE r.tenant_id = $1
		ORDER BY r.priority ASC, r.created_at ASC
	`
	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list routing rules: %w", err)
	}
	defer rows.Close()

	var rules []models.IDPRoutingRule
	for rows.Next() {
		var rule models.IDPRoutingRule
		if err := rows.Scan(
			&rule.ID, &rule.TenantID, &rule.IdentityProviderID, &rule.RuleType, &rule.RuleValue,
			&rule.Priority, &rule.IsEnabled, &rule.CreatedAt, &rule.UpdatedAt,
			&rule.ProviderName, &rule.ProviderType, &rule.ProviderDisplayName,
		); err != nil {
			return nil, fmt.Errorf("failed to scan routing rule: %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// FindByEmailDomain finds the highest-priority routing rule matching an
// email domain, regardless of whether the rule or its IDP is currently
// active.
//
// The query intentionally does NOT filter on `r.is_enabled` or
// `ip.is_active`. The caller (IDPRoutingService) inspects the joined
// `IsEnabled` + `ProviderIsActive` fields and decides how to route the
// response — pre-2026-05-21 filtering here collapsed three states
// ("no rule for this domain" / "rule was disabled" / "IDP was
// deactivated") into a single nil return, hiding the
// disabled-state-attempted-use signal from the SOC. See
// internal/services/idp_routing_service.go and
// docs/audits/2026-05-21-repo-state-filter-audit.md.
func (r *IDPRoutingRepository) FindByEmailDomain(ctx context.Context, tenantID uuid.UUID, domain string) (*models.IDPRoutingRule, error) {
	query := `
		SELECT r.id, r.tenant_id, r.identity_provider_id, r.rule_type, r.rule_value,
		       r.priority, r.is_enabled, r.created_at, r.updated_at,
		       ip.provider_name, ip.provider_type, ip.display_name, ip.is_active
		FROM iam_idp_routing_rules r
		JOIN iam_identity_providers ip ON ip.id = r.identity_provider_id
		WHERE r.tenant_id = $1 AND r.rule_type = 'email_domain' AND r.rule_value = $2
		ORDER BY r.priority ASC
		LIMIT 1
	`
	var rule models.IDPRoutingRule
	err := r.pool.QueryRow(ctx, query, tenantID, domain).Scan(
		&rule.ID, &rule.TenantID, &rule.IdentityProviderID, &rule.RuleType, &rule.RuleValue,
		&rule.Priority, &rule.IsEnabled, &rule.CreatedAt, &rule.UpdatedAt,
		&rule.ProviderName, &rule.ProviderType, &rule.ProviderDisplayName, &rule.ProviderIsActive,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find routing rule by email domain: %w", err)
	}
	return &rule, nil
}
