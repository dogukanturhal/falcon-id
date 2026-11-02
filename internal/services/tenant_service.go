// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// TenantCache interface for tenant lookup caching
type TenantCache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Del(ctx context.Context, key string) error
}

// TenantService handles tenant-related operations for platform admins
type TenantService struct {
	db        *pgxpool.Pool
	logger    *zap.Logger
	cache     TenantCache
	encryptor *crypto.EncryptionService
}

// NewTenantService creates a new tenant service
func NewTenantService(db *pgxpool.Pool, logger *zap.Logger) *TenantService {
	return &TenantService{
		db:     db,
		logger: logger,
	}
}

// SetEncryptor sets the encryption service for decrypting PII fields
func (s *TenantService) SetEncryptor(enc *crypto.EncryptionService) {
	s.encryptor = enc
}

// SetCache sets the Redis cache for tenant lookup caching
func (s *TenantService) SetCache(cache TenantCache) {
	s.cache = cache
}

// ListAll lists all tenants with pagination and filters (platform admin only)
func (s *TenantService) ListAll(ctx context.Context, page, pageSize int, filters models.TenantFilters) ([]models.TenantResponse, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	// Build WHERE conditions (shared between count and select queries)
	baseWhere := ""
	args := []interface{}{}
	argIndex := 1

	if filters.Status != "" {
		baseWhere += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, filters.Status)
		argIndex++
	}

	// ADR-0029 (Phase 3): iam_tenants.type and .plan were dropped.
	// Filters on type and plan are silently ignored here; the authoritative
	// SoR for both fields is tenant-management. Callers that need type/plan
	// filtering must query tenant-management directly.
	_ = filters.Type
	_ = filters.Plan

	if filters.Search != "" {
		baseWhere += fmt.Sprintf(" AND (name ILIKE $%d OR slug ILIKE $%d OR display_name ILIKE $%d)", argIndex, argIndex, argIndex)
		args = append(args, "%"+filters.Search+"%")
		argIndex++
	}

	// Get total count
	var total int64
	countQuery := "SELECT COUNT(*) FROM iam_tenants WHERE 1=1" + baseWhere
	err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		s.logger.Error("Failed to count tenants", zap.Error(err))
		return nil, 0, fmt.Errorf("ListAll: %w", err)
	}

	// Get tenants with pagination, user counts, and owner info.
	// ADR-0029 (Phase 3): type and plan columns were dropped from iam_tenants;
	// they are omitted from the projection and set to application-layer defaults.
	selectQuery := fmt.Sprintf(`SELECT t.id, t.name, t.slug, t.display_name, t.domain, t.status,
	                       COALESCE(t.billing_exempt, false) as billing_exempt,
	                       t.billing_email, t.max_users, t.max_storage, t.trial_ends_at,
	                       t.created_at, t.updated_at, t.suspended_at, t.cancelled_at,
	                       COALESCE(uc.cnt, 0) as user_count,
	                       owner.email as owner_email,
	                       owner.first_name as owner_first_name,
	                       owner.last_name as owner_last_name,
	                       owner.username as owner_username
	                       FROM iam_tenants t
	                       LEFT JOIN LATERAL (
	                           SELECT COUNT(*) as cnt FROM iam_users WHERE tenant_id = t.id AND is_active = true
	                       ) uc ON true
	                       LEFT JOIN LATERAL (
	                           SELECT email, username, first_name, last_name FROM iam_users
	                           WHERE tenant_id = t.id AND is_active = true
	                           ORDER BY created_at ASC LIMIT 1
	                       ) owner ON true
	                       WHERE 1=1%s
	                       ORDER BY t.created_at DESC LIMIT $%d OFFSET $%d`,
		baseWhere, argIndex, argIndex+1)
	args = append(args, pageSize, offset)

	rows, err := s.db.Query(ctx, selectQuery, args...)
	if err != nil {
		s.logger.Error("Failed to list tenants", zap.Error(err))
		return nil, 0, fmt.Errorf("ListAll: %w", err)
	}
	defer rows.Close()

	var tenants []models.TenantResponse
	for rows.Next() {
		var t models.TenantResponse
		var userCount int64
		var ownerFirstName, ownerLastName, ownerUsername *string
		err := rows.Scan(
			&t.ID, &t.Name, &t.Slug, &t.DisplayName, &t.Domain, &t.Status,
			&t.BillingExempt, &t.BillingEmail, &t.MaxUsers,
			&t.MaxStorage, &t.TrialEndsAt, &t.CreatedAt, &t.UpdatedAt,
			&t.SuspendedAt, &t.CancelledAt,
			&userCount, &t.OwnerEmail, &ownerFirstName, &ownerLastName, &ownerUsername,
		)
		// ADR-0029: type and plan are no longer in iam_tenants; set defaults.
		t.Type = string(models.TenantTypeCustomer)
		t.Plan = ""
		if err != nil {
			s.logger.Error("Failed to scan tenant", zap.Error(err))
			continue
		}
		t.UserCount = &userCount
		t.NamePlaceholder = models.IsPlaceholderTenantName(t.DisplayName)
		s.decryptTenantOwnerFields(&t, ownerFirstName, ownerLastName, ownerUsername)
		tenants = append(tenants, t)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListAll: row iteration error: %w", err)
	}

	return tenants, total, nil
}

// decryptTenantOwnerFields decrypts PII owner fields and sets OwnerName on the tenant response.
func (s *TenantService) decryptTenantOwnerFields(t *models.TenantResponse, ownerFirstName, ownerLastName, ownerUsername *string) {
	if s.encryptor == nil {
		t.OwnerName = ownerUsername
		return
	}
	if t.OwnerEmail != nil && *t.OwnerEmail != "" {
		if dec, err := s.encryptor.Decrypt(*t.OwnerEmail); err == nil {
			t.OwnerEmail = &dec
		}
	}
	firstName, lastName := "", ""
	if ownerFirstName != nil && *ownerFirstName != "" {
		if dec, err := s.encryptor.Decrypt(*ownerFirstName); err == nil {
			firstName = dec
		}
	}
	if ownerLastName != nil && *ownerLastName != "" {
		if dec, err := s.encryptor.Decrypt(*ownerLastName); err == nil {
			lastName = dec
		}
	}
	if firstName != "" || lastName != "" {
		name := strings.TrimSpace(firstName + " " + lastName)
		t.OwnerName = &name
	} else {
		t.OwnerName = ownerUsername
	}
}

// GetByID retrieves a tenant by ID
func (s *TenantService) GetByID(ctx context.Context, id uuid.UUID) (*models.TenantResponse, error) {
	// Try cache first if available
	if s.cache != nil {
		cacheKey := fmt.Sprintf("iam:tenant:id:%s", id.String())
		if cached, err := s.cache.Get(ctx, cacheKey); err == nil && cached != "" {
			var t models.TenantResponse
			if json.Unmarshal([]byte(cached), &t) == nil {
				return &t, nil
			}
		}
	}

	// ADR-0029 (Phase 3): type and plan columns were dropped from iam_tenants.
	query := `SELECT id, name, slug, display_name, domain, status,
	                 COALESCE(billing_exempt, false) as billing_exempt,
	                 billing_email, max_users, max_storage, trial_ends_at,
	                 created_at, updated_at, suspended_at, cancelled_at
	          FROM iam_tenants WHERE id = $1`

	var t models.TenantResponse
	err := s.db.QueryRow(ctx, query, id).Scan(
		&t.ID, &t.Name, &t.Slug, &t.DisplayName, &t.Domain, &t.Status,
		&t.BillingExempt, &t.BillingEmail, &t.MaxUsers,
		&t.MaxStorage, &t.TrialEndsAt, &t.CreatedAt, &t.UpdatedAt,
		&t.SuspendedAt, &t.CancelledAt,
	)
	// ADR-0029: type and plan are no longer in iam_tenants; set defaults.
	t.Type = string(models.TenantTypeCustomer)
	t.Plan = ""
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}

	// Get user counts - iam_users uses is_active (boolean) not status
	userQuery := `SELECT COUNT(*) as total,
	                     COUNT(*) FILTER (WHERE is_active = true) as active
	              FROM iam_users WHERE tenant_id = $1`
	var totalUsers, activeUsers int64
	if err := s.db.QueryRow(ctx, userQuery, id).Scan(&totalUsers, &activeUsers); err == nil {
		t.UserCount = &totalUsers
		t.ActiveUserCount = &activeUsers
	}

	// Cache result for 5 minutes
	if s.cache != nil {
		cacheKey := fmt.Sprintf("iam:tenant:id:%s", id.String())
		if data, err := json.Marshal(&t); err == nil {
			_ = s.cache.Set(ctx, cacheKey, string(data), 5*time.Minute)
		}
	}

	return &t, nil
}

// Update updates tenant fields (name, domain, status).
//
// ADR-0029 (Phase 3): iam_tenants.plan was dropped. The Tier field in
// UpdateTenantRequest is intentionally ignored here; plan updates must
// go through tenant-management (the authoritative SoR).
func (s *TenantService) Update(ctx context.Context, tenantID uuid.UUID, req *models.UpdateTenantRequest) (*models.TenantResponse, error) {
	// Build dynamic SET clause
	setClauses := []string{}
	args := []interface{}{}
	argIndex := 1

	if req.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d, display_name = $%d", argIndex, argIndex))
		args = append(args, *req.Name)
		argIndex++
	}
	if req.Domain != nil {
		setClauses = append(setClauses, fmt.Sprintf("domain = $%d", argIndex))
		args = append(args, *req.Domain)
		argIndex++
	}
	// ADR-0029: req.Tier (maps to iam_tenants.plan) is intentionally skipped —
	// the column was dropped. Tier updates must go through tenant-management.
	if req.Tier != nil {
		s.logger.Warn("TenantService.Update: Tier field ignored (ADR-0029: iam_tenants.plan dropped); route tier updates through tenant-management",
			zap.String("tenant_id", tenantID.String()),
			zap.String("requested_tier", *req.Tier))
	}
	if req.Status != nil {
		setClauses = append(setClauses, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, *req.Status)
		argIndex++
	}

	if len(setClauses) == 0 {
		return s.GetByID(ctx, tenantID)
	}

	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argIndex))
	args = append(args, time.Now())
	argIndex++

	args = append(args, tenantID)
	query := fmt.Sprintf("UPDATE iam_tenants SET %s WHERE id = $%d",
		strings.Join(setClauses, ", "), argIndex)

	result, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		s.logger.Error("Failed to update tenant", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return nil, fmt.Errorf("Update: %w", err)
	}
	if result.RowsAffected() == 0 {
		return nil, errors.New("tenant not found")
	}

	// Invalidate cache
	if s.cache != nil {
		cacheKey := fmt.Sprintf("iam:tenant:id:%s", tenantID.String())
		_ = s.cache.Del(ctx, cacheKey)
	}

	s.logger.Info("Tenant updated", zap.String("tenant_id", tenantID.String()))
	return s.GetByID(ctx, tenantID)
}

// Suspend suspends a tenant
func (s *TenantService) Suspend(ctx context.Context, tenantID uuid.UUID, reason string) error {
	now := time.Now()
	query := `UPDATE iam_tenants SET status = 'suspended', suspended_at = $1, updated_at = $1 WHERE id = $2 AND status = 'active'`
	result, err := s.db.Exec(ctx, query, now, tenantID)
	if err != nil {
		return fmt.Errorf("Suspend: %w", err)
	}
	if result.RowsAffected() == 0 {
		return errors.New("tenant not found or already suspended")
	}

	// Invalidate cache
	if s.cache != nil {
		cacheKey := fmt.Sprintf("iam:tenant:id:%s", tenantID.String())
		_ = s.cache.Del(ctx, cacheKey)
	}

	s.logger.Info("Tenant suspended", zap.String("tenant_id", tenantID.String()), zap.String("reason", reason))
	return nil
}

// Reactivate reactivates a suspended tenant
func (s *TenantService) Reactivate(ctx context.Context, tenantID uuid.UUID) error {
	now := time.Now()
	query := `UPDATE iam_tenants SET status = 'active', suspended_at = NULL, updated_at = $1 WHERE id = $2 AND status = 'suspended'`
	result, err := s.db.Exec(ctx, query, now, tenantID)
	if err != nil {
		return fmt.Errorf("Reactivate: %w", err)
	}
	if result.RowsAffected() == 0 {
		return errors.New("tenant not found or not suspended")
	}

	// Invalidate cache
	if s.cache != nil {
		cacheKey := fmt.Sprintf("iam:tenant:id:%s", tenantID.String())
		_ = s.cache.Del(ctx, cacheKey)
	}

	s.logger.Info("Tenant reactivated", zap.String("tenant_id", tenantID.String()))
	return nil
}

// GetPlatformStatistics gets platform-wide statistics
func (s *TenantService) GetPlatformStatistics(ctx context.Context) (*models.PlatformStatistics, error) {
	stats := &models.PlatformStatistics{
		CalculatedAt: time.Now(),
	}

	// Tenant statistics
	tenantQuery := `SELECT
		COUNT(*) as total,
		COUNT(*) FILTER (WHERE status = 'active') as active,
		COUNT(*) FILTER (WHERE status = 'trial') as trial,
		COUNT(*) FILTER (WHERE status = 'suspended') as suspended,
		COUNT(*) FILTER (WHERE created_at >= date_trunc('month', CURRENT_DATE)) as new_this_month,
		COUNT(*) FILTER (WHERE cancelled_at >= date_trunc('month', CURRENT_DATE)) as churned_this_month
	FROM iam_tenants`

	err := s.db.QueryRow(ctx, tenantQuery).Scan(
		&stats.TenantStats.TotalTenants,
		&stats.TenantStats.ActiveTenants,
		&stats.TenantStats.TrialTenants,
		&stats.TenantStats.SuspendedTenants,
		&stats.TenantStats.NewThisMonth,
		&stats.TenantStats.ChurnedThisMonth,
	)
	if err != nil {
		s.logger.Error("Failed to get tenant statistics", zap.Error(err))
	}

	// ADR-0029 (Phase 3): iam_tenants.plan and iam_tenants.type were dropped by
	// the GitOps repository !699. These analytics are now stubs returning empty maps.
	// The authoritative source of plan/type aggregations is tenant-management.
	// TODO: proxy these stats from tenant-management when its admin API is stable.
	s.logger.Warn("TenantStats.ByPlan and ByType are deprecated: iam_tenants.plan + .type dropped (ADR-0029). Query tenant-management for accurate aggregations.")
	stats.TenantStats.ByPlan = map[string]int64{}
	stats.TenantStats.ByType = map[string]int64{}

	// User statistics - iam_users uses is_active (boolean) and is_email_verified
	userQuery := `SELECT
		COUNT(*) as total,
		COUNT(*) FILTER (WHERE is_active = true) as active,
		COUNT(*) FILTER (WHERE is_locked = true) as locked,
		COUNT(*) FILTER (WHERE is_email_verified = true) as verified,
		COUNT(*) FILTER (WHERE mfa_enabled = true) as mfa_enabled,
		COUNT(*) FILTER (WHERE created_at >= date_trunc('month', CURRENT_DATE)) as new_this_month
	FROM iam_users`

	err = s.db.QueryRow(ctx, userQuery).Scan(
		&stats.UserStats.TotalUsers,
		&stats.UserStats.ActiveUsers,
		&stats.UserStats.LockedUsers,
		&stats.UserStats.VerifiedUsers,
		&stats.UserStats.MFAEnabledUsers,
		&stats.UserStats.NewThisMonth,
	)
	if err != nil {
		s.logger.Error("Failed to get user statistics", zap.Error(err))
	}

	// Login statistics (today) - table is iam_audit_log (singular)
	loginQuery := `SELECT
		COUNT(*) FILTER (WHERE action = 'login' AND created_at >= CURRENT_DATE) as attempts_today,
		COUNT(*) FILTER (WHERE action = 'login' AND success = true AND created_at >= CURRENT_DATE) as success_today,
		COUNT(*) FILTER (WHERE action = 'login' AND success = false AND created_at >= CURRENT_DATE) as failed_today
	FROM iam_audit_log`

	err = s.db.QueryRow(ctx, loginQuery).Scan(
		&stats.ActivityStats.LoginAttemptsToday,
		&stats.ActivityStats.SuccessfulLoginsToday,
		&stats.ActivityStats.FailedLoginsToday,
	)
	if err != nil {
		s.logger.Error("Failed to get activity statistics", zap.Error(err))
	}

	// Resource statistics
	stats.ResourceStats.AverageUsersPerTenant = 0
	if stats.TenantStats.TotalTenants > 0 {
		stats.ResourceStats.AverageUsersPerTenant = float64(stats.UserStats.TotalUsers) / float64(stats.TenantStats.TotalTenants)
	}

	return stats, nil
}
