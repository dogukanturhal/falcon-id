// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// tenantQuotaRepo is the persistence contract required by TenantQuotaService.
type tenantQuotaRepo interface {
	GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*models.TenantQuota, error)
	GetOrDefault(ctx context.Context, tenantID uuid.UUID, tier models.SubscriptionTier) (*models.TenantQuota, error)
	Upsert(ctx context.Context, q *models.TenantQuota) error
	Delete(ctx context.Context, tenantID uuid.UUID) error
}

// TenantQuotaService manages per-tenant quota configuration.  It supports:
//   - CRUD for explicit per-tenant overrides stored in tenant_quotas.
//   - Resolution: returning the effective quota for a tenant (explicit or tier default).
//   - In-memory tier default overrides that take effect without a database migration.
type TenantQuotaService struct {
	repo   tenantQuotaRepo
	logger *zap.Logger

	// tierDefaults holds the in-memory copy of DefaultQuotas that operators
	// can update at runtime via the API.
	mu           sync.RWMutex
	tierDefaults map[models.SubscriptionTier]models.QuotaDefaults
}

// NewTenantQuotaService creates a TenantQuotaService.
func NewTenantQuotaService(repo tenantQuotaRepo, logger *zap.Logger) *TenantQuotaService {
	// Deep-copy the package-level defaults so mutations don't affect the
	// original map.
	defaults := make(map[models.SubscriptionTier]models.QuotaDefaults, len(models.DefaultQuotas))
	for k, v := range models.DefaultQuotas {
		defaults[k] = v
	}
	return &TenantQuotaService{
		repo:         repo,
		logger:       logger,
		tierDefaults: defaults,
	}
}

// ============================================================
// Per-tenant CRUD
// ============================================================

// GetQuota returns the quota for a tenant.  When no explicit record exists the
// function synthesises one from the tier defaults and marks it as a default.
func (s *TenantQuotaService) GetQuota(ctx context.Context, tenantID uuid.UUID) (*models.TenantQuotaResponse, error) {
	q, err := s.repo.GetByTenantID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant_quota_service.GetQuota: %w", err)
	}

	if q != nil {
		resp := q.ToResponse()
		resp.IsDefault = false
		return resp, nil
	}

	// No explicit record — return defaults.
	def := s.tierDefaultFor(models.TierFree)
	resp := &models.TenantQuotaResponse{
		TenantID:              tenantID,
		SubscriptionTier:      def.SubscriptionTier,
		APIRequestsPerMinute:  def.APIRequestsPerMinute,
		APIRequestsPerHour:    def.APIRequestsPerHour,
		APIRequestsPerDay:     def.APIRequestsPerDay,
		AuthAttemptsPerMinute: def.AuthAttemptsPerMinute,
		TokenRefreshPerMinute: def.TokenRefreshPerMinute,
		BurstMultiplier:       def.BurstMultiplier,
		UpdatedAt:             time.Time{}, // zero — no DB row
		IsDefault:             true,
	}
	return resp, nil
}

// CreateOrUpdateQuota creates or replaces the quota for the given tenant.
func (s *TenantQuotaService) CreateOrUpdateQuota(
	ctx context.Context,
	tenantID uuid.UUID,
	req *models.CreateQuotaRequest,
	updatedBy *uuid.UUID,
) (*models.TenantQuotaResponse, error) {
	// Start from tier defaults so unspecified fields inherit sensible values.
	def := s.tierDefaultFor(req.SubscriptionTier)

	q := &models.TenantQuota{
		TenantID:              tenantID,
		SubscriptionTier:      req.SubscriptionTier,
		APIRequestsPerMinute:  def.APIRequestsPerMinute,
		APIRequestsPerHour:    def.APIRequestsPerHour,
		APIRequestsPerDay:     def.APIRequestsPerDay,
		AuthAttemptsPerMinute: def.AuthAttemptsPerMinute,
		TokenRefreshPerMinute: def.TokenRefreshPerMinute,
		BurstMultiplier:       def.BurstMultiplier,
		CustomLimits:          req.CustomLimits,
		UpdatedAt:             time.Now().UTC(),
		UpdatedBy:             updatedBy,
	}

	// Apply explicit overrides.
	if req.APIRequestsPerMinute != nil {
		q.APIRequestsPerMinute = *req.APIRequestsPerMinute
	}
	if req.APIRequestsPerHour != nil {
		q.APIRequestsPerHour = *req.APIRequestsPerHour
	}
	if req.APIRequestsPerDay != nil {
		q.APIRequestsPerDay = *req.APIRequestsPerDay
	}
	if req.AuthAttemptsPerMinute != nil {
		q.AuthAttemptsPerMinute = *req.AuthAttemptsPerMinute
	}
	if req.TokenRefreshPerMinute != nil {
		q.TokenRefreshPerMinute = *req.TokenRefreshPerMinute
	}
	if req.BurstMultiplier != nil {
		q.BurstMultiplier = *req.BurstMultiplier
	}

	if err := s.validate(q); err != nil {
		return nil, err
	}

	if err := s.repo.Upsert(ctx, q); err != nil {
		return nil, fmt.Errorf("tenant_quota_service.CreateOrUpdateQuota: %w", err)
	}

	s.logger.Info("Tenant quota created/updated",
		zap.String("tenant_id", tenantID.String()),
		zap.String("tier", string(q.SubscriptionTier)),
	)

	return q.ToResponse(), nil
}

// UpdateQuota applies a partial update to the existing quota for the given tenant.
// If no record exists the update is based on the tier default.
func (s *TenantQuotaService) UpdateQuota(
	ctx context.Context,
	tenantID uuid.UUID,
	req *models.UpdateQuotaRequest,
	updatedBy *uuid.UUID,
) (*models.TenantQuotaResponse, error) {
	existing, err := s.repo.GetByTenantID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant_quota_service.UpdateQuota: fetch: %w", err)
	}

	if existing == nil {
		// Bootstrap from defaults.
		d := models.FromDefaults(tenantID, models.TierFree)
		existing = &d
	}

	if req.SubscriptionTier != nil {
		existing.SubscriptionTier = *req.SubscriptionTier
	}
	if req.APIRequestsPerMinute != nil {
		existing.APIRequestsPerMinute = *req.APIRequestsPerMinute
	}
	if req.APIRequestsPerHour != nil {
		existing.APIRequestsPerHour = *req.APIRequestsPerHour
	}
	if req.APIRequestsPerDay != nil {
		existing.APIRequestsPerDay = *req.APIRequestsPerDay
	}
	if req.AuthAttemptsPerMinute != nil {
		existing.AuthAttemptsPerMinute = *req.AuthAttemptsPerMinute
	}
	if req.TokenRefreshPerMinute != nil {
		existing.TokenRefreshPerMinute = *req.TokenRefreshPerMinute
	}
	if req.BurstMultiplier != nil {
		existing.BurstMultiplier = *req.BurstMultiplier
	}
	if len(req.CustomLimits) > 0 {
		existing.CustomLimits = req.CustomLimits
	}
	existing.UpdatedAt = time.Now().UTC()
	existing.UpdatedBy = updatedBy

	if err := s.validate(existing); err != nil {
		return nil, err
	}

	if err := s.repo.Upsert(ctx, existing); err != nil {
		return nil, fmt.Errorf("tenant_quota_service.UpdateQuota: upsert: %w", err)
	}

	s.logger.Info("Tenant quota updated",
		zap.String("tenant_id", tenantID.String()),
	)

	return existing.ToResponse(), nil
}

// DeleteQuota removes the explicit quota record, effectively reverting to tier
// defaults.
func (s *TenantQuotaService) DeleteQuota(ctx context.Context, tenantID uuid.UUID) error {
	if err := s.repo.Delete(ctx, tenantID); err != nil {
		return fmt.Errorf("tenant_quota_service.DeleteQuota: %w", err)
	}
	s.logger.Info("Tenant quota deleted", zap.String("tenant_id", tenantID.String()))
	return nil
}

// ============================================================
// Tier defaults management
// ============================================================

// GetTierDefaults returns all current tier defaults.
func (s *TenantQuotaService) GetTierDefaults() models.TierDefaultsResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cp := make(map[models.SubscriptionTier]models.QuotaDefaults, len(s.tierDefaults))
	for k, v := range s.tierDefaults {
		cp[k] = v
	}
	return models.TierDefaultsResponse{Tiers: cp}
}

// UpdateTierDefault applies a partial update to the in-memory defaults for a
// tier.  Changes are applied immediately for all future GetQuota calls but are
// NOT persisted across restarts.  Callers that need durability must store the
// overrides in a configuration file or environment variable.
func (s *TenantQuotaService) UpdateTierDefault(
	tier models.SubscriptionTier,
	req *models.UpdateTierDefaultRequest,
) (models.QuotaDefaults, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.tierDefaults[tier]
	if !ok {
		return models.QuotaDefaults{}, fmt.Errorf("unknown subscription tier: %s", tier)
	}

	if req.APIRequestsPerMinute != nil {
		d.APIRequestsPerMinute = *req.APIRequestsPerMinute
	}
	if req.APIRequestsPerHour != nil {
		d.APIRequestsPerHour = *req.APIRequestsPerHour
	}
	if req.APIRequestsPerDay != nil {
		d.APIRequestsPerDay = *req.APIRequestsPerDay
	}
	if req.AuthAttemptsPerMinute != nil {
		d.AuthAttemptsPerMinute = *req.AuthAttemptsPerMinute
	}
	if req.TokenRefreshPerMinute != nil {
		d.TokenRefreshPerMinute = *req.TokenRefreshPerMinute
	}
	if req.BurstMultiplier != nil {
		d.BurstMultiplier = *req.BurstMultiplier
	}

	s.tierDefaults[tier] = d
	s.logger.Info("Tier default updated", zap.String("tier", string(tier)))
	return d, nil
}

// ============================================================
// Helpers
// ============================================================

func (s *TenantQuotaService) tierDefaultFor(tier models.SubscriptionTier) models.QuotaDefaults {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if d, ok := s.tierDefaults[tier]; ok {
		return d
	}
	return s.tierDefaults[models.TierFree]
}

func (s *TenantQuotaService) validate(q *models.TenantQuota) error {
	if q.APIRequestsPerMinute <= 0 {
		return fmt.Errorf("api_requests_per_minute must be positive")
	}
	if q.APIRequestsPerHour <= 0 {
		return fmt.Errorf("api_requests_per_hour must be positive")
	}
	if q.APIRequestsPerDay <= 0 {
		return fmt.Errorf("api_requests_per_day must be positive")
	}
	if q.AuthAttemptsPerMinute <= 0 {
		return fmt.Errorf("auth_attempts_per_minute must be positive")
	}
	if q.TokenRefreshPerMinute <= 0 {
		return fmt.Errorf("token_refresh_per_minute must be positive")
	}
	if q.BurstMultiplier <= 0 {
		return fmt.Errorf("burst_multiplier must be positive")
	}
	return nil
}
