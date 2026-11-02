// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/quota"
)

// ResourceTypeKioskUsers is the quota-service resource that counts shop-floor kiosk (seat_class='kiosk') users, R6 WP-23.
// Kiosk users are free (no paid seat) but limited per production plan (1 / 3 / unlimited, D20).
const ResourceTypeKioskUsers quota.ResourceType = "kiosk_users"

// ErrKioskQuotaExceeded is returned (wrapped in *KioskQuotaExceededError) when the tenant's kiosk_users quota is full.
var ErrKioskQuotaExceeded = errors.New("kiosk user quota exceeded for tenant plan")

// KioskQuotaExceededError carries the quota-service usage figures for the 403 body.
type KioskQuotaExceededError struct {
	CurrentUsage int64
	Limit        int64
	Message      string
}

func (e *KioskQuotaExceededError) Error() string {
	return fmt.Sprintf("%s (current: %d, limit: %d): %s", ErrKioskQuotaExceeded, e.CurrentUsage, e.Limit, e.Message)
}

func (e *KioskQuotaExceededError) Unwrap() error { return ErrKioskQuotaExceeded }

// CheckKioskQuota verifies the tenant may add one more kiosk user. A no-op while quota enforcement is off or no client is
// wired (same posture as the seat check in create). Fail-closed on quota-service errors unless QuotaCheckFailOpen is set.
func (s *UserService) CheckKioskQuota(ctx context.Context, tenantID uuid.UUID) error {
	if s.quotaClient == nil || !s.config.QuotaEnforcementEnabled {
		return nil
	}
	err := s.quotaClient.MustCheckQuota(ctx, tenantID, ResourceTypeKioskUsers, 1)
	if err == nil {
		return nil
	}
	var exceeded *quota.QuotaExceededError
	if quota.IsQuotaExceededError(err) && errors.As(err, &exceeded) {
		return &KioskQuotaExceededError{CurrentUsage: exceeded.CurrentUsage, Limit: exceeded.Limit, Message: exceeded.Message}
	}
	if s.config.QuotaCheckFailOpen {
		s.logger.Warn("kiosk quota check failed, failing OPEN (QUOTA_CHECK_FAIL_OPEN=true)", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return nil
	}
	s.logger.Error("kiosk quota check failed, failing CLOSED (QUOTA_CHECK_FAIL_OPEN=false)", zap.String("tenant_id", tenantID.String()), zap.Error(err))
	return fmt.Errorf("kiosk quota check failed: %w", err)
}

// RecordKioskUsage adds delta (+1 on provision, -1 on revoke) to the tenant's kiosk_users usage. Best effort: the
// failure is logged, never fails the request that already changed the account.
func (s *UserService) RecordKioskUsage(ctx context.Context, tenantID uuid.UUID, delta int64) {
	if s.quotaClient == nil || !s.config.QuotaEnforcementEnabled || delta == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	var err error
	if delta > 0 {
		_, err = s.quotaClient.IncrementUsage(ctx, tenantID, ResourceTypeKioskUsers, delta)
	} else {
		err = s.quotaClient.DecrementUsage(ctx, tenantID, ResourceTypeKioskUsers, -delta)
	}
	if err != nil {
		s.logger.Warn("failed to record kiosk_users usage", zap.String("tenant_id", tenantID.String()), zap.Int64("delta", delta), zap.Error(err))
	}
}
