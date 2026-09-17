// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// RevocationScope controls the breadth of a global revocation operation.
type RevocationScope string

const (
	// RevocationScopeUser revokes all tokens for a specific user.
	RevocationScopeUser RevocationScope = "user"
	// RevocationScopeTenant revokes all tokens for every user in a tenant.
	RevocationScopeTenant RevocationScope = "tenant"
	// RevocationScopeClient revokes all tokens issued to a specific OAuth client.
	RevocationScopeClient RevocationScope = "client"
)

// RevocationEvent records a global token revocation action for audit purposes.
type RevocationEvent struct {
	ID          uuid.UUID       `json:"id"`
	Scope       RevocationScope `json:"scope"`
	TargetID    string          `json:"target_id"`
	Reason      string          `json:"reason"`
	InitiatedBy uuid.UUID       `json:"initiated_by"`
	CreatedAt   time.Time       `json:"created_at"`
}

// TokenBlacklistWriter is the subset of the token blacklist needed for revocation.
// It is satisfied by the existing token blacklist implementation.
type TokenBlacklistWriter interface {
	BlacklistByUserID(ctx context.Context, userID uuid.UUID, expiresAt time.Time) error
	BlacklistByTenantID(ctx context.Context, tenantID uuid.UUID, expiresAt time.Time) error
	BlacklistByClientID(ctx context.Context, clientID string, expiresAt time.Time) error
}

// GlobalTokenRevocationService handles bulk token revocation operations for
// platform security responses (e.g., compromised credential invalidation).
type GlobalTokenRevocationService struct {
	blacklist TokenBlacklistWriter
	logger    *zap.Logger
}

// NewGlobalTokenRevocationService constructs a GlobalTokenRevocationService.
// blacklist may be nil; revocations are logged but not persisted when absent.
func NewGlobalTokenRevocationService(blacklist TokenBlacklistWriter, logger *zap.Logger) *GlobalTokenRevocationService {
	return &GlobalTokenRevocationService{
		blacklist: blacklist,
		logger:    logger,
	}
}

// RevokeByUser immediately invalidates all tokens for the given user.
// The expiry is set to the maximum token lifetime to ensure stale tokens
// cannot slip through after the blacklist entry expires.
func (s *GlobalTokenRevocationService) RevokeByUser(ctx context.Context, userID uuid.UUID, reason string, initiatedBy uuid.UUID) error {
	s.logger.Warn("Global token revocation: user",
		zap.String("user_id", userID.String()),
		zap.String("reason", reason),
		zap.String("initiated_by", initiatedBy.String()),
	)
	if s.blacklist == nil {
		return nil
	}
	expiry := time.Now().Add(30 * 24 * time.Hour) // 30-day maximum token lifetime
	return s.blacklist.BlacklistByUserID(ctx, userID, expiry)
}

// RevokeByTenant immediately invalidates all tokens for every user in the tenant.
func (s *GlobalTokenRevocationService) RevokeByTenant(ctx context.Context, tenantID uuid.UUID, reason string, initiatedBy uuid.UUID) error {
	s.logger.Warn("Global token revocation: tenant",
		zap.String("tenant_id", tenantID.String()),
		zap.String("reason", reason),
		zap.String("initiated_by", initiatedBy.String()),
	)
	if s.blacklist == nil {
		return nil
	}
	expiry := time.Now().Add(30 * 24 * time.Hour)
	return s.blacklist.BlacklistByTenantID(ctx, tenantID, expiry)
}

// RevokeByClient immediately invalidates all tokens issued to the given OAuth client.
func (s *GlobalTokenRevocationService) RevokeByClient(ctx context.Context, clientID string, reason string, initiatedBy uuid.UUID) error {
	s.logger.Warn("Global token revocation: client",
		zap.String("client_id", clientID),
		zap.String("reason", reason),
		zap.String("initiated_by", initiatedBy.String()),
	)
	if s.blacklist == nil {
		return nil
	}
	expiry := time.Now().Add(30 * 24 * time.Hour)
	return s.blacklist.BlacklistByClientID(ctx, clientID, expiry)
}
