// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"go.uber.org/zap"
)

const delegationNameUnknown = "Unknown"

// delegationServiceDelegationRepo defines the delegation repository methods needed by DelegationService.
type delegationServiceDelegationRepo interface {
	Create(ctx context.Context, delegation *models.Delegation) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Delegation, error)
	Revoke(ctx context.Context, delegationID, revokerID uuid.UUID) error
	ListByDelegator(ctx context.Context, userID uuid.UUID, includeRevoked bool) ([]*models.Delegation, error)
	ListByDelegatee(ctx context.Context, userID uuid.UUID, includeRevoked bool) ([]*models.Delegation, error)
	GetActiveDelegationsForUser(ctx context.Context, delegateeID uuid.UUID) ([]*models.Delegation, error)
	CleanupExpired(ctx context.Context, retentionDays int) (int64, error)
}

// delegationServiceUserRepo defines the user repository methods needed by DelegationService.
type delegationServiceUserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
}

// SpiceDBClient is an interface for SpiceDB operations needed by delegation service
type SpiceDBClient interface {
	CheckPermission(ctx context.Context, tenantID, userID uuid.UUID, resourceType, resourceID, permission string) (bool, error)
	WriteRelationship(ctx context.Context, tenantID uuid.UUID, relationship interface{}) error
	DeleteRelationship(ctx context.Context, tenantID uuid.UUID, relationship interface{}) error
}

// DelegationService is an exported type.
type DelegationService struct {
	delegationRepo delegationServiceDelegationRepo
	userRepo       delegationServiceUserRepo
	spicedb        SpiceDBClient
	auditService   *AuditService
	logger         *zap.Logger
}

// NewDelegationService is an exported function.
func NewDelegationService(
	delegationRepo delegationServiceDelegationRepo,
	userRepo delegationServiceUserRepo,
	spicedb SpiceDBClient,
	auditService *AuditService,
	logger *zap.Logger,
) *DelegationService {
	return &DelegationService{
		delegationRepo: delegationRepo,
		userRepo:       userRepo,
		spicedb:        spicedb,
		auditService:   auditService,
		logger:         logger,
	}
}

// CreateDelegation creates a new delegation
func (s *DelegationService) CreateDelegation(ctx context.Context, delegatorID, tenantID uuid.UUID, req *models.CreateDelegationRequest) (*models.Delegation, error) {
	// Validate delegator has the permissions they're delegating
	for _, perm := range req.Permissions {
		// Skip wildcard permission check - only admins can delegate wildcard
		if perm == "*" {
			// Check if delegator is admin
			allowed, err := s.spicedb.CheckPermission(ctx, tenantID, delegatorID, "tenant", tenantID.String(), "admin")
			if err != nil {
				return nil, fmt.Errorf("failed to check admin permission: %w", err)
			}
			if !allowed {
				return nil, fmt.Errorf("only admins can delegate wildcard permissions")
			}
			continue
		}

		// For specific permissions, check if delegator has them
		resourceType := auditResourceTypeUser
		resourceID := delegatorID.String()
		if req.ResourceType != nil {
			resourceType = *req.ResourceType
		}
		if req.ResourceID != nil {
			resourceID = *req.ResourceID
		}

		allowed, err := s.spicedb.CheckPermission(ctx, tenantID, delegatorID, resourceType, resourceID, perm)
		if err != nil {
			return nil, fmt.Errorf("failed to check permission %s: %w", perm, err)
		}
		if !allowed {
			return nil, fmt.Errorf("cannot delegate permission %s: you don't have it", perm)
		}
	}

	// Validate delegatee exists
	delegatee, err := s.userRepo.GetByID(ctx, req.DelegateeID)
	if err != nil {
		return nil, fmt.Errorf("delegatee user not found: %w", err)
	}
	if delegatee.TenantID != tenantID {
		return nil, fmt.Errorf("delegatee must be in the same tenant")
	}

	// Create delegation
	delegation := &models.Delegation{
		TenantID:     tenantID,
		DelegatorID:  delegatorID,
		DelegateeID:  req.DelegateeID,
		Permissions:  req.Permissions,
		ResourceType: req.ResourceType,
		ResourceID:   req.ResourceID,
		ExpiresAt:    time.Now().Add(time.Duration(req.Duration) * time.Second),
		Reason:       req.Reason,
	}

	// Store in database
	if err := s.delegationRepo.Create(ctx, delegation); err != nil {
		return nil, fmt.Errorf("failed to create delegation: %w", err)
	}

	s.logger.Info("Delegation created",
		zap.String("delegation_id", delegation.ID.String()),
		zap.String("delegator_id", delegatorID.String()),
		zap.String("delegatee_id", req.DelegateeID.String()),
		zap.Strings("permissions", req.Permissions),
		zap.Time("expires_at", delegation.ExpiresAt),
	)

	// Audit log
	s.auditService.LogUserAction(ctx, tenantID, &delegatorID, &req.DelegateeID, "delegation_created", true, map[string]interface{}{
		"delegation_id": delegation.ID.String(),
		"permissions":   req.Permissions,
		"resource_type": req.ResourceType,
		"resource_id":   req.ResourceID,
		"expires_at":    delegation.ExpiresAt,
		"reason":        req.Reason,
	})

	return delegation, nil
}

// RevokeDelegation revokes a delegation
func (s *DelegationService) RevokeDelegation(ctx context.Context, delegationID, revokerID, tenantID uuid.UUID) error {
	// Load delegation
	delegation, err := s.delegationRepo.GetByID(ctx, delegationID)
	if err != nil {
		return fmt.Errorf("delegation not found: %w", err)
	}

	// Verify tenant match
	if delegation.TenantID != tenantID {
		return fmt.Errorf("delegation not found in this tenant")
	}

	// Check authorization - only delegator or admin can revoke
	canRevoke := delegation.DelegatorID == revokerID
	if !canRevoke {
		// Check if revoker is admin
		isAdmin, err := s.spicedb.CheckPermission(ctx, tenantID, revokerID, "tenant", tenantID.String(), "admin")
		if err != nil {
			return fmt.Errorf("failed to check admin permission: %w", err)
		}
		canRevoke = isAdmin
	}

	if !canRevoke {
		return fmt.Errorf("only the delegator or admin can revoke this delegation")
	}

	// Revoke in database
	if err := s.delegationRepo.Revoke(ctx, delegationID, revokerID); err != nil {
		return fmt.Errorf("failed to revoke delegation: %w", err)
	}

	s.logger.Info("Delegation revoked",
		zap.String("delegation_id", delegationID.String()),
		zap.String("revoker_id", revokerID.String()),
	)

	// Audit log
	s.auditService.LogUserAction(ctx, tenantID, &revokerID, &delegation.DelegateeID, "delegation_revoked", true, map[string]interface{}{
		"delegation_id": delegationID.String(),
		"delegator_id":  delegation.DelegatorID.String(),
	})

	return nil
}

// ListMyDelegations lists all delegations created by or received by the user
func (s *DelegationService) ListMyDelegations(ctx context.Context, userID uuid.UUID, includeRevoked bool) ([]models.DelegationResponse, error) {
	// Get delegations given by user
	given, err := s.delegationRepo.ListByDelegator(ctx, userID, includeRevoked)
	if err != nil {
		return nil, fmt.Errorf("failed to get delegations given: %w", err)
	}

	// Get delegations received by user
	received, err := s.delegationRepo.ListByDelegatee(ctx, userID, includeRevoked)
	if err != nil {
		return nil, fmt.Errorf("failed to get delegations received: %w", err)
	}

	// Combine and convert to responses
	given = append(given, received...)
	allDelegations := given
	responses := make([]models.DelegationResponse, 0, len(allDelegations))

	// Collect all user IDs for batch lookup
	userIDs := make(map[uuid.UUID]bool)
	for _, d := range allDelegations {
		userIDs[d.DelegatorID] = true
		userIDs[d.DelegateeID] = true
	}

	// Fetch all users
	userCache := make(map[uuid.UUID]string)
	for userID := range userIDs {
		user, err := s.userRepo.GetByID(ctx, userID)
		if err != nil {
			s.logger.Warn("Failed to load user for delegation",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
			userCache[userID] = "Unknown User"
			continue
		}
		displayName := user.Email
		if user.DisplayName != nil && *user.DisplayName != "" {
			displayName = *user.DisplayName
		}
		userCache[userID] = displayName
	}

	// Convert to responses
	for _, d := range allDelegations {
		delegatorName := userCache[d.DelegatorID]
		delegateeName := userCache[d.DelegateeID]
		responses = append(responses, *d.ToResponse(delegatorName, delegateeName))
	}

	return responses, nil
}

// GetDelegation retrieves a delegation by ID
func (s *DelegationService) GetDelegation(ctx context.Context, delegationID, userID, tenantID uuid.UUID) (*models.DelegationResponse, error) {
	delegation, err := s.delegationRepo.GetByID(ctx, delegationID)
	if err != nil {
		return nil, fmt.Errorf("delegation not found: %w", err)
	}

	// Verify tenant match
	if delegation.TenantID != tenantID {
		return nil, fmt.Errorf("delegation not found in this tenant")
	}

	// Check if user is involved in the delegation or is admin
	isInvolved := delegation.DelegatorID == userID || delegation.DelegateeID == userID
	if !isInvolved {
		// Check if user is admin
		isAdmin, err := s.spicedb.CheckPermission(ctx, tenantID, userID, "tenant", tenantID.String(), "admin")
		if err != nil {
			return nil, fmt.Errorf("failed to check admin permission: %w", err)
		}
		if !isAdmin {
			return nil, fmt.Errorf("delegation not found")
		}
	}

	// Load user names
	delegator, _ := s.userRepo.GetByID(ctx, delegation.DelegatorID)
	delegatee, _ := s.userRepo.GetByID(ctx, delegation.DelegateeID)

	delegatorName := delegationNameUnknown
	if delegator != nil {
		delegatorName = delegator.Email
		if delegator.DisplayName != nil {
			delegatorName = *delegator.DisplayName
		}
	}

	delegateeName := delegationNameUnknown
	if delegatee != nil {
		delegateeName = delegatee.Email
		if delegatee.DisplayName != nil {
			delegateeName = *delegatee.DisplayName
		}
	}

	return delegation.ToResponse(delegatorName, delegateeName), nil
}

// GetActiveDelegationsForUser returns all active delegations for a user
func (s *DelegationService) GetActiveDelegationsForUser(ctx context.Context, delegateeID uuid.UUID) ([]*models.Delegation, error) {
	return s.delegationRepo.GetActiveDelegationsForUser(ctx, delegateeID)
}

// CleanupExpiredDelegations removes expired delegations
func (s *DelegationService) CleanupExpiredDelegations(ctx context.Context, retentionDays int) error {
	count, err := s.delegationRepo.CleanupExpired(ctx, retentionDays)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired delegations: %w", err)
	}

	if count > 0 {
		s.logger.Info("Cleaned up expired delegations",
			zap.Int64("count", count),
		)
	}

	return nil
}
