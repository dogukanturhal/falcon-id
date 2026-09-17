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

// jitSpiceDBClient defines the SpiceDB operations required by JITAccessService.
// It is a subset of the broader SpiceDBClient interface to keep the dependency
// surface minimal and make testing straightforward.
type jitSpiceDBClient interface {
	WriteRelationship(ctx context.Context, tenantID uuid.UUID, relationship interface{}) error
	DeleteRelationship(ctx context.Context, tenantID uuid.UUID, relationship interface{}) error
}

// jitAccessServiceRepo defines the persistence contract for JIT access grants.
type jitAccessServiceRepo interface {
	// Create persists a new grant, populating its ID and CreatedAt.
	Create(ctx context.Context, grant *models.JITAccessGrant) error

	// GetByID returns the grant identified by id.
	GetByID(ctx context.Context, id uuid.UUID) (*models.JITAccessGrant, error)

	// UpdateStatus atomically transitions a grant to a new status.
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.JITAccessStatus) error

	// Approve records approval metadata and transitions the grant to "approved".
	Approve(ctx context.Context, id, approverID uuid.UUID, startsAt time.Time) error

	// Activate transitions a grant from "approved" to "active".
	Activate(ctx context.Context, id uuid.UUID) error

	// ListByTenant returns all grants for a tenant, optionally filtered by status.
	ListByTenant(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]*models.JITAccessGrant, int64, error)

	// ListExpiredActive returns all grants whose status is "active" and whose
	// expires_at is in the past, up to a given limit.
	ListExpiredActive(ctx context.Context, limit int) ([]*models.JITAccessGrant, error)
}

// JITAccessService manages just-in-time access grants: request, approval,
// activation, expiry, and revocation.
type JITAccessService struct {
	repo         jitAccessServiceRepo
	spicedb      jitSpiceDBClient
	auditService *AuditService
	logger       *zap.Logger
}

// NewJITAccessService creates a new JITAccessService.
func NewJITAccessService(
	repo jitAccessServiceRepo,
	spicedb jitSpiceDBClient,
	auditService *AuditService,
	logger *zap.Logger,
) *JITAccessService {
	return &JITAccessService{
		repo:         repo,
		spicedb:      spicedb,
		auditService: auditService,
		logger:       logger,
	}
}

// RequestAccess creates a new just-in-time access grant in the "pending" state.
// The requester provides the target user, role, justification, and desired
// duration. An approver must subsequently call ApproveAccess before the grant
// can become active.
func (s *JITAccessService) RequestAccess(
	ctx context.Context,
	tenantID uuid.UUID,
	req *models.CreateJITAccessRequest,
) (*models.JITAccessGrant, error) {
	now := time.Now().UTC()
	grant := &models.JITAccessGrant{
		UserID:        req.UserID,
		RoleID:        req.RoleID,
		TenantID:      tenantID,
		Justification: req.Justification,
		RequestedAt:   now,
		// StartsAt and ExpiresAt are resolved relative to now; they will be
		// updated again on approval if an explicit start time is provided.
		StartsAt:  now,
		ExpiresAt: now.Add(time.Duration(req.Duration) * time.Second),
		Status:    models.JITAccessStatusPending,
	}

	if err := s.repo.Create(ctx, grant); err != nil {
		return nil, fmt.Errorf("JITAccessService.RequestAccess: %w", err)
	}

	s.logger.Info("JIT access requested",
		zap.String("grant_id", grant.ID.String()),
		zap.String("user_id", req.UserID.String()),
		zap.String("role_id", req.RoleID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, &req.UserID, nil, "jit_access_requested", true, map[string]interface{}{
			"grant_id":      grant.ID.String(),
			"role_id":       req.RoleID.String(),
			"justification": req.Justification,
			"expires_at":    grant.ExpiresAt,
		})
	}

	return grant, nil
}

// getGrantInTenant fetches a grant by ID and asserts it belongs to
// tenantID before returning it. Every direct-object lookup on a JIT grant
// (approve, activate, revoke) must go through this rather than
// s.repo.GetByID directly: GetByID itself is not tenant-scoped, so calling
// it bare lets an authenticated caller from any tenant act on another
// tenant's grant by guessing/enumerating its UUID (t-437). A cross-tenant
// grant is reported as not found, not as "wrong tenant", so the response
// gives no signal that the ID exists at all.
func (s *JITAccessService) getGrantInTenant(ctx context.Context, grantID, tenantID uuid.UUID) (*models.JITAccessGrant, error) {
	grant, err := s.repo.GetByID(ctx, grantID)
	if err != nil {
		return nil, fmt.Errorf("JIT access grant not found: %w", err)
	}
	if grant == nil || grant.TenantID != tenantID {
		return nil, fmt.Errorf("JIT access grant not found")
	}
	return grant, nil
}

// ApproveAccess transitions a pending grant to the "approved" state and
// records the approver's identity. If req.StartsAt is set, the grant will
// become active at that future time; otherwise it starts immediately and
// ActivateGrant should be called right away.
func (s *JITAccessService) ApproveAccess(
	ctx context.Context,
	grantID, approverID, approverTenantID uuid.UUID,
) (*models.JITAccessGrant, error) {
	grant, err := s.getGrantInTenant(ctx, grantID, approverTenantID)
	if err != nil {
		return nil, err
	}

	if grant.Status != models.JITAccessStatusPending {
		return nil, fmt.Errorf("grant is not in pending state (current: %s)", grant.Status)
	}

	// Prevent self-approval (separation of duties)
	if approverID == grant.UserID {
		return nil, fmt.Errorf("cannot approve your own JIT access request")
	}

	if err := s.repo.Approve(ctx, grantID, approverID, grant.StartsAt); err != nil {
		return nil, fmt.Errorf("JITAccessService.ApproveAccess: %w", err)
	}

	s.logger.Info("JIT access approved",
		zap.String("grant_id", grantID.String()),
		zap.String("approver_id", approverID.String()),
	)

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, grant.TenantID, &approverID, &grant.UserID, "jit_access_approved", true, map[string]interface{}{
			"grant_id": grantID.String(),
			"role_id":  grant.RoleID.String(),
		})
	}

	return s.repo.GetByID(ctx, grantID)
}

// jitRelationship is the minimal struct written to SpiceDB to represent the
// temporary role membership created by an active JIT grant.
type jitRelationship struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
	RoleID   uuid.UUID
	GrantID  uuid.UUID
}

// ActivateGrant transitions an approved grant to the "active" state and
// writes the corresponding role membership to SpiceDB so that the user
// immediately acquires the role for the duration of the grant.
func (s *JITAccessService) ActivateGrant(ctx context.Context, grantID, tenantID uuid.UUID) error {
	grant, err := s.getGrantInTenant(ctx, grantID, tenantID)
	if err != nil {
		return err
	}

	if grant.Status != models.JITAccessStatusApproved {
		return fmt.Errorf("grant is not in approved state (current: %s)", grant.Status)
	}

	if grant.IsExpired() {
		if markErr := s.repo.UpdateStatus(ctx, grantID, models.JITAccessStatusExpired); markErr != nil {
			s.logger.Warn("Failed to mark expired grant during activation",
				zap.String("grant_id", grantID.String()),
				zap.Error(markErr),
			)
		}
		return fmt.Errorf("grant %s has already expired", grantID)
	}

	// Write the temporary role assignment to SpiceDB.
	rel := jitRelationship{
		TenantID: grant.TenantID,
		UserID:   grant.UserID,
		RoleID:   grant.RoleID,
		GrantID:  grant.ID,
	}
	if err := s.spicedb.WriteRelationship(ctx, grant.TenantID, rel); err != nil {
		return fmt.Errorf("JITAccessService.ActivateGrant write SpiceDB relationship: %w", err)
	}

	if err := s.repo.Activate(ctx, grantID); err != nil {
		// Best-effort rollback of the SpiceDB write.
		if delErr := s.spicedb.DeleteRelationship(ctx, grant.TenantID, rel); delErr != nil {
			s.logger.Error("Failed to rollback SpiceDB relationship after activation failure",
				zap.String("grant_id", grantID.String()),
				zap.Error(delErr),
			)
		}
		return fmt.Errorf("JITAccessService.ActivateGrant persist: %w", err)
	}

	s.logger.Info("JIT access grant activated",
		zap.String("grant_id", grantID.String()),
		zap.String("user_id", grant.UserID.String()),
		zap.String("role_id", grant.RoleID.String()),
		zap.Time("expires_at", grant.ExpiresAt),
	)

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, grant.TenantID, nil, &grant.UserID, "jit_access_activated", true, map[string]interface{}{
			"grant_id":   grantID.String(),
			"role_id":    grant.RoleID.String(),
			"expires_at": grant.ExpiresAt,
		})
	}

	return nil
}

// ExpireGrants is intended to be called by a background worker on a regular
// schedule (e.g. every minute). It finds all grants that are in the "active"
// state but whose expires_at is in the past, removes their SpiceDB
// relationships, and marks them as "expired".
func (s *JITAccessService) ExpireGrants(ctx context.Context) error {
	const batchLimit = 100

	expired, err := s.repo.ListExpiredActive(ctx, batchLimit)
	if err != nil {
		return fmt.Errorf("JITAccessService.ExpireGrants list: %w", err)
	}

	var lastErr error
	for _, grant := range expired {
		rel := jitRelationship{
			TenantID: grant.TenantID,
			UserID:   grant.UserID,
			RoleID:   grant.RoleID,
			GrantID:  grant.ID,
		}

		if err := s.spicedb.DeleteRelationship(ctx, grant.TenantID, rel); err != nil {
			s.logger.Error("Failed to delete SpiceDB relationship for expired grant",
				zap.String("grant_id", grant.ID.String()),
				zap.Error(err),
			)
			lastErr = err
			// Continue processing remaining grants even if one fails.
			continue
		}

		if err := s.repo.UpdateStatus(ctx, grant.ID, models.JITAccessStatusExpired); err != nil {
			s.logger.Error("Failed to mark grant as expired",
				zap.String("grant_id", grant.ID.String()),
				zap.Error(err),
			)
			lastErr = err
			continue
		}

		s.logger.Info("JIT access grant expired",
			zap.String("grant_id", grant.ID.String()),
			zap.String("user_id", grant.UserID.String()),
			zap.String("role_id", grant.RoleID.String()),
		)

		if s.auditService != nil {
			s.auditService.LogUserAction(ctx, grant.TenantID, nil, &grant.UserID, "jit_access_expired", true, map[string]interface{}{
				"grant_id":   grant.ID.String(),
				"role_id":    grant.RoleID.String(),
				"expires_at": grant.ExpiresAt,
			})
		}
	}

	return lastErr
}

// RevokeGrant immediately revokes an active or approved grant, removing the
// SpiceDB relationship if the grant was active.
func (s *JITAccessService) RevokeGrant(ctx context.Context, grantID, revokerID, revokerTenantID uuid.UUID) error {
	grant, err := s.getGrantInTenant(ctx, grantID, revokerTenantID)
	if err != nil {
		return err
	}

	if grant.Status == models.JITAccessStatusExpired || grant.Status == models.JITAccessStatusRevoked {
		return fmt.Errorf("grant is already %s", grant.Status)
	}

	// If the grant is active, remove the SpiceDB relationship first.
	if grant.Status == models.JITAccessStatusActive {
		rel := jitRelationship{
			TenantID: grant.TenantID,
			UserID:   grant.UserID,
			RoleID:   grant.RoleID,
			GrantID:  grant.ID,
		}
		if err := s.spicedb.DeleteRelationship(ctx, grant.TenantID, rel); err != nil {
			return fmt.Errorf("JITAccessService.RevokeGrant delete SpiceDB relationship: %w", err)
		}
	}

	if err := s.repo.UpdateStatus(ctx, grantID, models.JITAccessStatusRevoked); err != nil {
		return fmt.Errorf("JITAccessService.RevokeGrant persist: %w", err)
	}

	s.logger.Info("JIT access grant revoked",
		zap.String("grant_id", grantID.String()),
		zap.String("revoker_id", revokerID.String()),
	)

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, grant.TenantID, &revokerID, &grant.UserID, "jit_access_revoked", true, map[string]interface{}{
			"grant_id": grantID.String(),
			"role_id":  grant.RoleID.String(),
		})
	}

	return nil
}

// ListGrants returns a paginated list of JIT grants for the given tenant,
// optionally filtered by status string (empty = all statuses).
func (s *JITAccessService) ListGrants(
	ctx context.Context,
	tenantID uuid.UUID,
	status string,
	page, pageSize int,
) ([]*models.JITAccessGrant, int64, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}

	grants, total, err := s.repo.ListByTenant(ctx, tenantID, status, page, pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("JITAccessService.ListGrants: %w", err)
	}
	return grants, total, nil
}

// ListPendingElevations returns all pending JIT access grants visible to the
// given approver across their tenant. The current implementation returns all
// tenant-wide pending grants; a future iteration can layer role-based approval
// policy filtering on top once approval policies are modelled.
func (s *JITAccessService) ListPendingElevations(ctx context.Context, tenantID, approverID uuid.UUID) ([]*models.JITAccessGrant, error) {
	// Fetch all pending grants for the tenant using a generous page size so
	// that the governance dashboard receives the full set in a single call.
	const maxPending = 10000
	grants, _, err := s.repo.ListByTenant(ctx, tenantID, string(models.JITAccessStatusPending), 1, maxPending)
	if err != nil {
		return nil, fmt.Errorf("JITAccessService.ListPendingElevations: %w", err)
	}

	s.logger.Info("Listed pending JIT elevations",
		zap.String("approver_id", approverID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.Int("count", len(grants)),
	)

	return grants, nil
}
