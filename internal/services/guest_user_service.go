// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// guestUserRepo narrows the repository surface needed by GuestUserService.
type guestUserRepo interface {
	Create(ctx context.Context, g *models.GuestUser) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.GuestUser, error)
	GetByHomeUser(ctx context.Context, hostTenantID, homeUserID uuid.UUID) (*models.GuestUser, error)
	List(ctx context.Context, hostTenantID uuid.UUID, filter models.GuestUserListFilter) ([]*models.GuestUser, int64, error)
	Update(ctx context.Context, g *models.GuestUser) error
	Delete(ctx context.Context, id uuid.UUID) error
	AddRole(ctx context.Context, a *models.GuestRoleAssignment) error
	RemoveRole(ctx context.Context, guestUserID, roleID uuid.UUID) error
	ListRoles(ctx context.Context, guestUserID uuid.UUID) ([]*models.GuestRoleAssignment, error)
	LogAccess(ctx context.Context, log *models.GuestAccessLog) error
}

// GuestUserService implements B2B guest user management.
type GuestUserService struct {
	guestRepo    guestUserRepo
	roleRepo     *repositories.RoleRepository
	auditService *AuditService
}

// NewGuestUserService constructs a GuestUserService.
func NewGuestUserService(
	guestRepo *repositories.GuestUserRepository,
	roleRepo *repositories.RoleRepository,
	auditService *AuditService,
) *GuestUserService {
	return &GuestUserService{
		guestRepo:    guestRepo,
		roleRepo:     roleRepo,
		auditService: auditService,
	}
}

// InviteGuest creates a pending guest user record for a cross-tenant invitation.
func (s *GuestUserService) InviteGuest(ctx context.Context, hostTenantID uuid.UUID, req *models.InviteGuestRequest, invitedBy uuid.UUID) (*models.GuestUserResponse, error) {
	// Defaults
	guestType := req.GuestType
	if guestType == "" {
		guestType = models.GuestUserTypeMember
	}

	guest := &models.GuestUser{
		HostTenantID: hostTenantID,
		HomeTenantID: uuid.Nil, // resolved when invitation is accepted
		HomeUserID:   uuid.Nil, // resolved when invitation is accepted
		Email:        req.Email,
		GuestType:    guestType,
		Status:       models.GuestUserStatusPending,
		InvitedBy:    invitedBy,
	}

	if req.InvitationMessage != "" {
		guest.InvitationMessage = &req.InvitationMessage
	}
	if req.ExpiryDays > 0 {
		t := time.Now().Add(time.Duration(req.ExpiryDays) * 24 * time.Hour)
		guest.ExpiresAt = &t
	}

	if err := s.guestRepo.Create(ctx, guest); err != nil {
		logger.Error("GuestUserService.InviteGuest: failed to create guest", zap.Error(err))
		return nil, fmt.Errorf("failed to create guest invitation")
	}

	// Assign initial roles if provided
	for _, roleID := range req.RoleIDs {
		a := &models.GuestRoleAssignment{
			GuestUserID: guest.ID,
			RoleID:      roleID,
			AssignedBy:  invitedBy,
		}
		if err := s.guestRepo.AddRole(ctx, a); err != nil {
			logger.Warn("GuestUserService.InviteGuest: failed to assign role",
				zap.String("role_id", roleID.String()), zap.Error(err))
		}
	}

	logger.Info("Guest invitation created",
		zap.String("guest_id", guest.ID.String()),
		zap.String("email", req.Email),
		zap.String("host_tenant_id", hostTenantID.String()),
	)

	return guest.ToResponse(), nil
}

// AcceptInvitation activates a pending guest user after they authenticate in their home tenant.
func (s *GuestUserService) AcceptInvitation(ctx context.Context, guestID, homeUserID, homeTenantID uuid.UUID) (*models.GuestUserResponse, error) {
	guest, err := s.guestRepo.GetByID(ctx, guestID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve guest invitation")
	}
	if guest == nil {
		return nil, fmt.Errorf("guest invitation not found")
	}
	if guest.Status != models.GuestUserStatusPending {
		return nil, fmt.Errorf("invitation is no longer pending (status: %s)", guest.Status)
	}
	if guest.IsExpired() {
		return nil, fmt.Errorf("invitation has expired")
	}

	now := time.Now()
	guest.Status = models.GuestUserStatusActive
	guest.HomeUserID = homeUserID
	guest.HomeTenantID = homeTenantID
	guest.AcceptedAt = &now

	if err := s.guestRepo.Update(ctx, guest); err != nil {
		logger.Error("GuestUserService.AcceptInvitation: failed to update guest", zap.Error(err))
		return nil, fmt.Errorf("failed to accept invitation")
	}

	logger.Info("Guest invitation accepted",
		zap.String("guest_id", guestID.String()),
		zap.String("home_user_id", homeUserID.String()),
	)

	return guest.ToResponse(), nil
}

// RevokeGuest revokes an active or pending guest user.
func (s *GuestUserService) RevokeGuest(ctx context.Context, guestID uuid.UUID) error {
	guest, err := s.guestRepo.GetByID(ctx, guestID)
	if err != nil {
		return fmt.Errorf("failed to retrieve guest")
	}
	if guest == nil {
		return fmt.Errorf("guest not found")
	}

	guest.Status = models.GuestUserStatusRevoked
	if err := s.guestRepo.Update(ctx, guest); err != nil {
		logger.Error("GuestUserService.RevokeGuest: failed to update guest", zap.Error(err))
		return fmt.Errorf("failed to revoke guest")
	}

	logger.Info("Guest revoked", zap.String("guest_id", guestID.String()))
	return nil
}

// ListGuests returns a paginated list of guests for a host tenant.
func (s *GuestUserService) ListGuests(ctx context.Context, hostTenantID uuid.UUID, filter models.GuestUserListFilter) (*models.GuestUserListResponse, error) {
	guests, total, err := s.guestRepo.List(ctx, hostTenantID, filter)
	if err != nil {
		return nil, fmt.Errorf("GuestUserService.ListGuests: %w", err)
	}

	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	page := filter.Page
	if page < 1 {
		page = 1
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	responses := make([]*models.GuestUserResponse, len(guests))
	for i, g := range guests {
		responses[i] = g.ToResponse()
	}

	return &models.GuestUserListResponse{
		Guests:     responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetGuest retrieves a single guest user by ID.
func (s *GuestUserService) GetGuest(ctx context.Context, guestID uuid.UUID) (*models.GuestUserResponse, error) {
	guest, err := s.guestRepo.GetByID(ctx, guestID)
	if err != nil {
		return nil, fmt.Errorf("GuestUserService.GetGuest: %w", err)
	}
	if guest == nil {
		return nil, nil
	}
	return guest.ToResponse(), nil
}

// UpdateGuest applies mutable field changes to a guest record.
func (s *GuestUserService) UpdateGuest(ctx context.Context, guestID uuid.UUID, req *models.UpdateGuestRequest) (*models.GuestUserResponse, error) {
	guest, err := s.guestRepo.GetByID(ctx, guestID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve guest")
	}
	if guest == nil {
		return nil, fmt.Errorf("guest not found")
	}

	if req.GuestType != nil {
		guest.GuestType = *req.GuestType
	}
	if req.Status != nil {
		guest.Status = *req.Status
	}
	if req.DisplayName != nil {
		guest.DisplayName = req.DisplayName
	}
	if req.ExpiresAt != nil {
		guest.ExpiresAt = req.ExpiresAt
	}

	if err := s.guestRepo.Update(ctx, guest); err != nil {
		logger.Error("GuestUserService.UpdateGuest: failed to update guest", zap.Error(err))
		return nil, fmt.Errorf("failed to update guest")
	}

	return guest.ToResponse(), nil
}

// SetRoles replaces the full set of role assignments for a guest user.
//
// hostTenantID is the tenant the acting admin is operating as (derived from
// request context, never client input). Two checks are performed before any
// mutation: (1) the guest actually belongs to hostTenantID — without this an
// admin of tenant A could silently reassign roles for a guest hosted by
// tenant B, given only the guest's UUID; (2) every requested role ID belongs
// to hostTenantID via RoleRepository.GetByIDAndTenant — the same
// tenant-scoping check already used by RoleHandler.GetByID/Update/Delete and
// TeamInvitationHandler's role-assignment paths, applied here for
// consistency across every surface that persists a role assignment.
func (s *GuestUserService) SetRoles(ctx context.Context, hostTenantID, guestID uuid.UUID, req *models.SetGuestRolesRequest, assignedBy uuid.UUID) error {
	guest, err := s.guestRepo.GetByID(ctx, guestID)
	if err != nil {
		return fmt.Errorf("GuestUserService.SetRoles get guest: %w", err)
	}
	if guest == nil || guest.HostTenantID != hostTenantID {
		return fmt.Errorf("guest not found")
	}

	for _, roleID := range req.RoleIDs {
		role, err := s.roleRepo.GetByIDAndTenant(ctx, roleID, hostTenantID)
		if err != nil {
			return fmt.Errorf("GuestUserService.SetRoles verify role %s: %w", roleID, err)
		}
		if role == nil {
			return fmt.Errorf("one or more role IDs are invalid for this tenant")
		}
	}

	// Remove all existing roles first
	existing, err := s.guestRepo.ListRoles(ctx, guestID)
	if err != nil {
		return fmt.Errorf("GuestUserService.SetRoles list existing: %w", err)
	}
	for _, a := range existing {
		if err := s.guestRepo.RemoveRole(ctx, guestID, a.RoleID); err != nil {
			logger.Warn("GuestUserService.SetRoles: failed to remove role",
				zap.String("role_id", a.RoleID.String()), zap.Error(err))
		}
	}

	// Add new roles
	for _, roleID := range req.RoleIDs {
		a := &models.GuestRoleAssignment{
			GuestUserID: guestID,
			RoleID:      roleID,
			AssignedBy:  assignedBy,
		}
		if err := s.guestRepo.AddRole(ctx, a); err != nil {
			logger.Error("GuestUserService.SetRoles: failed to add role",
				zap.String("role_id", roleID.String()), zap.Error(err))
			return fmt.Errorf("failed to assign role %s", roleID)
		}
	}

	return nil
}

// ResendInvitation re-sends the guest invitation email (email dispatch is a no-op stub here;
// hook into EmailService as needed).
func (s *GuestUserService) ResendInvitation(ctx context.Context, guestID uuid.UUID) (*models.GuestUserResponse, error) {
	guest, err := s.guestRepo.GetByID(ctx, guestID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve guest")
	}
	if guest == nil {
		return nil, fmt.Errorf("guest not found")
	}
	if guest.Status != models.GuestUserStatusPending {
		return nil, fmt.Errorf("can only resend invitation for pending guests")
	}

	logger.Info("Guest invitation resent", zap.String("guest_id", guestID.String()))
	return guest.ToResponse(), nil
}
