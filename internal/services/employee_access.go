// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// Errors of EmployeeAccessService.SetExpiry.
var (
	ErrEmployeeMembershipNotFound = errors.New("employee membership not found")
	ErrNotEmployeeSeat            = errors.New("membership is not an employee seat")
)

// EmployeeAccessService ends the access of employee-class (ESS) seats, R-HR WP-21. One implementation serves the S2S
// access-expiry endpoint and EmployeeAccessExpiryWorker. Every step is idempotent and the membership is deactivated
// LAST, so a failure part-way is retried by the worker (it lists only still-active memberships).
type EmployeeAccessService struct {
	users       *repositories.UserRepository
	memberships *repositories.UserMembershipRepository
	bootstrap   *TenantBootstrapService
	logger      *zap.Logger
}

// NewEmployeeAccessService constructs the service. bootstrap may be nil only in tests (SpiceDB sync then fails closed).
func NewEmployeeAccessService(users *repositories.UserRepository, memberships *repositories.UserMembershipRepository, bootstrap *TenantBootstrapService, logger *zap.Logger) *EmployeeAccessService {
	return &EmployeeAccessService{users: users, memberships: memberships, bootstrap: bootstrap, logger: logger}
}

// SetExpiry stores the expiry on the employee membership; an expiry at or before now deactivates the account immediately.
func (s *EmployeeAccessService) SetExpiry(ctx context.Context, tenantID, userID uuid.UUID, expiresAt *time.Time) error {
	m, err := s.memberships.GetByTenantAndUser(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if m == nil {
		return ErrEmployeeMembershipNotFound
	}
	if m.SeatClass != models.SeatClassEmployee {
		return ErrNotEmployeeSeat
	}
	if _, err := s.memberships.SetAccessExpiry(ctx, tenantID, userID, expiresAt); err != nil {
		return err
	}
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return s.Deactivate(ctx, tenantID, userID)
	}
	return nil
}

// Deactivate switches the employee user off in PostgreSQL and SpiceDB and finally closes the membership.
func (s *EmployeeAccessService) Deactivate(ctx context.Context, tenantID, userID uuid.UUID) error {
	resourceType := "user"
	audit := &models.AuditLog{
		TenantID: tenantID, TargetUserID: &userID, Action: "employee_access_expired", ResourceType: &resourceType, ResourceID: &userID,
		Details: map[string]interface{}{"result": "success", "seat_class": string(models.SeatClassEmployee)}, Success: true,
	}
	if err := s.users.DeactivateEmployeeUser(ctx, tenantID, userID, audit); err != nil && !errors.Is(err, repositories.ErrTeamTargetNotFound) {
		return err
	}
	if err := s.users.RevokeTenantRoles(ctx, userID, tenantID); err != nil {
		return err
	}
	if s.bootstrap == nil {
		return fmt.Errorf("EmployeeAccessService: SpiceDB bootstrap not wired")
	}
	if err := s.bootstrap.SyncUserAccess(ctx, tenantID, userID, false, false, nil); err != nil {
		return fmt.Errorf("EmployeeAccessService: authorization revocation: %w", err)
	}
	if _, err := s.memberships.DeactivateEmployee(ctx, tenantID, userID); err != nil {
		return err
	}
	return nil
}
