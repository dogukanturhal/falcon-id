// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ==================== Mock declarations ====================

// MockImpersonationRepo mocks impersonationServiceImpersonationRepo.
type MockImpersonationRepo struct {
	mock.Mock
}

func (m *MockImpersonationRepo) GetActiveByAdminID(ctx context.Context, adminUserID uuid.UUID) (*models.ImpersonationSession, error) {
	args := m.Called(ctx, adminUserID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ImpersonationSession), args.Error(1)
}

func (m *MockImpersonationRepo) Create(ctx context.Context, session *models.ImpersonationSession) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockImpersonationRepo) EndSession(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockImpersonationRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.ImpersonationSession, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ImpersonationSession), args.Error(1)
}

func (m *MockImpersonationRepo) GetWithUsers(ctx context.Context, id uuid.UUID) (*models.ImpersonationSession, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ImpersonationSession), args.Error(1)
}

func (m *MockImpersonationRepo) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, adminUserID, targetUserID *uuid.UUID, activeOnly bool) ([]*models.ImpersonationSession, int, error) {
	args := m.Called(ctx, tenantID, page, pageSize, adminUserID, targetUserID, activeOnly)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.ImpersonationSession), args.Int(1), args.Error(2)
}

// MockImpersonationUserRepo mocks impersonationServiceUserRepo.
type MockImpersonationUserRepo struct {
	mock.Mock
}

func (m *MockImpersonationUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockImpersonationUserRepo) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *MockImpersonationUserRepo) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

// ==================== Helpers ====================

func newImpersonationService(ir *MockImpersonationRepo, ur *MockImpersonationUserRepo) *ImpersonationService {
	return &ImpersonationService{
		impersonationRepo: ir,
		userRepo:          ur,
		// sessionRepo, auditService, authService left nil for tests that do not
		// reach those branches (e.g. error-path tests).
	}
}

func buildAdminUser(tenantID uuid.UUID) *models.User {
	return &models.User{
		ID:       uuid.New(),
		TenantID: tenantID,
		Username: "admin-user",
		Email:    "admin@example.com",
		IsActive: true,
	}
}

func buildRegularUser(tenantID uuid.UUID) *models.User {
	return &models.User{
		ID:       uuid.New(),
		TenantID: tenantID,
		Username: "regular-user",
		Email:    "user@example.com",
		IsActive: true,
	}
}

// ==================== StartImpersonation error paths ====================

func TestImpersonationService_StartImpersonation_AdminNotFound(t *testing.T) {
	ctx := context.Background()
	adminID := uuid.New()
	targetID := uuid.New()

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ur.On("GetByID", ctx, adminID).Return(nil, errors.New("not found"))

	_, err := svc.StartImpersonation(ctx, adminID, targetID, "valid reason here", "127.0.0.1", "test-agent", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "admin user not found")
}

func TestImpersonationService_StartImpersonation_TargetNotFound(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	admin := buildAdminUser(tenantID)
	targetID := uuid.New()

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ur.On("GetByID", ctx, admin.ID).Return(admin, nil)
	ur.On("GetByID", ctx, targetID).Return(nil, errors.New("not found"))

	_, err := svc.StartImpersonation(ctx, admin.ID, targetID, "valid reason here", "127.0.0.1", "agent", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "target user not found")
}

func TestImpersonationService_StartImpersonation_CannotImpersonateSelf(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	admin := buildAdminUser(tenantID)

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	// Both GetByID calls return the same user (admin impersonating self)
	ur.On("GetByID", ctx, admin.ID).Return(admin, nil).Times(2)

	_, err := svc.StartImpersonation(ctx, admin.ID, admin.ID, "valid reason here", "127.0.0.1", "agent", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot impersonate yourself")
}

func TestImpersonationService_StartImpersonation_DifferentTenant(t *testing.T) {
	ctx := context.Background()
	tenantA := uuid.New()
	tenantB := uuid.New()

	admin := buildAdminUser(tenantA)
	target := buildRegularUser(tenantB) // different tenant

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ur.On("GetByID", ctx, admin.ID).Return(admin, nil)
	ur.On("GetByID", ctx, target.ID).Return(target, nil)

	_, err := svc.StartImpersonation(ctx, admin.ID, target.ID, "valid reason here", "127.0.0.1", "agent", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot impersonate user from different tenant")
}

func TestImpersonationService_StartImpersonation_AlreadyActive(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	admin := buildAdminUser(tenantID)
	target := buildRegularUser(tenantID)

	existingSession := &models.ImpersonationSession{
		ID:          uuid.New(),
		AdminUserID: admin.ID,
		TenantID:    tenantID,
	}

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ur.On("GetByID", ctx, admin.ID).Return(admin, nil)
	ur.On("GetByID", ctx, target.ID).Return(target, nil)
	ir.On("GetActiveByAdminID", ctx, admin.ID).Return(existingSession, nil)

	_, err := svc.StartImpersonation(ctx, admin.ID, target.ID, "valid reason here", "127.0.0.1", "agent", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already have an active impersonation session")
}

func TestImpersonationService_StartImpersonation_ReasonTooShort(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	admin := buildAdminUser(tenantID)
	target := buildRegularUser(tenantID)

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ur.On("GetByID", ctx, admin.ID).Return(admin, nil)
	ur.On("GetByID", ctx, target.ID).Return(target, nil)
	ir.On("GetActiveByAdminID", ctx, admin.ID).Return(nil, nil)

	_, err := svc.StartImpersonation(ctx, admin.ID, target.ID, "short", "127.0.0.1", "agent", nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 10 characters")
}

// ==================== EndImpersonation ====================

func TestImpersonationService_EndImpersonation_SessionNotFound(t *testing.T) {
	ctx := context.Background()
	sessionID := uuid.New()
	adminID := uuid.New()

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ir.On("GetByID", ctx, sessionID).Return(nil, errors.New("not found"))

	err := svc.EndImpersonation(ctx, sessionID, adminID, "127.0.0.1", "agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "impersonation session not found")
}

func TestImpersonationService_EndImpersonation_WrongAdmin(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	adminID := uuid.New()
	otherAdminID := uuid.New()
	sessionID := uuid.New()

	session := &models.ImpersonationSession{
		ID:           sessionID,
		TenantID:     tenantID,
		AdminUserID:  adminID, // session belongs to adminID
		TargetUserID: uuid.New(),
	}

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ir.On("GetByID", ctx, sessionID).Return(session, nil)

	// otherAdminID tries to end a session they didn't start
	err := svc.EndImpersonation(ctx, sessionID, otherAdminID, "127.0.0.1", "agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "did not start this impersonation session")
}

func TestImpersonationService_EndImpersonation_AlreadyEnded(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	adminID := uuid.New()
	sessionID := uuid.New()

	endedAt := time.Now().Add(-10 * time.Minute)
	session := &models.ImpersonationSession{
		ID:           sessionID,
		TenantID:     tenantID,
		AdminUserID:  adminID,
		TargetUserID: uuid.New(),
		EndedAt:      &endedAt, // already ended
	}

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ir.On("GetByID", ctx, sessionID).Return(session, nil)

	err := svc.EndImpersonation(ctx, sessionID, adminID, "127.0.0.1", "agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already ended")
}

func TestImpersonationService_EndImpersonation_Valid(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	adminID := uuid.New()
	sessionID := uuid.New()

	session := &models.ImpersonationSession{
		ID:           sessionID,
		TenantID:     tenantID,
		AdminUserID:  adminID,
		TargetUserID: uuid.New(),
		EndedAt:      nil, // active
	}

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	// Nil audit service: logAuditEvent checks for nil and returns early.
	svc := newImpersonationService(ir, ur)

	ir.On("GetByID", ctx, sessionID).Return(session, nil)
	ir.On("EndSession", ctx, sessionID).Return(nil)

	err := svc.EndImpersonation(ctx, sessionID, adminID, "127.0.0.1", "agent")

	require.NoError(t, err)
	ir.AssertExpectations(t)
}

// ==================== ListImpersonationSessions ====================

func TestImpersonationService_ListImpersonationSessions_ActiveOnly(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	adminID := uuid.New()
	targetID := uuid.New()

	sessions := []*models.ImpersonationSession{
		{ID: uuid.New(), TenantID: tenantID, AdminUserID: adminID, TargetUserID: targetID},
	}

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ir.On("List", ctx, tenantID, 1, 20, (*uuid.UUID)(nil), (*uuid.UUID)(nil), true).
		Return(sessions, 1, nil)
	ur.On("GetByID", ctx, adminID).Return(buildAdminUser(tenantID), nil)
	ur.On("GetByID", ctx, targetID).Return(buildRegularUser(tenantID), nil)

	result, err := svc.ListImpersonationSessions(ctx, tenantID, 1, 20, nil, nil, true)

	require.NoError(t, err)
	assert.Len(t, result.Sessions, 1)
	assert.Equal(t, 1, result.Total)
}

func TestImpersonationService_ListImpersonationSessions_Empty(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ir.On("List", ctx, tenantID, 1, 20, (*uuid.UUID)(nil), (*uuid.UUID)(nil), false).
		Return([]*models.ImpersonationSession{}, 0, nil)

	result, err := svc.ListImpersonationSessions(ctx, tenantID, 1, 20, nil, nil, false)

	require.NoError(t, err)
	assert.Empty(t, result.Sessions)
	assert.Equal(t, 0, result.Total)
}

// ==================== GetImpersonationStatus ====================

func TestImpersonationService_GetImpersonationStatus_NoImpersonator(t *testing.T) {
	ctx := context.Background()

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	status, err := svc.GetImpersonationStatus(ctx, nil, nil)

	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.IsImpersonating)
}

func TestImpersonationService_GetImpersonationStatus_ActiveSession(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	adminID := uuid.New()
	targetID := uuid.New()
	sessionID := uuid.New()

	admin := buildAdminUser(tenantID)
	admin.ID = adminID
	target := buildRegularUser(tenantID)
	target.ID = targetID

	reason := "support investigation"
	startedAt := time.Now().Add(-5 * time.Minute)
	session := &models.ImpersonationSession{
		ID:           sessionID,
		TenantID:     tenantID,
		AdminUserID:  adminID,
		TargetUserID: targetID,
		Reason:       reason,
		StartedAt:    startedAt,
		EndedAt:      nil,
		AdminUser:    admin,
		TargetUser:   target,
	}

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ir.On("GetWithUsers", ctx, sessionID).Return(session, nil)

	status, err := svc.GetImpersonationStatus(ctx, &adminID, &sessionID)

	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.IsImpersonating)
	require.NotNil(t, status.AdminUsername)
	assert.Equal(t, admin.Username, *status.AdminUsername)
}

func TestImpersonationService_GetImpersonationStatus_SessionEnded(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	adminID := uuid.New()
	sessionID := uuid.New()

	endedAt := time.Now().Add(-1 * time.Minute)
	session := &models.ImpersonationSession{
		ID:          sessionID,
		TenantID:    tenantID,
		AdminUserID: adminID,
		EndedAt:     &endedAt,
	}

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ir.On("GetWithUsers", ctx, sessionID).Return(session, nil)

	status, err := svc.GetImpersonationStatus(ctx, &adminID, &sessionID)

	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.IsImpersonating)
}

// ==================== GetActiveImpersonation ====================

func TestImpersonationService_GetActiveImpersonation_Found(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	adminID := uuid.New()
	targetID := uuid.New()

	admin := buildAdminUser(tenantID)
	admin.ID = adminID
	target := buildRegularUser(tenantID)
	target.ID = targetID

	session := &models.ImpersonationSession{
		ID:           uuid.New(),
		TenantID:     tenantID,
		AdminUserID:  adminID,
		TargetUserID: targetID,
	}

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ir.On("GetActiveByAdminID", ctx, adminID).Return(session, nil)
	ur.On("GetByID", ctx, adminID).Return(admin, nil)
	ur.On("GetByID", ctx, targetID).Return(target, nil)

	result, err := svc.GetActiveImpersonation(ctx, adminID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotNil(t, result.AdminUser)
	assert.NotNil(t, result.TargetUser)
}

func TestImpersonationService_GetActiveImpersonation_NotFound(t *testing.T) {
	ctx := context.Background()
	adminID := uuid.New()

	ir := new(MockImpersonationRepo)
	ur := new(MockImpersonationUserRepo)
	svc := newImpersonationService(ir, ur)

	ir.On("GetActiveByAdminID", ctx, adminID).Return(nil, nil)

	result, err := svc.GetActiveImpersonation(ctx, adminID)

	require.NoError(t, err)
	assert.Nil(t, result)
}
