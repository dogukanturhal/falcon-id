// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockDelegationRepo struct {
	mock.Mock
}

func (m *mockDelegationRepo) Create(ctx context.Context, delegation *models.Delegation) error {
	args := m.Called(ctx, delegation)
	return args.Error(0)
}

func (m *mockDelegationRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Delegation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Delegation), args.Error(1)
}

func (m *mockDelegationRepo) Revoke(ctx context.Context, delegationID, revokerID uuid.UUID) error {
	args := m.Called(ctx, delegationID, revokerID)
	return args.Error(0)
}

func (m *mockDelegationRepo) ListByDelegator(ctx context.Context, userID uuid.UUID, includeRevoked bool) ([]*models.Delegation, error) {
	args := m.Called(ctx, userID, includeRevoked)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Delegation), args.Error(1)
}

func (m *mockDelegationRepo) ListByDelegatee(ctx context.Context, userID uuid.UUID, includeRevoked bool) ([]*models.Delegation, error) {
	args := m.Called(ctx, userID, includeRevoked)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Delegation), args.Error(1)
}

func (m *mockDelegationRepo) GetActiveDelegationsForUser(ctx context.Context, delegateeID uuid.UUID) ([]*models.Delegation, error) {
	args := m.Called(ctx, delegateeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Delegation), args.Error(1)
}

func (m *mockDelegationRepo) CleanupExpired(ctx context.Context, retentionDays int) (int64, error) {
	args := m.Called(ctx, retentionDays)
	return args.Get(0).(int64), args.Error(1)
}

type mockDelegationUserRepo struct {
	mock.Mock
}

func (m *mockDelegationUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

type mockSpiceDBClient struct {
	mock.Mock
}

func (m *mockSpiceDBClient) CheckPermission(ctx context.Context, tenantID, userID uuid.UUID, resourceType, resourceID, permission string) (bool, error) {
	args := m.Called(ctx, tenantID, userID, resourceType, resourceID, permission)
	return args.Bool(0), args.Error(1)
}

func (m *mockSpiceDBClient) WriteRelationship(ctx context.Context, tenantID uuid.UUID, relationship interface{}) error {
	args := m.Called(ctx, tenantID, relationship)
	return args.Error(0)
}

func (m *mockSpiceDBClient) DeleteRelationship(ctx context.Context, tenantID uuid.UUID, relationship interface{}) error {
	args := m.Called(ctx, tenantID, relationship)
	return args.Error(0)
}

type mockDelegationAuditService struct {
	mock.Mock
}

func (m *mockDelegationAuditService) LogUserAction(ctx context.Context, tenantID uuid.UUID, actorID, targetUserID *uuid.UUID, action string, success bool, details map[string]interface{}) {
	m.Called(ctx, tenantID, actorID, targetUserID, action, success, details)
}

// auditServiceAdapter adapts mockDelegationAuditService to *AuditService by
// embedding a real AuditService with nil fields, and overriding only LogUserAction.
// Because DelegationService holds a *AuditService (concrete), we build a real
// AuditService and call its method via a thin wrapper approach.
//
// Instead, we expose the test delegation service through a helper that accepts
// a mock and wires it up correctly.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestDelegationService constructs a DelegationService wired with mocks.
// Because DelegationService uses *AuditService (concrete), we supply a real
// AuditService backed by a mock tokenRepo so calls to LogUserAction hit a
// real (no-op) path with a mock token repo that silently discards the log.
func newTestDelegationService(
	delegationRepo delegationServiceDelegationRepo,
	userRepo delegationServiceUserRepo,
	spicedb SpiceDBClient,
	_ *mockDelegationAuditService,
) *DelegationService {
	// Wire a real AuditService with a mock tokenRepo that accepts any
	// CreateAuditLog call and returns nil, so LogUserAction calls don't panic.
	// MockAuditTokenRepo is declared in audit_service_test.go (same package).
	tokenRepo := new(MockAuditTokenRepo)
	tokenRepo.On("CreateAuditLog", mock.Anything, mock.Anything).Return(nil).Maybe()
	auditSvc := NewAuditService(tokenRepo, nil)
	log := zap.NewNop()
	return NewDelegationService(delegationRepo, userRepo, spicedb, auditSvc, log)
}

func buildActiveDelegation(tenantID, delegatorID, delegateeID uuid.UUID) *models.Delegation {
	return &models.Delegation{
		ID:          uuid.New(),
		TenantID:    tenantID,
		DelegatorID: delegatorID,
		DelegateeID: delegateeID,
		Permissions: pq.StringArray{"reports:read", "users:list"},
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func buildRevokedDelegation(tenantID, delegatorID, delegateeID uuid.UUID) *models.Delegation {
	d := buildActiveDelegation(tenantID, delegatorID, delegateeID)
	revokedAt := time.Now().Add(-5 * time.Minute)
	revokedBy := uuid.New()
	d.RevokedAt = &revokedAt
	d.RevokedBy = &revokedBy
	return d
}

// ---------------------------------------------------------------------------
// TestDelegationService_CreateDelegation
// ---------------------------------------------------------------------------

func TestDelegationService_CreateDelegation_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegateeUser := &models.User{
		ID:       delegateeID,
		TenantID: tenantID,
		Email:    "delegatee@example.com",
	}

	perm := "reports:read"
	reason := "on leave"
	req := &models.CreateDelegationRequest{
		DelegateeID: delegateeID,
		Permissions: []string{perm},
		Duration:    3600,
		Reason:      &reason,
	}

	// Delegator has the permission being delegated
	spicedb.On("CheckPermission", ctx, tenantID, delegatorID, "user", delegatorID.String(), perm).Return(true, nil)
	userRepo.On("GetByID", ctx, delegateeID).Return(delegateeUser, nil)
	delegationRepo.On("Create", ctx, mock.AnythingOfType("*models.Delegation")).Return(nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	result, err := svc.CreateDelegation(ctx, delegatorID, tenantID, req)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, delegatorID, result.DelegatorID)
	assert.Equal(t, delegateeID, result.DelegateeID)
	assert.Equal(t, tenantID, result.TenantID)
	assert.Equal(t, []string{perm}, result.Permissions)
	assert.True(t, result.ExpiresAt.After(time.Now()))

	delegationRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
	spicedb.AssertExpectations(t)
}

func TestDelegationService_CreateDelegation_DelegateeNotInTenant(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()
	otherTenantID := uuid.New()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegateeUser := &models.User{
		ID:       delegateeID,
		TenantID: otherTenantID, // different tenant
	}

	req := &models.CreateDelegationRequest{
		DelegateeID: delegateeID,
		Permissions: []string{"read"},
		Duration:    3600,
	}

	spicedb.On("CheckPermission", ctx, tenantID, delegatorID, "user", delegatorID.String(), "read").Return(true, nil)
	userRepo.On("GetByID", ctx, delegateeID).Return(delegateeUser, nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	result, err := svc.CreateDelegation(ctx, delegatorID, tenantID, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "same tenant")
}

func TestDelegationService_CreateDelegation_DelegateeNotFound(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	req := &models.CreateDelegationRequest{
		DelegateeID: delegateeID,
		Permissions: []string{"read"},
		Duration:    3600,
	}

	spicedb.On("CheckPermission", ctx, tenantID, delegatorID, "user", delegatorID.String(), "read").Return(true, nil)
	userRepo.On("GetByID", ctx, delegateeID).Return(nil, errors.New("not found"))

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	result, err := svc.CreateDelegation(ctx, delegatorID, tenantID, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "delegatee user not found")
}

func TestDelegationService_CreateDelegation_DelegatorLacksPermission(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	req := &models.CreateDelegationRequest{
		DelegateeID: delegateeID,
		Permissions: []string{"admin:delete"},
		Duration:    3600,
	}

	// Delegator does NOT have the permission
	spicedb.On("CheckPermission", ctx, tenantID, delegatorID, "user", delegatorID.String(), "admin:delete").Return(false, nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	result, err := svc.CreateDelegation(ctx, delegatorID, tenantID, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "cannot delegate permission")
}

func TestDelegationService_CreateDelegation_WildcardOnlyForAdmin(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	req := &models.CreateDelegationRequest{
		DelegateeID: delegateeID,
		Permissions: []string{"*"},
		Duration:    3600,
	}

	// Non-admin tries to delegate wildcard
	spicedb.On("CheckPermission", ctx, tenantID, delegatorID, "tenant", tenantID.String(), "admin").Return(false, nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	result, err := svc.CreateDelegation(ctx, delegatorID, tenantID, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "only admins can delegate wildcard")
}

func TestDelegationService_CreateDelegation_WildcardAdminSucceeds(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegateeUser := &models.User{
		ID:       delegateeID,
		TenantID: tenantID,
		Email:    "delegatee@example.com",
	}

	req := &models.CreateDelegationRequest{
		DelegateeID: delegateeID,
		Permissions: []string{"*"},
		Duration:    3600,
	}

	// Admin user delegates wildcard
	spicedb.On("CheckPermission", ctx, tenantID, delegatorID, "tenant", tenantID.String(), "admin").Return(true, nil)
	userRepo.On("GetByID", ctx, delegateeID).Return(delegateeUser, nil)
	delegationRepo.On("Create", ctx, mock.AnythingOfType("*models.Delegation")).Return(nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	result, err := svc.CreateDelegation(ctx, delegatorID, tenantID, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestDelegationService_CreateDelegation_SpiceDBError(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	req := &models.CreateDelegationRequest{
		DelegateeID: delegateeID,
		Permissions: []string{"read"},
		Duration:    3600,
	}

	spicedb.On("CheckPermission", ctx, tenantID, delegatorID, "user", delegatorID.String(), "read").Return(false, errors.New("spicedb unavailable"))

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	result, err := svc.CreateDelegation(ctx, delegatorID, tenantID, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to check permission")
}

// ---------------------------------------------------------------------------
// TestDelegationService_RevokeDelegation
// ---------------------------------------------------------------------------

func TestDelegationService_RevokeDelegation_ByDelegator_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()

	delegation := buildActiveDelegation(tenantID, delegatorID, delegateeID)

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("GetByID", ctx, delegation.ID).Return(delegation, nil)
	delegationRepo.On("Revoke", ctx, delegation.ID, delegatorID).Return(nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	err := svc.RevokeDelegation(ctx, delegation.ID, delegatorID, tenantID)

	require.NoError(t, err)
	delegationRepo.AssertExpectations(t)
}

func TestDelegationService_RevokeDelegation_ByAdmin_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()
	adminID := uuid.New()

	delegation := buildActiveDelegation(tenantID, delegatorID, delegateeID)

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("GetByID", ctx, delegation.ID).Return(delegation, nil)
	// adminID is not the delegator so spicedb check is performed
	spicedb.On("CheckPermission", ctx, tenantID, adminID, "tenant", tenantID.String(), "admin").Return(true, nil)
	delegationRepo.On("Revoke", ctx, delegation.ID, adminID).Return(nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	err := svc.RevokeDelegation(ctx, delegation.ID, adminID, tenantID)

	require.NoError(t, err)
	delegationRepo.AssertExpectations(t)
	spicedb.AssertExpectations(t)
}

func TestDelegationService_RevokeDelegation_Unauthorized(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()
	randomUserID := uuid.New()

	delegation := buildActiveDelegation(tenantID, delegatorID, delegateeID)

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("GetByID", ctx, delegation.ID).Return(delegation, nil)
	spicedb.On("CheckPermission", ctx, tenantID, randomUserID, "tenant", tenantID.String(), "admin").Return(false, nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	err := svc.RevokeDelegation(ctx, delegation.ID, randomUserID, tenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only the delegator or admin can revoke")
}

func TestDelegationService_RevokeDelegation_DelegationNotFound(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegationID := uuid.New()
	revokerID := uuid.New()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("GetByID", ctx, delegationID).Return(nil, errors.New("not found"))

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	err := svc.RevokeDelegation(ctx, delegationID, revokerID, tenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delegation not found")
}

func TestDelegationService_RevokeDelegation_WrongTenant(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	otherTenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()

	delegation := buildActiveDelegation(otherTenantID, delegatorID, delegateeID)

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("GetByID", ctx, delegation.ID).Return(delegation, nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	// tenantID does not match delegation.TenantID (otherTenantID)
	err := svc.RevokeDelegation(ctx, delegation.ID, delegatorID, tenantID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delegation not found in this tenant")
}

// ---------------------------------------------------------------------------
// TestDelegationService_ListMyDelegations
// ---------------------------------------------------------------------------

func TestDelegationService_ListMyDelegations_ReturnsCombinedList(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()
	otherUserID := uuid.New()

	given := []*models.Delegation{
		buildActiveDelegation(tenantID, userID, otherUserID),
	}
	received := []*models.Delegation{
		buildActiveDelegation(tenantID, otherUserID, userID),
	}

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("ListByDelegator", ctx, userID, false).Return(given, nil)
	delegationRepo.On("ListByDelegatee", ctx, userID, false).Return(received, nil)

	userDisplayName := "Other User"
	otherUser := &models.User{
		ID:          otherUserID,
		TenantID:    tenantID,
		Email:       "other@example.com",
		DisplayName: &userDisplayName,
	}
	currentUser := &models.User{
		ID:       userID,
		TenantID: tenantID,
		Email:    "current@example.com",
	}

	userRepo.On("GetByID", ctx, userID).Return(currentUser, nil)
	userRepo.On("GetByID", ctx, otherUserID).Return(otherUser, nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	results, err := svc.ListMyDelegations(ctx, userID, false)

	require.NoError(t, err)
	assert.Len(t, results, 2)

	delegationRepo.AssertExpectations(t)
}

func TestDelegationService_ListMyDelegations_IncludeRevoked(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()
	otherUserID := uuid.New()

	given := []*models.Delegation{
		buildRevokedDelegation(tenantID, userID, otherUserID),
	}

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("ListByDelegator", ctx, userID, true).Return(given, nil)
	delegationRepo.On("ListByDelegatee", ctx, userID, true).Return([]*models.Delegation{}, nil)

	otherUser := &models.User{ID: otherUserID, TenantID: tenantID, Email: "other@example.com"}
	currentUser := &models.User{ID: userID, TenantID: tenantID, Email: "me@example.com"}
	userRepo.On("GetByID", ctx, userID).Return(currentUser, nil)
	userRepo.On("GetByID", ctx, otherUserID).Return(otherUser, nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	results, err := svc.ListMyDelegations(ctx, userID, true)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "revoked", results[0].Status)
}

func TestDelegationService_ListMyDelegations_UserNotFoundUsesUnknown(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()
	otherUserID := uuid.New()

	given := []*models.Delegation{
		buildActiveDelegation(tenantID, userID, otherUserID),
	}

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("ListByDelegator", ctx, userID, false).Return(given, nil)
	delegationRepo.On("ListByDelegatee", ctx, userID, false).Return([]*models.Delegation{}, nil)

	// Both user lookups fail
	userRepo.On("GetByID", ctx, userID).Return(nil, errors.New("db error"))
	userRepo.On("GetByID", ctx, otherUserID).Return(nil, errors.New("db error"))

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	results, err := svc.ListMyDelegations(ctx, userID, false)

	require.NoError(t, err)
	require.Len(t, results, 1)
	// Service falls back to "Unknown User" for both names
	assert.Equal(t, "Unknown User", results[0].DelegatorName)
	assert.Equal(t, "Unknown User", results[0].DelegateeName)
}

func TestDelegationService_ListMyDelegations_RepoError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("ListByDelegator", ctx, userID, false).Return(nil, errors.New("db error"))

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	results, err := svc.ListMyDelegations(ctx, userID, false)

	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "failed to get delegations given")
}

// ---------------------------------------------------------------------------
// TestDelegationService_GetActiveDelegationsForUser
// ---------------------------------------------------------------------------

func TestDelegationService_GetActiveDelegationsForUser_ReturnsActiveDelegations(t *testing.T) {
	ctx := context.Background()
	delegateeID := uuid.New()
	tenantID := uuid.New()
	delegatorID := uuid.New()

	active := []*models.Delegation{
		buildActiveDelegation(tenantID, delegatorID, delegateeID),
		buildActiveDelegation(tenantID, uuid.New(), delegateeID),
	}

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("GetActiveDelegationsForUser", ctx, delegateeID).Return(active, nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	results, err := svc.GetActiveDelegationsForUser(ctx, delegateeID)

	require.NoError(t, err)
	assert.Len(t, results, 2)
	// All returned delegations should be active
	for _, d := range results {
		assert.True(t, d.IsActive())
	}
}

func TestDelegationService_GetActiveDelegationsForUser_Empty(t *testing.T) {
	ctx := context.Background()
	delegateeID := uuid.New()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("GetActiveDelegationsForUser", ctx, delegateeID).Return([]*models.Delegation{}, nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	results, err := svc.GetActiveDelegationsForUser(ctx, delegateeID)

	require.NoError(t, err)
	assert.Empty(t, results)
}

// ---------------------------------------------------------------------------
// TestDelegationService_CleanupExpiredDelegations
// ---------------------------------------------------------------------------

func TestDelegationService_CleanupExpiredDelegations_Success(t *testing.T) {
	ctx := context.Background()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("CleanupExpired", ctx, 30).Return(int64(5), nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	err := svc.CleanupExpiredDelegations(ctx, 30)

	require.NoError(t, err)
	delegationRepo.AssertExpectations(t)
}

func TestDelegationService_CleanupExpiredDelegations_RepoError(t *testing.T) {
	ctx := context.Background()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("CleanupExpired", ctx, 30).Return(int64(0), errors.New("db error"))

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	err := svc.CleanupExpiredDelegations(ctx, 30)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to cleanup expired delegations")
}

// ---------------------------------------------------------------------------
// TestDelegationService_GetDelegation
// ---------------------------------------------------------------------------

func TestDelegationService_GetDelegation_AsInvolvedUser(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()

	delegation := buildActiveDelegation(tenantID, delegatorID, delegateeID)

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("GetByID", ctx, delegation.ID).Return(delegation, nil)
	delegatorUser := &models.User{ID: delegatorID, TenantID: tenantID, Email: "delegator@example.com"}
	delegateeUser := &models.User{ID: delegateeID, TenantID: tenantID, Email: "delegatee@example.com"}
	userRepo.On("GetByID", ctx, delegatorID).Return(delegatorUser, nil)
	userRepo.On("GetByID", ctx, delegateeID).Return(delegateeUser, nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	// delegatorID is involved in the delegation
	result, err := svc.GetDelegation(ctx, delegation.ID, delegatorID, tenantID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, delegation.ID.String(), result.ID)
}

func TestDelegationService_GetDelegation_AsAdminNotInvolved(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()
	adminID := uuid.New()

	delegation := buildActiveDelegation(tenantID, delegatorID, delegateeID)

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("GetByID", ctx, delegation.ID).Return(delegation, nil)
	spicedb.On("CheckPermission", ctx, tenantID, adminID, "tenant", tenantID.String(), "admin").Return(true, nil)
	delegatorUser := &models.User{ID: delegatorID, TenantID: tenantID, Email: "delegator@example.com"}
	delegateeUser := &models.User{ID: delegateeID, TenantID: tenantID, Email: "delegatee@example.com"}
	userRepo.On("GetByID", ctx, delegatorID).Return(delegatorUser, nil)
	userRepo.On("GetByID", ctx, delegateeID).Return(delegateeUser, nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	result, err := svc.GetDelegation(ctx, delegation.ID, adminID, tenantID)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestDelegationService_GetDelegation_UnauthorizedUser(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()
	randomUserID := uuid.New()

	delegation := buildActiveDelegation(tenantID, delegatorID, delegateeID)

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegationRepo.On("GetByID", ctx, delegation.ID).Return(delegation, nil)
	spicedb.On("CheckPermission", ctx, tenantID, randomUserID, "tenant", tenantID.String(), "admin").Return(false, nil)

	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	result, err := svc.GetDelegation(ctx, delegation.ID, randomUserID, tenantID)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "delegation not found")
}

// ---------------------------------------------------------------------------
// Duration-based expiry in CreateDelegation
// ---------------------------------------------------------------------------

func TestDelegationService_CreateDelegation_ExpiryMatchesDuration(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()

	delegationRepo := new(mockDelegationRepo)
	userRepo := new(mockDelegationUserRepo)
	spicedb := new(mockSpiceDBClient)
	auditMock := new(mockDelegationAuditService)

	delegateeUser := &models.User{
		ID:       delegateeID,
		TenantID: tenantID,
		Email:    "delegatee@example.com",
	}

	durationSeconds := 7200 // 2 hours
	req := &models.CreateDelegationRequest{
		DelegateeID: delegateeID,
		Permissions: []string{"read"},
		Duration:    durationSeconds,
	}

	spicedb.On("CheckPermission", ctx, tenantID, delegatorID, "user", delegatorID.String(), "read").Return(true, nil)
	userRepo.On("GetByID", ctx, delegateeID).Return(delegateeUser, nil)
	delegationRepo.On("Create", ctx, mock.AnythingOfType("*models.Delegation")).Return(nil)

	before := time.Now()
	svc := newTestDelegationService(delegationRepo, userRepo, spicedb, auditMock)
	result, err := svc.CreateDelegation(ctx, delegatorID, tenantID, req)
	after := time.Now()

	require.NoError(t, err)
	expectedExpiry := before.Add(time.Duration(durationSeconds) * time.Second)
	assert.True(t, result.ExpiresAt.After(expectedExpiry.Add(-time.Second)),
		"ExpiresAt should be approximately now + duration")
	assert.True(t, result.ExpiresAt.Before(after.Add(time.Duration(durationSeconds)*time.Second+time.Second)),
		"ExpiresAt should not exceed expected upper bound")
}
