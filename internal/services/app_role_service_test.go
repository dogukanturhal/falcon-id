// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock: mockApplicationRoleAssignmentRepo
// ---------------------------------------------------------------------------

type mockApplicationRoleAssignmentRepo struct {
	mock.Mock
}

func (m *mockApplicationRoleAssignmentRepo) Create(ctx context.Context, a *models.ApplicationRoleAssignment) error {
	args := m.Called(ctx, a)
	return args.Error(0)
}

func (m *mockApplicationRoleAssignmentRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockApplicationRoleAssignmentRepo) ListByApplication(ctx context.Context, appID uuid.UUID) ([]models.ApplicationRoleAssignment, error) {
	args := m.Called(ctx, appID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.ApplicationRoleAssignment), args.Error(1)
}

func (m *mockApplicationRoleAssignmentRepo) ListByPrincipal(ctx context.Context, principalType string, principalID uuid.UUID) ([]models.ApplicationRoleAssignment, error) {
	args := m.Called(ctx, principalType, principalID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.ApplicationRoleAssignment), args.Error(1)
}

func (m *mockApplicationRoleAssignmentRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.ApplicationRoleAssignment, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ApplicationRoleAssignment), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: mockAppRoleAppRepo
// ---------------------------------------------------------------------------

type mockAppRoleAppRepo struct {
	mock.Mock
}

func (m *mockAppRoleAppRepo) GetAppRoles(ctx context.Context, appID uuid.UUID) ([]byte, error) {
	args := m.Called(ctx, appID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeAppRolesJSON(roles []models.AppRole) []byte {
	b, _ := json.Marshal(roles)
	return b
}

func newAppRoleService(repo *mockApplicationRoleAssignmentRepo, appRepo *mockAppRoleAppRepo) *AppRoleService {
	return NewAppRoleService(repo, appRepo)
}

// ---------------------------------------------------------------------------
// TestAppRoleService_AssignRole
// ---------------------------------------------------------------------------

func TestAppRoleService_AssignRole_Success(t *testing.T) {
	ctx := context.Background()
	appID := uuid.New()
	roleID := uuid.New()
	principalID := uuid.New()
	assignedBy := uuid.New()

	roles := []models.AppRole{{ID: roleID.String(), Value: "admin", DisplayName: "Admin", IsEnabled: true}}

	repo := &mockApplicationRoleAssignmentRepo{}
	appRepo := &mockAppRoleAppRepo{}

	appRepo.On("GetAppRoles", ctx, appID).Return(makeAppRolesJSON(roles), nil)
	repo.On("Create", ctx, mock.AnythingOfType("*models.ApplicationRoleAssignment")).Return(nil)

	svc := newAppRoleService(repo, appRepo)

	req := &models.AssignAppRoleRequest{
		AppRoleID:     roleID,
		PrincipalType: "user",
		PrincipalID:   principalID,
	}

	assignment, err := svc.AssignRole(ctx, appID, req, assignedBy)

	require.NoError(t, err)
	assert.Equal(t, appID, assignment.ApplicationID)
	assert.Equal(t, roleID, assignment.AppRoleID)
	assert.Equal(t, "user", assignment.PrincipalType)
	assert.Equal(t, principalID, assignment.PrincipalID)
	assert.Equal(t, assignedBy, assignment.AssignedBy)

	repo.AssertExpectations(t)
	appRepo.AssertExpectations(t)
}

func TestAppRoleService_AssignRole_InvalidRoleID(t *testing.T) {
	ctx := context.Background()
	appID := uuid.New()
	unknownRoleID := uuid.New()
	principalID := uuid.New()
	assignedBy := uuid.New()

	// The app has roles but none matching unknownRoleID
	roles := []models.AppRole{{ID: uuid.New().String(), Value: "reader", DisplayName: "Reader", IsEnabled: true}}

	repo := &mockApplicationRoleAssignmentRepo{}
	appRepo := &mockAppRoleAppRepo{}

	appRepo.On("GetAppRoles", ctx, appID).Return(makeAppRolesJSON(roles), nil)

	svc := newAppRoleService(repo, appRepo)

	req := &models.AssignAppRoleRequest{
		AppRoleID:     unknownRoleID,
		PrincipalType: "user",
		PrincipalID:   principalID,
	}

	_, err := svc.AssignRole(ctx, appID, req, assignedBy)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in application")

	// Create should never have been called
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
	appRepo.AssertExpectations(t)
}

func TestAppRoleService_AssignRole_DisabledRole(t *testing.T) {
	ctx := context.Background()
	appID := uuid.New()
	roleID := uuid.New()

	roles := []models.AppRole{{ID: roleID.String(), Value: "admin", DisplayName: "Admin", IsEnabled: false}}

	repo := &mockApplicationRoleAssignmentRepo{}
	appRepo := &mockAppRoleAppRepo{}

	appRepo.On("GetAppRoles", ctx, appID).Return(makeAppRolesJSON(roles), nil)

	svc := newAppRoleService(repo, appRepo)

	req := &models.AssignAppRoleRequest{
		AppRoleID:     roleID,
		PrincipalType: "user",
		PrincipalID:   uuid.New(),
	}

	_, err := svc.AssignRole(ctx, appID, req, uuid.New())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "is disabled")
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// TestAppRoleService_UnassignRole
// ---------------------------------------------------------------------------

func TestAppRoleService_UnassignRole_Success(t *testing.T) {
	ctx := context.Background()
	assignmentID := uuid.New()

	repo := &mockApplicationRoleAssignmentRepo{}
	appRepo := &mockAppRoleAppRepo{}

	repo.On("Delete", ctx, assignmentID).Return(nil)

	svc := newAppRoleService(repo, appRepo)

	err := svc.UnassignRole(ctx, assignmentID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestAppRoleService_UnassignRole_RepoError(t *testing.T) {
	ctx := context.Background()
	assignmentID := uuid.New()

	repo := &mockApplicationRoleAssignmentRepo{}
	appRepo := &mockAppRoleAppRepo{}

	repo.On("Delete", ctx, assignmentID).Return(errors.New("no rows"))

	svc := newAppRoleService(repo, appRepo)

	err := svc.UnassignRole(ctx, assignmentID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "AppRoleService.UnassignRole")
}

// ---------------------------------------------------------------------------
// TestAppRoleService_ListAssignments
// ---------------------------------------------------------------------------

func TestAppRoleService_ListAssignments_Success(t *testing.T) {
	ctx := context.Background()
	appID := uuid.New()

	expected := []models.ApplicationRoleAssignment{
		{ID: uuid.New(), ApplicationID: appID, AppRoleID: uuid.New(), PrincipalType: "user", PrincipalID: uuid.New()},
		{ID: uuid.New(), ApplicationID: appID, AppRoleID: uuid.New(), PrincipalType: "group", PrincipalID: uuid.New()},
	}

	repo := &mockApplicationRoleAssignmentRepo{}
	appRepo := &mockAppRoleAppRepo{}

	repo.On("ListByApplication", ctx, appID).Return(expected, nil)

	svc := newAppRoleService(repo, appRepo)

	got, err := svc.ListAssignments(ctx, appID)

	require.NoError(t, err)
	assert.Len(t, got, 2)
	assert.Equal(t, expected[0].ID, got[0].ID)
	repo.AssertExpectations(t)
}

func TestAppRoleService_ListAssignments_Empty(t *testing.T) {
	ctx := context.Background()
	appID := uuid.New()

	repo := &mockApplicationRoleAssignmentRepo{}
	appRepo := &mockAppRoleAppRepo{}

	repo.On("ListByApplication", ctx, appID).Return([]models.ApplicationRoleAssignment{}, nil)

	svc := newAppRoleService(repo, appRepo)

	got, err := svc.ListAssignments(ctx, appID)

	require.NoError(t, err)
	assert.Empty(t, got)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestAppRoleService_ListByPrincipal
// ---------------------------------------------------------------------------

func TestAppRoleService_ListByPrincipal_Success(t *testing.T) {
	ctx := context.Background()
	principalID := uuid.New()

	expected := []models.ApplicationRoleAssignment{
		{ID: uuid.New(), PrincipalType: "user", PrincipalID: principalID},
	}

	repo := &mockApplicationRoleAssignmentRepo{}
	appRepo := &mockAppRoleAppRepo{}

	repo.On("ListByPrincipal", ctx, "user", principalID).Return(expected, nil)

	svc := newAppRoleService(repo, appRepo)

	got, err := svc.ListByPrincipal(ctx, "user", principalID)

	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, principalID, got[0].PrincipalID)
	repo.AssertExpectations(t)
}
