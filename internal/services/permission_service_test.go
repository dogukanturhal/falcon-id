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

// ---------------------------------------------------------------------------
// Mock: permissionServicePermissionRepo
// ---------------------------------------------------------------------------

type mockPermissionServiceRepo struct {
	mock.Mock
}

func (m *mockPermissionServiceRepo) DeprecateUnlistedInModule(ctx context.Context, module string, activePermissionNames []string, sunsetWindow time.Duration) (int, error) {
	args := m.Called(ctx, module, activePermissionNames, sunsetWindow)
	return args.Int(0), args.Error(1)
}

func (m *mockPermissionServiceRepo) RegisterPermissionsBatch(ctx context.Context, permissions []*models.Permission) (int, int, error) {
	args := m.Called(ctx, permissions)
	return args.Int(0), args.Int(1), args.Error(2)
}

func (m *mockPermissionServiceRepo) List(ctx context.Context) ([]models.Permission, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *mockPermissionServiceRepo) ListByModule(ctx context.Context, module string) ([]models.Permission, error) {
	args := m.Called(ctx, module)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *mockPermissionServiceRepo) GetModules(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockPermissionServiceRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Permission, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Permission), args.Error(1)
}

func (m *mockPermissionServiceRepo) GetByName(ctx context.Context, name string) (*models.Permission, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Permission), args.Error(1)
}

func (m *mockPermissionServiceRepo) Create(ctx context.Context, perm *models.Permission) error {
	args := m.Called(ctx, perm)
	// Simulate setting ID and CreatedAt
	if args.Error(0) == nil {
		perm.ID = uuid.New()
	}
	return args.Error(0)
}

func (m *mockPermissionServiceRepo) Update(ctx context.Context, id uuid.UUID, displayName *string, description *string) error {
	args := m.Called(ctx, id, displayName, description)
	return args.Error(0)
}

func (m *mockPermissionServiceRepo) DeleteIfNotInUse(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockPermissionServiceRepo) ListByModules(ctx context.Context, modules []string) ([]models.Permission, error) {
	args := m.Called(ctx, modules)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newPermissionServiceForTest(t *testing.T, repo permissionServicePermissionRepo) *PermissionService {
	t.Helper()
	auditRepo := new(mockAuditTokenRepo)
	auditRepo.On("CreateAuditLog", mock.Anything, mock.AnythingOfType("*models.AuditLog")).Return(nil)
	audit := NewAuditService(auditRepo, nil)
	return NewPermissionService(repo, audit)
}

// ---------------------------------------------------------------------------
// TestPermissionService_RegisterModule
// ---------------------------------------------------------------------------

func TestPermissionService_RegisterModule_Valid(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	req := &models.RegisterModuleRequest{
		Module: "crm",
		Permissions: []models.PermissionDefinition{
			{Resource: "contacts", Actions: []string{"read", "write", "delete"}},
		},
	}

	// The service builds 3 permissions before calling the repo
	repo.On("RegisterPermissionsBatch", ctx, mock.MatchedBy(func(perms []*models.Permission) bool {
		return len(perms) == 3
	})).Return(3, 0, nil)

	resp, err := svc.RegisterModule(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "crm", resp.Module)
	assert.Equal(t, 3, resp.Registered)
	assert.Equal(t, 0, resp.Updated)
	assert.Len(t, resp.Permissions, 3)
	repo.AssertExpectations(t)
}

func TestPermissionService_RegisterModule_WithDisplayName(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	req := &models.RegisterModuleRequest{
		Module: "fico",
		Permissions: []models.PermissionDefinition{
			{Resource: "invoices", Actions: []string{"approve"}, DisplayName: "Invoice Management"},
		},
	}

	repo.On("RegisterPermissionsBatch", ctx, mock.MatchedBy(func(perms []*models.Permission) bool {
		if len(perms) != 1 {
			return false
		}
		// DisplayName should be formatted as "Invoice Management - Approve"
		return perms[0].DisplayName == "Invoice Management - Approve"
	})).Return(1, 0, nil)

	resp, err := svc.RegisterModule(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, 1, resp.Registered)
	repo.AssertExpectations(t)
}

func TestPermissionService_RegisterModule_WithDescription(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	req := &models.RegisterModuleRequest{
		Module: "hr",
		Permissions: []models.PermissionDefinition{
			{Resource: "employees", Actions: []string{"read"}, Description: "Read employee data"},
		},
	}

	repo.On("RegisterPermissionsBatch", ctx, mock.MatchedBy(func(perms []*models.Permission) bool {
		if len(perms) != 1 {
			return false
		}
		return perms[0].Description != nil && *perms[0].Description == "Read employee data"
	})).Return(1, 0, nil)

	resp, err := svc.RegisterModule(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, 1, resp.Registered)
}

func TestPermissionService_RegisterModule_EmptyModuleName(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	req := &models.RegisterModuleRequest{
		Module: "",
		Permissions: []models.PermissionDefinition{
			{Resource: "contacts", Actions: []string{"read"}},
		},
	}

	resp, err := svc.RegisterModule(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "module name is required")
	repo.AssertNotCalled(t, "RegisterPermissionsBatch")
}

func TestPermissionService_RegisterModule_EmptyPermissions(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	req := &models.RegisterModuleRequest{
		Module:      "crm",
		Permissions: []models.PermissionDefinition{},
	}

	resp, err := svc.RegisterModule(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "at least one permission is required")
}

func TestPermissionService_RegisterModule_EmptyResource(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	req := &models.RegisterModuleRequest{
		Module: "crm",
		Permissions: []models.PermissionDefinition{
			{Resource: "", Actions: []string{"read"}},
		},
	}

	resp, err := svc.RegisterModule(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "resource name is required")
}

func TestPermissionService_RegisterModule_EmptyActions(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	req := &models.RegisterModuleRequest{
		Module: "crm",
		Permissions: []models.PermissionDefinition{
			{Resource: "contacts", Actions: []string{}},
		},
	}

	resp, err := svc.RegisterModule(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "at least one action is required")
}

func TestPermissionService_RegisterModule_RepoError(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	req := &models.RegisterModuleRequest{
		Module: "crm",
		Permissions: []models.PermissionDefinition{
			{Resource: "contacts", Actions: []string{"read"}},
		},
	}

	repo.On("RegisterPermissionsBatch", ctx, mock.Anything).Return(0, 0, errors.New("db error"))

	resp, err := svc.RegisterModule(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to register permissions")
}

func TestPermissionService_RegisterModule_UpdatesExisting(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	req := &models.RegisterModuleRequest{
		Module: "crm",
		Permissions: []models.PermissionDefinition{
			{Resource: "contacts", Actions: []string{"read", "write"}},
		},
	}

	// 1 registered, 1 updated
	repo.On("RegisterPermissionsBatch", ctx, mock.Anything).Return(1, 1, nil)

	resp, err := svc.RegisterModule(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, 1, resp.Registered)
	assert.Equal(t, 1, resp.Updated)
}

func TestPermissionService_RegisterModule_GeneratesPermissionNames(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	req := &models.RegisterModuleRequest{
		Module: "crm",
		Permissions: []models.PermissionDefinition{
			{Resource: "contacts", Actions: []string{"read"}},
		},
	}

	repo.On("RegisterPermissionsBatch", ctx, mock.MatchedBy(func(perms []*models.Permission) bool {
		if len(perms) != 1 {
			return false
		}
		p := perms[0]
		return p.Name == "crm:contacts:read" &&
			p.Module == "crm" &&
			p.Resource == "contacts" &&
			p.Action == "read"
	})).Return(1, 0, nil)

	resp, err := svc.RegisterModule(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, "crm:contacts:read", resp.Permissions[0].Name)
}

// ---------------------------------------------------------------------------
// TestPermissionService_List
// ---------------------------------------------------------------------------

func TestPermissionService_List_ReturnsAll(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	perms := []models.Permission{
		{ID: uuid.New(), Module: "crm", Resource: "contacts", Action: "read", Name: "crm:contacts:read", DisplayName: "Crm Contacts Read"},
		{ID: uuid.New(), Module: "hr", Resource: "employees", Action: "write", Name: "hr:employees:write", DisplayName: "Hr Employees Write"},
	}

	repo.On("List", ctx).Return(perms, nil)

	result, err := svc.List(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, int64(2), result.Total)
	assert.Len(t, result.Permissions, 2)
	repo.AssertExpectations(t)
}

func TestPermissionService_List_Empty(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	repo.On("List", ctx).Return([]models.Permission{}, nil)

	result, err := svc.List(ctx)

	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
	assert.Empty(t, result.Permissions)
}

func TestPermissionService_List_Error(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	repo.On("List", ctx).Return(nil, errors.New("db error"))

	result, err := svc.List(ctx)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "List:")
}

// ---------------------------------------------------------------------------
// TestPermissionService_ListByModule
// ---------------------------------------------------------------------------

func TestPermissionService_ListByModule_Filters(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	perms := []models.Permission{
		{ID: uuid.New(), Module: "crm", Resource: "contacts", Action: "read", Name: "crm:contacts:read"},
		{ID: uuid.New(), Module: "crm", Resource: "contacts", Action: "write", Name: "crm:contacts:write"},
	}

	repo.On("ListByModule", ctx, "crm").Return(perms, nil)

	result, err := svc.ListByModule(ctx, "crm")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, int64(2), result.Total)
	for _, p := range result.Permissions {
		assert.Equal(t, "crm", p.Module)
	}
	repo.AssertExpectations(t)
}

func TestPermissionService_ListByModule_NotFound(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	repo.On("ListByModule", ctx, "nonexistent").Return([]models.Permission{}, nil)

	result, err := svc.ListByModule(ctx, "nonexistent")

	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
}

func TestPermissionService_ListByModule_Error(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	repo.On("ListByModule", ctx, "crm").Return(nil, errors.New("db error"))

	result, err := svc.ListByModule(ctx, "crm")

	assert.Error(t, err)
	assert.Nil(t, result)
}

// ---------------------------------------------------------------------------
// TestPermissionService_ListModules (GetModules)
// ---------------------------------------------------------------------------

func TestPermissionService_ListModules_ReturnsModuleList(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	modules := []string{"crm", "hr", "fico", "pm"}
	repo.On("GetModules", ctx).Return(modules, nil)

	result, err := svc.ListModules(ctx)

	require.NoError(t, err)
	assert.Equal(t, modules, result)
	repo.AssertExpectations(t)
}

func TestPermissionService_ListModules_Empty(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	repo.On("GetModules", ctx).Return([]string{}, nil)

	result, err := svc.ListModules(ctx)

	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestPermissionService_ListModules_Error(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	repo.On("GetModules", ctx).Return(nil, errors.New("db error"))

	result, err := svc.ListModules(ctx)

	assert.Error(t, err)
	assert.Nil(t, result)
}

// ---------------------------------------------------------------------------
// TestPermissionService_ListGroupedByModule
// ---------------------------------------------------------------------------

func TestPermissionService_ListGroupedByModule(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	perms := []models.Permission{
		{ID: uuid.New(), Module: "crm", Resource: "contacts", Action: "read", Name: "crm:contacts:read"},
		{ID: uuid.New(), Module: "crm", Resource: "contacts", Action: "write", Name: "crm:contacts:write"},
		{ID: uuid.New(), Module: "hr", Resource: "employees", Action: "read", Name: "hr:employees:read"},
	}

	repo.On("List", ctx).Return(perms, nil)

	result, err := svc.ListGroupedByModule(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)
	// Two unique modules
	assert.Len(t, result, 2)

	// Verify group contents
	moduleMap := make(map[string]int)
	for _, group := range result {
		moduleMap[group.Module] = len(group.Permissions)
	}
	assert.Equal(t, 2, moduleMap["crm"])
	assert.Equal(t, 1, moduleMap["hr"])
}

// ---------------------------------------------------------------------------
// TestToTitle (package-private helper)
// ---------------------------------------------------------------------------

func TestToTitle(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty string", input: "", expected: ""},
		{name: "lowercase word", input: "read", expected: "Read"},
		{name: "already capitalized", input: "Write", expected: "Write"},
		{name: "single char", input: "a", expected: "A"},
		{name: "number start", input: "1read", expected: "1read"},
		{name: "multi-word", input: "manage users", expected: "Manage users"},
		{name: "unicode", input: "étude", expected: "Étude"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := toTitle(tc.input)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Mock: SpiceDBPermSyncer
// ---------------------------------------------------------------------------

type mockSpiceDBPermSyncer struct {
	mock.Mock
}

func (m *mockSpiceDBPermSyncer) SyncPermissionGrant(ctx context.Context, permissionName string) error {
	args := m.Called(ctx, permissionName)
	return args.Error(0)
}

func (m *mockSpiceDBPermSyncer) DeletePermissionGrant(ctx context.Context, permissionName string) error {
	args := m.Called(ctx, permissionName)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// TestPermissionService_Create_SpiceDBSync (GAP 1)
// ---------------------------------------------------------------------------

func TestPermissionService_Create_SyncsToSpiceDB(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	syncer := new(mockSpiceDBPermSyncer)
	svc.SetSpiceDBSyncer(syncer)

	repo.On("GetByName", ctx, "crm:contacts:read").Return(nil, nil)
	repo.On("Create", ctx, mock.AnythingOfType("*models.Permission")).Return(nil)
	syncer.On("SyncPermissionGrant", ctx, "crm:contacts:read").Return(nil)

	resp, err := svc.Create(ctx, &models.CreatePermissionRequest{
		Module:      "crm",
		Resource:    "contacts",
		Action:      "read",
		DisplayName: "CRM Contacts Read",
	}, nil)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "crm:contacts:read", resp.Name)

	syncer.AssertCalled(t, "SyncPermissionGrant", ctx, "crm:contacts:read")
}

func TestPermissionService_Create_SpiceDBSyncError_DoesNotFailCreate(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	syncer := new(mockSpiceDBPermSyncer)
	svc.SetSpiceDBSyncer(syncer)

	repo.On("GetByName", ctx, "crm:contacts:write").Return(nil, nil)
	repo.On("Create", ctx, mock.AnythingOfType("*models.Permission")).Return(nil)
	// Syncer returns error — must NOT propagate to caller
	syncer.On("SyncPermissionGrant", ctx, "crm:contacts:write").Return(errors.New("spicedb unavailable"))

	resp, err := svc.Create(ctx, &models.CreatePermissionRequest{
		Module:      "crm",
		Resource:    "contacts",
		Action:      "write",
		DisplayName: "CRM Contacts Write",
	}, nil)

	require.NoError(t, err, "SpiceDB sync error must not fail Create()")
	require.NotNil(t, resp)
	syncer.AssertExpectations(t)
}

func TestPermissionService_Create_NoSyncer_Succeeds(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	// No syncer wired — must not panic and must succeed
	svc := newPermissionServiceForTest(t, repo)

	repo.On("GetByName", ctx, "hr:employees:delete").Return(nil, nil)
	repo.On("Create", ctx, mock.AnythingOfType("*models.Permission")).Return(nil)

	resp, err := svc.Create(ctx, &models.CreatePermissionRequest{
		Module:      "hr",
		Resource:    "employees",
		Action:      "delete",
		DisplayName: "HR Employees Delete",
	}, nil)

	require.NoError(t, err)
	require.NotNil(t, resp)
}

// ---------------------------------------------------------------------------
// TestPermissionService_Delete_SpiceDBSync (GAP 1)
// ---------------------------------------------------------------------------

func TestPermissionService_Delete_SyncsDeleteToSpiceDB(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	syncer := new(mockSpiceDBPermSyncer)
	svc.SetSpiceDBSyncer(syncer)

	permID := uuid.New()
	existingPerm := &models.Permission{
		ID:       permID,
		Module:   "crm",
		Resource: "contacts",
		Action:   "read",
		Name:     "crm:contacts:read",
	}

	repo.On("GetByID", ctx, permID).Return(existingPerm, nil)
	repo.On("DeleteIfNotInUse", ctx, permID).Return(nil)
	syncer.On("DeletePermissionGrant", ctx, "crm:contacts:read").Return(nil)

	err := svc.Delete(ctx, permID, nil)

	require.NoError(t, err)
	syncer.AssertCalled(t, "DeletePermissionGrant", ctx, "crm:contacts:read")
}

func TestPermissionService_Delete_SpiceDBDeleteError_DoesNotFailDelete(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	syncer := new(mockSpiceDBPermSyncer)
	svc.SetSpiceDBSyncer(syncer)

	permID := uuid.New()
	existingPerm := &models.Permission{
		ID:       permID,
		Module:   "crm",
		Resource: "contacts",
		Action:   "delete",
		Name:     "crm:contacts:delete",
	}

	repo.On("GetByID", ctx, permID).Return(existingPerm, nil)
	repo.On("DeleteIfNotInUse", ctx, permID).Return(nil)
	// SpiceDB error must be non-fatal
	syncer.On("DeletePermissionGrant", ctx, "crm:contacts:delete").Return(errors.New("spicedb timeout"))

	err := svc.Delete(ctx, permID, nil)

	require.NoError(t, err, "SpiceDB sync error must not fail Delete()")
	syncer.AssertExpectations(t)
}

func TestPermissionService_Delete_NoSyncer_Succeeds(t *testing.T) {
	ctx := context.Background()

	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	permID := uuid.New()
	existingPerm := &models.Permission{
		ID:       permID,
		Module:   "hr",
		Resource: "employees",
		Action:   "read",
		Name:     "hr:employees:read",
	}

	repo.On("GetByID", ctx, permID).Return(existingPerm, nil)
	repo.On("DeleteIfNotInUse", ctx, permID).Return(nil)

	err := svc.Delete(ctx, permID, nil)

	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// TestPermissionService_getEntitledModules / ListForTenant / etc. — fail-closed
//
// spec 23 §1.4: an entitlement-repo outage must never make the permission
// catalog show everything. A per-module check error excludes that module; a
// repo-level error (can't even list modules) returns an empty set plus an
// error rather than falling back to "all modules".
// ---------------------------------------------------------------------------

func TestPermissionService_GetEntitledModules_TableDriven(t *testing.T) {
	tenantID := uuid.New()

	tests := []struct {
		name            string
		noChecker       bool
		modulesErr      error
		entitlementFunc func(module string) (bool, error)
		wantModules     []string
		wantErr         bool
	}{
		{
			name:      "no entitlement checker wired: nil,nil signals unfiltered fallback",
			noChecker: true,
		},
		{
			name:       "repo error listing modules: fail-closed, empty set + error",
			modulesErr: errors.New("postgres unavailable"),
			wantErr:    true,
		},
		{
			name: "per-module entitlement check error: module excluded (fail-closed)",
			entitlementFunc: func(module string) (bool, error) {
				if module == "crm" {
					return false, errors.New("redis unavailable")
				}
				return module == "hr", nil
			},
			wantModules: []string{"core", "iam", "hr"},
		},
		{
			name: "happy path: entitled modules returned, non-entitled excluded",
			entitlementFunc: func(module string) (bool, error) {
				return module == "hr", nil
			},
			wantModules: []string{"core", "iam", "hr"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			repo := new(mockPermissionServiceRepo)
			svc := newPermissionServiceForTest(t, repo)

			if tt.noChecker {
				modules, err := svc.getEntitledModules(ctx, tenantID)
				assert.NoError(t, err)
				assert.Nil(t, modules)
				return
			}

			if tt.modulesErr != nil {
				repo.On("GetModules", ctx).Return(nil, tt.modulesErr)
			} else {
				repo.On("GetModules", ctx).Return([]string{"crm", "hr"}, nil)
			}

			checker := &funcEntitlementChecker{fn: tt.entitlementFunc}
			svc.SetModuleEntitlementChecker(checker)

			modules, err := svc.getEntitledModules(ctx, tenantID)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, modules)
				return
			}
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.wantModules, modules)
		})
	}
}

// funcEntitlementChecker adapts a plain function to ModuleEntitlementChecker
// for table-driven tests.
type funcEntitlementChecker struct {
	fn func(module string) (bool, error)
}

func (f *funcEntitlementChecker) IsTenantEntitled(_ context.Context, _ uuid.UUID, module string) (bool, error) {
	return f.fn(module)
}

func TestPermissionService_ListForTenant_EntitlementRepoError_FailsClosed(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	repo.On("GetModules", ctx).Return(nil, errors.New("postgres unavailable"))
	svc.SetModuleEntitlementChecker(&funcEntitlementChecker{fn: func(string) (bool, error) { return true, nil }})

	result, err := svc.ListForTenant(ctx, tenantID)

	assert.Error(t, err, "an entitlement-check outage must be surfaced as an error, not silently return everything")
	assert.Nil(t, result)
	repo.AssertNotCalled(t, "List", mock.Anything)
}

func TestPermissionService_ListForTenant_NoEntitlementChecker_FallsBackToAll(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	repo.On("List", ctx).Return([]models.Permission{{Module: "crm", Resource: "contacts", Action: "read", Name: "crm:contacts:read"}}, nil)

	result, err := svc.ListForTenant(ctx, tenantID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Permissions, 1)
}

func TestPermissionService_ListModulesForTenant_EntitlementRepoError_FailsClosed(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	repo := new(mockPermissionServiceRepo)
	svc := newPermissionServiceForTest(t, repo)

	repo.On("GetModules", ctx).Return(nil, errors.New("postgres unavailable"))
	svc.SetModuleEntitlementChecker(&funcEntitlementChecker{fn: func(string) (bool, error) { return true, nil }})

	modules, err := svc.ListModulesForTenant(ctx, tenantID)

	assert.Error(t, err)
	assert.Empty(t, modules)
}
