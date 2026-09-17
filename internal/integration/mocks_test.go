// SPDX-License-Identifier: AGPL-3.0-or-later

// Package integration contains end-to-end service-layer tests that wire real
// service instances with mock repositories. No HTTP handlers, no database.
package integration

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// ---------------------------------------------------------------------------
// userRepoMock implements userServiceUserRepo + groupServiceUserRepo
// ---------------------------------------------------------------------------

type userRepoMock struct{ mock.Mock }

func (m *userRepoMock) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *userRepoMock) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*models.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *userRepoMock) GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error) {
	args := m.Called(ctx, tenantID, username)
	if v := args.Get(0); v != nil {
		return v.(*models.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *userRepoMock) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	args := m.Called(ctx, tenantID, email)
	if v := args.Get(0); v != nil {
		return v.(*models.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *userRepoMock) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *userRepoMock) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *userRepoMock) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]models.User, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search)
	return args.Get(0).([]models.User), args.Get(1).(int64), args.Error(2)
}

func (m *userRepoMock) ListTenantMemberCards(ctx context.Context, tenantID, viewerID uuid.UUID, limit, offset int) ([]models.User, int, error) {
	args := m.Called(ctx, tenantID, viewerID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]models.User), args.Int(1), args.Error(2)
}

func (m *userRepoMock) AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, userID, roleIDs, assignedBy)
	return args.Error(0)
}

func (m *userRepoMock) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]models.Role), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *userRepoMock) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]models.Permission), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *userRepoMock) UnlockUser(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// roleRepoMock implements userServiceRoleRepo + roleServiceRoleRepo + groupServiceRoleRepo
// ---------------------------------------------------------------------------

type roleRepoMock struct{ mock.Mock }

func (m *roleRepoMock) GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*models.Role), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *roleRepoMock) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error) {
	args := m.Called(ctx, tenantID, name)
	if v := args.Get(0); v != nil {
		return v.(*models.Role), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *roleRepoMock) GetDefaultRoles(ctx context.Context, tenantID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, tenantID)
	if v := args.Get(0); v != nil {
		return v.([]models.Role), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *roleRepoMock) Create(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	// Assign a deterministic ID so callers can reference it
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	return args.Error(0)
}

func (m *roleRepoMock) Update(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *roleRepoMock) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *roleRepoMock) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]models.Role, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search)
	if v := args.Get(0); v != nil {
		return v.([]models.Role), args.Get(1).(int64), args.Error(2)
	}
	return nil, 0, args.Error(2)
}

func (m *roleRepoMock) ListForModules(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string, modules []string) ([]models.Role, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search, modules)
	if v := args.Get(0); v != nil {
		return v.([]models.Role), args.Get(1).(int64), args.Error(2)
	}
	return nil, 0, args.Error(2)
}

func (m *roleRepoMock) AssignPermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, roleID, permissionIDs, assignedBy)
	return args.Error(0)
}

func (m *roleRepoMock) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, roleID)
	if v := args.Get(0); v != nil {
		return v.([]models.Permission), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *roleRepoMock) CreateSystemRoles(ctx context.Context, tenantID uuid.UUID) error {
	args := m.Called(ctx, tenantID)
	return args.Error(0)
}

func (m *roleRepoMock) GetByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id, tenantID)
	if v := args.Get(0); v != nil {
		return v.(*models.Role), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *roleRepoMock) GetMaxPriorityForUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error) {
	args := m.Called(ctx, userID, tenantID)
	return args.Int(0), args.Error(1)
}

func (m *roleRepoMock) GetRoleMembers(ctx context.Context, tenantID uuid.UUID, roleIdentifier string, page, pageSize int) ([]repositories.RoleMemberResult, int, error) {
	args := m.Called(ctx, tenantID, roleIdentifier, page, pageSize)
	if v := args.Get(0); v != nil {
		return v.([]repositories.RoleMemberResult), args.Int(1), args.Error(2)
	}
	return nil, 0, args.Error(2)
}

// ---------------------------------------------------------------------------
// permissionRepoMock implements roleServicePermissionRepo
// ---------------------------------------------------------------------------

type permissionRepoMock struct{ mock.Mock }

func (m *permissionRepoMock) List(ctx context.Context) ([]models.Permission, error) {
	args := m.Called(ctx)
	if v := args.Get(0); v != nil {
		return v.([]models.Permission), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *permissionRepoMock) GetModules(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	if v := args.Get(0); v != nil {
		return v.([]string), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *permissionRepoMock) ListByModules(ctx context.Context, modules []string) ([]models.Permission, error) {
	args := m.Called(ctx, modules)
	if v := args.Get(0); v != nil {
		return v.([]models.Permission), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *permissionRepoMock) GetPermissionNamesByIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	args := m.Called(ctx, ids)
	if v := args.Get(0); v != nil {
		return v.(map[uuid.UUID]string), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *permissionRepoMock) GetUserPermissionIDs(ctx context.Context, userID, tenantID uuid.UUID) ([]uuid.UUID, error) {
	args := m.Called(ctx, userID, tenantID)
	if v := args.Get(0); v != nil {
		return v.([]uuid.UUID), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *permissionRepoMock) GetUserPermissionNames(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, userID, tenantID)
	if v := args.Get(0); v != nil {
		return v.([]string), args.Error(1)
	}
	return nil, args.Error(1)
}

// ---------------------------------------------------------------------------
// tokenServiceMock implements userServiceTokenService
// ---------------------------------------------------------------------------

type tokenServiceMock struct{ mock.Mock }

func (m *tokenServiceMock) RevokeAllUserOAuthTokens(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// auditServiceMock implements userServiceAuditService
// ---------------------------------------------------------------------------

type auditServiceMock struct{ mock.Mock }

func (m *auditServiceMock) LogUserAction(ctx context.Context, tenantID uuid.UUID, actorID, targetUserID *uuid.UUID, action string, success bool, details map[string]interface{}) {
	m.Called(ctx, tenantID, actorID, targetUserID, action, success, details)
}

func (m *auditServiceMock) LogRoleAction(ctx context.Context, tenantID uuid.UUID, actorID, roleID *uuid.UUID, action string, success bool, details map[string]interface{}) {
	m.Called(ctx, tenantID, actorID, roleID, action, success, details)
}

// ---------------------------------------------------------------------------
// groupRepoMock implements groupServiceGroupRepo
// ---------------------------------------------------------------------------

type groupRepoMock struct{ mock.Mock }

func (m *groupRepoMock) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Group, error) {
	args := m.Called(ctx, tenantID, name)
	if v := args.Get(0); v != nil {
		return v.(*models.Group), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *groupRepoMock) GetByID(ctx context.Context, id uuid.UUID) (*models.Group, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*models.Group), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *groupRepoMock) Create(ctx context.Context, group *models.Group) error {
	args := m.Called(ctx, group)
	return args.Error(0)
}

func (m *groupRepoMock) AssignRole(ctx context.Context, groupID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, groupID, roleID, assignedBy)
	return args.Error(0)
}

func (m *groupRepoMock) AddMember(ctx context.Context, groupID, userID uuid.UUID, addedBy *uuid.UUID) error {
	args := m.Called(ctx, groupID, userID, addedBy)
	return args.Error(0)
}

func (m *groupRepoMock) Update(ctx context.Context, group *models.Group) error {
	args := m.Called(ctx, group)
	return args.Error(0)
}

func (m *groupRepoMock) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *groupRepoMock) GetRoles(ctx context.Context, groupID uuid.UUID) ([]*models.Role, error) {
	args := m.Called(ctx, groupID)
	if v := args.Get(0); v != nil {
		return v.([]*models.Role), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *groupRepoMock) GetChildGroups(ctx context.Context, parentID uuid.UUID) ([]*models.Group, error) {
	args := m.Called(ctx, parentID)
	if v := args.Get(0); v != nil {
		return v.([]*models.Group), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *groupRepoMock) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]*models.Group, int, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search)
	if v := args.Get(0); v != nil {
		return v.([]*models.Group), args.Int(1), args.Error(2)
	}
	return nil, 0, args.Error(2)
}

func (m *groupRepoMock) GetMembers(ctx context.Context, groupID uuid.UUID, page, pageSize int) ([]*models.GroupMember, int, error) {
	args := m.Called(ctx, groupID, page, pageSize)
	if v := args.Get(0); v != nil {
		return v.([]*models.GroupMember), args.Int(1), args.Error(2)
	}
	return nil, 0, args.Error(2)
}

func (m *groupRepoMock) GetUserGroups(ctx context.Context, userID uuid.UUID) ([]*models.Group, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]*models.Group), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *groupRepoMock) RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error {
	args := m.Called(ctx, groupID, userID)
	return args.Error(0)
}

func (m *groupRepoMock) RemoveRole(ctx context.Context, groupID, roleID uuid.UUID) error {
	args := m.Called(ctx, groupID, roleID)
	return args.Error(0)
}

func (m *groupRepoMock) GetUserEffectiveRoles(ctx context.Context, userID uuid.UUID) ([]*models.EffectiveRole, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]*models.EffectiveRole), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *groupRepoMock) GetRootGroups(ctx context.Context, tenantID uuid.UUID) ([]*models.Group, error) {
	args := m.Called(ctx, tenantID)
	if v := args.Get(0); v != nil {
		return v.([]*models.Group), args.Error(1)
	}
	return nil, args.Error(1)
}

// ---------------------------------------------------------------------------
// auditRepoMock implements auditServiceTokenRepo (used by the real AuditService)
// ---------------------------------------------------------------------------

type auditRepoMock struct{ mock.Mock }

func (m *auditRepoMock) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	return m.Called(ctx, log).Error(0)
}

func (m *auditRepoMock) GetAuditLogByID(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) (*models.AuditLog, error) {
	args := m.Called(ctx, id, tenantID)
	if v := args.Get(0); v != nil {
		return v.(*models.AuditLog), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *auditRepoMock) ListAuditLogs(ctx context.Context, tenantID uuid.UUID, page, pageSize int, filters map[string]interface{}) ([]models.AuditLog, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, filters)
	if v := args.Get(0); v != nil {
		return v.([]models.AuditLog), args.Get(1).(int64), args.Error(2)
	}
	return nil, 0, args.Error(2)
}

// ---------------------------------------------------------------------------
// realmResolverMock implements userServiceRealmResolver
// ---------------------------------------------------------------------------

// realmResolverMock is a test double that unconditionally resolves any tenant
// to WellKnownRealmShared, simulating the production path where every tenant
// has an explicit entry in realm_tenants.
type realmResolverMock struct{}

func (m *realmResolverMock) GetTenantRealm(_ context.Context, _ uuid.UUID) (*models.Realm, error) {
	return &models.Realm{ID: models.WellKnownRealmShared}, nil
}

// ---------------------------------------------------------------------------
// test fixture helpers
// ---------------------------------------------------------------------------

func newTestRole(tenantID uuid.UUID, name string) *models.Role {
	return &models.Role{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        name,
		DisplayName: name + " display",
		IsSystem:    false,
		IsDefault:   false,
		Priority:    10,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func newTestPermission(module, resource, action string) *models.Permission {
	name := module + ":" + resource + ":" + action
	return &models.Permission{
		ID:          uuid.New(),
		Module:      module,
		Resource:    resource,
		Action:      action,
		Name:        name,
		DisplayName: name,
		IsSystem:    false,
		CreatedAt:   time.Now(),
	}
}

func newTestUser(tenantID uuid.UUID, username, email string) *models.User {
	return &models.User{
		ID:               uuid.New(),
		TenantID:         tenantID,
		Username:         username,
		Email:            email,
		IsActive:         true,
		IsLocked:         false,
		MFAEnabled:       false,
		ActivationStatus: "active",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

func newTestGroup(tenantID uuid.UUID, name string) *models.Group {
	dispName := name + " group"
	return &models.Group{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        name,
		DisplayName: &dispName,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}
