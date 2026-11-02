// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/authorization"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// wildcardCovers checks if a caller's permission (which may contain wildcards)
// covers a target permission. Supports three-segment format: module:resource:action.
//
// Examples:
//   - "crm:*:*" covers "crm:companies:read" → true
//   - "crm:companies:*" covers "crm:companies:read" → true
//   - "crm:companies:read" covers "crm:companies:read" → true (exact match)
//   - "crm:contacts:*" covers "crm:companies:read" → false (different resource)
func wildcardCovers(callerPerm, targetPerm string) bool {
	if callerPerm == targetPerm {
		return true
	}

	callerParts := strings.SplitN(callerPerm, ":", 3)
	targetParts := strings.SplitN(targetPerm, ":", 3)

	if len(callerParts) != 3 || len(targetParts) != 3 {
		return false
	}

	// Module must match exactly
	if callerParts[0] != targetParts[0] {
		return false
	}

	// Resource: "*" matches any resource
	if callerParts[1] != "*" && callerParts[1] != targetParts[1] {
		return false
	}

	// Action: "*" matches any action
	if callerParts[2] != "*" && callerParts[2] != targetParts[2] {
		return false
	}

	return true
}

// checkCallerCoversPermissions validates C-2: the caller can only assign permissions
// they themselves hold (with wildcard expansion). Returns an error if any target
// permission is not covered by the caller's permission set.
func (s *RoleService) checkCallerCoversPermissions(ctx context.Context, callerID, tenantID uuid.UUID, permissionIDs []uuid.UUID) error {
	// Get caller's permission names (includes wildcards like crm:*:*)
	callerNames, err := s.permissionRepo.GetUserPermissionNames(ctx, callerID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to get caller permissions: %w", err)
	}

	// Get the names for the permissions being assigned
	targetNameMap, err := s.permissionRepo.GetPermissionNamesByIDs(ctx, permissionIDs)
	if err != nil {
		return fmt.Errorf("failed to resolve permission names: %w", err)
	}

	// Check each target permission is covered by at least one caller permission
	for _, pid := range permissionIDs {
		targetName, ok := targetNameMap[pid]
		if !ok {
			return fmt.Errorf("permission %s not found", pid)
		}

		covered := false
		for _, callerName := range callerNames {
			if wildcardCovers(callerName, targetName) {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf("cannot assign permission %s (%s) that you do not hold", pid, targetName)
		}
	}
	return nil
}

// EventPublisher interface for publishing IAM events to Kafka for SpiceDB sync
type EventPublisher interface {
	// PublishEvent publishes an event to Kafka
	PublishEvent(ctx context.Context, topic string, key string, payload interface{}) error
}

// IAMEventTopics defines Kafka topics for IAM events (SpiceDB sync)
var IAMEventTopics = struct {
	RoleCreated       string
	RoleUpdated       string
	RoleDeleted       string
	UserRoleAssigned  string
	UserRoleRevoked   string
	PermissionGranted string
	PermissionRevoked string
}{
	RoleCreated:       "example.iam.role.created",
	RoleUpdated:       "example.iam.role.updated",
	RoleDeleted:       "example.iam.role.deleted",
	UserRoleAssigned:  "example.iam.user.role.assigned",
	UserRoleRevoked:   "example.iam.user.role.revoked",
	PermissionGranted: "example.iam.permission.granted",
	PermissionRevoked: "example.iam.permission.revoked",
}

// IAMEventPayload is the payload for IAM events sent to Kafka for SpiceDB sync
type IAMEventPayload struct {
	TenantID       uuid.UUID  `json:"tenant_id"`
	UserID         *uuid.UUID `json:"user_id,omitempty"`
	RoleID         *uuid.UUID `json:"role_id,omitempty"`
	PermissionID   *uuid.UUID `json:"permission_id,omitempty"`
	RoleName       string     `json:"role_name,omitempty"`
	PermissionName string     `json:"permission_name,omitempty"`
	Permissions    []string   `json:"permissions,omitempty"`
	ResourceType   string     `json:"resource_type,omitempty"`
	ResourceID     string     `json:"resource_id,omitempty"`
	Relation       string     `json:"relation,omitempty"`
	SubjectType    string     `json:"subject_type,omitempty"`
	SubjectID      string     `json:"subject_id,omitempty"`
}

// roleServiceRoleRepo defines the role repository methods needed by RoleService.
type roleServiceRoleRepo interface {
	GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error)
	Create(ctx context.Context, role *models.Role) error
	AssignPermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, assignedBy *uuid.UUID) error
	// GrantPermissionsByName is purely additive ("INSERT ... ON CONFLICT DO
	// NOTHING"), unlike AssignPermissions which deletes a role's existing
	// grants before inserting - used by AcmeAppRoleProvisioner's reconcile
	// path so a top-up run can never drop a permission a role already has.
	GrantPermissionsByName(ctx context.Context, roleID uuid.UUID, permissionNames []string) error
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error)
	GetByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Role, error)
	GetMaxPriorityForUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error)
	Update(ctx context.Context, role *models.Role) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]models.Role, int64, error)
	ListForModules(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string, modules []string) ([]models.Role, int64, error)
	CreateSystemRoles(ctx context.Context, tenantID uuid.UUID) error
	GetRoleMembers(ctx context.Context, tenantID uuid.UUID, roleIdentifier string, page, pageSize int) ([]repositories.RoleMemberResult, int, error)
}

// roleServicePermissionRepo defines the permission repository methods needed by RoleService.
type roleServicePermissionRepo interface {
	List(ctx context.Context) ([]models.Permission, error)
	ListByModules(ctx context.Context, modules []string) ([]models.Permission, error)
	GetModules(ctx context.Context) ([]string, error)
	GetUserPermissionIDs(ctx context.Context, userID, tenantID uuid.UUID) ([]uuid.UUID, error)
	GetUserPermissionNames(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error)
	GetPermissionNamesByIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error)
	// GetByID resolves a single permission (module/resource/action/name),
	// used by the ADR-A10 grant-permission boundary check to learn the
	// module a permission belongs to before deciding whether the grant is
	// allowed.
	GetByID(ctx context.Context, id uuid.UUID) (*models.Permission, error)
}

// RoleService is an exported type.
type RoleService struct {
	roleRepo           roleServiceRoleRepo
	permissionRepo     roleServicePermissionRepo
	auditService       *AuditService
	eventPublisher     EventPublisher           // Optional: for SpiceDB sync events
	sessionCache       SessionCache             // Optional: for real-time permission invalidation
	tenantBootstrap    *TenantBootstrapService  // Optional: for direct SpiceDB sync on mutations
	entitlementChecker ModuleEntitlementChecker // Optional: for subscription-scoped permission listing

	// caeService is optional. When set, AssignPermissions publishes
	// CAERoleRevoked so receivers (Talon IAP, SSE subscribers) re-
	// evaluate any active session whose authentication context
	// references this role — closing the "permission still effective
	// until next token refresh" window. Wired in cmd/services.go;
	// nil-safe.
	caeService *CAEService

	// apiKeyUsage optional: blocks API-key-forbidden grants to roles that
	// active tenant API keys hold. See guardAPIKeyRoleGrant.
	apiKeyUsage RoleAPIKeyUsage
}

// SetCAEService wires the CAEP publisher into RoleService. Safe to
// call with nil; underlying DB role/permission writes remain
// authoritative even when the publisher is unwired.
func (s *RoleService) SetCAEService(svc *CAEService) {
	s.caeService = svc
}

// SessionCache interface for session invalidation
type SessionCache interface {
	IncrementRoleVersion(ctx context.Context, tenantID uuid.UUID) (int64, error)
	PublishPermissionInvalidation(ctx context.Context, msg interface{}) error
	InvalidateUserSessionsByRoleVersion(ctx context.Context, userID uuid.UUID, minRoleVersion int64) error
}

// NewRoleService is an exported function.
func NewRoleService(
	roleRepo roleServiceRoleRepo,
	permissionRepo roleServicePermissionRepo,
	auditService *AuditService,
) *RoleService {
	return &RoleService{
		roleRepo:       roleRepo,
		permissionRepo: permissionRepo,
		auditService:   auditService,
	}
}

// SetEventPublisher sets the event publisher for SpiceDB sync
func (s *RoleService) SetEventPublisher(publisher EventPublisher) {
	s.eventPublisher = publisher
}

// SetSessionCache sets the session cache for real-time permission invalidation
func (s *RoleService) SetSessionCache(cache SessionCache) {
	s.sessionCache = cache
}

// SetTenantBootstrap sets the tenant bootstrap service for direct SpiceDB sync
func (s *RoleService) SetTenantBootstrap(bootstrap *TenantBootstrapService) {
	s.tenantBootstrap = bootstrap
}

// publishEvent safely publishes an event if publisher is configured
func (s *RoleService) publishEvent(ctx context.Context, topic string, key string, payload IAMEventPayload) {
	if s.eventPublisher == nil {
		return // No publisher configured, skip silently
	}

	// Convert payload to JSON for logging
	payloadJSON, _ := json.Marshal(payload)

	if err := s.eventPublisher.PublishEvent(ctx, topic, key, payload); err != nil {
		logger.Warn("Failed to publish IAM event",
			zap.String("topic", topic),
			zap.String("key", key),
			zap.String("payload", string(payloadJSON)),
			zap.Error(err),
		)
	} else {
		logger.Debug("Published IAM event",
			zap.String("topic", topic),
			zap.String("key", key),
		)
	}
}

// isReservedRoleName reports names that carry admin rank elsewhere (tenant
// administrator names and iam_admin); custom roles must not use them or they
// would spoof the name-based rank checks.
func isReservedRoleName(name string) bool {
	n := strings.TrimSpace(name)
	return authorization.IsTenantAdministratorRole(n) || strings.EqualFold(n, "iam_admin")
}

// MaxPriorityForUser returns the highest role priority the user holds in a tenant.
func (s *RoleService) MaxPriorityForUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error) {
	return s.roleRepo.GetMaxPriorityForUser(ctx, userID, tenantID)
}

// Create creates a new role
func (s *RoleService) Create(ctx context.Context, req *models.CreateRoleRequest, createdBy *uuid.UUID) (*models.RoleResponse, error) {
	if isReservedRoleName(req.Name) {
		return nil, fmt.Errorf("role name %q is reserved", strings.TrimSpace(req.Name))
	}
	// Check if role name already exists
	existing, err := s.roleRepo.GetByName(ctx, req.TenantID, req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check role name: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("role name already exists")
	}

	// C-1: priority ceiling — caller cannot create a role with priority >= their own maximum
	if createdBy != nil {
		callerMax, err := s.roleRepo.GetMaxPriorityForUser(ctx, *createdBy, req.TenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to check caller priority: %w", err)
		}
		if req.Priority >= callerMax {
			return nil, fmt.Errorf("cannot create role with priority >= your highest role priority (%d)", callerMax)
		}
	}

	role := &models.Role{
		TenantID:    req.TenantID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		IsDefault:   req.IsDefault,
		Priority:    req.Priority,
		IsSystem:    false,
		CreatedBy:   createdBy,
	}

	if err := s.roleRepo.Create(ctx, role); err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	// Assign permissions
	if len(req.PermissionIDs) > 0 {
		// C-2: caller can only assign permissions they themselves hold (wildcard-aware)
		if createdBy != nil {
			if err := s.checkCallerCoversPermissions(ctx, *createdBy, req.TenantID, req.PermissionIDs); err != nil {
				return nil, err
			}
		}
		if err := s.roleRepo.AssignPermissions(ctx, role.ID, req.PermissionIDs, createdBy); err != nil {
			return nil, fmt.Errorf("failed to assign permissions: %w", err)
		}
	}

	// Get permissions for response
	permissions, _ := s.roleRepo.GetRolePermissions(ctx, role.ID)
	role.Permissions = permissions

	// Sync permissions to SpiceDB (direct write, reconciler will repair gaps)
	if s.tenantBootstrap != nil && len(permissions) > 0 {
		var permNames []string
		for _, perm := range permissions {
			permNames = append(permNames, perm.Name)
		}
		if _, err := s.tenantBootstrap.BootstrapRolePermissions(ctx, req.TenantID, role.ID, permNames); err != nil {
			logger.Warn("Failed to sync role permissions to SpiceDB on create (reconciler will repair)",
				zap.String("role_id", role.ID.String()),
				zap.Error(err),
			)
		}
	}

	// Audit log
	s.auditService.LogRoleAction(ctx, req.TenantID, createdBy, &role.ID, "role_create", true, nil)

	// Publish event for SpiceDB sync
	s.publishEvent(ctx, IAMEventTopics.RoleCreated, role.ID.String(), IAMEventPayload{
		TenantID: req.TenantID,
		RoleID:   &role.ID,
		RoleName: role.Name,
	})

	return role.ToResponse(), nil
}

// GetByID gets a role by ID
func (s *RoleService) GetByID(ctx context.Context, id uuid.UUID) (*models.RoleResponse, error) {
	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}

	if role == nil {
		return nil, fmt.Errorf("role not found")
	}

	// Get permissions
	permissions, _ := s.roleRepo.GetRolePermissions(ctx, id)
	role.Permissions = permissions

	return role.ToResponse(), nil
}

// ErrRoleNotFound is returned by TenantOf when the role does not exist.
var ErrRoleNotFound = errors.New("role not found")

// TenantOf returns the tenant that owns a role, without loading its permissions.
func (s *RoleService) TenantOf(ctx context.Context, id uuid.UUID) (uuid.UUID, error) {
	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("TenantOf: %w", err)
	}
	if role == nil {
		return uuid.Nil, ErrRoleNotFound
	}
	return role.TenantID, nil
}

// Update updates a role
func (s *RoleService) Update(ctx context.Context, id uuid.UUID, req *models.UpdateRoleRequest, updatedBy *uuid.UUID) (*models.RoleResponse, error) {
	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("Update: %w", err)
	}

	if role == nil {
		return nil, fmt.Errorf("role not found")
	}

	if req.PermissionIDs != nil {
		if err := s.guardAPIKeyRoleGrant(ctx, role, req.PermissionIDs); err != nil {
			return nil, err
		}
	}

	// System roles can only have permissions updated
	if role.IsSystem {
		if req.DisplayName != nil || req.IsDefault != nil || req.Priority != nil {
			return nil, fmt.Errorf("cannot modify system role properties")
		}
	}

	// C-1: priority ceiling check when priority is being changed
	if req.Priority != nil && *req.Priority != role.Priority && updatedBy != nil {
		callerMax, err := s.roleRepo.GetMaxPriorityForUser(ctx, *updatedBy, role.TenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to check caller priority: %w", err)
		}
		if *req.Priority >= callerMax {
			return nil, fmt.Errorf("cannot set role priority >= your highest role priority (%d)", callerMax)
		}
		if role.Priority >= callerMax {
			return nil, fmt.Errorf("cannot modify role with priority >= your highest role priority")
		}
	}

	// C-3: system role permission changes require platform admin (priority >= 100)
	if role.IsSystem && req.PermissionIDs != nil && updatedBy != nil {
		callerMax, err := s.roleRepo.GetMaxPriorityForUser(ctx, *updatedBy, role.TenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to check caller priority: %w", err)
		}
		if callerMax < 100 {
			return nil, fmt.Errorf("only platform administrators can modify system role permissions")
		}
	}

	// Update fields
	if req.DisplayName != nil {
		role.DisplayName = *req.DisplayName
	}
	if req.Description != nil {
		role.Description = req.Description
	}
	if req.IsDefault != nil {
		role.IsDefault = *req.IsDefault
	}
	if req.Priority != nil {
		role.Priority = *req.Priority
	}

	role.UpdatedBy = updatedBy

	if err := s.roleRepo.Update(ctx, role); err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	// Update permissions if provided
	if req.PermissionIDs != nil {
		// C-2: caller can only assign permissions they themselves hold (wildcard-aware)
		if updatedBy != nil {
			if err := s.checkCallerCoversPermissions(ctx, *updatedBy, role.TenantID, req.PermissionIDs); err != nil {
				return nil, err
			}
		}
		if err := s.roleRepo.AssignPermissions(ctx, id, req.PermissionIDs, updatedBy); err != nil {
			return nil, fmt.Errorf("failed to update permissions: %w", err)
		}
	}

	// Get updated permissions
	permissions, _ := s.roleRepo.GetRolePermissions(ctx, id)
	role.Permissions = permissions

	// Audit log
	s.auditService.LogRoleAction(ctx, role.TenantID, updatedBy, &id, "role_update", true, nil)

	// Publish event for SpiceDB sync
	var permNames []string
	for _, perm := range permissions {
		permNames = append(permNames, perm.Name)
	}
	s.publishEvent(ctx, IAMEventTopics.RoleUpdated, id.String(), IAMEventPayload{
		TenantID:    role.TenantID,
		RoleID:      &id,
		RoleName:    role.Name,
		Permissions: permNames,
	})

	return role.ToResponse(), nil
}

// Delete deletes a role
func (s *RoleService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}

	if role == nil {
		return fmt.Errorf("role not found")
	}

	if role.IsSystem {
		return fmt.Errorf("cannot delete system role")
	}

	// C-1: caller cannot delete a role with priority >= their own maximum
	if deletedBy != nil {
		callerMax, err := s.roleRepo.GetMaxPriorityForUser(ctx, *deletedBy, role.TenantID)
		if err != nil {
			return fmt.Errorf("failed to check caller priority: %w", err)
		}
		if role.Priority >= callerMax {
			return fmt.Errorf("cannot delete role with priority >= your highest role priority")
		}
	}

	if err := s.roleRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	// Audit log
	s.auditService.LogRoleAction(ctx, role.TenantID, deletedBy, &id, "role_delete", true, nil)

	// Publish event for SpiceDB sync (to delete all role relationships)
	s.publishEvent(ctx, IAMEventTopics.RoleDeleted, id.String(), IAMEventPayload{
		TenantID: role.TenantID,
		RoleID:   &id,
		RoleName: role.Name,
	})

	return nil
}

// List lists every role for a tenant, unfiltered by product/module. This is
// the platform-admin view (see ListByTenant / platform_management_handler_
// roles.go) where seeing every role a tenant owns — including roles for
// products the tenant may not currently be entitled to — is the point.
// Tenant self-service surfaces (the "Edit roles" / invite picker) must use
// ListSelfService instead.
func (s *RoleService) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) (*models.RoleListResponse, error) {
	return s.list(ctx, tenantID, page, pageSize, search, nil)
}

// ListSelfService lists roles for a tenant's own self-service role picker
// (invite/edit-roles), scoped to the modules the tenant is entitled to.
//
// This reuses the exact entitlement mechanism already wired for permission
// listing (getEntitledModules / entitlementChecker / UniversalModules) —
// see ListAllPermissionsForTenant — rather than introducing a second,
// parallel notion of "which roles belong to this tenant's context". A role
// is attributed to a module transitively, through the permissions it
// carries (iam_role_permissions -> iam_permissions.module), because iam_roles
// itself has no product/module column.
func (s *RoleService) ListSelfService(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) (*models.RoleListResponse, error) {
	modules, err := s.getEntitledModules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListSelfService: entitlement lookup: %w", err)
	}
	return s.list(ctx, tenantID, page, pageSize, search, modules)
}

// ListManageableSelfService returns only roles the actor may assign through
// tenant self-service. System roles and roles at/above the actor's priority are
// deliberately excluded rather than exposed as disabled catalogue entries.
func (s *RoleService) ListManageableSelfService(ctx context.Context, tenantID, actorID uuid.UUID, page, pageSize int, search string) (*models.RoleListResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	maxPriority, err := s.roleRepo.GetMaxPriorityForUser(ctx, actorID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListManageableSelfService: actor priority: %w", err)
	}
	modules, err := s.getEntitledModules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListManageableSelfService: entitlement lookup: %w", err)
	}
	manageable := make([]models.Role, 0)
	const fetchSize = 100
	for fetchPage := 1; ; fetchPage++ {
		var roles []models.Role
		var total int64
		if modules == nil {
			roles, total, err = s.roleRepo.List(ctx, tenantID, fetchPage, fetchSize, search)
		} else {
			roles, total, err = s.roleRepo.ListForModules(ctx, tenantID, fetchPage, fetchSize, search, modules)
		}
		if err != nil {
			return nil, fmt.Errorf("ListManageableSelfService: %w", err)
		}
		for _, role := range roles {
			if role.TenantID == tenantID {
				manageable = append(manageable, role)
			}
		}
		if len(roles) == 0 || int64(fetchPage*fetchSize) >= total {
			break
		}
	}

	total := len(manageable)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	responses := make([]models.RoleResponse, 0, end-start)
	for _, role := range manageable[start:end] {
		response := role.ToResponse()
		response.Source = models.RoleSourceTenantCatalogue
		response.Editable = !role.IsSystem && role.Priority < maxPriority
		response.Locked = !response.Editable
		if response.Editable {
			permissions, _ := s.roleRepo.GetRolePermissions(ctx, role.ID)
			role.Permissions = permissions
			response = role.ToResponse()
			response.Source = models.RoleSourceTenantCatalogue
			response.Editable = true
		}
		if role.IsSystem {
			response.Source = models.RoleSourceSystem
			response.Reason = "system role"
		} else if !response.Editable {
			response.Reason = "not manageable by this actor"
		}
		responses = append(responses, *response)
	}
	totalPages := total / pageSize
	if total%pageSize != 0 {
		totalPages++
	}
	return &models.RoleListResponse{Roles: responses, Total: int64(total), Page: page, PageSize: pageSize, TotalPages: totalPages}, nil
}

// ManageableSelfServiceRoleIDs is the exact allow-list used by tenant role
// mutations. It shares the catalogue predicate, so a UI cannot display a role
// that the write path would reject (or vice versa).
func (s *RoleService) ManageableSelfServiceRoleIDs(ctx context.Context, tenantID, actorID uuid.UUID) (map[uuid.UUID]bool, error) {
	visible := make(map[uuid.UUID]bool)
	for page := 1; ; page++ {
		response, err := s.ListManageableSelfService(ctx, tenantID, actorID, page, 100, "")
		if err != nil {
			return nil, err
		}
		for _, role := range response.Roles {
			if role.Editable {
				visible[role.ID] = true
			}
		}
		if page >= response.TotalPages {
			break
		}
	}
	return visible, nil
}

// SelfServiceVisibleRoleIDs returns every role ID the tenant self-service
// picker (GET /api/v1/roles → ListSelfService) would show for tenantID —
// the exact same entitled-module filter, unpaginated and with no search
// term, calling the repo methods directly (skipping list()'s per-role
// permission fetch, which callers of this method don't need).
//
// This exists so member responses can distinguish grants excluded by module
// entitlement from grants excluded by the actor-specific manageable catalogue.
func (s *RoleService) SelfServiceVisibleRoleIDs(ctx context.Context, tenantID uuid.UUID) (map[uuid.UUID]bool, error) {
	modules, err := s.getEntitledModules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("SelfServiceVisibleRoleIDs: entitlement lookup: %w", err)
	}

	visible := make(map[uuid.UUID]bool)
	const pageSize = 100
	for page := 1; ; page++ {
		var roles []models.Role
		var total int64
		var err error
		if modules == nil {
			roles, total, err = s.roleRepo.List(ctx, tenantID, page, pageSize, "")
		} else {
			roles, total, err = s.roleRepo.ListForModules(ctx, tenantID, page, pageSize, "", modules)
		}
		if err != nil {
			return nil, fmt.Errorf("SelfServiceVisibleRoleIDs: %w", err)
		}
		for _, r := range roles {
			visible[r.ID] = true
		}
		if len(roles) == 0 || int64(page*pageSize) >= total {
			break
		}
	}

	return visible, nil
}

func (s *RoleService) list(
	ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string, modules []string,
) (*models.RoleListResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	// When modules is nil (unfiltered List, or ListSelfService with no
	// entitlement checker configured / fail-open), call the plain List
	// repo method rather than ListForModules(..., nil) — this keeps the
	// unfiltered path's repo call identical to before this change, so it
	// doesn't depend on ListForModules being implemented by every
	// roleServiceRoleRepo (repositories.RoleRepository.ListForModules
	// itself delegates to List for nil modules anyway; this just avoids
	// requiring that of every caller/mock).
	var roles []models.Role
	var total int64
	var err error
	if modules == nil {
		roles, total, err = s.roleRepo.List(ctx, tenantID, page, pageSize, search)
	} else {
		roles, total, err = s.roleRepo.ListForModules(ctx, tenantID, page, pageSize, search, modules)
	}
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	roleResponses := make([]models.RoleResponse, len(roles))
	for i, role := range roles {
		// Get permissions for each role
		permissions, _ := s.roleRepo.GetRolePermissions(ctx, role.ID)
		role.Permissions = permissions
		roleResponses[i] = *role.ToResponse()
	}

	return &models.RoleListResponse{
		Roles:      roleResponses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// ListByTenant lists all roles for a tenant (convenience method for platform admin)
func (s *RoleService) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.RoleResponse, error) {
	response, err := s.List(ctx, tenantID, 1, 100, "")
	if err != nil {
		return nil, fmt.Errorf("ListByTenant: List failed: %w", err)
	}
	return response.Roles, nil
}

// GetPermissions gets all permissions for a role
func (s *RoleService) GetPermissions(ctx context.Context, roleID uuid.UUID) ([]models.PermissionResponse, error) {
	permissions, err := s.roleRepo.GetRolePermissions(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("GetPermissions: %w", err)
	}

	result := make([]models.PermissionResponse, len(permissions))
	for i, perm := range permissions {
		result[i] = *perm.ToResponse()
	}

	return result, nil
}

// AssignPermissions assigns permissions to a role
func (s *RoleService) AssignPermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return fmt.Errorf("AssignPermissions: %w", err)
	}

	if role == nil {
		return fmt.Errorf("role not found")
	}

	if err := s.guardAPIKeyRoleGrant(ctx, role, permissionIDs); err != nil {
		return err
	}

	// C-3: system role modifications require platform admin (priority >= 100)
	if role.IsSystem && assignedBy != nil {
		callerMax, err := s.roleRepo.GetMaxPriorityForUser(ctx, *assignedBy, role.TenantID)
		if err != nil {
			return fmt.Errorf("failed to check caller priority: %w", err)
		}
		if callerMax < 100 {
			return fmt.Errorf("only platform administrators can modify system role permissions")
		}
	}

	// C-2: caller can only assign permissions they themselves hold (wildcard-aware)
	if assignedBy != nil {
		if err := s.checkCallerCoversPermissions(ctx, *assignedBy, role.TenantID, permissionIDs); err != nil {
			return err
		}
	}

	// ADR-A10 permission boundary (ties into 23-authorization-rbac-abac-
	// rebac.md §3.2/§12.2): a tenant admin can never grant a permission
	// outside their own entitlement/tenant-plane boundary, even via the
	// PUT-permissions "replace the set" path — not just the dedicated
	// internal/v1 grant-permission action endpoint. Checked per-permission
	// so a partially-entitled request fails closed on the first violation
	// rather than silently dropping the offending permission.
	if err := s.checkGrantBoundaryForIDs(ctx, role.TenantID, permissionIDs); err != nil {
		return err
	}

	if err := s.roleRepo.AssignPermissions(ctx, roleID, permissionIDs, assignedBy); err != nil {
		return fmt.Errorf("failed to assign permissions: %w", err)
	}

	// Audit log
	s.auditService.LogRoleAction(ctx, role.TenantID, assignedBy, &roleID, "role_permissions_update", true, map[string]interface{}{
		"permission_count": len(permissionIDs),
	})

	// Sync permissions to SpiceDB (direct write, reconciler will repair gaps)
	permissions, _ := s.roleRepo.GetRolePermissions(ctx, roleID)
	var permNames []string
	for _, perm := range permissions {
		permNames = append(permNames, perm.Name)
	}

	if s.tenantBootstrap != nil && len(permNames) > 0 {
		if _, err := s.tenantBootstrap.BootstrapRolePermissions(ctx, role.TenantID, roleID, permNames); err != nil {
			logger.Warn("Failed to sync role permissions to SpiceDB (reconciler will repair)",
				zap.String("role_id", roleID.String()),
				zap.Error(err),
			)
		}
	}

	// Publish events for SpiceDB sync (permission grants)
	s.publishEvent(ctx, IAMEventTopics.RoleUpdated, roleID.String(), IAMEventPayload{
		TenantID:    role.TenantID,
		RoleID:      &roleID,
		RoleName:    role.Name,
		Permissions: permNames,
	})

	// Publish CAERoleRevoked tenant-scoped (UserID=Nil per CAEEvent
	// shape; the metadata.role_id lets receivers fan out to every
	// affected user). Permission CHANGES on a role — including
	// additions — count as a "permissions you held may have shifted"
	// signal that warrants session re-evaluation: a permission that
	// was implicitly tightened (e.g. moved from broad to narrow) is
	// indistinguishable from a removal at the role-bundle level
	// without a diff against the prior set, and falsely-conservative
	// invalidation is preferable to falsely-permissive caching here.
	// Receivers (Talon IAP) look up role membership and act on the
	// affected sessions.
	if s.caeService != nil {
		_ = s.caeService.PublishEvent(ctx, CAEEvent{
			Type:      CAERoleRevoked,
			UserID:    uuid.Nil, // tenant-scoped; receivers fan out per role membership
			TenantID:  role.TenantID,
			Timestamp: time.Now().UTC(),
			Metadata: map[string]string{
				"role_id":          roleID.String(),
				"role_name":        role.Name,
				"permission_count": fmt.Sprintf("%d", len(permissionIDs)),
				"reason":           "permissions_changed",
			},
		})
	}

	return nil
}

// ListAllPermissions lists all available permissions
func (s *RoleService) ListAllPermissions(ctx context.Context) (*models.PermissionListResponse, error) {
	permissions, err := s.permissionRepo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("ListAllPermissions: %w", err)
	}

	result := make([]models.PermissionResponse, len(permissions))
	for i, perm := range permissions {
		result[i] = *perm.ToResponse()
	}

	return &models.PermissionListResponse{
		Permissions: result,
		Total:       int64(len(permissions)),
	}, nil
}

// ListPermissionsByModule lists permissions grouped by module
func (s *RoleService) ListPermissionsByModule(ctx context.Context) ([]models.PermissionsByModule, error) {
	permissions, err := s.permissionRepo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("ListPermissionsByModule: %w", err)
	}

	// Group by module
	moduleMap := make(map[string][]models.PermissionResponse)
	for _, perm := range permissions {
		moduleMap[perm.Module] = append(moduleMap[perm.Module], *perm.ToResponse())
	}

	result := make([]models.PermissionsByModule, 0, len(moduleMap))
	for module, perms := range moduleMap {
		result = append(result, models.PermissionsByModule{
			Module:      module,
			Permissions: perms,
		})
	}

	return result, nil
}

// SetModuleEntitlementChecker wires an optional module entitlement checker.
// When set, tenant-aware listing methods filter permissions to the modules
// the tenant is subscribed to. Errors from the checker are fail-open.
func (s *RoleService) SetModuleEntitlementChecker(checker ModuleEntitlementChecker) {
	s.entitlementChecker = checker
}

// EntitledModules returns the fail-closed module set for a tenant mutation.
// It is intentionally public for transaction owners that must re-check a
// role's effective permissions immediately before granting it.
func (s *RoleService) EntitledModules(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	return s.getEntitledModules(ctx, tenantID)
}

// getEntitledModules returns the modules a tenant is subscribed to, always
// including "core" and "iam". Missing optional entitlement infrastructure
// limits a tenant catalogue to those universal modules. Lookup and database
// errors are returned so callers cannot disclose or assign paid-module roles.
func (s *RoleService) getEntitledModules(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	if s.entitlementChecker == nil {
		return append([]string(nil), UniversalModules...), nil
	}

	allModules, err := s.permissionRepo.GetModules(ctx)
	if err != nil {
		return nil, fmt.Errorf("get modules: %w", err)
	}

	entitled := make([]string, len(UniversalModules))
	copy(entitled, UniversalModules)
	seen := make(map[string]bool, len(UniversalModules))
	for _, m := range UniversalModules {
		seen[m] = true
	}

	for _, module := range allModules {
		if seen[module] {
			continue
		}
		ok, err := s.entitlementChecker.IsTenantEntitled(ctx, tenantID, module)
		if err != nil {
			return nil, fmt.Errorf("check entitlement for module %q: %w", module, err)
		}
		if ok {
			entitled = append(entitled, module)
			seen[module] = true
		}
	}

	return entitled, nil
}

// ListAllPermissionsForTenant lists permissions filtered to the tenant's subscribed modules.
func (s *RoleService) ListAllPermissionsForTenant(ctx context.Context, tenantID uuid.UUID) (*models.PermissionListResponse, error) {
	modules, err := s.getEntitledModules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListAllPermissionsForTenant: entitlement lookup: %w", err)
	}

	permissions, err := s.permissionRepo.ListByModules(ctx, modules)
	if err != nil {
		return nil, fmt.Errorf("ListAllPermissionsForTenant: %w", err)
	}

	result := make([]models.PermissionResponse, len(permissions))
	for i, perm := range permissions {
		result[i] = *perm.ToResponse()
	}

	return &models.PermissionListResponse{
		Permissions: result,
		Total:       int64(len(permissions)),
	}, nil
}

// ListPermissionsByModuleForTenant lists permissions grouped by module, filtered
// to the tenant's subscribed modules.
func (s *RoleService) ListPermissionsByModuleForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.PermissionsByModule, error) {
	modules, err := s.getEntitledModules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListPermissionsByModuleForTenant: entitlement lookup: %w", err)
	}

	permissions, err := s.permissionRepo.ListByModules(ctx, modules)
	if err != nil {
		return nil, fmt.Errorf("ListPermissionsByModuleForTenant: %w", err)
	}

	moduleMap := make(map[string][]models.PermissionResponse)
	for _, perm := range permissions {
		moduleMap[perm.Module] = append(moduleMap[perm.Module], *perm.ToResponse())
	}

	result := make([]models.PermissionsByModule, 0, len(moduleMap))
	for module, perms := range moduleMap {
		result = append(result, models.PermissionsByModule{
			Module:      module,
			Permissions: perms,
		})
	}

	return result, nil
}

// InitializeTenantRoles creates default system roles for a new tenant
func (s *RoleService) InitializeTenantRoles(ctx context.Context, tenantID uuid.UUID) error {
	return s.roleRepo.CreateSystemRoles(ctx, tenantID)
}

// GetRoleMembers returns a paginated list of users who hold the role identified
// by roleIdentifier (UUID or name such as "crm:manager").
func (s *RoleService) GetRoleMembers(ctx context.Context, tenantID uuid.UUID, roleIdentifier string, page, pageSize int) (*models.RoleMembersResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 100
	}

	members, total, err := s.roleRepo.GetRoleMembers(ctx, tenantID, roleIdentifier, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("GetRoleMembers: %w", err)
	}

	data := make([]models.RoleMember, len(members))
	for i, m := range members {
		data[i] = models.RoleMember{
			UserID:   m.UserID,
			UserName: m.UserName,
			Email:    m.Email,
		}
	}

	return &models.RoleMembersResponse{
		Data:     data,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}
