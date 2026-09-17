// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

// AuthorizationService handles authorization checks
type AuthorizationService struct {
	permissionRepo *repositories.PermissionRepository
	userRepo       *repositories.UserRepository
	opaService     *OPAService
	auditService   *AuditService
	spicedbClient  *spicedb.Client
	config         *config.Config
	authzEngine    AuthorizationEngine
}

// NewAuthorizationService creates a new authorization service
func NewAuthorizationService(
	permissionRepo *repositories.PermissionRepository,
	userRepo *repositories.UserRepository,
	opaService *OPAService,
	auditService *AuditService,
) *AuthorizationService {
	return &AuthorizationService{
		permissionRepo: permissionRepo,
		userRepo:       userRepo,
		opaService:     opaService,
		auditService:   auditService,
	}
}

// SetSpiceDBClient sets the SpiceDB client for ReBAC authorization
func (s *AuthorizationService) SetSpiceDBClient(client *spicedb.Client, cfg *config.Config) {
	s.spicedbClient = client
	s.config = cfg
	logger.Info("SpiceDB client wired to authorization service (primary engine)",
		zap.Bool("enabled", client != nil),
	)
}

// SetAuthorizationEngine wires the unified AuthorizationEngine. When set,
// AuthorizeBatch delegates to engine.BatchCheckPermissions() instead of
// querying PostgreSQL directly. This is the preferred production path.
func (s *AuthorizationService) SetAuthorizationEngine(engine AuthorizationEngine) {
	s.authzEngine = engine
}

// Authorize checks if a user has a specific permission
func (s *AuthorizationService) Authorize(ctx context.Context, req *models.AuthorizeRequest) (*models.AuthorizeResponse, error) {
	if req.UserID == uuid.Nil {
		return &models.AuthorizeResponse{
			Allowed: false,
			Reason:  "user ID is required",
		}, nil
	}

	if req.Permission == "" {
		return &models.AuthorizeResponse{
			Allowed: false,
			Reason:  "permission is required",
		}, nil
	}

	// SpiceDB is the primary authorization engine
	if s.spicedbClient != nil && s.config != nil {
		return s.authorizeSpiceDB(ctx, req)
	}

	// Fallback: RBAC + ABAC (only if SpiceDB not wired — should not happen in production)
	return s.authorizeRBAC(ctx, req)
}

// authorizeRBAC performs authorization using traditional RBAC + ABAC
func (s *AuthorizationService) authorizeRBAC(ctx context.Context, req *models.AuthorizeRequest) (*models.AuthorizeResponse, error) {
	// Check permission in database (role-based)
	allowed, err := s.checkPermission(ctx, req.UserID, req.TenantID, req.Permission)
	if err != nil {
		return nil, fmt.Errorf("failed to check permission: %w", err)
	}

	if allowed {
		return &models.AuthorizeResponse{
			Allowed: true,
			Reason:  "granted via role",
		}, nil
	}

	// If OPA service is available and enabled, check ABAC policies
	if s.opaService != nil && s.opaService.IsEnabled() {
		if allowed := s.checkOPAPermission(ctx, req); allowed {
			return &models.AuthorizeResponse{
				Allowed: true,
				Reason:  "granted via ABAC policy",
			}, nil
		}
	}

	return &models.AuthorizeResponse{
		Allowed: false,
		Reason:  "permission denied",
	}, nil
}

// authorizeSpiceDB performs authorization using SpiceDB (ReBAC)
func (s *AuthorizationService) authorizeSpiceDB(ctx context.Context, req *models.AuthorizeRequest) (*models.AuthorizeResponse, error) {
	// Parse permission to determine object type and action
	objectType, objectID, action := s.parsePermission(req.Permission, req.ResourceType, req.ResourceID)

	// Check permission via SpiceDB
	allowed, err := s.spicedbClient.CheckPermission(ctx, req.TenantID, req.UserID, objectType, objectID, action)
	if err != nil {
		// SpiceDB failure - log and potentially fallback
		logger.Error("SpiceDB permission check failed",
			zap.Error(err),
			zap.String("permission", req.Permission),
			zap.String("user_id", req.UserID.String()),
		)

		// SECURITY: Fail-closed when SpiceDB check fails
		return nil, fmt.Errorf("SpiceDB authorization failed: %w", err)
	}

	reason := "granted via SpiceDB"
	if !allowed {
		reason = "denied by SpiceDB"
	}

	return &models.AuthorizeResponse{
		Allowed: allowed,
		Reason:  reason,
	}, nil
}

// parsePermission parses a permission string into SpiceDB object type, ID, and action.
// Uses the access_grant pattern consistent with AuthorizationEngine.
func (s *AuthorizationService) parsePermission(permission, resourceType, resourceID string) (objectType, objectID, action string) {
	// If resourceType and resourceID are provided, use them directly
	if resourceType != "" && resourceID != "" {
		return resourceType, resourceID, permission
	}

	// Parse permission format: "module:resource:action" -> access_grant pattern
	parts := strings.Split(permission, ":")
	if len(parts) == 3 {
		objectType = "access_grant"
		objectID = spicedb.PermissionToSpiceDBID(permission)
		action = "check"
		return
	}

	// Fallback: treat entire permission as action on tenant
	objectType = "tenant"
	objectID = "default"
	action = permission
	return
}

// AuthorizeBatch checks multiple permissions for a user.
// When an AuthorizationEngine is wired (preferred), it delegates to
// engine.BatchCheckPermissions() which queries SpiceDB as the authoritative
// source. Falls back to direct PostgreSQL queries for backward compatibility
// when no engine is set.
func (s *AuthorizationService) AuthorizeBatch(ctx context.Context, req *models.BatchAuthorizeRequest) (*models.BatchAuthorizeResponse, error) {
	if req.UserID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}

	if len(req.Permissions) == 0 {
		return nil, fmt.Errorf("at least one permission is required")
	}

	// Preferred path: delegate to the unified AuthorizationEngine (SpiceDB).
	if s.authzEngine != nil {
		results, err := s.authzEngine.BatchCheckPermissions(ctx, req.UserID, req.TenantID, req.Permissions)
		if err != nil {
			return nil, err
		}
		return &models.BatchAuthorizeResponse{Results: results}, nil
	}

	// Fallback path: query PostgreSQL directly.
	// Used only when no engine is wired (e.g., during startup or tests that
	// exercise the legacy code path). Not recommended for production.
	results := make(map[string]bool, len(req.Permissions))

	// Get user's effective permissions once, scoped to the request's tenant.
	userPerms, err := s.permissionRepo.GetUserPermissions(ctx, req.UserID, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Build a permission map for quick lookup
	// SECURITY: Only honor wildcards that are explicitly assigned in the database.
	// Do NOT synthesize wildcard entries from regular permissions, as that would
	// grant all module/resource permissions to any user with a single permission.
	permMap := make(map[string]bool)
	for _, p := range userPerms {
		permMap[p.Name] = true
	}

	// Check each requested permission
	for _, perm := range req.Permissions {
		allowed := s.matchPermission(permMap, perm)
		results[perm] = allowed
	}

	return &models.BatchAuthorizeResponse{
		Results: results,
	}, nil
}

// GetEffectivePermissions returns all effective permissions for a user scoped to their tenant.
func (s *AuthorizationService) GetEffectivePermissions(ctx context.Context, userID, tenantID uuid.UUID) (*models.EffectivePermissionsResponse, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}

	// Get permissions scoped to the caller's tenant.
	permissions, err := s.permissionRepo.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Get roles scoped to the caller's tenant.
	roles, err := s.permissionRepo.GetUserRoles(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Convert to response format
	permResponses := make([]models.PermissionResponse, len(permissions))
	for i, perm := range permissions {
		permResponses[i] = *perm.ToResponse()
	}

	return &models.EffectivePermissionsResponse{
		UserID:      userID,
		Permissions: permResponses,
		Roles:       roles,
	}, nil
}

// checkPermission checks if a user has a specific permission via roles, scoped to the given tenant.
func (s *AuthorizationService) checkPermission(ctx context.Context, userID, tenantID uuid.UUID, permission string) (bool, error) {
	// Get user's permissions scoped to tenantID to prevent cross-tenant privilege escalation.
	permissions, err := s.permissionRepo.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return false, fmt.Errorf("checkPermission: %w", err)
	}

	// Build permission map
	// SECURITY: Only honor wildcards that are explicitly assigned in the database.
	// Do NOT synthesize wildcard entries from regular permissions.
	permMap := make(map[string]bool)
	for _, p := range permissions {
		permMap[p.Name] = true
	}

	return s.matchPermission(permMap, permission), nil
}

// matchPermission checks if a permission matches any in the permission map (supports wildcards)
func (s *AuthorizationService) matchPermission(permMap map[string]bool, permission string) bool {
	// Direct match
	if permMap[permission] {
		return true
	}

	// Superadmin wildcard
	if permMap["*"] {
		return true
	}

	// Parse permission: module:resource:action
	parts := strings.Split(permission, ":")
	if len(parts) != 3 {
		return false
	}

	module, resource, _ := parts[0], parts[1], parts[2]

	// Module wildcard: module:*
	if permMap[module+":*"] {
		return true
	}

	// Resource wildcard: module:resource:*
	if permMap[module+":"+resource+":*"] {
		return true
	}

	return false
}

// checkOPAPermission invokes the OPA service for an ABAC decision.
// Returns true if the policy explicitly allows the request.
func (s *AuthorizationService) checkOPAPermission(ctx context.Context, req *models.AuthorizeRequest) bool {
	roles, _ := s.permissionRepo.GetUserRoles(ctx, req.UserID, req.TenantID)
	perms, _ := s.permissionRepo.GetUserPermissions(ctx, req.UserID, req.TenantID)
	permNames := make([]string, len(perms))
	for i, p := range perms {
		permNames[i] = p.Name
	}

	var username, email string
	if s.userRepo != nil {
		if user, err := s.userRepo.GetByID(ctx, req.UserID); err == nil && user != nil {
			username = user.Username
			email = user.Email
		}
	}

	var ownerID string
	if req.OwnerID != nil {
		ownerID = req.OwnerID.String()
	}

	result, err := s.opaService.EvaluatePermission(
		ctx,
		req.UserID,
		req.TenantID,
		username,
		email,
		roles,
		permNames,
		nil,
		req.Permission,
		req.ResourceType,
		req.ResourceID,
		ownerID,
		req.Attributes,
		req.IPAddress,
		req.UserAgent,
		req.RequestPath,
	)
	return err == nil && result != nil && result.Allowed
}
