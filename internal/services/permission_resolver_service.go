// SPDX-License-Identifier: AGPL-3.0-or-later

// Package services provides business logic for the IAM service.
// This file implements the Permission Resolution Service for resolving
// roles and permissions for v2 SpiceDB tokens.
package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

// PermissionResolverSource indicates where permissions were resolved from
type PermissionResolverSource string

const (
	// SourceSpiceDB is an exported identifier.
	SourceSpiceDB PermissionResolverSource = "spicedb"
	// SourceRedis is an exported identifier.
	SourceRedis PermissionResolverSource = "redis"
	// SourceDatabase is an exported identifier.
	SourceDatabase PermissionResolverSource = "database"
	// SourceFailed is an exported identifier.
	SourceFailed PermissionResolverSource = "failed"
)

// ResolvedPermissions contains the resolved roles and permissions for a user
type ResolvedPermissions struct {
	Roles       []string
	Permissions []string
	Source      PermissionResolverSource
	ResolvedAt  time.Time
}

// PermissionResolverService resolves permissions for v2 SpiceDB tokens.
// SpiceDB is the MANDATORY authorization system - no fallback to database.
//
// CVE-HEXX-IAM-007: SpiceDB Token Authorization Bypass (CVSS 9.1)
// This service addresses the security vulnerability where v2 SpiceDB tokens have nil
// Roles/Permissions in JWT claims, but the authorization middleware expects these values
// to be populated for role-based access control decisions.
//
// Security Model: Fail-closed with SpiceDB as mandatory source
// - V2 tokens REQUIRE SpiceDB for authorization
// - If SpiceDB is unavailable, access is DENIED (no database fallback)
// - This ensures consistent authorization via ReBAC model
// - Redis is used for caching/performance only, NOT as fallback
type PermissionResolverService struct {
	spicedbClient *spicedb.Client
	sessionCache  *redis.SessionCache
	userRepo      *repositories.UserRepository
	permRepo      *repositories.PermissionRepository
	config        *config.Config
	syncService   *SpiceDBSyncService

	// Circuit breaker for SpiceDB
	spicedbCircuitBreaker *circuitBreaker
	// Circuit breaker for Redis (for caching only)
	redisCircuitBreaker *circuitBreaker
}

// circuitBreaker implements a simple circuit breaker pattern
type circuitBreaker struct {
	mu              sync.RWMutex
	failures        int
	threshold       int
	lastFailureTime time.Time
	resetTimeout    time.Duration
	isOpen          bool
}

func newCircuitBreaker(threshold int, resetTimeout time.Duration) *circuitBreaker {
	return &circuitBreaker{
		threshold:    threshold,
		resetTimeout: resetTimeout,
	}
}

func (cb *circuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	if cb.failures >= cb.threshold && !cb.isOpen {
		cb.isOpen = true
		logger.Log.Warn("Circuit breaker OPENED",
			zap.Int("failure_count", cb.failures),
		)
	}
}

func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.isOpen {
		logger.Log.Info("Circuit breaker CLOSED after successful operation")
	}
	cb.failures = 0
	cb.isOpen = false
}

func (cb *circuitBreaker) isCircuitOpen() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if !cb.isOpen {
		return false
	}

	// Check if enough time has passed to attempt recovery
	if time.Since(cb.lastFailureTime) > cb.resetTimeout {
		return false // Allow one attempt
	}

	return true
}

// NewPermissionResolverService creates a new permission resolver service.
// spicedbClient is REQUIRED for v2 token support - pass nil only if v2 tokens are disabled.
func NewPermissionResolverService(
	spicedbClient *spicedb.Client,
	sessionCache *redis.SessionCache,
	userRepo *repositories.UserRepository,
	permRepo *repositories.PermissionRepository,
	cfg *config.Config,
) *PermissionResolverService {
	svc := &PermissionResolverService{
		spicedbClient:         spicedbClient,
		sessionCache:          sessionCache,
		userRepo:              userRepo,
		permRepo:              permRepo,
		config:                cfg,
		spicedbCircuitBreaker: newCircuitBreaker(5, 30*time.Second),
		redisCircuitBreaker:   newCircuitBreaker(5, 30*time.Second),
	}

	// Create SpiceDB sync service if client is available
	if spicedbClient != nil {
		svc.syncService = NewSpiceDBSyncService(spicedbClient)
	}

	return svc
}

// SetSyncService sets the SpiceDB sync service (for dependency injection)
func (s *PermissionResolverService) SetSyncService(syncService *SpiceDBSyncService) {
	s.syncService = syncService
}

// GetSyncService returns the SpiceDB sync service
func (s *PermissionResolverService) GetSyncService() *SpiceDBSyncService {
	return s.syncService
}

// IsSpiceDBAvailable returns true if SpiceDB client is configured
func (s *PermissionResolverService) IsSpiceDBAvailable() bool {
	return s.spicedbClient != nil
}

// ResolvePermissions resolves roles and permissions for a user via SpiceDB.
// SpiceDB is MANDATORY - if it fails, authorization is denied (fail-closed).
//
// SECURITY: No database fallback for v2 tokens.
// SpiceDB is the single source of truth for authorization decisions.
func (s *PermissionResolverService) ResolvePermissions(ctx context.Context, userID, tenantID, _ uuid.UUID) (*ResolvedPermissions, error) {
	startTime := time.Now()

	// SpiceDB is MANDATORY - check if client is available
	if s.spicedbClient == nil {
		logger.Log.Error("SECURITY: SpiceDB client not initialized - v2 token authorization denied",
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", tenantID.String()),
		)
		return nil, fmt.Errorf("SpiceDB is required for v2 token authorization but client is not initialized")
	}

	// Check circuit breaker - if open, deny access (fail-closed)
	if s.spicedbCircuitBreaker.isCircuitOpen() {
		logger.Log.Error("SECURITY: SpiceDB circuit breaker is OPEN - authorization denied",
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", tenantID.String()),
		)
		return nil, fmt.Errorf("SpiceDB circuit breaker is open - authorization service temporarily unavailable")
	}

	// Resolve permissions from SpiceDB (MANDATORY)
	resolved, err := s.resolveFromSpiceDB(ctx, userID, tenantID)
	if err != nil {
		s.spicedbCircuitBreaker.recordFailure()
		logger.Log.Error("SECURITY: SpiceDB permission resolution failed - authorization denied",
			zap.Error(err),
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", tenantID.String()),
		)
		return nil, fmt.Errorf("SpiceDB authorization failed: %w", err)
	}

	s.spicedbCircuitBreaker.recordSuccess()
	logger.Log.Info("Permissions resolved from SpiceDB (mandatory)",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.Int("roles_count", len(resolved.Roles)),
		zap.Int("permissions_count", len(resolved.Permissions)),
		zap.Duration("duration", time.Since(startTime)),
	)

	return resolved, nil
}

// ResolvePermissionsWithFallback resolves permissions using SpiceDB with database fallback.
// Use this ONLY for legacy/migration scenarios where database fallback is acceptable.
// For v2 tokens, use ResolvePermissions() which enforces SpiceDB-only.
func (s *PermissionResolverService) ResolvePermissionsWithFallback(ctx context.Context, userID, tenantID, _ uuid.UUID) (*ResolvedPermissions, error) {
	startTime := time.Now()

	// Try SpiceDB first (if available and circuit breaker is closed)
	if s.spicedbClient != nil && !s.spicedbCircuitBreaker.isCircuitOpen() {
		resolved, err := s.resolveFromSpiceDB(ctx, userID, tenantID)
		if err == nil {
			s.spicedbCircuitBreaker.recordSuccess()
			logger.Log.Debug("Permissions resolved from SpiceDB",
				zap.String("user_id", userID.String()),
				zap.Int("roles_count", len(resolved.Roles)),
				zap.Duration("duration", time.Since(startTime)),
			)
			return resolved, nil
		}
		s.spicedbCircuitBreaker.recordFailure()
		logger.Log.Warn("SpiceDB failed, falling back to database (legacy mode)",
			zap.Error(err),
			zap.String("user_id", userID.String()),
		)
	}

	// Fall back to database (legacy mode only). Pass tenantID for cross-tenant isolation.
	resolved, err := s.resolveFromDatabase(ctx, userID, tenantID)
	if err != nil {
		logger.Log.Error("Database permission resolution failed",
			zap.Error(err),
			zap.String("user_id", userID.String()),
		)
		return nil, fmt.Errorf("failed to resolve permissions: %w", err)
	}

	logger.Log.Info("Permissions resolved from database (legacy fallback)",
		zap.String("user_id", userID.String()),
		zap.Int("roles_count", len(resolved.Roles)),
		zap.Duration("duration", time.Since(startTime)),
	)
	return resolved, nil
}

// resolveFromSpiceDB resolves permissions using SpiceDB as the authoritative source.
// SpiceDB stores relationships (user->role, role->permission) and we query these
// to build the complete permission set for the user.
func (s *PermissionResolverService) resolveFromSpiceDB(ctx context.Context, userID, tenantID uuid.UUID) (*ResolvedPermissions, error) {
	// Step 1: Get user's roles from SpiceDB
	roleIDs, err := s.spicedbClient.LookupUserRoles(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("SpiceDB LookupUserRoles failed: %w", err)
	}

	// Step 2: Convert role IDs to role names
	// SpiceDB returns role IDs in format "tenant_id:role_id", we need role names
	var roleNames []string
	roleIDMap := make(map[uuid.UUID]bool)

	for _, roleIDStr := range roleIDs {
		// Parse the role ID (already extracted from SpiceDB format)
		roleID, parseErr := uuid.Parse(roleIDStr)
		if parseErr != nil {
			logger.Log.Debug("Failed to parse role ID from SpiceDB",
				zap.String("role_id_str", roleIDStr),
				zap.Error(parseErr),
			)
			continue
		}
		roleIDMap[roleID] = true
	}

	// Look up role names from database (read-only, not authorization decision)
	if s.permRepo != nil && len(roleIDMap) > 0 {
		for roleID := range roleIDMap {
			roleName, roleErr := s.permRepo.GetRoleNameByID(ctx, roleID)
			if roleErr != nil {
				logger.Log.Debug("Could not find role name",
					zap.String("role_id", roleID.String()),
					zap.Error(roleErr),
				)
				continue
			}
			roleNames = append(roleNames, roleName)
		}
	}

	// Step 3: Get permissions for these roles from SpiceDB
	// Query SpiceDB for all permissions granted to the user
	var permissionNames []string
	permissions, err := s.spicedbClient.LookupUserPermissions(ctx, tenantID, userID)
	if err != nil {
		// Log but don't fail - roles are the primary authorization mechanism
		logger.Log.Warn("SpiceDB LookupUserPermissions failed, using role-based auth only",
			zap.Error(err),
			zap.String("user_id", userID.String()),
		)
	} else {
		permissionNames = permissions
	}

	// If SpiceDB has no relationships yet (new deployment), check tenant admin status
	// Tenant admins implicitly have all permissions
	if len(roleNames) == 0 && len(permissionNames) == 0 {
		isAdmin, checkErr := s.spicedbClient.CheckPermission(ctx, tenantID, userID, "tenant", tenantID.String(), "manage")
		if checkErr == nil && isAdmin {
			roleNames = append(roleNames, "admin")
			logger.Log.Debug("User is tenant admin via SpiceDB",
				zap.String("user_id", userID.String()),
				zap.String("tenant_id", tenantID.String()),
			)
		}
	}

	// Validate we got authorization data from SpiceDB
	if len(roleNames) == 0 && len(permissionNames) == 0 {
		logger.Log.Warn("SpiceDB returned no roles or permissions for user",
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", tenantID.String()),
		)
		// This is not an error - user may legitimately have no roles
		// Return empty permissions (user has no access to protected resources)
	}

	return &ResolvedPermissions{
		Roles:       roleNames,
		Permissions: permissionNames,
		Source:      SourceSpiceDB,
		ResolvedAt:  time.Now(),
	}, nil
}

// resolveFromDatabase resolves permissions from the database.
// tenantID is required to enforce cross-tenant isolation when querying the PermissionRepository:
// both GetUserRoles and GetUserPermissions filter by r.tenant_id = $2 to prevent a user's
// roles from one tenant being visible when resolving permissions in another tenant.
func (s *PermissionResolverService) resolveFromDatabase(ctx context.Context, userID, tenantID uuid.UUID) (*ResolvedPermissions, error) {
	// Get roles
	var roleNames []string
	if s.permRepo != nil {
		roles, err := s.permRepo.GetUserRoles(ctx, userID, tenantID)
		if err != nil {
			return nil, fmt.Errorf("database GetUserRoles failed: %w", err)
		}
		roleNames = roles
	} else if s.userRepo != nil {
		roles, err := s.userRepo.GetUserRoles(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("database GetUserRoles failed: %w", err)
		}
		for _, r := range roles {
			roleNames = append(roleNames, r.Name)
		}
	}

	// Get permissions
	permissionNames := s.resolvePermissionNames(ctx, userID, tenantID)

	return &ResolvedPermissions{
		Roles:       roleNames,
		Permissions: permissionNames,
		Source:      SourceDatabase,
		ResolvedAt:  time.Now(),
	}, nil
}

// resolvePermissionNames returns permission names from permRepo or userRepo (best-effort fallback).
func (s *PermissionResolverService) resolvePermissionNames(ctx context.Context, userID, tenantID uuid.UUID) []string {
	var names []string
	if s.permRepo != nil {
		permissions, err := s.permRepo.GetUserPermissions(ctx, userID, tenantID)
		if err != nil {
			logger.Log.Warn("Failed to get permissions from database",
				zap.Error(err),
				zap.String("user_id", userID.String()),
			)
			return names
		}
		for _, p := range permissions {
			names = append(names, p.Name)
		}
		return names
	}
	if s.userRepo != nil {
		permissions, err := s.userRepo.GetUserPermissions(ctx, userID)
		if err != nil {
			logger.Log.Warn("Failed to get permissions from database",
				zap.Error(err),
				zap.String("user_id", userID.String()),
			)
			return names
		}
		for _, p := range permissions {
			names = append(names, p.Name)
		}
	}
	return names
}

// IsV2Token checks if the claims indicate a v2 SpiceDB token
// V2 tokens have nil Roles and nil Permissions in the claims
func IsV2Token(claims *models.Claims) bool {
	return claims.Roles == nil && claims.Permissions == nil
}

// PopulateCurrentUserPermissions resolves and populates permissions on a CurrentUser
// for v2 tokens. This should be called from the RequireAuth middleware.
//
// Returns the permission source for logging/metrics purposes
func (s *PermissionResolverService) PopulateCurrentUserPermissions(
	ctx context.Context,
	user *models.CurrentUser,
	sessionID uuid.UUID,
) (PermissionResolverSource, error) {
	resolved, err := s.ResolvePermissions(ctx, user.ID, user.TenantID, sessionID)
	if err != nil {
		return SourceFailed, fmt.Errorf("PopulateCurrentUserPermissions: ResolvePermissions failed: %w", err)
	}

	user.Roles = resolved.Roles
	user.Permissions = resolved.Permissions

	return resolved.Source, nil
}

// =====================================================
// ZedToken-Aware Permission Operations
// =====================================================

// AssignRoleWithToken assigns a role to a user and returns the ZedToken.
// This is the recommended method for role assignment as it enables
// consistency guarantees for subsequent permission checks.
func (s *PermissionResolverService) AssignRoleWithToken(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error) {
	if s.spicedbClient == nil {
		return "", fmt.Errorf("SpiceDB client not initialized")
	}

	// Write relationship — now returns ZedToken for consistency guarantees
	token, err := s.spicedbClient.WriteUserRole(ctx, tenantID, userID, roleID)
	if err != nil {
		return "", fmt.Errorf("failed to assign role: %w", err)
	}

	logger.Log.Info("Role assigned with ZedToken",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.String("role_id", roleID.String()),
		zap.Bool("has_token", token != ""),
	)

	return token, nil
}

// CheckPermissionWithConsistency checks if a user has permission on a resource
// with the specified consistency guarantee.
//
// Use this for operations that require consistency guarantees:
// - Edit/Delete after creation (AtLeastAsFresh)
// - Financial approvals (FullyConsistent)
// - Permission check after grant (AtLeastAsFresh)
func (s *PermissionResolverService) CheckPermissionWithConsistency(
	ctx context.Context,
	tenantID, userID uuid.UUID,
	resourceType, resourceID, permission string,
	mode spicedb.ConsistencyMode,
	zedToken string,
) (bool, error) {
	if s.spicedbClient == nil {
		return false, fmt.Errorf("SpiceDB client not initialized")
	}

	return s.spicedbClient.CheckPermissionWithConsistency(
		ctx, tenantID, userID, resourceType, resourceID, permission,
		mode, zedToken,
	)
}

// CheckPermissionAfterGrant checks if a user has permission immediately after granting it.
// This uses AtLeastAsFresh consistency with the provided ZedToken to ensure
// the user can immediately exercise their new permission.
//
// Example:
//
//	token, _ := resolver.AssignRoleWithToken(ctx, tenantID, userID, roleID)
//	allowed, _ := resolver.CheckPermissionAfterGrant(ctx, tenantID, userID, "invoice", invoiceID, "approve", token)
func (s *PermissionResolverService) CheckPermissionAfterGrant(
	ctx context.Context,
	tenantID, userID uuid.UUID,
	resourceType, resourceID, permission string,
	zedToken string,
) (bool, error) {
	return s.CheckPermissionWithConsistency(
		ctx, tenantID, userID, resourceType, resourceID, permission,
		spicedb.ConsistencyAtLeastAsFresh, zedToken,
	)
}

// CheckCriticalPermission checks permission with FullyConsistent mode.
// Use this for critical operations like financial approvals, security changes, etc.
func (s *PermissionResolverService) CheckCriticalPermission(
	ctx context.Context,
	tenantID, userID uuid.UUID,
	resourceType, resourceID, permission string,
) (bool, error) {
	return s.CheckPermissionWithConsistency(
		ctx, tenantID, userID, resourceType, resourceID, permission,
		spicedb.ConsistencyFullyConsistent, "",
	)
}
