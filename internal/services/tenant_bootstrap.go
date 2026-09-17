// SPDX-License-Identifier: AGPL-3.0-or-later

// Package services provides the tenant bootstrap service.
// This service seeds default SpiceDB relationships when a new tenant is created,
// establishing the minimum authorization graph required for the tenant to function.
package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

// TenantBootstrapService seeds default SpiceDB relationships when a new tenant is
// created. All write operations use OPERATION_TOUCH, making every call idempotent —
// re-running bootstrap on an existing tenant is safe and produces no duplicates.
// Individual write failures are collected rather than propagated immediately so that
// a single transient error cannot block the remaining relationships; the outbox
// reconciler will close any gaps on the next run.
type TenantBootstrapService struct {
	client *spicedb.Client
}

// BootstrapResult aggregates the outcome of a bootstrap operation.
type BootstrapResult struct {
	// TenantID is the tenant that was bootstrapped.
	TenantID uuid.UUID

	// RelationshipsWritten is the number of SpiceDB relationships successfully
	// written during the operation.
	RelationshipsWritten int

	// LastZedToken is the ZedToken returned by the final successful write.
	// Callers can use this with AtLeastAsFresh consistency to read their own
	// writes immediately after bootstrap completes.
	LastZedToken string

	// Errors contains any per-relationship write failures that were collected
	// without aborting the overall bootstrap. An empty slice means full success.
	Errors []error
}

// NewTenantBootstrapService creates a TenantBootstrapService backed by the given
// SpiceDB client. The client must be non-nil; passing nil will cause every method
// to return an error at call time.
func NewTenantBootstrapService(client *spicedb.Client) *TenantBootstrapService {
	return &TenantBootstrapService{
		client: client,
	}
}

// BootstrapTenant seeds all default SpiceDB relationships required for a newly
// created tenant. It writes both the "admin" and "member" relationships for the
// founding admin user so that permission checks succeed immediately after tenant
// creation.
//
// The method is intentionally resilient: individual write failures are appended to
// BootstrapResult.Errors without aborting the remaining writes. Callers should
// inspect the Errors slice and alert or schedule a retry when it is non-empty.
func (s *TenantBootstrapService) BootstrapTenant(
	ctx context.Context,
	tenantID uuid.UUID,
	adminUserID uuid.UUID,
) (*BootstrapResult, error) {
	if s.client == nil {
		return nil, fmt.Errorf("BootstrapTenant: SpiceDB client not initialized")
	}

	result := &BootstrapResult{TenantID: tenantID}

	logger.Log.Info("Bootstrapping new tenant in SpiceDB",
		zap.String("tenant_id", tenantID.String()),
		zap.String("admin_user_id", adminUserID.String()),
	)

	// Step 1: write the admin relationship.
	adminToken, err := s.client.WriteUserTenant(ctx, tenantID, adminUserID, "admin")
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("write admin relationship: %w", err))
		logger.Log.Error("Failed to write tenant admin relationship",
			zap.String("tenant_id", tenantID.String()),
			zap.String("admin_user_id", adminUserID.String()),
			zap.Error(err),
		)
	} else {
		result.RelationshipsWritten++
		result.LastZedToken = adminToken
		logger.Log.Info("Wrote tenant admin relationship",
			zap.String("tenant_id", tenantID.String()),
			zap.String("admin_user_id", adminUserID.String()),
			zap.Bool("has_zed_token", adminToken != ""),
		)
	}

	// Step 2: write the member relationship.
	memberToken, err := s.client.WriteUserTenant(ctx, tenantID, adminUserID, "member")
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("write member relationship: %w", err))
		logger.Log.Error("Failed to write tenant member relationship",
			zap.String("tenant_id", tenantID.String()),
			zap.String("admin_user_id", adminUserID.String()),
			zap.Error(err),
		)
	} else {
		result.RelationshipsWritten++
		result.LastZedToken = memberToken
		logger.Log.Info("Wrote tenant member relationship",
			zap.String("tenant_id", tenantID.String()),
			zap.String("admin_user_id", adminUserID.String()),
			zap.Bool("has_zed_token", memberToken != ""),
		)
	}

	logger.Log.Info("Tenant bootstrap complete",
		zap.String("tenant_id", tenantID.String()),
		zap.Int("relationships_written", result.RelationshipsWritten),
		zap.Int("errors", len(result.Errors)),
		zap.Bool("has_zed_token", result.LastZedToken != ""),
	)

	return result, nil
}

// BootstrapUserMembership writes the SpiceDB relationships required when a user
// joins an existing tenant. A "member" relationship is always written; when
// isAdmin is true an "admin" relationship is written in addition.
//
// The returned ZedToken belongs to the last successful write. Callers should store
// it and pass it to subsequent permission checks via AtLeastAsFresh consistency so
// that the checks see the newly written relationships immediately.
func (s *TenantBootstrapService) BootstrapUserMembership(
	ctx context.Context,
	tenantID uuid.UUID,
	userID uuid.UUID,
	isAdmin bool,
) (string, error) {
	if s.client == nil {
		return "", fmt.Errorf("BootstrapUserMembership: SpiceDB client not initialized")
	}

	logger.Log.Info("Bootstrapping user membership in SpiceDB",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.Bool("is_admin", isAdmin),
	)

	memberToken, err := s.client.WriteUserTenant(ctx, tenantID, userID, "member")
	if err != nil {
		return "", fmt.Errorf("BootstrapUserMembership: write member relationship: %w", err)
	}

	logger.Log.Info("Wrote user member relationship",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.Bool("has_zed_token", memberToken != ""),
	)

	lastToken := memberToken

	if isAdmin {
		adminToken, err := s.client.WriteUserTenant(ctx, tenantID, userID, "admin")
		if err != nil {
			return "", fmt.Errorf("BootstrapUserMembership: write admin relationship: %w", err)
		}

		lastToken = adminToken

		logger.Log.Info("Wrote user admin relationship",
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.Bool("has_zed_token", adminToken != ""),
		)
	}

	return lastToken, nil
}

// BootstrapRolePermissions seeds SpiceDB "granted_to_role" relationships for
// every permission name in the permissions slice. Each permission is modelled as
// an access_grant object whose "granted_to_role" subject is the role, matching
// the example_complete.zed schema: WriteRolePermission(ctx, tenantID, roleID,
// "access_grant", permName, "granted_to_role").
//
// Failures are collected into BootstrapResult.Errors so that a single transient
// error does not prevent the remaining permissions from being written. The
// RelationshipsWritten field reflects only the successfully written relationships.
func (s *TenantBootstrapService) BootstrapRolePermissions(
	ctx context.Context,
	tenantID uuid.UUID,
	roleID uuid.UUID,
	permissions []string,
) (*BootstrapResult, error) {
	if s.client == nil {
		return nil, fmt.Errorf("BootstrapRolePermissions: SpiceDB client not initialized")
	}

	result := &BootstrapResult{TenantID: tenantID}

	logger.Log.Info("Bootstrapping role permissions in SpiceDB",
		zap.String("tenant_id", tenantID.String()),
		zap.String("role_id", roleID.String()),
		zap.Int("permission_count", len(permissions)),
	)

	for _, permName := range permissions {
		spicedbPermID := spicedb.PermissionToSpiceDBID(permName)
		token, err := s.client.WriteRolePermission(ctx, tenantID, roleID, "access_grant", spicedbPermID, "granted_to_role")
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("write permission %q: %w", permName, err))
			logger.Log.Error("Failed to write role permission relationship",
				zap.String("tenant_id", tenantID.String()),
				zap.String("role_id", roleID.String()),
				zap.String("permission", permName),
				zap.Error(err),
			)
			continue
		}

		result.RelationshipsWritten++
		result.LastZedToken = token

		logger.Log.Info("Wrote role permission relationship",
			zap.String("tenant_id", tenantID.String()),
			zap.String("role_id", roleID.String()),
			zap.String("permission", permName),
			zap.Bool("has_zed_token", token != ""),
		)
	}

	logger.Log.Info("Role permissions bootstrap complete",
		zap.String("tenant_id", tenantID.String()),
		zap.String("role_id", roleID.String()),
		zap.Int("relationships_written", result.RelationshipsWritten),
		zap.Int("errors", len(result.Errors)),
	)

	return result, nil
}

// BootstrapUserRole assigns a role to a user in SpiceDB by writing the user-role
// "member" relationship. The returned ZedToken can be used to ensure subsequent
// permission checks are performed against a replica that has already applied this
// write (AtLeastAsFresh consistency).
func (s *TenantBootstrapService) BootstrapUserRole(
	ctx context.Context,
	tenantID uuid.UUID,
	userID uuid.UUID,
	roleID uuid.UUID,
) (string, error) {
	if s.client == nil {
		return "", fmt.Errorf("BootstrapUserRole: SpiceDB client not initialized")
	}

	logger.Log.Info("Bootstrapping user role assignment in SpiceDB",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.String("role_id", roleID.String()),
	)

	token, err := s.client.WriteUserRole(ctx, tenantID, userID, roleID)
	if err != nil {
		return "", fmt.Errorf("BootstrapUserRole: %w", err)
	}

	logger.Log.Info("Wrote user role assignment",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.String("role_id", roleID.String()),
		zap.Bool("has_zed_token", token != ""),
	)

	return token, nil
}

// SyncUserRoles makes one user's tenant-scoped SpiceDB role memberships match
// PostgreSQL exactly. Removals run before additions so a partial failure cannot
// broaden access beyond the database authority.
func (s *TenantBootstrapService) SyncUserRoles(
	ctx context.Context,
	tenantID uuid.UUID,
	userID uuid.UUID,
	roleIDs []uuid.UUID,
) error {
	if s.client == nil {
		return fmt.Errorf("SyncUserRoles: SpiceDB client not initialized")
	}

	desired := make(map[string]uuid.UUID, len(roleIDs))
	for _, roleID := range roleIDs {
		desired[roleID.String()] = roleID
	}
	actual, err := s.client.LookupUserRoles(ctx, tenantID, userID)
	if err != nil {
		return fmt.Errorf("SyncUserRoles: lookup: %w", err)
	}
	actualSet := make(map[string]struct{}, len(actual))
	var syncErrors []error
	for _, role := range actual {
		actualSet[role] = struct{}{}
		if _, keep := desired[role]; keep {
			continue
		}
		roleID, parseErr := uuid.Parse(role)
		if parseErr != nil {
			syncErrors = append(syncErrors, fmt.Errorf("invalid SpiceDB role id %q: %w", role, parseErr))
			continue
		}
		if _, deleteErr := s.client.DeleteUserRole(ctx, tenantID, userID, roleID); deleteErr != nil {
			syncErrors = append(syncErrors, fmt.Errorf("delete role %s: %w", roleID, deleteErr))
		}
	}
	for role, roleID := range desired {
		if _, exists := actualSet[role]; exists {
			continue
		}
		if _, writeErr := s.client.WriteUserRole(ctx, tenantID, userID, roleID); writeErr != nil {
			syncErrors = append(syncErrors, fmt.Errorf("write role %s: %w", roleID, writeErr))
		}
	}
	return errors.Join(syncErrors...)
}

// SyncUserAccess converges both tenant membership and exact role membership.
// Deactivation removes every authorization edge; reactivation restores only
// the relationships represented by the current PostgreSQL state.
func (s *TenantBootstrapService) SyncUserAccess(
	ctx context.Context,
	tenantID uuid.UUID,
	userID uuid.UUID,
	active bool,
	isAdmin bool,
	roleIDs []uuid.UUID,
) error {
	if s.client == nil {
		return fmt.Errorf("SyncUserAccess: SpiceDB client not initialized")
	}
	if !active {
		roleIDs = nil
	}
	if err := s.SyncUserRoles(ctx, tenantID, userID, roleIDs); err != nil {
		return fmt.Errorf("SyncUserAccess: roles: %w", err)
	}
	relation := ""
	if active {
		relation = "member"
		if isAdmin {
			relation = "admin"
		}
	}
	if _, err := s.client.ReplaceUserTenant(ctx, tenantID, userID, relation); err != nil {
		return fmt.Errorf("SyncUserAccess: tenant membership: %w", err)
	}
	return nil
}
