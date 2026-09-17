// SPDX-License-Identifier: AGPL-3.0-or-later

// Package spicedb provides tenant validation for SpiceDB operations.
// This file implements CRITICAL security controls for tenant isolation.
//
// SECURITY (CVE-HEXX-SPICEDB-001): Tenant Isolation Bypass Prevention
// All SpiceDB operations MUST validate that the requesting user belongs to
// the tenant they're attempting to access. This prevents cross-tenant attacks.
package spicedb

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// contextKey is a type for context keys to avoid collisions
type contextKey string

const (
	// ContextKeyAuthenticatedTenantID is the context key for authenticated tenant ID
	// This MUST be set by the auth middleware after JWT validation
	ContextKeyAuthenticatedTenantID contextKey = "authenticated_tenant_id"

	// ContextKeyAuthenticatedUserID is the context key for authenticated user ID
	// This MUST be set by the auth middleware after JWT validation
	ContextKeyAuthenticatedUserID contextKey = "authenticated_user_id"

	// ContextKeyPlatformAdmin indicates if the user is a platform admin
	// Platform admins can bypass tenant validation (exampletenant tenant only)
	ContextKeyPlatformAdmin contextKey = "is_platform_admin"
)

var (
	// ErrTenantMismatch is returned when requested tenant doesn't match authenticated tenant
	ErrTenantMismatch = errors.New("tenant mismatch: access denied")

	// ErrTenantContextMissing is returned when tenant context is not found
	ErrTenantContextMissing = errors.New("tenant context not found")

	// ErrUserContextMissing is returned when user context is not found
	ErrUserContextMissing = errors.New("user context not found")

	// ErrInvalidTenantID is returned when tenant ID is invalid (nil or zero)
	ErrInvalidTenantID = errors.New("invalid tenant ID")

	// ErrInvalidUserID is returned when user ID is invalid (nil or zero)
	ErrInvalidUserID = errors.New("invalid user ID")
)

// ValidateTenantContext validates that the requested tenant ID matches the authenticated tenant.
// This is the CRITICAL security check that prevents cross-tenant access.
//
// SECURITY RULES:
// 1. Platform admins (exampletenant) can access any tenant
// 2. Regular users can ONLY access their own tenant
// 3. Fail-closed: any validation error results in access denial
//
// Returns error if validation fails (access MUST be denied)
func (c *Client) ValidateTenantContext(ctx context.Context, requestedTenantID uuid.UUID) error {
	// CRITICAL: Validate tenant ID is not zero/nil
	if requestedTenantID == uuid.Nil {
		if logger.Log != nil {
			logger.Log.Error("SECURITY: Invalid tenant ID (zero UUID)",
				zap.String("event", "tenant_validation_failed"),
				zap.String("reason", "invalid_tenant_id"),
			)
		}
		return ErrInvalidTenantID
	}

	// Extract authenticated tenant from context (set by auth middleware)
	authenticatedTenantID, ok := ctx.Value(ContextKeyAuthenticatedTenantID).(uuid.UUID)
	if !ok {
		if logger.Log != nil {
			logger.Log.Error("SECURITY: Authenticated tenant context not found",
				zap.String("event", "tenant_validation_failed"),
				zap.String("reason", "missing_context"),
				zap.String("requested_tenant", requestedTenantID.String()),
			)
		}
		return ErrTenantContextMissing
	}

	// CRITICAL: Validate authenticated tenant is not zero/nil
	if authenticatedTenantID == uuid.Nil {
		if logger.Log != nil {
			logger.Log.Error("SECURITY: Authenticated tenant ID is zero UUID",
				zap.String("event", "tenant_validation_failed"),
				zap.String("reason", "invalid_auth_tenant"),
			)
		}
		return ErrInvalidTenantID
	}

	// Check if user is platform admin (can bypass tenant validation)
	isPlatformAdmin, _ := ctx.Value(ContextKeyPlatformAdmin).(bool)
	if isPlatformAdmin {
		if logger.Log != nil {
			logger.Log.Debug("Platform admin accessing resource - tenant validation bypassed",
				zap.String("authenticated_tenant", authenticatedTenantID.String()),
				zap.String("requested_tenant", requestedTenantID.String()),
			)
		}
		return nil
	}

	// CRITICAL: Enforce tenant isolation - must match exactly
	if authenticatedTenantID != requestedTenantID {
		// SECURITY AUDIT LOG: Cross-tenant access attempt detected
		if logger.Log != nil {
			logger.Log.Warn("SECURITY: Cross-tenant access attempt blocked",
				zap.String("event", "cross_tenant_access_blocked"),
				zap.String("authenticated_tenant", authenticatedTenantID.String()),
				zap.String("requested_tenant", requestedTenantID.String()),
				zap.String("violation_type", "tenant_mismatch"),
			)
		}
		return ErrTenantMismatch
	}

	// Validation passed
	return nil
}

// ValidateUserContext validates that the requested user ID matches the authenticated user,
// or that the authenticated user has permission to act on behalf of another user.
//
// SECURITY RULES:
//  1. Platform admins can access any user in any tenant
//  2. Users can always access their own data
//  3. For cross-user access, caller must have appropriate permissions
//     (checked separately via SpiceDB permission check)
//
// Returns error if validation fails (access MUST be denied)
func (c *Client) ValidateUserContext(ctx context.Context, requestedUserID uuid.UUID, allowCrossUser bool) error {
	// CRITICAL: Validate user ID is not zero/nil
	if requestedUserID == uuid.Nil {
		if logger.Log != nil {
			logger.Log.Error("SECURITY: Invalid user ID (zero UUID)",
				zap.String("event", "user_validation_failed"),
				zap.String("reason", "invalid_user_id"),
			)
		}
		return ErrInvalidUserID
	}

	// Extract authenticated user from context
	authenticatedUserID, ok := ctx.Value(ContextKeyAuthenticatedUserID).(uuid.UUID)
	if !ok {
		if logger.Log != nil {
			logger.Log.Error("SECURITY: Authenticated user context not found",
				zap.String("event", "user_validation_failed"),
				zap.String("reason", "missing_context"),
				zap.String("requested_user", requestedUserID.String()),
			)
		}
		return ErrUserContextMissing
	}

	// CRITICAL: Validate authenticated user is not zero/nil
	if authenticatedUserID == uuid.Nil {
		if logger.Log != nil {
			logger.Log.Error("SECURITY: Authenticated user ID is zero UUID",
				zap.String("event", "user_validation_failed"),
				zap.String("reason", "invalid_auth_user"),
			)
		}
		return ErrInvalidUserID
	}

	// Check if user is platform admin (can bypass user validation)
	isPlatformAdmin, _ := ctx.Value(ContextKeyPlatformAdmin).(bool)
	if isPlatformAdmin {
		if logger.Log != nil {
			logger.Log.Debug("Platform admin accessing user - user validation bypassed",
				zap.String("authenticated_user", authenticatedUserID.String()),
				zap.String("requested_user", requestedUserID.String()),
			)
		}
		return nil
	}

	// Same user - always allowed
	if authenticatedUserID == requestedUserID {
		return nil
	}

	// Cross-user access - only allowed if explicitly permitted
	if !allowCrossUser {
		if logger.Log != nil {
			logger.Log.Warn("SECURITY: Cross-user access attempt without permission",
				zap.String("event", "cross_user_access_blocked"),
				zap.String("authenticated_user", authenticatedUserID.String()),
				zap.String("requested_user", requestedUserID.String()),
			)
		}
		return fmt.Errorf("cross-user access not permitted")
	}

	// Cross-user access allowed by caller - caller must perform additional
	// permission checks via SpiceDB (e.g., admin role, specific permission)
	if logger.Log != nil {
		logger.Log.Debug("Cross-user access permitted by caller",
			zap.String("authenticated_user", authenticatedUserID.String()),
			zap.String("requested_user", requestedUserID.String()),
		)
	}
	return nil
}

// SetAuthenticatedTenant adds the authenticated tenant to context.
// This MUST be called by the auth middleware after JWT validation.
func SetAuthenticatedTenant(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, ContextKeyAuthenticatedTenantID, tenantID)
}

// SetAuthenticatedUser adds the authenticated user to context.
// This MUST be called by the auth middleware after JWT validation.
func SetAuthenticatedUser(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, ContextKeyAuthenticatedUserID, userID)
}

// SetPlatformAdmin marks the user as a platform admin in context.
// This MUST be called by the auth middleware for exampletenant users only.
func SetPlatformAdmin(ctx context.Context, isPlatformAdmin bool) context.Context {
	return context.WithValue(ctx, ContextKeyPlatformAdmin, isPlatformAdmin)
}

// GetAuthenticatedTenant retrieves the authenticated tenant from context.
// Returns uuid.Nil if not found.
func GetAuthenticatedTenant(ctx context.Context) uuid.UUID {
	tenantID, ok := ctx.Value(ContextKeyAuthenticatedTenantID).(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return tenantID
}

// GetAuthenticatedUser retrieves the authenticated user from context.
// Returns uuid.Nil if not found.
func GetAuthenticatedUser(ctx context.Context) uuid.UUID {
	userID, ok := ctx.Value(ContextKeyAuthenticatedUserID).(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return userID
}

// IsPlatformAdmin checks if the user is a platform admin from context.
func IsPlatformAdmin(ctx context.Context) bool {
	isPlatformAdmin, ok := ctx.Value(ContextKeyPlatformAdmin).(bool)
	return ok && isPlatformAdmin
}
