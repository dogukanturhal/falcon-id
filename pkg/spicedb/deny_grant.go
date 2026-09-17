// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// DenyGrant represents an explicit deny override for a user+action pair scoped to a tenant.
//
// A deny_grant relationship overrides any allowed permission: when a deny_grant exists for
// a given (TenantID, UserID, Action) triple, the action is denied regardless of what any
// SpiceDB allow check returns. This implements the "deny wins" semantic on top of SpiceDB's
// positive-grant model.
type DenyGrant struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
	Action   string
}

// DenyGrantWriter is the write-side interface required by WriteDenyGrant and DeleteDenyGrant.
//
// Separating write operations from the read-side DenyGrantChecker interface allows callers to
// supply a narrower dependency and keeps test mocks focused. The concrete *Client implements
// this interface via WriteResourceRelationship and DeleteResourceRelationship.
type DenyGrantWriter interface {
	// WriteRelationship writes (or touches) a single SpiceDB relationship.
	// Returns the ZedToken produced by the write.
	WriteRelationship(ctx context.Context, objectType, objectID, relation, subjectType, subjectID string) (string, error)

	// DeleteRelationship removes a single SpiceDB relationship.
	DeleteRelationship(ctx context.Context, objectType, objectID, relation, subjectType, subjectID string) error
}

// DenyGrantChecker is the read-side interface required by CheckDenyGrant.
//
// It is intentionally minimal: only the single CheckPermission method is needed
// to evaluate whether a deny_grant relationship exists. The concrete *Client
// satisfies this interface. Callers in other packages (e.g. services) that
// already have a SpiceDBChecker-compatible value can pass it directly because
// SpiceDBChecker is a superset of DenyGrantChecker.
type DenyGrantChecker interface {
	// CheckPermission uses minimize-latency consistency to verify whether
	// the subject identified by (tenantID, userID) holds the given permission
	// on the (objectType, objectID) resource.
	CheckPermission(ctx context.Context, tenantID, userID uuid.UUID, objectType, objectID, permission string) (bool, error)
}

// denyGrantObjectID returns the SpiceDB object ID for a deny_grant resource.
//
// Format: {tenantID}_{spicedbSafeAction}
//
// The tenantID prefix scopes the object to a single tenant. The action is
// sanitised through PermissionToSpiceDBID to replace colons with double
// underscores, satisfying the SpiceDB ObjectId regex:
//
//	^(([a-zA-Z0-9/_|\-=+]{1,})|\*)$
//
// Examples:
//
//	tenant "abc", action "crm:contacts:read"  -> "abc_crm__contacts__read"
//	tenant "abc", action "delete"             -> "abc_delete"
func denyGrantObjectID(tenantID uuid.UUID, action string) string {
	return fmt.Sprintf("%s_%s", tenantID.String(), PermissionToSpiceDBID(action))
}

// denyGrantSubjectID returns the SpiceDB subject ID for the denied user.
//
// Format: {tenantID}_{userID}
//
// Using the same tenant-scoped convention as the rest of the SpiceDB subject IDs
// in this package ensures the subject namespace does not collide across tenants.
func denyGrantSubjectID(tenantID, userID uuid.UUID) string {
	return fmt.Sprintf("%s_%s", tenantID.String(), userID.String())
}

// WriteDenyGrant writes a deny_grant relationship to SpiceDB for the given grant.
//
// The relationship encodes:
//
//	deny_grant:{tenantID}_{action}#denied_user@user:{tenantID}_{userID}
//
// Callers MUST store the returned ZedToken and pass it to any subsequent
// CheckDenyGrant call that must read-your-own-write (New Enemy Problem prevention).
//
// Returns the ZedToken from the write operation, or an empty string when the
// writer returns no token (acceptable for some test doubles).
func WriteDenyGrant(ctx context.Context, writer DenyGrantWriter, grant DenyGrant) (string, error) {
	if grant.TenantID == uuid.Nil {
		return "", fmt.Errorf("WriteDenyGrant: tenant ID must not be nil")
	}
	if grant.UserID == uuid.Nil {
		return "", fmt.Errorf("WriteDenyGrant: user ID must not be nil")
	}
	if grant.Action == "" {
		return "", fmt.Errorf("WriteDenyGrant: action must not be empty")
	}

	objectID := denyGrantObjectID(grant.TenantID, grant.Action)
	subjectID := denyGrantSubjectID(grant.TenantID, grant.UserID)

	token, err := writer.WriteRelationship(ctx, "deny_grant", objectID, "denied_user", spicedbObjectTypeUser, subjectID)
	if err != nil {
		return "", fmt.Errorf("WriteDenyGrant: failed to write relationship: %w", err)
	}

	logger.Info("deny_grant relationship written",
		zap.String("tenant_id", grant.TenantID.String()),
		zap.String("user_id", grant.UserID.String()),
		zap.String("action", grant.Action),
		zap.String("object_id", objectID),
		zap.Bool("has_zed_token", token != ""),
	)

	return token, nil
}

// DeleteDenyGrant removes a deny_grant relationship from SpiceDB.
//
// After deletion the user regains any permissions their roles ordinarily grant.
// A non-existent relationship is not treated as an error by SpiceDB's DELETE
// operation, so this call is idempotent.
func DeleteDenyGrant(ctx context.Context, writer DenyGrantWriter, grant DenyGrant) error {
	if grant.TenantID == uuid.Nil {
		return fmt.Errorf("DeleteDenyGrant: tenant ID must not be nil")
	}
	if grant.UserID == uuid.Nil {
		return fmt.Errorf("DeleteDenyGrant: user ID must not be nil")
	}
	if grant.Action == "" {
		return fmt.Errorf("DeleteDenyGrant: action must not be empty")
	}

	objectID := denyGrantObjectID(grant.TenantID, grant.Action)
	subjectID := denyGrantSubjectID(grant.TenantID, grant.UserID)

	if err := writer.DeleteRelationship(ctx, "deny_grant", objectID, "denied_user", spicedbObjectTypeUser, subjectID); err != nil {
		return fmt.Errorf("DeleteDenyGrant: failed to delete relationship: %w", err)
	}

	logger.Info("deny_grant relationship deleted",
		zap.String("tenant_id", grant.TenantID.String()),
		zap.String("user_id", grant.UserID.String()),
		zap.String("action", grant.Action),
		zap.String("object_id", objectID),
	)

	return nil
}

// CheckDenyGrant reports whether an explicit deny exists for the given
// (tenantID, userID, action) triple.
//
// It checks the "check" permission on the deny_grant object type via SpiceDB.
// Callers MUST treat a returned denied=true as an unconditional veto: the action
// must be rejected even when a positive SpiceDB allow check would succeed.
//
// Security contract (fail-closed):
//   - If the SpiceDB checker returns an error, the error is propagated and the
//     caller is expected to deny access (fail-closed). CheckDenyGrant does NOT
//     silently swallow errors because a missed deny is a security regression.
//
// Returns:
//
//	denied=true  — explicit deny exists; the action MUST be blocked
//	denied=false — no deny grant; proceed with normal allow checks
//	err != nil   — SpiceDB unavailable; caller should fail-closed
func CheckDenyGrant(ctx context.Context, checker DenyGrantChecker, tenantID, userID uuid.UUID, action string) (denied bool, err error) {
	if tenantID == uuid.Nil {
		return false, fmt.Errorf("CheckDenyGrant: tenant ID must not be nil")
	}
	if userID == uuid.Nil {
		return false, fmt.Errorf("CheckDenyGrant: user ID must not be nil")
	}
	if action == "" {
		return false, fmt.Errorf("CheckDenyGrant: action must not be empty")
	}

	objectID := denyGrantObjectID(tenantID, action)

	denied, err = checker.CheckPermission(ctx, tenantID, userID, "deny_grant", objectID, "check")
	if err != nil {
		return false, fmt.Errorf("CheckDenyGrant: SpiceDB check failed: %w", err)
	}

	return denied, nil
}
