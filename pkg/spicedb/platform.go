// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

// Platform plane (R1 JIT elevation + break-glass) SpiceDB writes.
//
// Design decision — caveat vs. native relationship expiry: the
// Relationship proto ALSO exposes OptionalExpiresAt (a native
// per-relationship TTL), which would need no caveat context at CHECK
// time. It was rejected here because SpiceDB's relationship-expiration
// feature requires (a) the target relation be declared with an
// `[expiration]` annotation in the schema and (b) the cluster's
// datastore be started with the experimental relationship-expiration
// flag enabled — neither is confirmed on this cluster, and enabling a
// cluster-wide experimental datastore flag is out of scope for a single
// feature's rollout. The active_elevation caveat (see the definition
// added to deploy/helm/spicedb-schema/files/spicedb.zed in this same
// change) needs nothing beyond what's already live: authzed-go v1.8.0
// (already vendored) supports ContextualizedCaveat on writes and
// Context on CheckPermission, so it works today with zero cluster
// reconfiguration. See migration 0016's header for the fuller rationale.

import (
	"context"
	"fmt"
	"strings"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/structpb"

	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	spicedbObjectTypePlatform  = "hxl_platform"
	spicedbPlatformObjectID    = "hexxlock"
	spicedbActiveElevationName = "active_elevation"
)

// PlatformRoleKeyToRelation maps iam_platform_roles.role_key /
// iam_jit_elevations.role_key values 1:1 onto the hxl_platform SpiceDB
// relation names (see the definition's doc comment in spicedb.zed).
var PlatformRoleKeyToRelation = map[string]string{
	"platform_admin":    "admin",
	"platform_support":  "support",
	"platform_billing":  "billing",
	"platform_security": "security",
	"platform_viewer":   "viewer",

	"platform_compliance": "compliance",
	"platform_sre":        "sre",
}

// WritePlatformElevation writes a time-bound hxl_platform relationship for
// a JIT elevation or break-glass grant, with an active_elevation(now,
// expires_at) caveat so the grant stops passing permission checks the
// instant `expiresAt` is reached — independent of whether the auto-revoke
// sweep has already run. roleKey must be a key of PlatformRoleKeyToRelation
// (i.e. never "platform_viewer" — that role is always standing, never
// materialized through this path).
func (c *Client) WritePlatformElevation(ctx context.Context, userID uuid.UUID, roleKey string, expiresAt time.Time) (string, error) {
	startTime := time.Now()

	relation, ok := PlatformRoleKeyToRelation[roleKey]
	if !ok {
		return "", fmt.Errorf("unknown platform role_key %q", roleKey)
	}

	caveatCtx, err := structpb.NewStruct(map[string]interface{}{
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return "", fmt.Errorf("failed to build active_elevation caveat context: %w", err)
	}

	resp, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{
			{
				Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: spicedbObjectTypePlatform,
						ObjectId:   spicedbPlatformObjectID,
					},
					Relation: relation,
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: spicedbObjectTypeUser,
							ObjectId:   userID.String(),
						},
					},
					OptionalCaveat: &v1.ContextualizedCaveat{
						CaveatName: spicedbActiveElevationName,
						Context:    caveatCtx,
					},
				},
			},
		},
	})
	if err != nil {
		RecordError("write_platform_elevation", "grpc_error")
		return "", fmt.Errorf("failed to write hxl_platform relationship: %w", err)
	}

	RecordRelationshipWrite(uuid.Nil, "hxl_platform", relation, "touch", time.Since(startTime))

	// Elevated grants must take effect (and, below, revocations must bite)
	// immediately, not after the check-cache TTL.
	c.invalidateUserAllTenantsCache(ctx, userID)

	token := ""
	if resp != nil && resp.WrittenAt != nil {
		token = resp.WrittenAt.Token
	}

	logger.Info("Platform elevation relationship written to SpiceDB",
		zap.String("user_id", userID.String()),
		zap.String("role_key", roleKey),
		zap.String("relation", relation),
		zap.Time("expires_at", expiresAt),
		zap.Bool("has_zed_token", token != ""),
	)

	return token, nil
}

// DeletePlatformElevation removes a previously-written hxl_platform
// relationship. Called by both the explicit revoke path and the
// auto-revoke sweep; safe to call on an already-deleted relationship
// (SpiceDB DELETE is idempotent — a no-op TOUCH-equivalent for absence).
func (c *Client) DeletePlatformElevation(ctx context.Context, userID uuid.UUID, roleKey string) (string, error) {
	startTime := time.Now()

	relation, ok := PlatformRoleKeyToRelation[roleKey]
	if !ok {
		return "", fmt.Errorf("unknown platform role_key %q", roleKey)
	}

	resp, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{
			{
				Operation: v1.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: spicedbObjectTypePlatform,
						ObjectId:   spicedbPlatformObjectID,
					},
					Relation: relation,
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: spicedbObjectTypeUser,
							ObjectId:   userID.String(),
						},
					},
				},
			},
		},
	})
	if err != nil {
		RecordError("delete_platform_elevation", "grpc_error")
		return "", fmt.Errorf("failed to delete hxl_platform relationship: %w", err)
	}

	RecordRelationshipWrite(uuid.Nil, "hxl_platform", relation, "delete", time.Since(startTime))

	c.invalidateUserAllTenantsCache(ctx, userID)

	token := ""
	if resp != nil && resp.WrittenAt != nil {
		token = resp.WrittenAt.Token
	}

	logger.Info("Platform elevation relationship deleted from SpiceDB",
		zap.String("user_id", userID.String()),
		zap.String("role_key", roleKey),
		zap.Bool("has_zed_token", token != ""),
	)

	return token, nil
}

// OpsPermissions are the operator-console permissions (wire form
// ops:<domain>:<verb>) defined on hxl_platform in spicedb.zed as
// ops_<domain>_<verb>. SpiceDB permission names cannot contain ':'.
var OpsPermissions = []string{
	"ops:tenants:read",
	"ops:tenants:write",
	"ops:tenants:lifecycle",
	"ops:tenants:purge",
	"ops:users:read",
	"ops:users:write",
	"ops:pii:reveal",
	"ops:billing:read",
	"ops:billing:write",
	"ops:billing:refund",
	"ops:payments:config",
	"ops:catalog:write",
	"ops:quota:read",
	"ops:quota:write",
	"ops:quota:plan",
	"ops:quota:reset",
	"ops:edoc:read",
	"ops:edoc:write",
	"ops:flags:read",
	"ops:flags:write",
	"ops:notify:read",
	"ops:notify:write",
	"ops:staff:manage",
	"ops:audit:read",
	"ops:audit:export",
	"ops:system:read",
}

// OpsPermissionZedName maps a wire permission (ops:tenants:read) to its
// SpiceDB permission name (ops_tenants_read).
func OpsPermissionZedName(wire string) string { return strings.ReplaceAll(wire, ":", "_") }

// PlatformOpsPermissions returns, in OpsPermissions order, the operator
// permissions the user currently holds on hxl_platform:hexxlock. Platform
// tuples are written with the raw user id (no tenant-scoped prefix, see
// WritePlatformElevation), so this does not go through the tenant-scoped
// CheckPermission. Fully consistent, uncached: the result is stamped into a
// 5-minute token. Any per-item failure denies that permission (fail-closed).
func (c *Client) PlatformOpsPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	items := make([]*v1.CheckBulkPermissionsRequestItem, len(OpsPermissions))
	for i, wire := range OpsPermissions {
		items[i] = c.newCheckBulkItem(
			&v1.ObjectReference{ObjectType: spicedbObjectTypePlatform, ObjectId: spicedbPlatformObjectID},
			&v1.ObjectReference{ObjectType: spicedbObjectTypeUser, ObjectId: userID.String()},
			OpsPermissionZedName(wire),
		)
	}
	var resp *v1.CheckBulkPermissionsResponse
	err := c.runRead(ctx, func(ctx context.Context) error {
		var e error
		resp, e = c.spicedb.CheckBulkPermissions(ctx, &v1.CheckBulkPermissionsRequest{
			Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
			Items:       items,
		})
		return e
	})
	if err != nil {
		RecordError("platform_ops_permissions", "grpc_error")
		return nil, fmt.Errorf("PlatformOpsPermissions: %w", err)
	}
	granted := make([]string, 0, len(OpsPermissions))
	if resp == nil {
		return granted, nil
	}
	for i, pair := range resp.Pairs {
		if i >= len(OpsPermissions) {
			break
		}
		if item := pair.GetItem(); item != nil && item.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
			granted = append(granted, OpsPermissions[i])
		}
	}
	return granted, nil
}

// WritePlatformStandingRole writes the plain (caveat-free) hxl_platform
// relationship for a standing role. Only platform_viewer is ever standing.
// Idempotent (TOUCH).
func (c *Client) WritePlatformStandingRole(ctx context.Context, userID uuid.UUID, roleKey string) (string, error) {
	if c == nil || c.spicedb == nil {
		return "", nil
	}
	relation, ok := PlatformRoleKeyToRelation[roleKey]
	if !ok {
		return "", fmt.Errorf("unknown platform role_key %q", roleKey)
	}
	resp, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{ObjectType: spicedbObjectTypePlatform, ObjectId: spicedbPlatformObjectID},
				Relation: relation,
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{ObjectType: spicedbObjectTypeUser, ObjectId: userID.String()},
				},
			},
		}},
	})
	if err != nil {
		RecordError("write_platform_standing_role", "grpc_error")
		return "", fmt.Errorf("failed to write standing hxl_platform relationship: %w", err)
	}
	c.invalidateUserAllTenantsCache(ctx, userID)
	if resp != nil && resp.WrittenAt != nil {
		return resp.WrittenAt.Token, nil
	}
	return "", nil
}
