// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// Entitlement and role-assignment SpiceDB writes (spec 23 section 4.2).
//
//	tenant:<T>#entitled_module@module:<T>/<module_code>           (no end date)
//	tenant:<T>#entitled_module@module:<T>/<module_code>[entitlement_window]
//	role_assignment:<T>/<module_code>/<user>#{tenant,module,assigned}
//
// entitled_module follows iam_tenant_module_entitlements: active, trialing and
// grace write the tuple (with the entitlement_window caveat when the row has
// an end date, so a lapsed entitlement fails closed even before the next
// sync); expired deletes it. Writes use TOUCH, so repeating one is idempotent
// and a changed end date replaces the previous caveat context.
const (
	spicedbObjectTypeModule         = "module"
	spicedbObjectTypeRoleAssignment = "role_assignment"
	spicedbEntitlementWindowCaveat  = "entitlement_window"
)

// spicedbIDSafe is SpiceDB's object-id alphabet minus the wildcard form.
var spicedbIDSafe = regexp.MustCompile(`^[a-zA-Z0-9/_|\-=+]{1,127}$`)

// EntitledModuleObjectID is the module object id used on the tenant's
// entitled_module relation (tenant-scoped like every other tenant object).
func EntitledModuleObjectID(tenantID uuid.UUID, moduleCode string) string {
	return fmt.Sprintf("%s/%s", tenantID, strings.ToLower(moduleCode))
}

// SyncEntitledModule makes the tenant's entitled_module tuple for moduleCode
// match the entitlement state: entitled=true touches it (caveated with
// expiresAt when non-nil), entitled=false deletes it. Safe to repeat.
func (c *Client) SyncEntitledModule(ctx context.Context, tenantID uuid.UUID, moduleCode string, entitled bool, expiresAt *time.Time) error {
	code := strings.ToLower(moduleCode)
	if !spicedbIDSafe.MatchString(code) {
		// A code SpiceDB cannot represent can never have a tuple, so there is
		// nothing to sync; retrying would not help.
		logger.Warn("entitled_module sync skipped: module code is not a valid SpiceDB id",
			zap.String("tenant_id", tenantID.String()), zap.String("module_code", moduleCode))
		return nil
	}

	rel := &v1.Relationship{
		Resource: &v1.ObjectReference{ObjectType: spicedbObjectTypeTenant, ObjectId: tenantID.String()},
		Relation: "entitled_module",
		Subject: &v1.SubjectReference{Object: &v1.ObjectReference{
			ObjectType: spicedbObjectTypeModule, ObjectId: EntitledModuleObjectID(tenantID, code),
		}},
	}
	op, opName := v1.RelationshipUpdate_OPERATION_DELETE, "delete"
	if entitled {
		op, opName = v1.RelationshipUpdate_OPERATION_TOUCH, "touch"
		if expiresAt != nil {
			caveatCtx, err := structpb.NewStruct(map[string]interface{}{
				"expires_at": expiresAt.UTC().Format(time.RFC3339),
			})
			if err != nil {
				return fmt.Errorf("build entitlement_window caveat context: %w", err)
			}
			rel.OptionalCaveat = &v1.ContextualizedCaveat{CaveatName: spicedbEntitlementWindowCaveat, Context: caveatCtx}
		}
	}

	startTime := time.Now()
	if _, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{{Operation: op, Relationship: rel}},
	}); err != nil {
		RecordError("sync_entitled_module", "grpc_error")
		return fmt.Errorf("sync entitled_module %s (%s): %w", code, opName, err)
	}
	RecordRelationshipWrite(tenantID, spicedbObjectTypeTenant, "entitled_module", opName, time.Since(startTime))
	c.invalidateRoleCache(ctx, tenantID, uuid.Nil)
	return nil
}

// roleAssignmentUpdates builds the three tuples that make up one
// role_assignment object (user x module inside a tenant).
func (c *Client) roleAssignmentUpdates(op v1.RelationshipUpdate_Operation, tenantID, userID uuid.UUID, moduleCode string) []*v1.RelationshipUpdate {
	obj := &v1.ObjectReference{
		ObjectType: spicedbObjectTypeRoleAssignment,
		ObjectId:   fmt.Sprintf("%s/%s/%s", tenantID, strings.ToLower(moduleCode), userID),
	}
	mk := func(relation string, subj *v1.ObjectReference) *v1.RelationshipUpdate {
		return &v1.RelationshipUpdate{Operation: op, Relationship: &v1.Relationship{
			Resource: obj, Relation: relation, Subject: &v1.SubjectReference{Object: subj},
		}}
	}
	return []*v1.RelationshipUpdate{
		mk("tenant", &v1.ObjectReference{ObjectType: spicedbObjectTypeTenant, ObjectId: tenantID.String()}),
		mk("module", &v1.ObjectReference{ObjectType: spicedbObjectTypeModule, ObjectId: EntitledModuleObjectID(tenantID, moduleCode)}),
		mk("assigned", &v1.ObjectReference{ObjectType: spicedbObjectTypeUser, ObjectId: c.tenantScopedID(tenantID, userID.String())}),
	}
}

// WriteRoleAssignment records that userID holds a role belonging to moduleCode
// in the tenant (role_assignment#assigned). Idempotent.
func (c *Client) WriteRoleAssignment(ctx context.Context, tenantID, userID uuid.UUID, moduleCode string) error {
	return c.writeRoleAssignment(ctx, v1.RelationshipUpdate_OPERATION_TOUCH, tenantID, userID, moduleCode)
}

// DeleteRoleAssignment removes the role_assignment tuples for user x module.
// The caller must only invoke it when the user no longer holds ANY role of
// that module. Deleting absent tuples is not an error.
func (c *Client) DeleteRoleAssignment(ctx context.Context, tenantID, userID uuid.UUID, moduleCode string) error {
	return c.writeRoleAssignment(ctx, v1.RelationshipUpdate_OPERATION_DELETE, tenantID, userID, moduleCode)
}

func (c *Client) writeRoleAssignment(ctx context.Context, op v1.RelationshipUpdate_Operation, tenantID, userID uuid.UUID, moduleCode string) error {
	if !spicedbIDSafe.MatchString(strings.ToLower(moduleCode)) {
		return nil
	}
	if _, err := c.spicedb.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: c.roleAssignmentUpdates(op, tenantID, userID, moduleCode),
	}); err != nil {
		RecordError("write_role_assignment", "grpc_error")
		return fmt.Errorf("write role_assignment %s: %w", moduleCode, err)
	}
	c.invalidateUserCache(ctx, tenantID, userID)
	return nil
}
