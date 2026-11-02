// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// checkCaveatContext is the ONLY source of check-time caveat context. It
// supplies `now` (server UTC, RFC3339 - the form WritePlatformElevation /
// SyncEntitledModule use for expires_at) so the time-bound caveats
// (active_elevation, entitlement_window) can be decided. It takes no input
// on purpose: callers, and therefore clients, can neither supply nor override
// `now`. Any other context a caveat needs stays missing, which SpiceDB
// reports as CONDITIONAL and falcon-id treats as deny (fail-closed).
//
// Every permission request must be built through newCheckRequest /
// newCheckBulkItem / newLookupResourcesRequest so no call site can forget it.
func checkCaveatContext() *structpb.Struct {
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		"now": structpb.NewStringValue(time.Now().UTC().Format(time.RFC3339)),
	}}
}

// newCheckRequest builds a CheckPermissionRequest with the check-time caveat
// context attached.
func (c *Client) newCheckRequest(consistency *v1.Consistency, resource, subject *v1.ObjectReference, permission string) *v1.CheckPermissionRequest {
	return &v1.CheckPermissionRequest{
		Resource:    resource,
		Permission:  permission,
		Subject:     &v1.SubjectReference{Object: subject},
		Consistency: consistency,
		Context:     checkCaveatContext(),
	}
}

// newCheckBulkItem builds one CheckBulkPermissions item with the check-time
// caveat context attached.
func (c *Client) newCheckBulkItem(resource, subject *v1.ObjectReference, permission string) *v1.CheckBulkPermissionsRequestItem {
	return &v1.CheckBulkPermissionsRequestItem{
		Resource:   resource,
		Permission: permission,
		Subject:    &v1.SubjectReference{Object: subject},
		Context:    checkCaveatContext(),
	}
}

// newLookupResourcesRequest builds a LookupResourcesRequest with the
// check-time caveat context attached.
func (c *Client) newLookupResourcesRequest(consistency *v1.Consistency, resourceType, permission string, subject *v1.ObjectReference) *v1.LookupResourcesRequest {
	return &v1.LookupResourcesRequest{
		ResourceObjectType: resourceType,
		Permission:         permission,
		Subject:            &v1.SubjectReference{Object: subject},
		Consistency:        consistency,
		Context:            checkCaveatContext(),
	}
}
