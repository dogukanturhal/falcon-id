// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"fmt"
	"io"
	"sort"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
)

// LookupApprovalSubjects bypasses cached/minimize-latency checks. Conditional
// candidates remain eligible for SoD purposes: missing document context must
// never turn a possible second approver into a sole-approver proof.
func (c *Client) LookupApprovalSubjects(ctx context.Context, resourceType, resourceID, permission string) ([]string, error) {
	if c == nil || c.spicedb == nil {
		return nil, fmt.Errorf("authorization directory unavailable")
	}
	stream, err := c.spicedb.LookupSubjects(ctx, &v1.LookupSubjectsRequest{
		Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		Resource:    &v1.ObjectReference{ObjectType: resourceType, ObjectId: resourceID},
		Permission:  permission, SubjectObjectType: "user",
	})
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for {
		row, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		found := row.GetSubject()
		if found == nil {
			return nil, fmt.Errorf("missing subject in authorization directory")
		}
		if found.SubjectObjectId == "*" {
			return nil, fmt.Errorf("wildcard subjects cannot prove complete eligibility")
		}
		if found.Permissionship == v1.LookupPermissionship_LOOKUP_PERMISSIONSHIP_HAS_PERMISSION || found.Permissionship == v1.LookupPermissionship_LOOKUP_PERMISSIONSHIP_CONDITIONAL_PERMISSION {
			ids[found.SubjectObjectId] = true
		} else {
			return nil, fmt.Errorf("unknown lookup permissionship")
		}
		// Exclusions only apply to wildcard results. Refusing wildcards above
		// avoids misinterpreting conditional exclusions or returning a partial set.
		if len(row.GetExcludedSubjects()) != 0 {
			return nil, fmt.Errorf("unsupported subject exclusions")
		}
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result, nil
}

// CheckApprovalPermissions is a fresh, fully consistent batch. Conditional
// permissions do NOT grant access (unlike conservative eligibility lookup).
func (c *Client) CheckApprovalPermissions(ctx context.Context, tenantID, userID string, checks []*v1.CheckBulkPermissionsRequestItem) ([]bool, error) {
	if c == nil || c.spicedb == nil {
		return nil, fmt.Errorf("authorization directory unavailable")
	}
	for _, check := range checks {
		check.Subject = &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: "user", ObjectId: tenantID + "/" + userID}}
	}
	response, err := c.spicedb.CheckBulkPermissions(ctx, &v1.CheckBulkPermissionsRequest{
		Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}}, Items: checks,
	})
	if err != nil {
		return nil, err
	}
	if len(response.Pairs) != len(checks) {
		return nil, fmt.Errorf("incomplete batch response")
	}
	result := make([]bool, len(checks))
	for i, pair := range response.Pairs {
		if pair.GetError() != nil || pair.GetItem() == nil {
			return nil, fmt.Errorf("failed batch item")
		}
		result[i] = pair.GetItem().Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION
	}
	return result, nil
}
