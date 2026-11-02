// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"testing"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// R2 WP-02: company/branch definitions and the approval_limit /
// record_not_locked caveats on the pre-accounting finance resources.
// Named TestAuthzReasons_* so hack/run-authz-reasons-tests.sh picks them up.

type preaccTuple struct {
	resType, resID, relation string
	subType, subID, subRel   string
	caveat                   string
	caveatCtx                map[string]any
}

func preaccWrite(t *testing.T, c *Client, tuples ...preaccTuple) {
	t.Helper()
	var ups []*v1.RelationshipUpdate
	for _, tp := range tuples {
		rel := &v1.Relationship{
			Resource: &v1.ObjectReference{ObjectType: tp.resType, ObjectId: tp.resID},
			Relation: tp.relation,
			Subject: &v1.SubjectReference{
				Object:           &v1.ObjectReference{ObjectType: tp.subType, ObjectId: tp.subID},
				OptionalRelation: tp.subRel,
			},
		}
		if tp.caveat != "" {
			cc := &v1.ContextualizedCaveat{CaveatName: tp.caveat}
			if tp.caveatCtx != nil {
				st, err := structpb.NewStruct(tp.caveatCtx)
				require.NoError(t, err)
				cc.Context = st
			}
			rel.OptionalCaveat = cc
		}
		ups = append(ups, &v1.RelationshipUpdate{Operation: v1.RelationshipUpdate_OPERATION_TOUCH, Relationship: rel})
	}
	_, err := c.AuthzedClient().WriteRelationships(context.Background(), &v1.WriteRelationshipsRequest{Updates: ups})
	require.NoError(t, err)
}

// preaccCheck returns (allowed, conditional, missingContext).
func preaccCheck(t *testing.T, c *Client, resType, resID, perm, user string, ctx map[string]any) (bool, bool, []string) {
	t.Helper()
	req := &v1.CheckPermissionRequest{
		Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		Resource:    &v1.ObjectReference{ObjectType: resType, ObjectId: resID},
		Permission:  perm,
		Subject:     &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: "user", ObjectId: user}},
	}
	if ctx != nil {
		st, err := structpb.NewStruct(ctx)
		require.NoError(t, err)
		req.Context = st
	}
	resp, err := c.AuthzedClient().CheckPermission(context.Background(), req)
	require.NoError(t, err)
	var missing []string
	if resp.PartialCaveatInfo != nil {
		// SpiceDB may repeat a name (one entry per evaluated path): dedupe.
		seen := map[string]bool{}
		for _, m := range resp.PartialCaveatInfo.MissingRequiredContext {
			if !seen[m] {
				seen[m] = true
				missing = append(missing, m)
			}
		}
	}
	return resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION,
		resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_CONDITIONAL_PERMISSION,
		missing
}

func TestAuthzReasons_CompanyBranch(t *testing.T) {
	c := newAuthzReasonsClient(t)
	preaccWrite(t, c,
		preaccTuple{resType: "tenant", resID: "ta", relation: "owner", subType: "user", subID: "t-owner"},
		preaccTuple{resType: "tenant", resID: "ta", relation: "admin", subType: "user", subID: "t-admin"},
		preaccTuple{resType: "company", resID: "ta/c1", relation: "tenant", subType: "tenant", subID: "ta"},
		preaccTuple{resType: "company", resID: "ta/c1", relation: "admin", subType: "user", subID: "c-admin"},
		preaccTuple{resType: "company", resID: "ta/c1", relation: "member", subType: "user", subID: "c-member"},
		preaccTuple{resType: "company", resID: "ta/c1", relation: "guest", subType: "user", subID: "c-guest"},
		preaccTuple{resType: "branch", resID: "ta/b1", relation: "company", subType: "company", subID: "ta/c1"},
		// a different tenant's company: no path from ta users
		preaccTuple{resType: "tenant", resID: "tb", relation: "owner", subType: "user", subID: "tb-owner"},
		preaccTuple{resType: "company", resID: "tb/c1", relation: "tenant", subType: "tenant", subID: "tb"},
	)
	cases := []struct {
		res, id, perm, user string
		want                bool
	}{
		{"company", "ta/c1", "manage", "t-owner", true}, // via tenant->owner
		{"company", "ta/c1", "view", "t-owner", true},
		{"company", "ta/c1", "manage", "c-admin", true},
		{"company", "ta/c1", "view", "c-member", true},
		{"company", "ta/c1", "manage", "c-member", false},
		{"company", "ta/c1", "view", "c-guest", true},
		{"company", "ta/c1", "manage", "c-guest", false},
		{"company", "ta/c1", "view", "t-admin", true}, // reference reads inherit tenant->view; management remains owner-only
		{"company", "ta/c1", "manage", "t-admin", false},
		{"company", "ta/c1", "view", "nobody", false},
		{"company", "ta/c1", "view", "tb-owner", false}, // cross-tenant
		{"company", "tb/c1", "view", "t-owner", false},  // cross-tenant
		{"branch", "ta/b1", "view", "c-guest", true},
		{"branch", "ta/b1", "manage", "c-guest", false},
		{"branch", "ta/b1", "manage", "c-admin", true},
		{"branch", "ta/b1", "view", "tb-owner", false},
	}
	for _, tc := range cases {
		ok, cond, _ := preaccCheck(t, c, tc.res, tc.id, tc.perm, tc.user, nil)
		assert.False(t, cond, "%s:%s#%s %s", tc.res, tc.id, tc.perm, tc.user)
		assert.Equal(t, tc.want, ok, "%s:%s#%s %s", tc.res, tc.id, tc.perm, tc.user)
	}
}

func TestAuthzReasons_ApprovalLimitCaveat(t *testing.T) {
	c := newAuthzReasonsClient(t)
	for _, res := range []string{"invoice", "payment", "bill", "expense_report"} {
		t.Run(res, func(t *testing.T) {
			id := "ta/" + res + "-1"
			preaccWrite(t, c,
				preaccTuple{resType: res, resID: id, relation: "tenant", subType: "tenant", subID: "ta"},
				preaccTuple{resType: res, resID: id, relation: "approver", subType: "user", subID: "limited",
					caveat: "approval_limit"},
				// legacy uncaveated approver tuple: existing writers must keep working
				preaccTuple{resType: res, resID: id, relation: "approver", subType: "user", subID: "legacy"},
			)
			limit := func(amount float64, cur string) map[string]any {
				return map[string]any{"amount": amount, "currency": cur, "limit_amount": 50000.0, "limit_currency": "TRY"}
			}
			ok, cond, _ := preaccCheck(t, c, res, id, "approve", "limited", limit(49999.99, "TRY"))
			assert.True(t, ok, "below limit")
			assert.False(t, cond)

			ok, _, _ = preaccCheck(t, c, res, id, "approve", "limited", limit(50000.00, "TRY"))
			assert.True(t, ok, "exactly at limit passes")

			ok, cond, _ = preaccCheck(t, c, res, id, "approve", "limited", limit(50000.01, "TRY"))
			assert.False(t, ok, "limit+0.01 fails")
			assert.False(t, cond, "false, not conditional")

			ok, cond, _ = preaccCheck(t, c, res, id, "approve", "limited", limit(1.0, "USD"))
			assert.False(t, ok, "currency mismatch fails closed")
			assert.False(t, cond)

			// missing context: never allowed, reported conditional with the missing params
			ok, cond, missing := preaccCheck(t, c, res, id, "approve", "limited", nil)
			assert.False(t, ok)
			assert.True(t, cond)
			// CEL short-circuits, so only the first undecidable terms are reported.
			assert.NotEmpty(t, missing)
			assert.Subset(t, []string{"amount", "currency", "limit_amount", "limit_currency"}, missing)

			ok, cond, missing = preaccCheck(t, c, res, id, "approve", "limited",
				map[string]any{"amount": 1.0, "currency": "TRY", "limit_currency": "TRY"})
			assert.False(t, ok)
			assert.True(t, cond)
			assert.Equal(t, []string{"limit_amount"}, missing)

			// non-approver and other tenant
			ok, _, _ = preaccCheck(t, c, res, id, "approve", "stranger", limit(1.0, "TRY"))
			assert.False(t, ok)

			// backward compat: uncaveated approver tuples still resolve with no context
			ok, cond, _ = preaccCheck(t, c, res, id, "approve", "legacy", nil)
			assert.True(t, ok)
			assert.False(t, cond)
		})
	}
}

func TestAuthzReasons_RecordNotLockedCaveat(t *testing.T) {
	c := newAuthzReasonsClient(t)
	for _, res := range []string{"invoice", "payment", "bill", "expense_report"} {
		t.Run(res, func(t *testing.T) {
			open := "ta/" + res + "-open"
			noGate := "ta/" + res + "-nogate"
			creator := "owner"
			creatorRel := "creator"
			if res == "expense_report" {
				creatorRel = "owner"
			}
			for _, id := range []string{open, noGate} {
				preaccWrite(t, c,
					preaccTuple{resType: res, resID: id, relation: "tenant", subType: "tenant", subID: "ta"},
					preaccTuple{resType: res, resID: id, relation: creatorRel, subType: "user", subID: creator},
					preaccTuple{resType: res, resID: id, relation: "approver", subType: "user", subID: "appr"},
				)
			}
			preaccWrite(t, c, preaccTuple{resType: res, resID: open, relation: "record_open",
				subType: "user", subID: "*", caveat: "record_not_locked"})

			status := func(s string) map[string]any { return map[string]any{"record_status": s} }
			for _, perm := range []string{"edit_unlocked"} {
				ok, cond, _ := preaccCheck(t, c, res, open, perm, creator, status("draft"))
				assert.True(t, ok, perm+" draft")
				assert.False(t, cond)
				ok, _, _ = preaccCheck(t, c, res, open, perm, creator, status("posted"))
				assert.False(t, ok, perm+" posted")
				ok, _, _ = preaccCheck(t, c, res, open, perm, creator, status("locked"))
				assert.False(t, ok, perm+" locked")
				ok, cond, missing := preaccCheck(t, c, res, open, perm, creator, nil)
				assert.False(t, ok, perm+" missing context")
				assert.True(t, cond)
				assert.Equal(t, []string{"record_status"}, missing)
				// no gate tuple: fail closed even for a draft
				ok, _, _ = preaccCheck(t, c, res, noGate, perm, creator, status("draft"))
				assert.False(t, ok, perm+" without record_open tuple")
				// the relation grant itself is still required
				ok, _, _ = preaccCheck(t, c, res, open, perm, "stranger", status("draft"))
				assert.False(t, ok, perm+" stranger")
			}
			ok, _, _ := preaccCheck(t, c, res, open, "approve_unlocked", "appr", status("draft"))
			assert.True(t, ok, "approve_unlocked draft")
			ok, _, _ = preaccCheck(t, c, res, open, "approve_unlocked", "appr", status("posted"))
			assert.False(t, ok, "approve_unlocked posted")
			ok, _, _ = preaccCheck(t, c, res, open, "approve_unlocked", "creator-only", status("draft"))
			assert.False(t, ok, "approve_unlocked non-approver")

			// existing permissions are untouched by the lock gate
			ok, cond, _ := preaccCheck(t, c, res, noGate, "edit", creator, nil)
			assert.True(t, ok, "legacy edit unaffected")
			assert.False(t, cond)
			ok, _, _ = preaccCheck(t, c, res, open, "approve", "appr", status("posted"))
			assert.True(t, ok, "legacy approve unaffected by lock status")
		})
	}
}
