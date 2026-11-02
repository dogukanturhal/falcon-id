// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"testing"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestApprovalDirectorySpiceDB(t *testing.T) {
	c := newAuthzReasonsClient(t)
	ctx := context.Background()
	tenant, user, run := uuid.NewString(), uuid.NewString(), uuid.NewString()
	subject := tenant + "/" + user
	preaccWrite(t, c,
		preaccTuple{resType: "module", resID: tenant + "/mm", relation: "admin", subType: "user", subID: subject},
		preaccTuple{resType: "payroll_run", resID: tenant + "/" + run, relation: "approver", subType: "user", subID: subject},
		preaccTuple{resType: "payroll_run", resID: tenant + "/" + run, relation: "calculator", subType: "user", subID: subject},
		preaccTuple{resType: "bill", resID: tenant + "/bill", relation: "approver", subType: "user", subID: subject, caveat: "approval_limit"},
	)
	ids, err := c.LookupApprovalSubjects(ctx, "module", tenant+"/mm", "purchase_orders_approve")
	require.NoError(t, err)
	require.Equal(t, []string{subject}, ids)
	ids, err = c.LookupApprovalSubjects(ctx, "module", tenant+"_mm", "purchase_orders_approve")
	require.NoError(t, err)
	require.Empty(t, ids, "underscore IDs are not falcon-id scoped IDs")
	ids, err = c.LookupApprovalSubjects(ctx, "bill", tenant+"/bill", "approve")
	require.NoError(t, err)
	require.Equal(t, []string{subject}, ids, "conditional candidate must not disappear")
	checks := []*v1.CheckBulkPermissionsRequestItem{
		{Resource: &v1.ObjectReference{ObjectType: "module", ObjectId: tenant + "/mm"}, Permission: "purchase_orders_approve"},
		{Resource: &v1.ObjectReference{ObjectType: "payroll_run", ObjectId: tenant + "/" + run}, Permission: "approve_any"},
		{Resource: &v1.ObjectReference{ObjectType: "payroll_run", ObjectId: tenant + "/" + run}, Permission: "approve"},
		{Resource: &v1.ObjectReference{ObjectType: "bill", ObjectId: tenant + "/bill"}, Permission: "approve"},
	}
	allowed, err := c.CheckApprovalPermissions(ctx, tenant, user, checks)
	require.NoError(t, err)
	require.Equal(t, []bool{true, true, false, false}, allowed)
	allowed, err = c.CheckApprovalPermissions(ctx, tenant, uuid.NewString(), checks)
	require.NoError(t, err)
	require.Equal(t, []bool{false, false, false, false}, allowed)
}
