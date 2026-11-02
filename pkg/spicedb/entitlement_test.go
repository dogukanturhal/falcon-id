// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"testing"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntitledModuleObjectID_TenantScopedLowercase(t *testing.T) {
	tid := uuid.New()
	assert.Equal(t, tid.String()+"/crm", EntitledModuleObjectID(tid, "CRM"))
}

func TestSpiceDBIDSafe(t *testing.T) {
	for _, ok := range []string{"crm", "marketing", "bundle-pro", "mm_2"} {
		assert.True(t, spicedbIDSafe.MatchString(ok), ok)
	}
	for _, bad := range []string{"", "a b", "a:b", "*", "crm.view"} {
		assert.False(t, spicedbIDSafe.MatchString(bad), bad)
	}
}

func TestRoleAssignmentUpdates_ThreeTuplesOnOneObject(t *testing.T) {
	c := &Client{}
	tid, uid := uuid.New(), uuid.New()
	ups := c.roleAssignmentUpdates(v1.RelationshipUpdate_OPERATION_TOUCH, tid, uid, "CRM")
	require.Len(t, ups, 3)
	wantObj := tid.String() + "/crm/" + uid.String()
	got := map[string]string{}
	for _, u := range ups {
		r := u.Relationship
		assert.Equal(t, "role_assignment", r.Resource.ObjectType)
		assert.Equal(t, wantObj, r.Resource.ObjectId)
		assert.Equal(t, v1.RelationshipUpdate_OPERATION_TOUCH, u.Operation)
		got[r.Relation] = r.Subject.Object.ObjectType + ":" + r.Subject.Object.ObjectId
	}
	assert.Equal(t, "tenant:"+tid.String(), got["tenant"])
	assert.Equal(t, "module:"+tid.String()+"/crm", got["module"])
	assert.Equal(t, "user:"+tid.String()+"/"+uid.String(), got["assigned"])
}
