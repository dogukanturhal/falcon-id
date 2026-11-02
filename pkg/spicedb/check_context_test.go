// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertNowContext(t *testing.T, ctxStruct interface{ AsMap() map[string]interface{} }) {
	t.Helper()
	require.NotNil(t, ctxStruct)
	m := ctxStruct.AsMap()
	assert.Len(t, m, 1, "now is the only context the server supplies")
	ts, err := time.Parse(time.RFC3339, m["now"].(string))
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), ts, 5*time.Second)
	assert.Equal(t, time.UTC, ts.Location())
}

func TestCheckRequestBuildersAlwaysSupplyNow(t *testing.T) {
	c := &Client{}
	res := &v1.ObjectReference{ObjectType: "access_grant", ObjectId: "t/x"}
	sub := &v1.ObjectReference{ObjectType: "user", ObjectId: "t/u"}

	assertNowContext(t, c.newCheckRequest(nil, res, sub, "check").Context)
	assertNowContext(t, c.newCheckBulkItem(res, sub, "check").Context)
	assertNowContext(t, c.newLookupResourcesRequest(nil, "role", "member", sub).Context)
}
