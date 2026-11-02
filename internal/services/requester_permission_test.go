// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRequesterPermissionRelation(t *testing.T) {
	require.Equal(t, "maintenance_request_creator", requesterPermissionRelation("cmms:maintenance_requests:create_own"))
	require.Equal(t, "maintenance_request_reader", requesterPermissionRelation("cmms:maintenance_requests:read_own"))
	require.Equal(t, "legal_entity_reader", requesterPermissionRelation("core:legal_entities:read"))
	for _, name := range []string{"cmms:work_orders:read", "cmms:maintenance_requests:read", "cmms:maintenance_requests:create", "hr:employees:read"} {
		require.Empty(t, requesterPermissionRelation(name))
	}
}
