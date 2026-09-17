// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"errors"
	"testing"

	"github.com/dogukanturhal/falcon-id/pkg/falconcli/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestWhoamiCmd_TableOutput(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	whoamiResp := &client.WhoamiResponse{
		ID:         "user-abc",
		Email:      "admin@example.com",
		Username:   "admin",
		TenantID:   "tenant-123",
		TenantSlug: "exampletenant",
		Roles:      []string{"super-admin", "user"},
	}
	mockClient.On("Whoami", mock.Anything).Return(whoamiResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"whoami"})
	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "user-abc")
	assert.Contains(t, output, "admin@example.com")
	assert.Contains(t, output, "admin")
	assert.Contains(t, output, "tenant-123")
	assert.Contains(t, output, "exampletenant")
	assert.Contains(t, output, "super-admin")

	mockClient.AssertExpectations(t)
}

func TestWhoamiCmd_Error(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("Whoami", mock.Anything).Return(nil, errors.New("unauthorized"))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"whoami"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized")

	mockClient.AssertExpectations(t)
}

func TestWhoamiCmd_EmptyRoles(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	whoamiResp := &client.WhoamiResponse{
		ID:       "user-1",
		Email:    "user@test.com",
		Username: "testuser",
		Roles:    []string{},
	}
	mockClient.On("Whoami", mock.Anything).Return(whoamiResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"whoami"})
	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "testuser")
}
