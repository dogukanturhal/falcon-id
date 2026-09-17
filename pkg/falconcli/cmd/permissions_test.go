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

func TestPermissionsListCmd_TableOutput(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	permissions := []client.Permission{
		{ID: "p1", Name: "users:read", Description: "Read users", Resource: "users", Action: "read"},
		{ID: "p2", Name: "users:write", Description: "Write users", Resource: "users", Action: "write"},
	}
	listResp := &client.PermissionListResponse{
		Permissions: permissions,
		Total:       2,
		Page:        1,
		PageSize:    20,
		TotalPages:  1,
	}
	mockClient.On("ListPermissions", mock.Anything, mock.Anything).Return(listResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"permissions", "list"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "NAME")
	assert.Contains(t, out, "RESOURCE")
	assert.Contains(t, out, "ACTION")
	assert.Contains(t, out, "users:read")
	assert.Contains(t, out, "users:write")
	assert.Contains(t, out, "users")
	assert.Contains(t, out, "read")
	assert.Contains(t, out, "write")

	mockClient.AssertExpectations(t)
}

func TestPermissionsListCmd_WithFlags(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("ListPermissions", mock.Anything, &client.ListOptions{Page: 1, PageSize: 50, Search: "users"}).
		Return(&client.PermissionListResponse{}, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"permissions", "list", "--page", "1", "--page-size", "50", "--search", "users"})
	err := cmd.Execute()
	require.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestPermissionsListCmd_Empty(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	mockClient.On("ListPermissions", mock.Anything, mock.Anything).Return(&client.PermissionListResponse{
		Permissions: []client.Permission{},
	}, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"permissions", "list"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	// Headers should still be present
	assert.Contains(t, out, "NAME")
}

func TestPermissionsListCmd_Error(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("ListPermissions", mock.Anything, mock.Anything).Return(nil, errors.New("forbidden"))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"permissions", "list"})
	err := cmd.Execute()
	require.Error(t, err)
}
