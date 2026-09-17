// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"errors"
	"testing"
	"time"

	"github.com/dogukanturhal/falcon-id/pkg/falconcli/client"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func makeTestRole(id, name string, isSystem bool) client.Role {
	return client.Role{
		ID:          id,
		Name:        name,
		Description: "Role: " + name,
		IsSystem:    isSystem,
		CreatedAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestRolesListCmd_TableOutput(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	roles := []client.Role{
		makeTestRole("r1", "admin", true),
		makeTestRole("r2", "viewer", false),
	}
	listResp := &client.RoleListResponse{
		Roles:      roles,
		Total:      2,
		Page:       1,
		PageSize:   20,
		TotalPages: 1,
	}
	mockClient.On("ListRoles", mock.Anything, mock.Anything).Return(listResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"roles", "list"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "NAME")
	assert.Contains(t, out, "SYSTEM")
	assert.Contains(t, out, "admin")
	assert.Contains(t, out, "viewer")
	assert.Contains(t, out, "yes") // admin is system
	assert.Contains(t, out, "no")  // viewer is not system

	mockClient.AssertExpectations(t)
}

func TestRolesListCmd_WithFlags(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("ListRoles", mock.Anything, &client.ListOptions{Page: 1, PageSize: 5, Search: "admin"}).
		Return(&client.RoleListResponse{}, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"roles", "list", "--page", "1", "--page-size", "5", "--search", "admin"})
	err := cmd.Execute()
	require.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestRolesListCmd_Error(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("ListRoles", mock.Anything, mock.Anything).Return(nil, errors.New("api error"))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"roles", "list"})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestRolesGetCmd_Success(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	role := makeTestRole("r-abc", "superadmin", true)
	resp := &client.RoleResponse{Role: role}
	mockClient.On("GetRole", mock.Anything, "r-abc").Return(resp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"roles", "get", "r-abc"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "r-abc")
	assert.Contains(t, out, "superadmin")
	assert.Contains(t, out, "yes")

	mockClient.AssertExpectations(t)
}

func TestRolesGetCmd_RequiresID(t *testing.T) {
	_, _ = setupTestCmd(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"roles", "get"})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestRolesGetCmd_NotFound(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	apiErr := &client.APIError{StatusCode: 404, Message: "role not found"}
	mockClient.On("GetRole", mock.Anything, "missing").Return(nil, apiErr)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"roles", "get", "missing"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role not found")
}

func TestRolesCmd_Subcommands(t *testing.T) {
	rootCmd := NewRootCmd()
	var rolesCmd *cobra.Command
	for _, sub := range rootCmd.Commands() {
		if sub.Name() == "roles" {
			rolesCmd = sub
			break
		}
	}
	require.NotNil(t, rolesCmd)

	subNames := make([]string, 0)
	for _, sub := range rolesCmd.Commands() {
		subNames = append(subNames, sub.Name())
	}
	assert.Contains(t, subNames, "list")
	assert.Contains(t, subNames, "get")
}
