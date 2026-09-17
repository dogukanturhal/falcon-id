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

func makeTestUser(id, email, username, status string) client.User {
	return client.User{
		ID:        id,
		Email:     email,
		Username:  username,
		FirstName: "First",
		LastName:  "Last",
		Status:    status,
		CreatedAt: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
	}
}

func TestUsersListCmd_TableOutput(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	users := []client.User{
		makeTestUser("u1", "alice@test.com", "alice", "active"),
		makeTestUser("u2", "bob@test.com", "bob", "inactive"),
	}
	listResp := &client.UserListResponse{
		Users:      users,
		Total:      2,
		Page:       1,
		PageSize:   20,
		TotalPages: 1,
	}
	mockClient.On("ListUsers", mock.Anything, mock.Anything).Return(listResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"users", "list"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "EMAIL")
	assert.Contains(t, out, "USERNAME")
	assert.Contains(t, out, "alice@test.com")
	assert.Contains(t, out, "bob@test.com")
	assert.Contains(t, out, "2025-01-15")

	mockClient.AssertExpectations(t)
}

func TestUsersListCmd_WithFlags(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("ListUsers", mock.Anything, &client.ListOptions{Page: 2, PageSize: 10, Search: "alice"}).
		Return(&client.UserListResponse{}, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"users", "list", "--page", "2", "--page-size", "10", "--search", "alice"})
	err := cmd.Execute()
	require.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestUsersListCmd_Error(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("ListUsers", mock.Anything, mock.Anything).Return(nil, errors.New("server error"))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"users", "list"})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestUsersGetCmd_Success(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	user := makeTestUser("user-abc", "charlie@test.com", "charlie", "active")
	resp := &client.UserResponse{User: user}
	mockClient.On("GetUser", mock.Anything, "user-abc").Return(resp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"users", "get", "user-abc"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "user-abc")
	assert.Contains(t, out, "charlie@test.com")
	assert.Contains(t, out, "charlie")

	mockClient.AssertExpectations(t)
}

func TestUsersGetCmd_RequiresID(t *testing.T) {
	_, _ = setupTestCmd(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"users", "get"})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestUsersGetCmd_NotFound(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	apiErr := &client.APIError{StatusCode: 404, Message: "user not found"}
	mockClient.On("GetUser", mock.Anything, "missing").Return(nil, apiErr)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"users", "get", "missing"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestUsersCreateCmd_Success(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	createdUser := makeTestUser("new-id", "new@test.com", "newuser", "active")
	resp := &client.UserResponse{User: createdUser}
	mockClient.On("CreateUser", mock.Anything, &client.CreateUserRequest{
		Email:     "new@test.com",
		Username:  "newuser",
		Password:  "pass123",
		FirstName: "New",
		LastName:  "User",
	}).Return(resp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"users", "create",
		"--email", "new@test.com",
		"--username", "newuser",
		"--password", "pass123",
		"--first-name", "New",
		"--last-name", "User",
	})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "[OK]")
	assert.Contains(t, out, "newuser")
	assert.Contains(t, out, "new-id")

	mockClient.AssertExpectations(t)
}

func TestUsersCreateCmd_MissingRequiredEmail(t *testing.T) {
	_, _ = setupTestCmd(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"users", "create",
		"--username", "newuser",
		"--password", "pass123",
	})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestUsersCreateCmd_MissingRequiredPassword(t *testing.T) {
	_, _ = setupTestCmd(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"users", "create",
		"--email", "test@test.com",
		"--username", "newuser",
	})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestUsersCreateCmd_APIError(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	apiErr := &client.APIError{StatusCode: 409, Message: "user already exists"}
	mockClient.On("CreateUser", mock.Anything, mock.Anything).Return(nil, apiErr)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"users", "create",
		"--email", "existing@test.com",
		"--username", "existing",
		"--password", "pass",
	})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user already exists")
}

func TestUsersDeleteCmd_Success(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	mockClient.On("DeleteUser", mock.Anything, "del-id").Return(nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"users", "delete", "del-id"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "[OK]")
	assert.Contains(t, out, "del-id")

	mockClient.AssertExpectations(t)
}

func TestUsersDeleteCmd_RequiresID(t *testing.T) {
	_, _ = setupTestCmd(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"users", "delete"})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestUsersDeleteCmd_NotFound(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	apiErr := &client.APIError{StatusCode: 404, Message: "user not found"}
	mockClient.On("DeleteUser", mock.Anything, "missing").Return(apiErr)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"users", "delete", "missing"})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestUsersCmd_Subcommands(t *testing.T) {
	rootCmd := NewRootCmd()
	var usersCmd *cobra.Command
	for _, sub := range rootCmd.Commands() {
		if sub.Name() == "users" {
			usersCmd = sub
			break
		}
	}
	require.NotNil(t, usersCmd)

	subNames := make([]string, 0)
	for _, sub := range usersCmd.Commands() {
		subNames = append(subNames, sub.Name())
	}
	assert.Contains(t, subNames, "list")
	assert.Contains(t, subNames, "get")
	assert.Contains(t, subNames, "create")
	assert.Contains(t, subNames, "delete")
}
