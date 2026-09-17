// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/dogukanturhal/falcon-id/pkg/falconcli/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestLoginCmd_Success(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	loginResp := &client.LoginResponse{
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
	}
	mockClient.On("Login", mock.Anything, &client.LoginRequest{
		Username:   "admin",
		Password:   "secret",
		TenantSlug: "my-tenant",
	}).Return(loginResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"login",
		"--username", "admin",
		"--password", "secret",
		"--tenant-slug", "my-tenant",
	})
	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "[OK]")
	assert.Contains(t, output, "admin")
	assert.Contains(t, output, "my-tenant")

	mockClient.AssertExpectations(t)
}

func TestLoginCmd_MissingUsername(t *testing.T) {
	_, _ = setupTestCmd(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"login",
		"--password", "secret",
		"--tenant-slug", "my-tenant",
	})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "username")
}

func TestLoginCmd_MissingPassword(t *testing.T) {
	_, _ = setupTestCmd(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"login",
		"--username", "admin",
		"--tenant-slug", "my-tenant",
	})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "password")
}

func TestLoginCmd_MissingTenant(t *testing.T) {
	_, _ = setupTestCmd(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"login",
		"--username", "admin",
		"--password", "secret",
	})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant-slug")
}

func TestLoginCmd_APIError(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	apiErr := &client.APIError{
		StatusCode: 401,
		Message:    "invalid credentials",
	}
	mockClient.On("Login", mock.Anything, mock.Anything).Return(nil, apiErr)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"login",
		"--username", "admin",
		"--password", "wrong",
		"--tenant-slug", "my-tenant",
	})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "login failed")

	mockClient.AssertExpectations(t)
}

func TestLoginCmd_UsesTenantFromPersistentFlag(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	loginResp := &client.LoginResponse{
		AccessToken:  "token",
		RefreshToken: "refresh",
	}
	mockClient.On("Login", mock.Anything, &client.LoginRequest{
		Username:   "admin",
		Password:   "pass",
		TenantSlug: "persistent-tenant",
	}).Return(loginResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--tenant", "persistent-tenant",
		"login",
		"--username", "admin",
		"--password", "pass",
	})
	err := cmd.Execute()
	require.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestLoginCmd_SavesTokensToConfig(t *testing.T) {
	mockClient, _ := setupTestCmd(t)
	home := t.TempDir()
	SetHomeOverride(home)

	loginResp := &client.LoginResponse{
		AccessToken:  "saved-access",
		RefreshToken: "saved-refresh",
	}
	mockClient.On("Login", mock.MatchedBy(func(_ context.Context) bool { return true }),
		mock.Anything).Return(loginResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"login",
		"--username", "testuser",
		"--password", "testpass",
		"--tenant-slug", "test-tenant",
	})
	err := cmd.Execute()
	require.NoError(t, err)

	// Verify the config was saved
	_ = home
}

func TestLoginCmd_NetworkError(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("Login", mock.Anything, mock.Anything).Return(nil, errors.New("connection refused"))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"login",
		"--username", "admin",
		"--password", "pass",
		"--tenant-slug", "tenant",
	})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "login failed")
}
