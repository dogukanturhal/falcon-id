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

func TestTokensGenerateCmd_Success(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	tokenResp := &client.TokenResponse{
		ID:        "tok-123",
		Name:      "my-key",
		Key:       "sk_live_abcdefghijklmnop",
		ExpiresAt: "2027-01-01T00:00:00Z",
	}
	mockClient.On("GenerateToken", mock.Anything, &client.GenerateTokenRequest{
		Name:      "my-key",
		ExpiresIn: "30d",
		Scopes:    []string{"users:read", "roles:read"},
	}).Return(tokenResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"tokens", "generate",
		"--name", "my-key",
		"--expires-in", "30d",
		"--scopes", "users:read,roles:read",
	})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "[OK]")
	assert.Contains(t, out, "my-key")
	assert.Contains(t, out, "tok-123")
	assert.Contains(t, out, "sk_live_abcdefghijklmnop")
	assert.Contains(t, out, "2027-01-01T00:00:00Z")
	assert.Contains(t, out, "Store this key securely")

	mockClient.AssertExpectations(t)
}

func TestTokensGenerateCmd_MinimalSuccess(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	tokenResp := &client.TokenResponse{
		ID:   "tok-min",
		Name: "simple-key",
		Key:  "sk_test_xyz",
	}
	mockClient.On("GenerateToken", mock.Anything, &client.GenerateTokenRequest{
		Name: "simple-key",
	}).Return(tokenResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"tokens", "generate", "--name", "simple-key"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "simple-key")
	assert.Contains(t, out, "sk_test_xyz")
	// No ExpiresAt when not set
	assert.NotContains(t, out, "Expires At:")

	mockClient.AssertExpectations(t)
}

func TestTokensGenerateCmd_MissingName(t *testing.T) {
	_, _ = setupTestCmd(t)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"tokens", "generate"})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestTokensGenerateCmd_APIError(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	apiErr := &client.APIError{StatusCode: 403, Message: "insufficient permissions"}
	mockClient.On("GenerateToken", mock.Anything, mock.Anything).Return(nil, apiErr)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"tokens", "generate", "--name", "test-key"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient permissions")
}

func TestTokensGenerateCmd_NetworkError(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("GenerateToken", mock.Anything, mock.Anything).Return(nil, errors.New("connection refused"))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"tokens", "generate", "--name", "test-key"})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestTokensGenerateCmd_WithExpiresInOnly(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	tokenResp := &client.TokenResponse{
		ID:        "tok-exp",
		Name:      "expiring-key",
		Key:       "sk_live_exp",
		ExpiresAt: "2026-06-01T00:00:00Z",
	}
	mockClient.On("GenerateToken", mock.Anything, &client.GenerateTokenRequest{
		Name:      "expiring-key",
		ExpiresIn: "90d",
	}).Return(tokenResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"tokens", "generate", "--name", "expiring-key", "--expires-in", "90d"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "2026-06-01T00:00:00Z")
}
