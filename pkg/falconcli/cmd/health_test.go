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

func TestHealthCmd_HealthyOutput(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	healthResp := &client.HealthResponse{
		Status:  "ok",
		Version: "2.1.0",
		Services: map[string]string{
			"database": "up",
			"redis":    "up",
		},
	}
	mockClient.On("Health", mock.Anything).Return(healthResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"health"})
	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Version: 2.1.0")
	assert.Contains(t, output, "falcon-id")
	assert.Contains(t, output, "ok")

	mockClient.AssertExpectations(t)
}

func TestHealthCmd_NoVersion(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	healthResp := &client.HealthResponse{
		Status: "ok",
	}
	mockClient.On("Health", mock.Anything).Return(healthResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"health"})
	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	// Should not print Version line when version is empty
	assert.NotContains(t, output, "Version:")
	assert.Contains(t, output, "falcon-id")
}

func TestHealthCmd_WithServices(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	healthResp := &client.HealthResponse{
		Status: "degraded",
		Services: map[string]string{
			"database": "up",
			"redis":    "down",
			"spicedb":  "up",
		},
	}
	mockClient.On("Health", mock.Anything).Return(healthResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"health"})
	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "database")
	assert.Contains(t, output, "up")
	assert.Contains(t, output, "redis")
	assert.Contains(t, output, "down")
}

func TestHealthCmd_APIError(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	apiErr := &client.APIError{StatusCode: 503, Message: "service unavailable"}
	mockClient.On("Health", mock.Anything).Return(nil, apiErr)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"health"})
	err := cmd.Execute()
	require.Error(t, err)

	mockClient.AssertExpectations(t)
}

func TestHealthCmd_NetworkError(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("Health", mock.Anything).Return(nil, errors.New("connection refused"))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"health"})
	err := cmd.Execute()
	require.Error(t, err)
}
