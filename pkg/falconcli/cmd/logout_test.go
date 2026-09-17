// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestLogoutCmd_Success(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	mockClient.On("Logout", mock.Anything).Return(nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"logout"})
	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "[OK]")
	assert.Contains(t, output, "Logged out")

	mockClient.AssertExpectations(t)
}

func TestLogoutCmd_ServerErrorStillClearsLocal(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	// Server returns error but local credentials should still be cleared
	mockClient.On("Logout", mock.Anything).Return(errors.New("server error"))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"logout"})
	err := cmd.Execute()
	// Should not return error to user — just clears local credentials
	require.NoError(t, err)

	output := buf.String()
	// Should mention the server error
	assert.Contains(t, output, "Server logout failed")
	// Should still report success for local logout
	assert.Contains(t, output, "[OK]")

	mockClient.AssertExpectations(t)
}
