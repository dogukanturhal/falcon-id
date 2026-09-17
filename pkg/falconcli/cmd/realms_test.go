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

func TestRealmsListCmd_TableOutput(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	realms := []client.Realm{
		{ID: "realm-1", Name: "Default Realm", TenantID: "t1", Status: "active"},
		{ID: "realm-2", Name: "Dev Realm", TenantID: "t1", Status: "active"},
	}
	listResp := &client.RealmListResponse{
		Realms:     realms,
		Total:      2,
		Page:       1,
		PageSize:   20,
		TotalPages: 1,
	}
	mockClient.On("ListRealms", mock.Anything, mock.Anything).Return(listResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"realms", "list"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "NAME")
	assert.Contains(t, out, "TENANT ID")
	assert.Contains(t, out, "STATUS")
	assert.Contains(t, out, "realm-1")
	assert.Contains(t, out, "Default Realm")
	assert.Contains(t, out, "t1")
	assert.Contains(t, out, "[active]")

	mockClient.AssertExpectations(t)
}

func TestRealmsListCmd_WithFlags(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("ListRealms", mock.Anything, &client.ListOptions{Page: 1, PageSize: 10}).
		Return(&client.RealmListResponse{}, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"realms", "list", "--page", "1", "--page-size", "10"})
	err := cmd.Execute()
	require.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestRealmsListCmd_Error(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("ListRealms", mock.Anything, mock.Anything).Return(nil, errors.New("forbidden"))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"realms", "list"})
	err := cmd.Execute()
	require.Error(t, err)
}
