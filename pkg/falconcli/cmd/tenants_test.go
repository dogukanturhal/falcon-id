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

func TestTenantsListCmd_TableOutput(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	tenants := []client.Tenant{
		{ID: "t1", Name: "Acme Corp", Slug: "acme", Status: "active"},
		{ID: "t2", Name: "Beta Inc", Slug: "beta", Status: "suspended"},
	}
	listResp := &client.TenantListResponse{
		Tenants:    tenants,
		Total:      2,
		Page:       1,
		PageSize:   20,
		TotalPages: 1,
	}
	mockClient.On("ListTenants", mock.Anything, mock.Anything).Return(listResp, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"tenants", "list"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "NAME")
	assert.Contains(t, out, "SLUG")
	assert.Contains(t, out, "STATUS")
	assert.Contains(t, out, "Acme Corp")
	assert.Contains(t, out, "acme")
	assert.Contains(t, out, "Beta Inc")
	assert.Contains(t, out, "beta")
	// Badges in no-color mode use [status]
	assert.Contains(t, out, "[active]")
	assert.Contains(t, out, "[suspended]")

	mockClient.AssertExpectations(t)
}

func TestTenantsListCmd_WithFlags(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("ListTenants", mock.Anything, &client.ListOptions{Page: 2, PageSize: 5, Search: "acme"}).
		Return(&client.TenantListResponse{}, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"tenants", "list", "--page", "2", "--page-size", "5", "--search", "acme"})
	err := cmd.Execute()
	require.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestTenantsListCmd_Error(t *testing.T) {
	mockClient, _ := setupTestCmd(t)

	mockClient.On("ListTenants", mock.Anything, mock.Anything).Return(nil, errors.New("unauthorized"))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"tenants", "list"})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestTenantsListCmd_Empty(t *testing.T) {
	mockClient, buf := setupTestCmd(t)

	mockClient.On("ListTenants", mock.Anything, mock.Anything).Return(&client.TenantListResponse{
		Tenants: []client.Tenant{},
	}, nil)

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"tenants", "list"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "NAME") // headers present
}
