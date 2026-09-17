// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"testing"

	"github.com/dogukanturhal/falcon-id/pkg/falconcli/client"
	"github.com/dogukanturhal/falcon-id/pkg/falconcli/output"
	"github.com/stretchr/testify/mock"
)

// MockFalconClient implements client.FalconClient for testing.
type MockFalconClient struct {
	mock.Mock
}

func (m *MockFalconClient) Login(ctx context.Context, req *client.LoginRequest) (*client.LoginResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.LoginResponse), args.Error(1)
}

func (m *MockFalconClient) Logout(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockFalconClient) Whoami(ctx context.Context) (*client.WhoamiResponse, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.WhoamiResponse), args.Error(1)
}

func (m *MockFalconClient) ListUsers(ctx context.Context, opts *client.ListOptions) (*client.UserListResponse, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.UserListResponse), args.Error(1)
}

func (m *MockFalconClient) GetUser(ctx context.Context, id string) (*client.UserResponse, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.UserResponse), args.Error(1)
}

func (m *MockFalconClient) CreateUser(ctx context.Context, req *client.CreateUserRequest) (*client.UserResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.UserResponse), args.Error(1)
}

func (m *MockFalconClient) DeleteUser(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockFalconClient) ListRoles(ctx context.Context, opts *client.ListOptions) (*client.RoleListResponse, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.RoleListResponse), args.Error(1)
}

func (m *MockFalconClient) GetRole(ctx context.Context, id string) (*client.RoleResponse, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.RoleResponse), args.Error(1)
}

func (m *MockFalconClient) ListPermissions(ctx context.Context, opts *client.ListOptions) (*client.PermissionListResponse, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.PermissionListResponse), args.Error(1)
}

func (m *MockFalconClient) ListTenants(ctx context.Context, opts *client.ListOptions) (*client.TenantListResponse, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.TenantListResponse), args.Error(1)
}

func (m *MockFalconClient) ListRealms(ctx context.Context, opts *client.ListOptions) (*client.RealmListResponse, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.RealmListResponse), args.Error(1)
}

func (m *MockFalconClient) GenerateToken(ctx context.Context, req *client.GenerateTokenRequest) (*client.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.TokenResponse), args.Error(1)
}

func (m *MockFalconClient) Health(ctx context.Context) (*client.HealthResponse, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.HealthResponse), args.Error(1)
}

// setupTestCmd initializes the mock client and a captured output buffer for command tests.
func setupTestCmd(t *testing.T) (*MockFalconClient, *bytes.Buffer) {
	t.Helper()

	// Reset package-level variables
	cfgAPIURL = ""
	cfgOutput = ""
	cfgToken = ""
	cfgTenant = ""
	cfgNoColor = false

	mockClient := new(MockFalconClient)
	buf := &bytes.Buffer{}
	p := output.NewPrinter(output.FormatTable, true) // noColor=true for predictable output
	p.SetWriter(buf)
	SetClientOverride(mockClient)
	SetPrinterOverride(p)
	SetHomeOverride(t.TempDir())

	// Ensure overrides are cleaned up after the test
	t.Cleanup(func() {
		SetClientOverride(nil)
		SetPrinterOverride(nil)
		SetHomeOverride("")
		cfgAPIURL = ""
		cfgOutput = ""
		cfgToken = ""
		cfgTenant = ""
		cfgNoColor = false
	})

	return mockClient, buf
}
