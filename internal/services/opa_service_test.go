// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/tester"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

func newTestOPA(t *testing.T) *OPAService {
	t.Helper()
	// A bogus OPAPolicyPath must be irrelevant: policies are embedded.
	s, err := NewOPAService(&config.Config{UseABAC: true, OPAPolicyPath: "/nonexistent/policies"})
	require.NoError(t, err)
	return s
}

func TestOPAService_EmbeddedPolicyAllowsWithNoDenies(t *testing.T) {
	s := newTestOPA(t)

	d, err := s.Decide(context.Background(), map[string]any{"subject": map[string]any{"id": "u1"}})
	require.NoError(t, err)
	assert.True(t, d.Allow)
	assert.Empty(t, d.Denies)
	assert.Empty(t, d.Obligations)
	assert.Len(t, d.Revision, 12)
}

func TestOPAService_NoDefaultPolicyGrantsByRole(t *testing.T) {
	s := newTestOPA(t)

	// The old fallback special-cased role "admin"/"*" permission. The decision
	// must be identical for every subject: OPA never differentiates grants.
	admin, err := s.Decide(context.Background(), map[string]any{"user": map[string]any{"roles": []string{"admin"}, "permissions": []string{"*"}}})
	require.NoError(t, err)
	plain, err := s.Decide(context.Background(), map[string]any{"user": map[string]any{"roles": []string{}}})
	require.NoError(t, err)
	assert.Equal(t, plain, admin)
}

func TestOPAService_ReloadKeepsWorking(t *testing.T) {
	s := newTestOPA(t)
	require.NoError(t, s.ReloadPolicies(context.Background()))
	d, err := s.Decide(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.True(t, d.Allow)
}

// Runs the embedded policies/pdp/v1/*_test.rego suite (no opa CLI needed).
func TestEmbeddedRegoTests(t *testing.T) {
	mods, _, err := embeddedModules(true)
	require.NoError(t, err)

	parsed := make(map[string]*ast.Module, len(mods))
	for name, src := range mods {
		m, err := ast.ParseModule(name, src)
		require.NoError(t, err)
		parsed[name] = m
	}

	ch, err := tester.NewRunner().SetStore(inmem.New()).Run(context.Background(), parsed)
	require.NoError(t, err)
	n := 0
	for r := range ch {
		n++
		assert.NoError(t, r.Error, r.Name)
		assert.False(t, r.Fail, r.Name)
	}
	assert.GreaterOrEqual(t, n, 3)
}

// OPA is deny-only: an OPA "allow" must not grant when ReBAC denies.
func TestCheckContextualPermission_OPAAllowCannotGrantOverSpiceDBDeny(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reBAC *bool
	}{
		{name: "spicedb denies", reBAC: boolPtr(false)},
		{name: "spicedb unavailable", reBAC: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			permRepo := new(MockPermissionRepository)
			mockOPA := new(MockOPAService)
			var sdb SpiceDBChecker
			userID, tenantID := uuid.New(), uuid.New()
			if tc.reBAC != nil {
				m := new(MockSpiceDBChecker)
				m.On("CheckPermission", mock.Anything, tenantID, userID, mock.Anything, mock.Anything, mock.Anything).Return(*tc.reBAC, nil)
				sdb = m
			}
			engine := newTestEngine(permRepo, mockOPA, sdb)

			mockOPA.On("IsEnabled").Return(true)
			permRepo.On("GetUserRoles", mock.Anything, userID).Return([]string{"admin"}, nil)
			permRepo.On("GetUserPermissions", mock.Anything, userID).Return([]models.Permission{{Name: "x:y:z"}}, nil)
			mockOPA.On("EvaluatePermission", mock.Anything, userID, tenantID, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(&AuthzResult{Allowed: true}, nil)

			res, err := engine.CheckContextualPermission(context.Background(), ContextualPermissionRequest{
				UserID: userID, TenantID: tenantID, Action: "approve", ResourceType: "invoice", ResourceID: "r1",
			})
			require.NoError(t, err)
			assert.False(t, res.Allowed)
		})
	}
}
