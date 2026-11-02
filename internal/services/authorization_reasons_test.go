// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// boolOnlyEngine is an AuthorizationEngine whose BatchCheckPermissions answers
// only some keys, to prove the service fails closed on the rest.
type boolOnlyEngine struct {
	AuthorizationEngine
	answers map[string]bool
}

func (e boolOnlyEngine) BatchCheckPermissions(context.Context, uuid.UUID, uuid.UUID, []string) (map[string]bool, error) {
	return e.answers, nil
}

func TestAuthzReasons_Unit_UnansweredKeyFailsClosedAsUnknown(t *testing.T) {
	svc := NewAuthorizationService(nil, nil, nil, nil)
	svc.SetAuthorizationEngine(boolOnlyEngine{answers: map[string]bool{"a:b:c": true, "a:b:d": false}})

	resp, err := svc.AuthorizeBatch(context.Background(), &models.BatchAuthorizeRequest{
		UserID: uuid.New(), TenantID: uuid.New(), Permissions: []string{"a:b:c", "a:b:d", "a:b:missing"},
	})
	require.NoError(t, err)
	assert.Equal(t, models.PermissionDecision{Allowed: true}, resp.Decisions["a:b:c"])
	assert.Equal(t, models.DecisionReasonPermissionDenied, resp.Decisions["a:b:d"].Reason)
	assert.False(t, resp.Decisions["a:b:missing"].Allowed)
	assert.Equal(t, models.DecisionReasonUnknown, resp.Decisions["a:b:missing"].Reason)
	assert.False(t, resp.Results["a:b:missing"])
}

func TestAuthzReasons_Unit_SuspendedTenantDeniesEverythingWithoutAskingEngine(t *testing.T) {
	tenant := uuid.New()
	svc := NewAuthorizationService(nil, nil, nil, nil)
	svc.SetAuthorizationEngine(boolOnlyEngine{answers: map[string]bool{"a:b:c": true}})
	svc.SetTenantSuspensionChecker(fakeSuspension{tenant: true})

	resp, err := svc.AuthorizeBatch(context.Background(), &models.BatchAuthorizeRequest{
		UserID: uuid.New(), TenantID: tenant, Permissions: []string{"a:b:c"},
	})
	require.NoError(t, err)
	assert.Equal(t, models.DecisionReasonTenantSuspended, resp.Decisions["a:b:c"].Reason)
	assert.False(t, resp.Results["a:b:c"])
}
