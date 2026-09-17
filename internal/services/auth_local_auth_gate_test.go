// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// auth_local_auth_gate_test.go proves t-431's SSO-only login gate actually
// REJECTS a local-login attempt for a tenant with local_auth_disabled=true
// — not just that the flag/field exists (t-346's original gap: "the SSO
// button works, the password path is untested").

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// fakeFeatureFlagChecker lets tests drive IsEnabled without a real Postgres
// (satisfies featureFlagChecker structurally, see auth_service.go).
type fakeFeatureFlagChecker struct {
	enabled map[string]bool
	err     error
}

func (f *fakeFeatureFlagChecker) IsEnabled(_ context.Context, _ uuid.UUID, featureKey string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.enabled[featureKey], nil
}

func TestEnforceLocalAuthAllowed_RejectsLoginWhenTenantIsSSOOnly(t *testing.T) {
	svc := &AuthService{
		config:          newAuthCfg(),
		auditService:    newNopAuditSvc(),
		featureFlagRepo: &fakeFeatureFlagChecker{enabled: map[string]bool{FeatureKeyLocalAuthDisabled: true}},
		// userRepo deliberately nil: enforceLocalAuthAllowed nil-guards the
		// admin-review flag write, so the rejection itself does not depend
		// on a DB write succeeding.
	}
	user := &models.User{ID: uuid.New(), TenantID: uuid.New(), Username: "alice"}
	tenantCtx := &tenantContext{TenantID: user.TenantID, TenantSlug: "sso-only-co"}

	err := svc.enforceLocalAuthAllowed(context.Background(), tenantCtx, user, "1.2.3.4", "test-ua/1.0")

	require.Error(t, err, "an SSO-only tenant's local-login attempt must be ACTUALLY REJECTED, not merely flagged")
	assert.Contains(t, err.Error(), "SSO", "the rejection reason must point the caller at SSO, not a generic auth failure")
}

func TestEnforceLocalAuthAllowed_PermitsLoginWhenFlagIsUnsetOrFalse(t *testing.T) {
	svc := &AuthService{
		config:          newAuthCfg(),
		auditService:    newNopAuditSvc(),
		featureFlagRepo: &fakeFeatureFlagChecker{enabled: map[string]bool{}}, // local_auth_disabled absent -> false
	}
	user := &models.User{ID: uuid.New(), TenantID: uuid.New(), Username: "bob"}
	tenantCtx := &tenantContext{TenantID: user.TenantID, TenantSlug: "normal-co"}

	err := svc.enforceLocalAuthAllowed(context.Background(), tenantCtx, user, "1.2.3.4", "test-ua/1.0")

	assert.NoError(t, err, "a tenant that has not opted into SSO-only must keep local login working")
}

func TestEnforceLocalAuthAllowed_PermitsLoginWhenFeatureFlagStoreUnwired(t *testing.T) {
	svc := &AuthService{
		config:       newAuthCfg(),
		auditService: newNopAuditSvc(),
		// featureFlagRepo deliberately nil: environments without this
		// feature deployed must behave exactly as before t-431.
	}
	user := &models.User{ID: uuid.New(), TenantID: uuid.New(), Username: "carol"}
	tenantCtx := &tenantContext{TenantID: user.TenantID, TenantSlug: "legacy-co"}

	err := svc.enforceLocalAuthAllowed(context.Background(), tenantCtx, user, "1.2.3.4", "test-ua/1.0")

	assert.NoError(t, err, "an unwired feature-flag store must not itself block login")
}

func TestEnforceLocalAuthAllowed_FailsClosedOnPolicyQueryError(t *testing.T) {
	// c-265: an auth-boundary gate that IS deployed must not silently stand
	// down when it can't confirm policy -- a query error must reject, not
	// permit, the login.
	svc := &AuthService{
		config:          newAuthCfg(),
		auditService:    newNopAuditSvc(),
		featureFlagRepo: &fakeFeatureFlagChecker{err: errors.New("connection reset")},
	}
	user := &models.User{ID: uuid.New(), TenantID: uuid.New(), Username: "dave"}
	tenantCtx := &tenantContext{TenantID: user.TenantID, TenantSlug: "flaky-co"}

	err := svc.enforceLocalAuthAllowed(context.Background(), tenantCtx, user, "1.2.3.4", "test-ua/1.0")

	require.Error(t, err, "a policy-check failure must fail CLOSED (reject), never silently permit local auth")
}
