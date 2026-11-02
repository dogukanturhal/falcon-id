// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/stretchr/testify/require"
)

func TestBpaySignupFreeSelectionRejected(t *testing.T) {
	for _, code := range []string{"free", " Free ", "FREE"} {
		_, err := signupPlanSelection(code)
		require.Error(t, err)
	}
	code, err := signupPlanSelection("")
	require.NoError(t, err)
	require.Empty(t, code, "Commerce remains authoritative for the configured 14-day package")
}

func TestBpayBusinessSignupAlwaysUsesGrowthTrialTier(t *testing.T) {
	p := NewPostSignupProvisioner(nil, nil, nil)
	p.SetDefaultPlanCode("scale")
	p.SetTrialStarter(&mockTrialStarter{})
	product := &mockProductEntitlementProvisioner{}
	p.SetProductEntitlementProvisioner(product, uuid.New())
	require.NoError(t, p.OnSignupCompleteWithPlan(context.Background(), uuid.New(), uuid.New(), "business", "starter"))
	require.True(t, product.called)
	require.Equal(t, SignupTrialPackageCode, *product.event.PlanID)
}

func TestBpayConsumedOrFailedTrialNeverGrantsDefaultProductTier(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		t.Run(map[bool]string{true: "consumed", false: "source-unavailable"}[consumed], func(t *testing.T) {
			app := &mockDefaultAppAccessGranter{}
			p := NewPostSignupProvisioner(app, nil, nil)
			starter := &mockTrialStarter{err: ErrSignupTrialAlreadyConsumed}
			if !consumed {
				starter.err = context.DeadlineExceeded
			}
			p.SetTrialStarter(starter)
			product := &mockProductEntitlementProvisioner{}
			p.SetProductEntitlementProvisioner(product, uuid.New())
			err := p.OnSignupComplete(context.Background(), uuid.New(), uuid.New(), "business")
			if consumed {
				require.ErrorIs(t, err, ErrSignupTrialAlreadyConsumed)
			} else {
				require.NoError(t, err)
			}
			require.False(t, product.called)
			require.True(t, app.called, "basic recovery app access is not a trial/paid tier")
		})
	}
}

func TestBpayExpiredTrialDiscoveryAllowsRecoveryAndCompButNotOperatorBlock(t *testing.T) {
	for _, tc := range []struct {
		status  string
		expired bool
		want    bool
	}{
		{"active", false, true}, {"trial", false, true}, {"suspended", true, true},
		{"suspended", false, false}, {"deleted", true, false}, {"unknown", true, false},
	} {
		require.Equal(t, tc.want, slugLifecycleDiscoverable(&models.TenantSlugDiscoveryResponse{Status: tc.status, TrialAccessExpired: tc.expired}))
	}
	svc := NewHostDiscoveryService(nil, nil, nil)
	svc.slugCache["expired"] = slugCacheEntry{resp: &models.TenantSlugDiscoveryResponse{Status: "suspended", TrialAccessExpired: true, RecoveryOnly: false}}
	// The serialized flags distinguish routing/recovery from business grants.
	raw, err := json.Marshal(svc.slugCache["expired"].resp)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"trial_access_expired":true`)
}

func TestBpayConfirmedTrialProductRepairIsSourceGuardedAndRetryable(t *testing.T) {
	p := NewPostSignupProvisioner(nil, nil, nil)
	starter := &mockTrialStarter{err: context.DeadlineExceeded}
	p.SetTrialStarter(starter)
	product := &mockProductEntitlementProvisioner{}
	p.SetProductEntitlementProvisioner(product, uuid.New())
	id := uuid.New()
	require.ErrorIs(t, p.EnsureTrialProduct(context.Background(), id), context.DeadlineExceeded)
	require.False(t, product.called)
	starter.err = nil
	require.NoError(t, p.EnsureTrialProduct(context.Background(), id))
	require.True(t, product.called)
	require.Equal(t, SignupTrialPackageCode, *product.event.PlanID)
	product.called = false
	starter.err = ErrSignupTrialAlreadyConsumed
	require.NoError(t, p.EnsureTrialProduct(context.Background(), id))
	require.False(t, product.called, "stale trial-ready events must not overwrite paid/admin benefits")
}

func TestBpayConsumedTrialPropagatesSignupConflictWithoutNewBenefit(t *testing.T) {
	id := uuid.New()
	repo := &stubSignupRepo{req: &models.SignupRequest{CompletionSecretHash: testCompletionSecretHash(), ID: id, Email: "consumed@example.invalid", Verified: true, AccountType: "business", ExpiresAt: time.Now().Add(time.Hour)}}
	svc := NewSignupService(repo, &stubSignupEmail{}, &stubSignupTenantCreator{}, stubTenantManagementRegistrar{}, &stubSignupUserCreator{}, &stubSignupUserLookup{}, "test.invalid", "free", testOTPKey)
	svc.SetPostSignupHook(&mockPostSignupHook{err: ErrSignupTrialAlreadyConsumed})
	_, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret, SignupRequestID: id, Password: "TestPass123!"}, "", "")
	var state *SignupStateError
	require.ErrorAs(t, err, &state)
	require.Equal(t, "TRIAL_ALREADY_CONSUMED", state.Code)
	require.Equal(t, SignupTrialPackageCode, svc.defaultPlan(), "legacy Free config cannot select a signup benefit")
}
