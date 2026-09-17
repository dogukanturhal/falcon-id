// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---

type mockDefaultAppAccessGranter struct {
	called   bool
	tenantID uuid.UUID
	userID   uuid.UUID
	err      error
}

func (m *mockDefaultAppAccessGranter) GrantDefaultAccess(_ context.Context, tenantID, userID uuid.UUID) error {
	m.called = true
	m.tenantID = tenantID
	m.userID = userID
	return m.err
}

type mockSubdomainProvisioner struct {
	called   bool
	tenantID uuid.UUID
	slug     string
	err      error
}

func (m *mockSubdomainProvisioner) ProvisionSubdomain(_ context.Context, tenantID uuid.UUID, slug string) error {
	m.called = true
	m.tenantID = tenantID
	m.slug = slug
	return m.err
}

type mockTenantSlugResolver struct {
	slug string
	err  error
}

func (m *mockTenantSlugResolver) GetSlugByID(_ context.Context, _ uuid.UUID) (string, error) {
	return m.slug, m.err
}

// mockProductEntitlementProvisioner records the SubscriptionActivatedEvent it
// was called with, so tests can assert the post-signup hook actually routes
// through the same subscription-activation pipeline a billing webhook would
// use (see ProductEntitlementProvisioner / ProvisioningConsumer).
type mockProductEntitlementProvisioner struct {
	called bool
	event  SubscriptionActivatedEvent
	err    error
}

func (m *mockProductEntitlementProvisioner) HandleSubscriptionActivated(_ context.Context, event SubscriptionActivatedEvent) error {
	m.called = true
	m.event = event
	return m.err
}

type mockTrialStarter struct {
	called      bool
	tenantID    uuid.UUID
	packageCode string
	err         error
}

func (m *mockTrialStarter) StartTrial(_ context.Context, tenantID uuid.UUID, packageCode string) error {
	m.called = true
	m.tenantID = tenantID
	m.packageCode = packageCode
	return m.err
}

// blockingSyncEntitlementProvisioner implements SyncProductEntitlementProvisioner
// (the interface OnSignupComplete prefers, added by falcon-id!360) with a
// HandleSubscriptionActivatedSync that never returns on its own — it blocks
// until the ctx it is handed is Done. This is what exercises the 12s-bound
// timeout path from OnSignupComplete: a slow/stuck ReconcileUntilTerminal
// call, which is exactly the scenario !360 could not verify because the
// real bound is 12 real seconds. Also implements the async
// HandleSubscriptionActivated so it satisfies ProductEntitlementProvisioner
// too (OnSignupComplete's own type-assertion picks the sync path since this
// mock implements both, matching the real provisioning_orchestrator.go
// implementation's shape).
type blockingSyncEntitlementProvisioner struct {
	called       bool
	ctxErrAtExit error
}

func (m *blockingSyncEntitlementProvisioner) HandleSubscriptionActivated(_ context.Context, _ SubscriptionActivatedEvent) error {
	return nil
}

func (m *blockingSyncEntitlementProvisioner) HandleSubscriptionActivatedSync(ctx context.Context, _ SubscriptionActivatedEvent) error {
	m.called = true
	<-ctx.Done()
	m.ctxErrAtExit = ctx.Err()
	return ctx.Err()
}

// --- Tests ---

func TestPostSignupProvisioner_OnSignupComplete_GrantsAppAccess(t *testing.T) {
	granter := &mockDefaultAppAccessGranter{}
	provisioner := NewPostSignupProvisioner(granter, nil, nil)

	tenantID := uuid.New()
	userID := uuid.New()

	err := provisioner.OnSignupComplete(context.Background(), tenantID, userID, "business")

	assert.NoError(t, err)
	assert.True(t, granter.called)
	assert.Equal(t, tenantID, granter.tenantID)
	assert.Equal(t, userID, granter.userID)
}

func TestPostSignupProvisioner_OnSignupComplete_ProvisionesSubdomain(t *testing.T) {
	slugResolver := &mockTenantSlugResolver{slug: "acme-corp"}
	subdomainProv := &mockSubdomainProvisioner{}
	provisioner := NewPostSignupProvisioner(nil, subdomainProv, slugResolver)

	tenantID := uuid.New()
	userID := uuid.New()

	err := provisioner.OnSignupComplete(context.Background(), tenantID, userID, "business")

	assert.NoError(t, err)
	assert.True(t, subdomainProv.called)
	assert.Equal(t, "acme-corp", subdomainProv.slug)
}

func TestPostSignupProvisioner_OnSignupComplete_PersonalAccount_SkipsSubdomain(t *testing.T) {
	subdomainProv := &mockSubdomainProvisioner{}
	slugResolver := &mockTenantSlugResolver{slug: "personal-123"}
	provisioner := NewPostSignupProvisioner(nil, subdomainProv, slugResolver)

	err := provisioner.OnSignupComplete(context.Background(), uuid.New(), uuid.New(), "personal")

	assert.NoError(t, err)
	assert.False(t, subdomainProv.called, "subdomain should not be provisioned for personal accounts")
}

func TestPostSignupProvisioner_OnSignupComplete_AllErrors_NonFatal(t *testing.T) {
	granter := &mockDefaultAppAccessGranter{err: fmt.Errorf("access grant failed")}
	subdomainProv := &mockSubdomainProvisioner{err: fmt.Errorf("subdomain failed")}
	slugResolver := &mockTenantSlugResolver{slug: "test"}
	provisioner := NewPostSignupProvisioner(granter, subdomainProv, slugResolver)

	err := provisioner.OnSignupComplete(context.Background(), uuid.New(), uuid.New(), "business")

	assert.NoError(t, err, "all errors should be non-fatal")
	assert.True(t, granter.called)
	assert.True(t, subdomainProv.called)
}

func TestPostSignupProvisioner_OnSignupComplete_NilDeps_NoError(t *testing.T) {
	provisioner := NewPostSignupProvisioner(nil, nil, nil)

	err := provisioner.OnSignupComplete(context.Background(), uuid.New(), uuid.New(), "business")

	assert.NoError(t, err)
}

// TestPostSignupProvisioner_OnSignupComplete_GrantsProductEntitlement is the
// primary regression test for the self-service-signup 403 bug: a tenant
// produced by signup was left with no iam_product_instances row at all,
// so its first login was redirected to
// /unauthorized?reason=product_not_entitled by the falcon-id-client
// middleware. This asserts OnSignupComplete now routes the tenant + a
// specific product ID through HandleSubscriptionActivated (the exact same
// entrypoint a billing subscription.activated webhook uses), with the
// default plan (SIGNUP_DEFAULT_PLAN_CODE, "starter" when unset) self-service
// signup always grants today.
func TestPostSignupProvisioner_OnSignupComplete_GrantsProductEntitlement(t *testing.T) {
	entitlement := &mockProductEntitlementProvisioner{}
	provisioner := NewPostSignupProvisioner(nil, nil, nil)
	productID := uuid.New()
	provisioner.SetProductEntitlementProvisioner(entitlement, productID)

	tenantID := uuid.New()
	userID := uuid.New()

	err := provisioner.OnSignupComplete(context.Background(), tenantID, userID, "business")

	assert.NoError(t, err)
	assert.True(t, entitlement.called, "product entitlement provisioner should be invoked on signup completion")
	assert.Equal(t, tenantID, entitlement.event.TenantID)
	if assert.NotNil(t, entitlement.event.ProductID) {
		assert.Equal(t, productID, *entitlement.event.ProductID)
	}
	if assert.NotNil(t, entitlement.event.PlanID) {
		assert.Equal(t, "starter", *entitlement.event.PlanID)
	}
}

// TestPostSignupProvisioner_OnSignupComplete_EntitlementFailure_NonFatal
// mirrors the "all errors non-fatal" contract of every other post-signup
// step: a provisioning failure must not fail the signup request itself
// (the tenant/user already exist by this point), but it also must not be
// silently swallowed — see the logger.Error call site in OnSignupComplete,
// which is the one deliberately-elevated-severity step in this hook.
func TestPostSignupProvisioner_OnSignupComplete_EntitlementFailure_NonFatal(t *testing.T) {
	entitlement := &mockProductEntitlementProvisioner{err: fmt.Errorf("provisioning enqueue failed")}
	provisioner := NewPostSignupProvisioner(nil, nil, nil)
	provisioner.SetProductEntitlementProvisioner(entitlement, uuid.New())

	err := provisioner.OnSignupComplete(context.Background(), uuid.New(), uuid.New(), "business")

	assert.NoError(t, err, "entitlement provisioning failure should not fail signup itself")
	assert.True(t, entitlement.called)
}

// TestPostSignupProvisioner_OnSignupComplete_NoEntitlementWired_SkipsStep is
// the CONTROL for the two tests above: it proves the mock's `called` flag
// genuinely reflects whether OnSignupComplete invokes the entitlement step,
// rather than always being left true by some other code path. Without
// SetProductEntitlementProvisioner ever being called (the exact state
// cmd/services.go was in before this fix — see signup_service.go's
// postSignupHook wiring), the step must not run.
func TestPostSignupProvisioner_OnSignupComplete_NoEntitlementWired_SkipsStep(t *testing.T) {
	provisioner := NewPostSignupProvisioner(nil, nil, nil)
	// Deliberately do NOT call SetProductEntitlementProvisioner.

	err := provisioner.OnSignupComplete(context.Background(), uuid.New(), uuid.New(), "business")

	assert.NoError(t, err)
	// Nothing to assert "called" on since none was wired — the absence of a
	// panic/nil-deref here (p.productEntitlement is nil) combined with the
	// two tests above (which DO see `called == true` once wired) is itself
	// the control: it demonstrates the call in OnSignupComplete is
	// conditional on wiring, not unconditional.
}

// TestPostSignupProvisioner_OnSignupComplete_EntitlementSyncTimeout covers
// Gap 1 of the signup-provisioning-interstitial fix: falcon-id!360 added a
// productEntitlementSyncTimeout (12s) bound around
// SyncProductEntitlementProvisioner.HandleSubscriptionActivatedSync, but
// that MR could not itself verify the timeout-exceeded path (a real test
// would need to actually block for 12+ real seconds). Here
// entitlementSyncTimeout is overridden to a few milliseconds — an
// unexported field set directly by this same-package test, not a new
// exported API — so the bound can be exercised in test time.
//
// Assertions:
//  1. OnSignupComplete returns promptly (well under the mock's un-bounded
//     block), proving the timeout actually cuts the wait short rather than
//     the call happening to finish on its own.
//  2. It returns nil — a slow/stuck provisioning step must never fail the
//     signup request itself (same non-fatal contract as
//     TestPostSignupProvisioner_OnSignupComplete_EntitlementFailure_NonFatal).
//  3. The context actually handed to HandleSubscriptionActivatedSync had
//     its deadline expire (ctx.Err() == context.DeadlineExceeded), proving
//     this exercises the WithTimeout path and not some other early return.
func TestPostSignupProvisioner_OnSignupComplete_EntitlementSyncTimeout(t *testing.T) {
	entitlement := &blockingSyncEntitlementProvisioner{}
	provisioner := NewPostSignupProvisioner(nil, nil, nil)
	provisioner.SetProductEntitlementProvisioner(entitlement, uuid.New())
	provisioner.entitlementSyncTimeout = 20 * time.Millisecond

	start := time.Now()
	err := provisioner.OnSignupComplete(context.Background(), uuid.New(), uuid.New(), "business")
	elapsed := time.Since(start)

	assert.NoError(t, err, "a slow/stuck entitlement provisioning step must not fail signup itself")
	assert.True(t, entitlement.called, "the sync entitlement path should have been invoked")
	assert.Less(t, elapsed, 2*time.Second, "OnSignupComplete should return promptly once its bounded wait expires, not block indefinitely")
	require.NotNil(t, entitlement.ctxErrAtExit)
	assert.ErrorIs(t, entitlement.ctxErrAtExit, context.DeadlineExceeded, "the context passed to HandleSubscriptionActivatedSync should have its own deadline, not the caller's background context")
}

// TestPostSignupProvisioner_entitlementTimeout is the CONTROL for the test
// above: it proves entitlementTimeout() itself falls back to the real
// productEntitlementSyncTimeout constant when no override is set, so the
// timeout test above is verifying an actual override mechanism and not a
// helper that always returns some other hardcoded value regardless of the
// field.
func TestPostSignupProvisioner_entitlementTimeout(t *testing.T) {
	provisioner := NewPostSignupProvisioner(nil, nil, nil)
	assert.Equal(t, productEntitlementSyncTimeout, provisioner.entitlementTimeout())

	provisioner.entitlementSyncTimeout = 5 * time.Millisecond
	assert.Equal(t, 5*time.Millisecond, provisioner.entitlementTimeout())
}

// TestPostSignupProvisioner_OnSignupComplete_StartsTrial_BusinessAccount
// asserts step 7 (cardless trial start) fires for a business-account
// signup and is handed the tenant ID that just completed signup.
func TestPostSignupProvisioner_OnSignupComplete_StartsTrial_BusinessAccount(t *testing.T) {
	trialStarter := &mockTrialStarter{}
	provisioner := NewPostSignupProvisioner(nil, nil, nil)
	provisioner.SetTrialStarter(trialStarter)

	tenantID := uuid.New()
	err := provisioner.OnSignupComplete(context.Background(), tenantID, uuid.New(), "business")

	assert.NoError(t, err)
	assert.True(t, trialStarter.called, "trial starter should be invoked for a business-account signup")
	assert.Equal(t, tenantID, trialStarter.tenantID)
}

// TestPostSignupProvisioner_OnSignupComplete_PersonalAccount_SkipsTrialStart
// asserts personal/consumer signups never start a cardless trial — mirrors
// the existing business-only gating on subdomain provisioning and founder
// role assignment. subscription-management's TenantSubscription table has
// no meaning for a personal tenant.
func TestPostSignupProvisioner_OnSignupComplete_PersonalAccount_SkipsTrialStart(t *testing.T) {
	trialStarter := &mockTrialStarter{}
	provisioner := NewPostSignupProvisioner(nil, nil, nil)
	provisioner.SetTrialStarter(trialStarter)

	err := provisioner.OnSignupComplete(context.Background(), uuid.New(), uuid.New(), "personal")

	assert.NoError(t, err)
	assert.False(t, trialStarter.called, "trial starter must not be invoked for a personal-account signup")
}

// TestPostSignupProvisioner_OnSignupComplete_NoTrialStarterWired_SkipsStep
// is the CONTROL for the two tests above: without SetTrialStarter ever
// being called (p.trialStarter stays nil — the pre-MR2 state, and the
// state of any deployment with outbound S2S creds to
// subscription-management unconfigured), the step must not run and must
// not panic on a nil dereference.
func TestPostSignupProvisioner_OnSignupComplete_NoTrialStarterWired_SkipsStep(t *testing.T) {
	provisioner := NewPostSignupProvisioner(nil, nil, nil)
	// Deliberately do NOT call SetTrialStarter.

	err := provisioner.OnSignupComplete(context.Background(), uuid.New(), uuid.New(), "business")

	assert.NoError(t, err)
}

// TestPostSignupProvisioner_OnSignupComplete_TrialStartFailure_NonFatal
// mirrors the "all errors non-fatal" contract of every other post-signup
// step: a trial-start failure (e.g. subscription-management 422ing because
// no default trial package is configured) must not fail the signup
// request itself.
func TestPostSignupProvisioner_OnSignupComplete_TrialStartFailure_NonFatal(t *testing.T) {
	trialStarter := &mockTrialStarter{err: fmt.Errorf("no default trial package configured")}
	provisioner := NewPostSignupProvisioner(nil, nil, nil)
	provisioner.SetTrialStarter(trialStarter)

	err := provisioner.OnSignupComplete(context.Background(), uuid.New(), uuid.New(), "business")

	assert.NoError(t, err, "trial start failure should not fail signup itself")
	assert.True(t, trialStarter.called)
}
