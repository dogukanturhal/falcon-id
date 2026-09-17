// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// DDIL P3.2 — governed offline authorization tests.
//
// These exercise the three contract properties from the operating spec:
//   - served-within-budget: a signed last-known-good decision is served while
//     SpiceDB is (simulated) unreachable, as long as we are within the budget;
//   - denied-after: once the budget elapses, serving fails closed;
//   - revoked-epoch-offline: a revocation-epoch bump voids a cached decision
//     even while offline and within budget.
// Time is injected so budget boundaries are deterministic.

type fakeRoleVersion struct {
	version int64
	err     error
}

func (f *fakeRoleVersion) GetRoleVersion(_ context.Context, _ uuid.UUID) (int64, error) {
	return f.version, f.err
}

func newTestOfflineAuthz(t *testing.T, roleVer RoleVersionProvider) *offlineAuthz {
	t.Helper()
	cfg := &config.Config{
		DDILOfflineAuthzEnabled:           true,
		DDILOfflineAuthzStandardBudget:    15 * time.Minute,
		DDILOfflineAuthzPrivilegedBudget:  5 * time.Minute,
		DDILOfflineAuthzPrivilegedModules: []string{"iam", "core", "admin", "platform"},
		DDILOfflineAuthzClockLeeway:       0,
	}
	o, err := newOfflineAuthz(cfg, roleVer, nil)
	if err != nil {
		t.Fatalf("newOfflineAuthz: %v", err)
	}
	if o == nil {
		t.Fatal("newOfflineAuthz returned nil for an enabled config")
	}
	return o
}

func TestOfflineAuthz_ServedWithinBudget(t *testing.T) {
	ctx := context.Background()
	tenant, user := uuid.New(), uuid.New()
	const resource = "crm:contacts:read" // standard tier ⇒ 15m budget

	base := time.Now()
	clk := base
	o := newTestOfflineAuthz(t, &fakeRoleVersion{version: 1})
	o.now = func() time.Time { return clk }

	// Online success records a signed decision.
	o.record(ctx, tenant, user, resource, true)

	// Immediately servable.
	if allowed, served := o.serve(ctx, tenant, user, resource); !served || !allowed {
		t.Fatalf("expected served allow at t0, got served=%v allowed=%v", served, allowed)
	}

	// Still within budget (1s before the 15m boundary).
	clk = base.Add(15*time.Minute - time.Second)
	if allowed, served := o.serve(ctx, tenant, user, resource); !served || !allowed {
		t.Fatalf("expected served allow just inside budget, got served=%v allowed=%v", served, allowed)
	}
}

func TestOfflineAuthz_DeniedAfterBudget(t *testing.T) {
	ctx := context.Background()
	tenant, user := uuid.New(), uuid.New()
	const resource = "crm:contacts:read" // 15m budget

	base := time.Now()
	clk := base
	o := newTestOfflineAuthz(t, &fakeRoleVersion{version: 1})
	o.now = func() time.Time { return clk }

	o.record(ctx, tenant, user, resource, true)

	// One second past the budget → fail closed (not served).
	clk = base.Add(15*time.Minute + time.Second)
	if allowed, served := o.serve(ctx, tenant, user, resource); served || allowed {
		t.Fatalf("expected fail-closed after budget, got served=%v allowed=%v", served, allowed)
	}
}

func TestOfflineAuthz_PrivilegedTierShorterBudget(t *testing.T) {
	ctx := context.Background()
	tenant, user := uuid.New(), uuid.New()
	const resource = "iam:users:read" // privileged module ⇒ 5m budget

	base := time.Now()
	clk := base
	o := newTestOfflineAuthz(t, &fakeRoleVersion{version: 1})
	o.now = func() time.Time { return clk }

	o.record(ctx, tenant, user, resource, true)

	// Inside the 5m privileged budget.
	clk = base.Add(5*time.Minute - time.Second)
	if allowed, served := o.serve(ctx, tenant, user, resource); !served || !allowed {
		t.Fatalf("expected served inside privileged budget, got served=%v allowed=%v", served, allowed)
	}

	// A standard-tier decision would still be valid here, but the privileged
	// one must have already expired past 5m.
	clk = base.Add(5*time.Minute + time.Second)
	if allowed, served := o.serve(ctx, tenant, user, resource); served || allowed {
		t.Fatalf("expected privileged decision expired past 5m, got served=%v allowed=%v", served, allowed)
	}
}

func TestOfflineAuthz_RevokedEpochOffline(t *testing.T) {
	ctx := context.Background()
	tenant, user := uuid.New(), uuid.New()
	const resource = "crm:contacts:read"

	base := time.Now()
	clk := base
	roleVer := &fakeRoleVersion{version: 5}
	o := newTestOfflineAuthz(t, roleVer)
	o.now = func() time.Time { return clk }

	// Record a decision under epoch 5.
	o.record(ctx, tenant, user, resource, true)

	// Sanity: servable before revocation, well within budget.
	if allowed, served := o.serve(ctx, tenant, user, resource); !served || !allowed {
		t.Fatalf("expected served allow before revocation, got served=%v allowed=%v", served, allowed)
	}

	// A role/permission change bumps the tenant's revocation epoch to 6. This
	// is pushed to the offline layer (as the SessionCache hook would). We are
	// still WELL within the staleness budget.
	o.revokeTenant(tenant, 6)
	clk = base.Add(time.Minute)

	if allowed, served := o.serve(ctx, tenant, user, resource); served || allowed {
		t.Fatalf("expected fail-closed after offline revocation, got served=%v allowed=%v", served, allowed)
	}
}

func TestOfflineAuthz_EpochUnavailableSkipsRecord(t *testing.T) {
	ctx := context.Background()
	tenant, user := uuid.New(), uuid.New()
	const resource = "crm:contacts:read"

	o := newTestOfflineAuthz(t, &fakeRoleVersion{err: context.DeadlineExceeded})

	// Epoch source failing ⇒ nothing cached ⇒ nothing servable (fail closed).
	o.record(ctx, tenant, user, resource, true)
	if allowed, served := o.serve(ctx, tenant, user, resource); served || allowed {
		t.Fatalf("expected no cached decision when epoch unavailable, got served=%v allowed=%v", served, allowed)
	}
}

func TestOfflineAuthz_DisabledIsNilSafeNoop(t *testing.T) {
	ctx := context.Background()
	o, err := newOfflineAuthz(&config.Config{DDILOfflineAuthzEnabled: false}, nil, nil)
	if err != nil {
		t.Fatalf("newOfflineAuthz(disabled): %v", err)
	}
	if o != nil {
		t.Fatalf("expected nil offlineAuthz when disabled, got %v", o)
	}
	// All methods must be safe on the nil layer.
	o.record(ctx, uuid.New(), uuid.New(), "crm:contacts:read", true)
	if allowed, served := o.serve(ctx, uuid.New(), uuid.New(), "crm:contacts:read"); served || allowed {
		t.Fatalf("nil offline layer must never serve, got served=%v allowed=%v", served, allowed)
	}
	o.revokeTenant(uuid.New(), 1)
}

func TestOfflineAuthz_ClassifyTier(t *testing.T) {
	o := newTestOfflineAuthz(t, &fakeRoleVersion{version: 1})
	cases := map[string]string{
		"crm:contacts:read": "standard",
		"iam:users:read":    "privileged",
		"core:settings:get": "privileged",
		"platform:x:y":      "privileged",
		"nomodulehere":      "privileged", // unrecognisable ⇒ fail-closed bias
	}
	for resource, want := range cases {
		if got := string(o.classifyTier(resource)); got != want {
			t.Errorf("classifyTier(%q) = %q, want %q", resource, got, want)
		}
	}
}
