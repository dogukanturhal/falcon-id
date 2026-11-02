// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeOriginLister is a controllable TenantOriginLister test double.
type fakeOriginLister struct {
	origins []string
	err     error
	calls   int
}

func (f *fakeOriginLister) ListActiveOrigins(_ context.Context) ([]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.origins, nil
}

// TestDynamicOriginRegistry_NoLister_NeverContainsAnything is the control
// for "no registry wired at all" (e.g. tenant-management client disabled) —
// Contains must behave identically to a static-list-only world: always
// false, never a panic.
func TestDynamicOriginRegistry_NoLister_NeverContainsAnything(t *testing.T) {
	r := NewDynamicOriginRegistry(nil, time.Minute, time.Second, zap.NewNop())
	if r.Contains("https://acme.example.com") {
		t.Fatal("Contains reported true with no lister configured")
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh with no lister should no-op, got error: %v", err)
	}
}

// TestDynamicOriginRegistry_NilReceiver proves every method is safe to call
// on a nil *DynamicOriginRegistry, matching how CORS/CSRF call Contains
// unconditionally regardless of whether a registry was constructed.
func TestDynamicOriginRegistry_NilReceiver(t *testing.T) {
	var r *DynamicOriginRegistry
	if r.Contains("https://acme.example.com") {
		t.Fatal("nil registry Contains must be false")
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("nil registry Refresh must no-op, got: %v", err)
	}
	r.StartBackgroundRefresh(context.Background()) // must not panic
}

// TestDynamicOriginRegistry_FailsClosed_KeepsLastGoodSetOnError is the
// core Stage 3 security control: a registry lookup failure (timeout, 403
// on a not-yet-granted scope, tenant-management down, endpoint not
// deployed) must fall back to the last known-good set — and, before any
// success has ever happened, to the EMPTY set — never to "allow
// everything". The control proves the test is meaningful: a broken
// implementation that ignored the error and admitted the origin anyway
// would fail this assertion.
func TestDynamicOriginRegistry_FailsClosed_KeepsLastGoodSetOnError(t *testing.T) {
	lister := &fakeOriginLister{err: errors.New("tenant-management unreachable: dial tcp timeout")}
	r := NewDynamicOriginRegistry(lister, time.Minute, time.Second, zap.NewNop())

	err := r.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh should surface the lister error")
	}
	if r.Contains("https://evil-attacker-controlled.example") {
		t.Fatal("SECURITY: a failed refresh must never admit an origin — this would be fail-OPEN")
	}
	if r.Contains("https://acme.example.com") {
		t.Fatal("a failed refresh before any success must yield the empty set, not any origin")
	}

	// Now a good refresh happens...
	lister.err = nil
	lister.origins = []string{"https://acme.example.com"}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("expected refresh to succeed, got: %v", err)
	}
	if !r.Contains("https://acme.example.com") {
		t.Fatal("a successful refresh should admit the returned origin")
	}

	// ...and THEN a later refresh fails (tenant-management flaps). The
	// previously good set must survive — this is the "keeps last known
	// good" half of fail-closed, distinct from "starts empty".
	lister.err = errors.New("tenant-management 503")
	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("expected the second refresh to fail")
	}
	if !r.Contains("https://acme.example.com") {
		t.Fatal("a later failed refresh must keep the last known-good set, not clear it")
	}
	if r.Contains("https://not-previously-seen.example") {
		t.Fatal("a failed refresh must not admit any new origin")
	}
}

// TestDynamicOriginRegistry_InactiveOrUnlistedTenant_NeverAdmitted proves
// the registry only ever contains what ListActiveOrigins explicitly
// returns — an inactive/unverified tenant's host, which a correct
// TenantOriginLister implementation must never include, is refused. This
// is the registry-layer half of "an unverified host is refused"; the
// tenant-management-specific IsActive filtering itself lives in
// cmd/tenant_management_origin_lister.go (not unit-testable here without
// an HTTP fake), so this test is the control proving the registry does
// not itself widen whatever the lister hands it.
func TestDynamicOriginRegistry_InactiveOrUnlistedTenant_NeverAdmitted(t *testing.T) {
	lister := &fakeOriginLister{origins: []string{"https://active-tenant.example.com"}}
	r := NewDynamicOriginRegistry(lister, time.Minute, time.Second, zap.NewNop())

	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if !r.Contains("https://active-tenant.example.com") {
		t.Fatal("an origin the lister actually returned must be admitted")
	}
	// Control: an inactive/suspended tenant's host was never returned by
	// the lister (a correct lister filters it out before this point), so
	// it must not be admitted just because SOME tenant is active.
	if r.Contains("https://suspended-tenant.example.com") {
		t.Fatal("SECURITY: a host the lister did not return must never be admitted")
	}
}

func TestDynamicOriginRegistry_CaseInsensitive(t *testing.T) {
	lister := &fakeOriginLister{origins: []string{"https://Acme.example.com"}}
	r := NewDynamicOriginRegistry(lister, time.Minute, time.Second, zap.NewNop())
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !r.Contains("https://acme.example.com") {
		t.Fatal("Contains should match case-insensitively")
	}
}
