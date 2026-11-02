// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// fakeTenantConfigStore is a no-DB stand-in for tenantConfigStore: every
// tenant/key lookup misses (mirrors an empty iam_tenant_configs table, i.e.
// no admin has configured a per-tenant override), which is exactly the
// state that must fall through to FrontendURL's app-host resolver.
type fakeTenantConfigStore struct{}

func (fakeTenantConfigStore) Get(_ context.Context, _ uuid.UUID, _ string) (*models.TenantConfig, error) {
	return nil, nil
}

func (fakeTenantConfigStore) GetByScope(_ context.Context, _ uuid.UUID, _, _ *uuid.UUID, _ string) (*models.TenantConfig, error) {
	return nil, nil
}

func (fakeTenantConfigStore) UpsertByScope(_ context.Context, _ repositories.UpsertByScopeParams) error {
	return nil
}

// fakeAppHostResolver lets tests control ResolveAppHost's return without a
// real tenant-management HTTP call.
type fakeAppHostResolver struct {
	host string
	err  error
	// calls counts invocations so cache-hit tests can assert the resolver
	// is not called again after the first successful resolution.
	calls int
}

func (f *fakeAppHostResolver) ResolveAppHost(_ context.Context, _ uuid.UUID) (string, error) {
	f.calls++
	return f.host, f.err
}

func newTestConfigProvider(t *testing.T, staticFrontendURL string) *ConfigProvider {
	t.Helper()
	cp, err := NewConfigProvider(
		&config.Config{FrontendURL: staticFrontendURL},
		fakeTenantConfigStore{},
		nil, // no Redis in this test — exercises the L1-only path
		zap.NewNop(),
		DefaultConfigProviderConfig(),
	)
	if err != nil {
		t.Fatalf("NewConfigProvider: %v", err)
	}
	return cp
}

// TestFrontendURL_NullAppHost_YieldsTodaysValue mirrors the contract platform-
// core !80 describes: a tenant with no local override and a NULL
// tenants.app_host resolves server-side (in tenant-management) to
// "<slug>.<apex>" — "today's value" — before falcon-id ever sees it. From
// ConfigProvider's side that is indistinguishable from any other resolved
// host string, so this test simulates exactly that: the resolver returns
// the slug.apex host tenant-management would compute for a NULL app_host,
// and FrontendURL must surface it (scheme-qualified) instead of the static
// default.
func TestFrontendURL_NullAppHost_YieldsTodaysValue(t *testing.T) {
	cp := newTestConfigProvider(t, "http://localhost:3000")
	resolver := &fakeAppHostResolver{host: "acme.example.com"}
	cp.SetAppHostResolver(resolver)

	got := cp.FrontendURL(context.Background(), uuid.New())

	want := "https://acme.example.com"
	if got != want {
		t.Fatalf("FrontendURL = %q, want %q", got, want)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver called %d times, want 1", resolver.calls)
	}
}

// TestFrontendURL_AppHostResolved_PopulatesCache asserts the resolved value
// feeds the existing L1 cache chain rather than being re-fetched on every
// call — a per-request tenant-management round trip on every email send
// would be the "bypass the cache chain" failure mode Stage 2 explicitly
// rules out.
func TestFrontendURL_AppHostResolved_PopulatesCache(t *testing.T) {
	cp := newTestConfigProvider(t, "http://localhost:3000")
	resolver := &fakeAppHostResolver{host: "acme.example.com"}
	cp.SetAppHostResolver(resolver)

	tenantID := uuid.New()
	first := cp.FrontendURL(context.Background(), tenantID)
	second := cp.FrontendURL(context.Background(), tenantID)

	if first != second {
		t.Fatalf("FrontendURL not stable across calls: %q then %q", first, second)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver called %d times across two reads of the same tenant, want 1 (cache should have served the second read)", resolver.calls)
	}
}

// TestFrontendURL_ResolverUnavailable_FallsBackToStaticDefault is the
// control for the above: when the resolver errors (tenant-management down,
// scope not yet granted, endpoint not deployed), FrontendURL must degrade
// to the static default — never an empty string, never a panic.
func TestFrontendURL_ResolverUnavailable_FallsBackToStaticDefault(t *testing.T) {
	cp := newTestConfigProvider(t, "http://localhost:3000")
	resolver := &fakeAppHostResolver{err: errors.New("tenant-management app-host read failed (403): insufficient_scope")}
	cp.SetAppHostResolver(resolver)

	got := cp.FrontendURL(context.Background(), uuid.New())

	if got != "http://localhost:3000" {
		t.Fatalf("FrontendURL = %q, want static default %q", got, "http://localhost:3000")
	}
}

// TestFrontendURL_NoResolverConfigured_BehavesUnchanged is the pre-Stage-2
// control: with no resolver wired at all (SetAppHostResolver never called —
// e.g. TENANT_MANAGEMENT_INTERNAL_URL unset), behaviour must be identical
// to before this change.
func TestFrontendURL_NoResolverConfigured_BehavesUnchanged(t *testing.T) {
	cp := newTestConfigProvider(t, "http://localhost:3000")

	got := cp.FrontendURL(context.Background(), uuid.New())

	if got != "http://localhost:3000" {
		t.Fatalf("FrontendURL = %q, want static default %q", got, "http://localhost:3000")
	}
}

func TestAppHostToFrontendURL(t *testing.T) {
	cases := map[string]string{
		"acme.example.com":      "https://acme.example.com",
		"https://example.com":   "https://example.com",
		"http://localhost:3000": "http://localhost:3000",
	}
	for in, want := range cases {
		if got := appHostToFrontendURL(in); got != want {
			t.Errorf("appHostToFrontendURL(%q) = %q, want %q", in, got, want)
		}
	}
}
