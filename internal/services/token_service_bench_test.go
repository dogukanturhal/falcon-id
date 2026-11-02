// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// newBenchTokenService returns a TokenService configured for HMAC (HS256) signing
// with no optional dependencies. This is the minimal setup required to exercise
// GenerateAccessToken and ValidateAccessToken without any I/O.
func newBenchTokenService() *TokenService {
	cfg := &config.Config{ //nolint:gosec // test fixture value, not a real credential
		JWTSecret:              "bench-test-secret-32-bytes-pad12",
		JWTIssuer:              "bench-test-issuer",
		AccessTokenExpiry:      15 * time.Minute,
		JWTHMACFallbackEnabled: true,
		// SpiceDB token v2 disabled — benchmarks use legacy/minimal HMAC tokens.
		SpiceDBTokenV2Enabled: false,
	}
	return &TokenService{config: cfg}
}

// benchUser returns a minimal User suitable for token generation benchmarks.
func benchUser() *models.User {
	return &models.User{
		ID:       uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		TenantID: uuid.MustParse("00000000-0000-0000-0000-000000000002"),
		RealmID:  models.DefaultRealmID,
		Username: "bench-user",
		Email:    "bench@example.com",
		IsActive: true,
	}
}

// ---------------------------------------------------------------------------
// BenchmarkGenerateAccessToken — legacy (v0) token generation
// ---------------------------------------------------------------------------

// BenchmarkGenerateAccessToken benchmarks legacy token generation with a
// realistic role and permission set (10 roles, 20 permissions).
func BenchmarkGenerateAccessToken(b *testing.B) {
	svc := newBenchTokenService()
	ctx := context.Background()
	user := benchUser()
	sessionID := uuid.New()

	roles := []string{
		"admin", "crm-manager", "invoicing-user", "pm-member",
		"hr-viewer", "accounting-viewer", "inventory-user",
		"document-editor", "support-agent", "analytics-viewer",
	}
	permissions := []string{
		"crm:contacts:read", "crm:contacts:create", "crm:companies:read",
		"invoicing:invoices:read", "invoicing:invoices:create",
		"pm:projects:read", "pm:tasks:create", "pm:tasks:update",
		"hr:employees:read", "accounting:accounts:read",
		"inventory:items:read", "documents:files:read",
		"support:tickets:read", "analytics:reports:read",
		"crm:leads:read", "crm:leads:create",
		"invoicing:payments:read", "hr:payroll:read",
		"documents:files:create", "analytics:dashboards:read",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		token, err := svc.GenerateAccessToken(ctx, user, sessionID, roles, permissions)
		if err != nil {
			b.Fatalf("GenerateAccessToken failed: %v", err)
		}
		if token == "" {
			b.Fatal("expected non-empty token")
		}
	}
}

// BenchmarkGenerateAccessToken_NoPermissions benchmarks the minimal token case
// (a service account with no permissions — just a session token).
func BenchmarkGenerateAccessToken_NoPermissions(b *testing.B) {
	svc := newBenchTokenService()
	ctx := context.Background()
	user := benchUser()
	sessionID := uuid.New()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		//nolint:errcheck
		_, _ = svc.GenerateAccessToken(ctx, user, sessionID, nil, nil)
	}
}

// BenchmarkGenerateAccessToken_LargePermissionSet benchmarks token generation
// for a super-admin with 100 permissions (worst case for legacy token size).
func BenchmarkGenerateAccessToken_LargePermissionSet(b *testing.B) {
	svc := newBenchTokenService()
	ctx := context.Background()
	user := benchUser()
	sessionID := uuid.New()

	permissions := make([]string, 100)
	for i := range permissions {
		permissions[i] = "module:resource:action_" + string(rune('a'+i%26))
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		//nolint:errcheck
		_, _ = svc.GenerateAccessToken(ctx, user, sessionID, []string{"admin"}, permissions)
	}
}

// ---------------------------------------------------------------------------
// BenchmarkValidateAccessToken — token validation (hot path for every request)
// ---------------------------------------------------------------------------

// BenchmarkValidateAccessToken benchmarks token validation, which is called on
// every authenticated API request. This is the most critical path to optimise.
func BenchmarkValidateAccessToken(b *testing.B) {
	svc := newBenchTokenService()
	ctx := context.Background()
	user := benchUser()
	sessionID := uuid.New()

	roles := []string{"admin", "crm-manager"}
	permissions := []string{"crm:contacts:read", "crm:contacts:create"}

	// Generate a valid token once outside the benchmark loop.
	token, err := svc.GenerateAccessToken(ctx, user, sessionID, roles, permissions)
	if err != nil {
		b.Fatalf("setup: GenerateAccessToken failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		claims, err := svc.ValidateAccessToken(token)
		if err != nil {
			b.Fatalf("ValidateAccessToken failed: %v", err)
		}
		if claims == nil {
			b.Fatal("expected non-nil claims")
		}
	}
}

// BenchmarkValidateAccessToken_Parallel measures throughput under concurrent
// validation load — representative of a high-traffic API gateway.
func BenchmarkValidateAccessToken_Parallel(b *testing.B) {
	svc := newBenchTokenService()
	ctx := context.Background()
	user := benchUser()
	sessionID := uuid.New()

	token, err := svc.GenerateAccessToken(ctx, user, sessionID,
		[]string{"admin"},
		[]string{"crm:contacts:read"},
	)
	if err != nil {
		b.Fatalf("setup: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			//nolint:errcheck
			_, _ = svc.ValidateAccessToken(token)
		}
	})
}

// BenchmarkValidateAccessToken_Invalid benchmarks rejection of an invalid token.
// This should be fast since the JWT library fails early on signature mismatch.
func BenchmarkValidateAccessToken_Invalid(b *testing.B) {
	svc := newBenchTokenService()

	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.invalid-signature" //nolint:gosec // test fixture value, not a real credential

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		//nolint:errcheck
		_, _ = svc.ValidateAccessToken(invalidToken)
	}
}

// ---------------------------------------------------------------------------
// BenchmarkGenerateTokenPair — combined generation (access + refresh concept)
// ---------------------------------------------------------------------------

// BenchmarkGenerateAccessTokenWithOptions benchmarks the full
// GenerateAccessTokenWithOptions path (the real entrypoint for token generation
// with realm context), which underpins every login response.
func BenchmarkGenerateAccessTokenWithOptions(b *testing.B) {
	svc := newBenchTokenService()
	ctx := context.Background()
	user := benchUser()
	sessionID := uuid.New()

	roles := []string{"tenant-admin", "crm-manager"}
	permissions := []string{"crm:contacts:read", "invoicing:invoices:read"}

	opts := TokenGenerationOptions{
		RealmID:   models.DefaultRealmID,
		RealmSlug: "default",
		RealmType: string(models.RealmTypeShared),
		Scope:     "tenant",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		token, err := svc.GenerateAccessTokenWithOptions(ctx, user, sessionID, roles, permissions, opts)
		if err != nil {
			b.Fatalf("GenerateAccessTokenWithOptions failed: %v", err)
		}
		if token == "" {
			b.Fatal("expected non-empty token")
		}
	}
}

// BenchmarkValidateAndGenerate benchmarks the round-trip: generate a token, then
// validate it. Represents the login → first API call pattern.
func BenchmarkValidateAndGenerate(b *testing.B) {
	svc := newBenchTokenService()
	ctx := context.Background()
	user := benchUser()

	roles := []string{"admin"}
	permissions := []string{"crm:contacts:read"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		sessionID := uuid.New()

		token, err := svc.GenerateAccessToken(ctx, user, sessionID, roles, permissions)
		if err != nil {
			b.Fatalf("generate: %v", err)
		}

		claims, err := svc.ValidateAccessToken(token)
		if err != nil {
			b.Fatalf("validate: %v", err)
		}
		_ = claims
	}
}
