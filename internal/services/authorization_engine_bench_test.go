// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// Benchmark-local SpiceDB mock — returns immediately with configurable result.
// Kept in this file to avoid polluting the main test-mock set.
// ---------------------------------------------------------------------------

// benchSpiceDBChecker is a zero-overhead SpiceDB mock used exclusively in
// benchmarks. All calls return allowed=true and nil error without any heap
// allocation beyond the return value.
type benchSpiceDBChecker struct {
	allowed bool
}

func (b *benchSpiceDBChecker) CheckPermission(_ context.Context, _, _ uuid.UUID, _, _, _ string) (bool, error) {
	return b.allowed, nil
}

func (b *benchSpiceDBChecker) CheckPermissionConsistent(_ context.Context, _, _ uuid.UUID, _, _, _, _ string) (bool, error) {
	return b.allowed, nil
}

func (b *benchSpiceDBChecker) CheckBulkPermissions(_ context.Context, _, _ uuid.UUID, _ string, objectIDs []string, _ string) (map[string]bool, error) {
	result := make(map[string]bool, len(objectIDs))
	for _, id := range objectIDs {
		result[id] = b.allowed
	}
	return result, nil
}

// benchmarkOPAService is a disabled OPA service (IsEnabled returns false) so
// the engine always routes through the SpiceDB path.
type benchmarkOPAService struct{}

func (n *benchmarkOPAService) IsEnabled() bool { return false }
func (n *benchmarkOPAService) EvaluatePermission(_ context.Context, _, _ uuid.UUID, _, _ string, _, _, _ []string, _, _, _, _ string, _ map[string]interface{}, _, _, _ string) (*AuthzResult, error) {
	return &AuthzResult{Allowed: true}, nil
}

// newBenchEngine returns a fully constructed AuthorizationEngine backed by the
// no-op dependencies above. The engine is ready for single-goroutine use or
// concurrent use from multiple goroutines (the engine itself is concurrent-safe).
func newBenchEngine(allowed bool) AuthorizationEngine {
	return NewAuthorizationEngine(
		nil, // permissionRepo — not needed when OPA is disabled
		&benchmarkOPAService{},
		nil, // auditService
		nil, // sessionCache
		&benchSpiceDBChecker{allowed: allowed},
		&config.Config{},
	)
}

// ---------------------------------------------------------------------------
// BenchmarkCheckPermission — module-level permission (hot path)
// ---------------------------------------------------------------------------

// BenchmarkCheckPermission measures the per-call overhead of CheckPermission
// through the full engine (validation → SpiceDB mock → metrics → result).
// Target: well under 100 µs per operation in real deployments where SpiceDB
// returns in ~1 ms; this benchmark isolates engine overhead only.
func BenchmarkCheckPermission(b *testing.B) {
	engine := newBenchEngine(true)
	ctx := context.Background()

	userID := uuid.New()
	tenantID := uuid.New()

	req := PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := engine.CheckPermission(ctx, req)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			b.Fatal("expected allowed=true")
		}
	}
}

// BenchmarkCheckPermission_Denied benchmarks the denial path (SpiceDB returns false).
func BenchmarkCheckPermission_Denied(b *testing.B) {
	engine := newBenchEngine(false)
	ctx := context.Background()

	req := PermissionRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		Permission: "invoicing:invoices:delete",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		//nolint:errcheck
		_, _ = engine.CheckPermission(ctx, req)
	}
}

// BenchmarkCheckPermission_Parallel measures throughput under concurrent load.
// This is representative of API gateway deployments with many concurrent requests.
func BenchmarkCheckPermission_Parallel(b *testing.B) {
	engine := newBenchEngine(true)
	ctx := context.Background()

	req := PermissionRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		Permission: "crm:contacts:read",
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			//nolint:errcheck
			_, _ = engine.CheckPermission(ctx, req)
		}
	})
}

// ---------------------------------------------------------------------------
// BenchmarkBatchCheckPermissions — UI rendering path
// ---------------------------------------------------------------------------

// BenchmarkBatchCheckPermissions_10 benchmarks a batch of 10 permissions —
// typical for rendering a module navigation sidebar.
func BenchmarkBatchCheckPermissions_10(b *testing.B) {
	engine := newBenchEngine(true)
	ctx := context.Background()

	userID := uuid.New()
	tenantID := uuid.New()

	permissions := []string{
		"crm:contacts:read",
		"crm:companies:read",
		"invoicing:invoices:read",
		"invoicing:invoices:create",
		"pm:projects:read",
		"pm:tasks:create",
		"accounting:accounts:read",
		"hr:employees:read",
		"documents:files:read",
		"crm:leads:read",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result, err := engine.BatchCheckPermissions(ctx, userID, tenantID, permissions)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		if len(result) != len(permissions) {
			b.Fatalf("expected %d results, got %d", len(permissions), len(result))
		}
	}
}

// BenchmarkBatchCheckPermissions_50 benchmarks a large batch of 50 permissions —
// representative of a power user with broad module access.
func BenchmarkBatchCheckPermissions_50(b *testing.B) {
	engine := newBenchEngine(true)
	ctx := context.Background()

	userID := uuid.New()
	tenantID := uuid.New()

	permissions := make([]string, 50)
	modules := []string{"crm", "invoicing", "pm", "accounting", "hr", "documents", "inventory", "support", "marketing", "analytics"}
	actions := []string{"read", "create", "update", "delete", "export"}
	for i := range permissions {
		mod := modules[i%len(modules)]
		action := actions[i%len(actions)]
		permissions[i] = mod + ":resources:" + action
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		//nolint:errcheck
		_, _ = engine.BatchCheckPermissions(ctx, userID, tenantID, permissions)
	}
}

// ---------------------------------------------------------------------------
// BenchmarkCheckResourcePermission — object-level permission
// ---------------------------------------------------------------------------

// BenchmarkCheckResourcePermission benchmarks the resource-level check used
// for row-level authorization (e.g., "can user view invoice #123?").
func BenchmarkCheckResourcePermission(b *testing.B) {
	engine := newBenchEngine(true)
	ctx := context.Background()

	req := ResourcePermissionRequest{
		UserID:       uuid.New(),
		TenantID:     uuid.New(),
		ResourceType: "invoice",
		ResourceID:   uuid.New().String(),
		Action:       "view",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		//nolint:errcheck
		_, _ = engine.CheckResourcePermission(ctx, req)
	}
}

// ---------------------------------------------------------------------------
// BenchmarkCheckPermission_NilSpiceDB — fail-closed path overhead
// ---------------------------------------------------------------------------

// BenchmarkCheckPermission_NilSpiceDB benchmarks the fail-closed path when
// SpiceDB is unavailable. This should be very fast (no I/O, just error construction).
func BenchmarkCheckPermission_NilSpiceDB(b *testing.B) {
	// Engine with nil SpiceDB client — will always deny (fail-closed)
	engine := NewAuthorizationEngine(
		nil,
		&benchmarkOPAService{},
		nil,
		nil,
		nil, // nil SpiceDB
		&config.Config{},
	)

	ctx := context.Background()
	req := PermissionRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		Permission: "crm:contacts:read",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		//nolint:errcheck
		_, _ = engine.CheckPermission(ctx, req)
	}
}
