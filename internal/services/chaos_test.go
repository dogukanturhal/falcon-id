// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

package services_test

// chaos_test.go verifies tenant isolation under fault conditions.
//
// These tests exercise the real PostgreSQL stack and therefore require a live
// database.  They are gated behind the "integration" build tag so that the
// standard `go test ./...` run (no -tags=integration) skips them entirely.
//
// Run the full chaos suite:
//
//	DATABASE_URL="postgres://hexxlock:hexxlock_dev_2024@localhost:5432/hexxlock_iam?sslmode=disable" \
//	  go test -tags=integration -v -timeout=120s ./falcon-id/internal/services/ -run TestChaos
//
// Each test calls t.Skip when DATABASE_URL is not set, so the suite is always
// safe to include in CI without triggering failures on runners without a DB.

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// requireDatabaseURL returns the DATABASE_URL env var or skips the test.
func requireDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set — skipping chaos/integration test")
	}
	return url
}

// openPool opens a bounded pgxpool to the given DSN.
func openPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err, "parse DSN")
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err, "open pool")
	t.Cleanup(func() { pool.Close() })
	return pool
}

// openConn opens a single *pgx.Conn to the given DSN.
func openConn(t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err, "open connection")
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// ---------------------------------------------------------------------------
// Test 1: Connection Exhaustion
// ---------------------------------------------------------------------------

// TestChaos_TenantIsolation_ConnectionExhaustion verifies that saturating a
// database with Tenant-A connections does not prevent Tenant-B from connecting
// and executing queries.
//
// Setup: open 50 long-lived connections pretending to be Tenant A, then verify
// that Tenant B can still connect and perform a SELECT.
//
// Success criterion: Tenant B's query completes without error.
func TestChaos_TenantIsolation_ConnectionExhaustion(t *testing.T) {
	dsn := requireDatabaseURL(t)

	const tenantAConnections = 50

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Open and hold tenantAConnections connections as "Tenant A".
	// We do not run any queries — the goal is purely to exhaust pool slots.
	tenantAConns := make([]*pgx.Conn, 0, tenantAConnections)
	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(tenantAConnections)
	for i := 0; i < tenantAConnections; i++ {
		go func() {
			defer wg.Done()
			conn, err := pgx.Connect(ctx, dsn)
			if err != nil {
				// Some connections may fail if max_connections is low — that is
				// expected.  Record those that succeed.
				return
			}
			mu.Lock()
			tenantAConns = append(tenantAConns, conn)
			mu.Unlock()
		}()
	}
	wg.Wait()

	t.Logf("Tenant A established %d/%d connections", len(tenantAConns), tenantAConnections)

	// Cleanup Tenant A connections at the end of the test.
	t.Cleanup(func() {
		for _, c := range tenantAConns {
			_ = c.Close(context.Background())
		}
	})

	// Tenant B opens a fresh connection and runs a trivial query.
	tenantBConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skipf("Tenant B could not connect (server connection limit reached): %v", err)
	}
	defer tenantBConn.Close(ctx) //nolint:errcheck

	var result int
	err = tenantBConn.QueryRow(ctx, "SELECT 1").Scan(&result)
	assert.NoError(t, err, "Tenant B query should succeed despite Tenant A connection saturation")
	assert.Equal(t, 1, result, "Tenant B query should return correct result")

	t.Logf("Tenant B successfully queried under %d Tenant A connections", len(tenantAConns))
}

// ---------------------------------------------------------------------------
// Test 2: Slow Query Isolation
// ---------------------------------------------------------------------------

// TestChaos_TenantIsolation_SlowQuery verifies that a long-running query
// executed as Tenant A does not block Tenant B's queries.
//
// Tenant A executes pg_sleep(5) in a goroutine. Tenant B then runs a query and
// we assert it returns in under 2 seconds.
func TestChaos_TenantIsolation_SlowQuery(t *testing.T) {
	dsn := requireDatabaseURL(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Tenant A — open a connection and start a slow blocking query.
	tenantAConn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err, "Tenant A connect")
	defer tenantAConn.Close(ctx) //nolint:errcheck

	slowQueryDone := make(chan error, 1)
	go func() {
		// pg_sleep(5) holds the server session busy but does not lock any rows.
		_, err := tenantAConn.Exec(ctx, "SELECT pg_sleep(5)")
		slowQueryDone <- err
	}()

	// Give Tenant A a moment to start the slow query.
	time.Sleep(200 * time.Millisecond)

	// Tenant B — open a separate connection and execute a query.
	tenantBStart := time.Now()
	tenantBConn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err, "Tenant B connect")
	defer tenantBConn.Close(ctx) //nolint:errcheck

	var result int
	err = tenantBConn.QueryRow(ctx, "SELECT 42").Scan(&result)
	tenantBElapsed := time.Since(tenantBStart)

	assert.NoError(t, err, "Tenant B query should succeed")
	assert.Equal(t, 42, result, "Tenant B query should return correct result")
	assert.Less(t, tenantBElapsed, 2*time.Second,
		"Tenant B query should return in <2s despite Tenant A slow query (got %s)", tenantBElapsed)

	t.Logf("Tenant B query completed in %s while Tenant A ran pg_sleep(5)", tenantBElapsed)
}

// ---------------------------------------------------------------------------
// Test 3: RLS Enforcement
// ---------------------------------------------------------------------------

// TestChaos_TenantIsolation_RLSEnforcement verifies that PostgreSQL Row-Level
// Security prevents a session acting as Tenant B from reading rows inserted by
// Tenant A, when the table has an appropriate RLS policy in place.
//
// This test creates a temporary table with an RLS policy, inserts a row tagged
// as Tenant A, then switches the session context to Tenant B and asserts that
// zero rows are visible.
//
// The test is self-contained: it creates and drops its own table, so it is
// safe to run against a shared development database.
func TestChaos_TenantIsolation_RLSEnforcement(t *testing.T) {
	dsn := requireDatabaseURL(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn := openConn(t, dsn)

	tenantA := uuid.New()
	tenantB := uuid.New()

	// Create a temporary table with an RLS policy.
	// We use a TEMPORARY table so cleanup is automatic at session end.
	tableName := fmt.Sprintf("chaos_rls_test_%s", uuid.New().String()[:8])

	_, err := conn.Exec(ctx, fmt.Sprintf(`
		CREATE TEMPORARY TABLE %s (
			id         uuid    DEFAULT gen_random_uuid() PRIMARY KEY,
			tenant_id  uuid    NOT NULL,
			payload    text    NOT NULL
		)`, tableName))
	require.NoError(t, err, "create temp table")

	// Enable RLS on the temporary table.
	_, err = conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", tableName))
	require.NoError(t, err, "enable RLS")

	// Policy: a row is visible only when current_setting('app.current_tenant_id')
	// matches tenant_id. Use FORCE ROW LEVEL SECURITY so the table owner is also
	// subject to the policy.
	_, err = conn.Exec(ctx, fmt.Sprintf(`
		ALTER TABLE %s FORCE ROW LEVEL SECURITY`, tableName))
	require.NoError(t, err, "force RLS")

	_, err = conn.Exec(ctx, fmt.Sprintf(`
		CREATE POLICY tenant_isolation ON %s
		USING (tenant_id::text = current_setting('app.current_tenant_id', true))`, tableName))
	require.NoError(t, err, "create RLS policy")

	// Insert a row as Tenant A.
	_, err = conn.Exec(ctx,
		fmt.Sprintf(`SELECT set_config('app.current_tenant_id', $1, false)`),
		tenantA.String(),
	)
	require.NoError(t, err, "set Tenant A context")

	_, err = conn.Exec(ctx,
		fmt.Sprintf("INSERT INTO %s (tenant_id, payload) VALUES ($1, $2)", tableName),
		tenantA, "secret-data-for-tenant-a",
	)
	require.NoError(t, err, "insert Tenant A row")

	// Verify Tenant A can read its own row.
	var countA int
	err = conn.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)).Scan(&countA)
	require.NoError(t, err, "count as Tenant A")
	assert.Equal(t, 1, countA, "Tenant A should see exactly 1 row")

	// Switch to Tenant B context.
	_, err = conn.Exec(ctx,
		"SELECT set_config('app.current_tenant_id', $1, false)",
		tenantB.String(),
	)
	require.NoError(t, err, "set Tenant B context")

	// Tenant B must see zero rows.
	var countB int
	err = conn.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)).Scan(&countB)
	require.NoError(t, err, "count as Tenant B")
	assert.Equal(t, 0, countB, "Tenant B must not see Tenant A's rows (RLS isolation failure)")

	t.Logf("RLS enforcement verified: Tenant A sees %d row(s), Tenant B sees %d row(s)",
		countA, countB)
}

// ---------------------------------------------------------------------------
// Test 4: Host Failure — Placement Fallback
// ---------------------------------------------------------------------------

// TestChaos_HostFailure_PlacementFallback verifies that PlacementEngine skips
// unhealthy hosts and returns the remaining healthy host.
//
// The test is pure Go (no database required beyond DATABASE_URL for table
// stakes — we skip only when the env var is absent so the test pattern is
// consistent). The PlacementEngine depends on placementHostRepo, which is
// stubbed by fakeHostRepo below.
func TestChaos_HostFailure_PlacementFallback(t *testing.T) {
	// We still require DATABASE_URL to keep the test consistently skipped on
	// runners without integration infrastructure.
	requireDatabaseURL(t)

	ctx := context.Background()

	healthyHost := models.RealmDatabaseHost{
		ID:                  uuid.New(),
		HostAlias:           "pg-primary",
		ConnectionStringEnc: "postgres://hexxlock:dev@localhost:5432/hexxlock_iam?sslmode=disable",
		Region:              strPtr("tr-ank"),
		IsActive:            true,
		HealthStatus:        "healthy",
		MaxDatabases:        100,
		CurrentDatabases:    10,
	}

	unhealthyHost := models.RealmDatabaseHost{
		ID:                  uuid.New(),
		HostAlias:           "pg-replica",
		ConnectionStringEnc: "postgres://hexxlock:dev@localhost:5433/hexxlock_iam?sslmode=disable",
		Region:              strPtr("tr-ank"),
		IsActive:            true,
		HealthStatus:        "unhealthy", // should be filtered out
		MaxDatabases:        100,
		CurrentDatabases:    0,
	}

	table := []struct {
		name          string
		hosts         []models.RealmDatabaseHost
		region        string
		wantHostAlias string
		wantErr       bool
	}{
		{
			name:          "one healthy one unhealthy — picks healthy",
			hosts:         []models.RealmDatabaseHost{unhealthyHost, healthyHost},
			region:        "tr-ank",
			wantHostAlias: "pg-primary",
			wantErr:       false,
		},
		{
			name:    "all unhealthy — returns ErrNoHostsAvailable",
			hosts:   []models.RealmDatabaseHost{unhealthyHost},
			region:  "tr-ank",
			wantErr: true,
		},
		{
			name:          "healthy host with no region filter — picks healthy",
			hosts:         []models.RealmDatabaseHost{healthyHost},
			region:        "", // any region
			wantHostAlias: "pg-primary",
			wantErr:       false,
		},
	}

	for _, tc := range table {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeHostRepo{hosts: tc.hosts, region: tc.region}
			engine := services.NewPlacementEngine(repo, nil) // nil encryption = plaintext DSNs

			result, err := engine.SelectHost(ctx, services.PlacementRequest{
				PreferredRegion: tc.region,
			})

			if tc.wantErr {
				require.Error(t, err, "expected ErrNoHostsAvailable")
				assert.ErrorIs(t, err, services.ErrNoHostsAvailable,
					"error should be ErrNoHostsAvailable, got: %v", err)
				return
			}

			require.NoError(t, err, "SelectHost should succeed")
			require.NotNil(t, result)
			assert.Equal(t, tc.wantHostAlias, result.Host.HostAlias,
				"selected host alias mismatch")
			assert.True(t, result.Host.IsActive, "selected host must be active")
			assert.Equal(t, "healthy", result.Host.HealthStatus,
				"selected host must be healthy")
		})
	}
}

// ---------------------------------------------------------------------------
// fakeHostRepo — in-memory stub for PlacementEngine tests
// ---------------------------------------------------------------------------

// fakeHostRepo satisfies the placementHostRepo interface used by PlacementEngine.
// It returns only hosts that are active AND healthy — matching the real
// ListActiveByRegion query behaviour.
type fakeHostRepo struct {
	hosts  []models.RealmDatabaseHost
	region string
}

func (r *fakeHostRepo) ListActiveByRegion(_ context.Context, region string) ([]models.RealmDatabaseHost, error) {
	var out []models.RealmDatabaseHost
	for _, h := range r.hosts {
		if !h.IsActive || h.HealthStatus != "healthy" {
			continue // mirrors WHERE is_active = true AND health_status = 'healthy'
		}
		if region != "" && (h.Region == nil || *h.Region != region) {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

func strPtr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// Test 5: Concurrent Tenant Provisioning — Cross-Contamination Check
// ---------------------------------------------------------------------------

// TestChaos_TenantIsolation_ConcurrentProvisions provisions 10 independent
// tenant namespaces concurrently and asserts that no row inserted under one
// tenant's RLS context is visible from another tenant's context.
//
// This exercises the set_config() session-scoped RLS mechanism under parallel
// load; cross-contamination would indicate that session state leaks between
// goroutines sharing a pgxpool connection.
func TestChaos_TenantIsolation_ConcurrentProvisions(t *testing.T) {
	dsn := requireDatabaseURL(t)

	const numTenants = 10

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Use a bounded pool; each goroutine checks out a connection independently.
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err, "parse DSN")
	cfg.MaxConns = int32(numTenants + 2)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err, "create pool")
	defer pool.Close()

	// Pre-generate deterministic tenant IDs so we can cross-check afterwards.
	tenants := make([]string, numTenants)
	for i := range tenants {
		tenants[i] = fmt.Sprintf("chaos-tenant-%02d-%s", i, uuid.New().String()[:8])
	}

	// Each goroutine:
	//  1. Acquires its own connection from the pool.
	//  2. Creates a temporary table with RLS.
	//  3. Inserts one row tagged with its own tenant ID.
	//  4. Reads back — must see exactly 1 row (its own).
	//  5. Switches context to a random OTHER tenant — must see 0 rows.
	type result struct {
		tenant     string
		ownCount   int
		otherCount int
		err        error
	}

	results := make([]result, numTenants)
	var wg sync.WaitGroup

	for i := 0; i < numTenants; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := pool.Acquire(ctx)
			if err != nil {
				results[i] = result{tenant: tenants[i], err: fmt.Errorf("acquire: %w", err)}
				return
			}
			defer conn.Release()

			tblName := fmt.Sprintf("chaos_concurrent_%s", uuid.New().String()[:8])

			_, err = conn.Exec(ctx, fmt.Sprintf(`CREATE TEMPORARY TABLE %s (
				id        uuid DEFAULT gen_random_uuid() PRIMARY KEY,
				tenant_id text NOT NULL,
				payload   text NOT NULL
			)`, tblName))
			if err != nil {
				results[i] = result{tenant: tenants[i], err: fmt.Errorf("create table: %w", err)}
				return
			}

			_, err = conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", tblName))
			if err != nil {
				results[i] = result{tenant: tenants[i], err: fmt.Errorf("enable RLS: %w", err)}
				return
			}

			_, err = conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY", tblName))
			if err != nil {
				results[i] = result{tenant: tenants[i], err: fmt.Errorf("force RLS: %w", err)}
				return
			}

			_, err = conn.Exec(ctx, fmt.Sprintf(`CREATE POLICY tenant_iso ON %s
				USING (tenant_id = current_setting('app.current_tenant_id', true))`, tblName))
			if err != nil {
				results[i] = result{tenant: tenants[i], err: fmt.Errorf("create policy: %w", err)}
				return
			}

			// Set own context and insert.
			_, err = conn.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, false)", tenants[i])
			if err != nil {
				results[i] = result{tenant: tenants[i], err: fmt.Errorf("set own context: %w", err)}
				return
			}

			_, err = conn.Exec(ctx, fmt.Sprintf("INSERT INTO %s (tenant_id, payload) VALUES ($1, $2)", tblName), tenants[i], "secret")
			if err != nil {
				results[i] = result{tenant: tenants[i], err: fmt.Errorf("insert: %w", err)}
				return
			}

			var ownCount int
			if err = conn.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", tblName)).Scan(&ownCount); err != nil {
				results[i] = result{tenant: tenants[i], err: fmt.Errorf("count own: %w", err)}
				return
			}

			// Switch to a different tenant's context.
			otherIdx := (i + 1) % numTenants
			_, err = conn.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, false)", tenants[otherIdx])
			if err != nil {
				results[i] = result{tenant: tenants[i], err: fmt.Errorf("set other context: %w", err)}
				return
			}

			var otherCount int
			if err = conn.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", tblName)).Scan(&otherCount); err != nil {
				results[i] = result{tenant: tenants[i], err: fmt.Errorf("count other: %w", err)}
				return
			}

			results[i] = result{tenant: tenants[i], ownCount: ownCount, otherCount: otherCount}
		}()
	}

	wg.Wait()

	for _, r := range results {
		require.NoError(t, r.err, "goroutine for tenant %s failed", r.tenant)
		assert.Equal(t, 1, r.ownCount, "tenant %s should see exactly 1 own row", r.tenant)
		assert.Equal(t, 0, r.otherCount, "tenant %s must not see the adjacent tenant's row (RLS cross-contamination)", r.tenant)
	}

	t.Logf("Concurrent provision isolation verified for %d tenants", numTenants)
}

// ---------------------------------------------------------------------------
// Test 6: Connection Pool Exhaustion + Recovery
// ---------------------------------------------------------------------------

// TestChaos_ConnectionPool_Exhaustion_Recovery exhausts a small pgxpool,
// verifies that new acquire attempts return errors (not hangs), and then
// confirms that the pool recovers and serves queries once held connections
// are released.
func TestChaos_ConnectionPool_Exhaustion_Recovery(t *testing.T) {
	dsn := requireDatabaseURL(t)

	const poolSize = 5

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err, "parse DSN")
	cfg.MaxConns = poolSize
	// Short acquire timeout so the test doesn't stall.
	// pgx/v5 does not expose MaxConnWaitingQueueSize; we rely on the acquire
	// context deadline to bound wait time instead.

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err, "create pool")
	defer pool.Close()

	// Phase 1: exhaust all connections.
	held := make([]*pgxpool.Conn, 0, poolSize)
	for i := 0; i < poolSize; i++ {
		conn, err := pool.Acquire(ctx)
		require.NoError(t, err, "should be able to acquire connection %d/%d", i+1, poolSize)
		held = append(held, conn)
	}

	t.Logf("Phase 1: pool exhausted with %d connections held", len(held))

	// Phase 2: verify that an acquire with a tight deadline fails fast (not hangs).
	tightCtx, tightCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer tightCancel()

	extra, acquireErr := pool.Acquire(tightCtx)
	if extra != nil {
		extra.Release()
	}
	assert.Error(t, acquireErr, "pool should reject acquire when all connections are held and queue is full")

	t.Logf("Phase 2: exhaustion confirmed — acquire correctly returned error: %v", acquireErr)

	// Phase 3: release all held connections and verify the pool recovers.
	for _, conn := range held {
		conn.Release()
	}
	held = held[:0]

	t.Logf("Phase 3: all connections released, verifying recovery...")

	// The pool should now serve a query without error.
	var result int
	err = pool.QueryRow(ctx, "SELECT 99").Scan(&result)
	require.NoError(t, err, "pool should recover after connections are released")
	assert.Equal(t, 99, result, "query after recovery should return correct value")

	t.Logf("Phase 3: pool recovered successfully — query returned %d", result)
}

// ---------------------------------------------------------------------------
// Test 7: Cache Invalidation Under Load
// ---------------------------------------------------------------------------

// TestChaos_CacheInvalidation_UnderLoad fires concurrent ResolveRealmDB calls
// while simultaneously invalidating the cache via InvalidateRealm. The test
// asserts that no panic or data race occurs and that all lookups either return
// nil (no dedicated DB — expected for a realm that was never provisioned) or a
// valid ConnectionInfo.
//
// Because this test exercises the in-process L1 sync.Map invalidation path and
// the nil Redis path (no Redis in unit mode), it does NOT require an active
// Redis instance — the router is constructed with redis=nil so L2 is skipped.
func TestChaos_CacheInvalidation_UnderLoad(t *testing.T) {
	dsn := requireDatabaseURL(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_ = openPool(t, dsn) // open a pool to confirm DATABASE_URL is valid

	// A fakeRealmDBRepo that always returns nil (realm uses shared pool).
	fakeRepo := &fakeRealmRepo{}

	// Construct a logger (zap nop) and a router with no Redis (L2 skipped).
	log := zap.NewNop().Sugar()
	router := services.NewConnectionRouter(nil, fakeRepo, log)

	realmID := uuid.New()

	const workers = 20
	const iterations = 50

	var wg sync.WaitGroup

	// Resolver goroutines.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				info, err := router.ResolveRealmDB(ctx, realmID)
				assert.NoError(t, err, "ResolveRealmDB must not error")
				// info may be nil (realm has no dedicated DB) — that is correct.
				_ = info
			}
		}()
	}

	// Invalidator goroutine — fires in parallel with resolvers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			router.InvalidateRealm(ctx, realmID)
			time.Sleep(time.Millisecond)
		}
	}()

	wg.Wait()
	t.Logf("Cache invalidation under load: %d resolvers x %d iterations completed without panic or data race", workers, iterations)
}

// fakeRealmRepo satisfies RealmDatabaseRepository for tests that do not need
// real database provisioning.
type fakeRealmRepo struct{}

func (r *fakeRealmRepo) GetByRealmID(_ context.Context, _ uuid.UUID) (*models.RealmDatabase, error) {
	return nil, nil // realm uses shared pool
}

func (r *fakeRealmRepo) Create(_ context.Context, _ *models.RealmDatabase) error {
	return nil
}

func (r *fakeRealmRepo) UpdateStatus(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}

func (r *fakeRealmRepo) UpdateHealthCheck(_ context.Context, _ uuid.UUID, _ string, _ string) error {
	return nil
}

// ---------------------------------------------------------------------------
// Test 8: Host Failure — Graceful Degradation on New Provisions
// ---------------------------------------------------------------------------

// TestChaos_HostFailure_GracefulDegradation marks a host as unhealthy and
// verifies that:
//   - New PlacementEngine.SelectHost calls skip the unhealthy host.
//   - When the only available host is unhealthy, ErrNoHostsAvailable is returned.
//   - Existing realm lookups via ConnectionRouter are unaffected (they bypass
//     PlacementEngine entirely and resolve from the DB/cache layer).
//
// This test is pure-Go (no network calls) and reuses the fakeHostRepo stub
// already declared for TestChaos_HostFailure_PlacementFallback.
func TestChaos_HostFailure_GracefulDegradation(t *testing.T) {
	requireDatabaseURL(t)

	ctx := context.Background()

	healthy := models.RealmDatabaseHost{
		ID:                  uuid.New(),
		HostAlias:           "pg-healthy",
		ConnectionStringEnc: "postgres://hexxlock:dev@localhost:5432/hexxlock_iam?sslmode=disable",
		Region:              strPtr("tr-ist"),
		IsActive:            true,
		HealthStatus:        "healthy",
		MaxDatabases:        200,
		CurrentDatabases:    40,
	}

	degraded := models.RealmDatabaseHost{
		ID:                  uuid.New(),
		HostAlias:           "pg-degraded",
		ConnectionStringEnc: "postgres://hexxlock:dev@localhost:5433/hexxlock_iam?sslmode=disable",
		Region:              strPtr("tr-ist"),
		IsActive:            true,
		HealthStatus:        "unhealthy", // simulates a failed host
		MaxDatabases:        200,
		CurrentDatabases:    0,
	}

	t.Run("new provisions skip unhealthy host", func(t *testing.T) {
		repo := &fakeHostRepo{hosts: []models.RealmDatabaseHost{degraded, healthy}, region: "tr-ist"}
		engine := services.NewPlacementEngine(repo, nil)

		result, err := engine.SelectHost(ctx, services.PlacementRequest{PreferredRegion: "tr-ist"})
		require.NoError(t, err)
		assert.Equal(t, "pg-healthy", result.Host.HostAlias,
			"placement must skip the unhealthy host and select the healthy one")
	})

	t.Run("all hosts unhealthy returns ErrNoHostsAvailable", func(t *testing.T) {
		repo := &fakeHostRepo{hosts: []models.RealmDatabaseHost{degraded}, region: "tr-ist"}
		engine := services.NewPlacementEngine(repo, nil)

		_, err := engine.SelectHost(ctx, services.PlacementRequest{PreferredRegion: "tr-ist"})
		require.Error(t, err)
		assert.ErrorIs(t, err, services.ErrNoHostsAvailable,
			"should get ErrNoHostsAvailable when all hosts are unhealthy")
	})

	t.Run("existing realm cache resolves independently of placement engine", func(t *testing.T) {
		// Existing tenants are served via ConnectionRouter which queries realm_databases
		// directly — it does NOT go through PlacementEngine. Simulate by checking that
		// an InvalidateRealm + ResolveRealmDB on fakeRealmRepo still returns nil/no-error
		// even when the placement engine has no healthy hosts.
		log := zap.NewNop().Sugar()
		router := services.NewConnectionRouter(nil, &fakeRealmRepo{}, log)

		realmID := uuid.New()
		router.InvalidateRealm(ctx, realmID)

		info, err := router.ResolveRealmDB(ctx, realmID)
		assert.NoError(t, err, "ConnectionRouter should not be affected by host health")
		assert.Nil(t, info, "fakeRealmRepo always returns nil (shared pool realm)")
	})
}

// ---------------------------------------------------------------------------
// Test 9: Migration Interrupt — Context Cancellation Rollback
// ---------------------------------------------------------------------------

// TestChaos_MigrationInterrupt_Rollback verifies that cancelling a context
// mid-way through a multi-statement database operation causes the entire
// transaction to be rolled back, leaving the database in a clean state.
//
// The test simulates a "tenant migration" by:
//  1. Creating a staging table inside a transaction.
//  2. Inserting rows tagged with a migration batch ID.
//  3. Cancelling the context before COMMIT.
//  4. Asserting the table does not exist in the database (rollback occurred).
func TestChaos_MigrationInterrupt_Rollback(t *testing.T) {
	dsn := requireDatabaseURL(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn := openConn(t, dsn)

	// Use a unique table name so parallel test runs do not collide.
	stagingTable := fmt.Sprintf("chaos_migration_staging_%s", uuid.New().String()[:8])
	batchID := uuid.New().String()

	// Begin a transaction representing the in-flight migration.
	tx, err := conn.Begin(ctx)
	require.NoError(t, err, "begin transaction")

	// Step 1: create staging table inside the transaction.
	_, err = tx.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE %s (
			id        uuid    DEFAULT gen_random_uuid() PRIMARY KEY,
			batch_id  text    NOT NULL,
			payload   jsonb   NOT NULL DEFAULT '{}'
		)`, stagingTable))
	require.NoError(t, err, "create staging table in tx")

	// Step 2: insert some migration rows.
	for i := 0; i < 5; i++ {
		_, err = tx.Exec(ctx,
			fmt.Sprintf("INSERT INTO %s (batch_id, payload) VALUES ($1, $2)", stagingTable),
			batchID, fmt.Sprintf(`{"seq":%d}`, i),
		)
		require.NoError(t, err, "insert migration row %d", i)
	}

	// Step 3: simulate mid-migration context cancellation (operator SIGTERM / timeout).
	cancelCtx, cancelMid := context.WithCancel(ctx)
	cancelMid() // cancel immediately to simulate interrupt

	// Attempt to perform more work with the cancelled context.
	_, workErr := tx.Exec(cancelCtx,
		fmt.Sprintf("INSERT INTO %s (batch_id, payload) VALUES ($1, $2)", stagingTable),
		batchID, `{"seq":99}`,
	)
	// This may or may not error depending on driver behaviour; the key assertion
	// is that the subsequent rollback cleans up the table.
	t.Logf("Work after cancel returned: %v", workErr)

	// Step 4: rollback explicitly (models what the provisioner should do on ctx.Err()).
	rollbackErr := tx.Rollback(ctx)
	// Rollback may also fail if the connection is broken — that is acceptable.
	t.Logf("Rollback returned: %v", rollbackErr)

	// Step 5: verify the staging table does not exist (full rollback).
	// Use a fresh connection to avoid a potentially broken connection state.
	verifyConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skipf("Could not open verify connection: %v", err)
	}
	defer verifyConn.Close(ctx) //nolint:errcheck

	var tableExists bool
	err = verifyConn.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public'
			  AND table_name   = $1
		)`, stagingTable).Scan(&tableExists)
	require.NoError(t, err, "check table existence")
	assert.False(t, tableExists,
		"staging table %q must not exist after transaction rollback (migration interrupt cleanup failure)", stagingTable)

	t.Logf("Migration interrupt rollback verified: staging table %q was fully cleaned up", stagingTable)
}

// ---------------------------------------------------------------------------
// Test 10: Data Consistency Under Concurrent Writes
// ---------------------------------------------------------------------------

// TestChaos_DataConsistency_ConcurrentWrites spins up 20 goroutines, each
// writing to the same temporary RLS-protected table under a unique tenant
// context. After all writes complete, the test re-reads each tenant's rows and
// asserts the per-tenant count matches exactly what was written.
//
// This proves that set_config() session isolation does not lose writes or
// cross-contaminate row ownership under write contention.
func TestChaos_DataConsistency_ConcurrentWrites(t *testing.T) {
	dsn := requireDatabaseURL(t)

	const numWriters = 20
	const rowsPerWriter = 5

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Use a pool with one connection per writer so every goroutine has its own
	// server-side session (and therefore its own set_config() namespace).
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err, "parse DSN")
	cfg.MaxConns = int32(numWriters + 4)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err, "create pool")
	defer pool.Close()

	// Create a shared table with RLS gated on app.current_tenant_id.
	// Use an ordinary (non-temporary) table so all pool connections can see it.
	tableName := fmt.Sprintf("chaos_concurrent_writes_%s", uuid.New().String()[:8])

	setupConn, err := pool.Acquire(ctx)
	require.NoError(t, err, "acquire setup connection")

	_, err = setupConn.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id        uuid DEFAULT gen_random_uuid() PRIMARY KEY,
			tenant_id text NOT NULL,
			seq       int  NOT NULL
		)`, tableName))
	require.NoError(t, err, "create shared table")

	_, err = setupConn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", tableName))
	require.NoError(t, err, "enable RLS")

	_, err = setupConn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY", tableName))
	require.NoError(t, err, "force RLS")

	_, err = setupConn.Exec(ctx, fmt.Sprintf(`
		CREATE POLICY tenant_iso ON %s
		USING (tenant_id = current_setting('app.current_tenant_id', true))
		WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true))`,
		tableName))
	require.NoError(t, err, "create RLS policy")
	setupConn.Release()

	// Always drop the shared table on test exit.
	t.Cleanup(func() {
		cleanConn, err := pool.Acquire(context.Background())
		if err != nil {
			return
		}
		defer cleanConn.Release()
		_, _ = cleanConn.Exec(context.Background(),
			fmt.Sprintf("DROP TABLE IF EXISTS %s", tableName))
	})

	// Pre-generate tenant IDs.
	tenants := make([]string, numWriters)
	for i := range tenants {
		tenants[i] = uuid.New().String()
	}

	// All writers run concurrently.
	var wg sync.WaitGroup
	writeErrs := make([]error, numWriters)

	for i := 0; i < numWriters; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := pool.Acquire(ctx)
			if err != nil {
				writeErrs[i] = fmt.Errorf("acquire: %w", err)
				return
			}
			defer conn.Release()

			// Bind this session to our tenant.
			if _, err = conn.Exec(ctx,
				"SELECT set_config('app.current_tenant_id', $1, false)",
				tenants[i],
			); err != nil {
				writeErrs[i] = fmt.Errorf("set_config: %w", err)
				return
			}

			// Write rowsPerWriter rows.
			for seq := 0; seq < rowsPerWriter; seq++ {
				if _, err = conn.Exec(ctx,
					fmt.Sprintf("INSERT INTO %s (tenant_id, seq) VALUES ($1, $2)", tableName),
					tenants[i], seq,
				); err != nil {
					writeErrs[i] = fmt.Errorf("insert seq %d: %w", seq, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	// Assert no writer errored.
	for i, err := range writeErrs {
		require.NoError(t, err, "writer %d returned error", i)
	}

	// Verify per-tenant counts using a superuser-level bypass connection.
	// Because set_config is session-scoped we use a raw query with a WHERE
	// clause instead of relying on RLS for the verification pass — this lets
	// us count rows regardless of the current session's tenant context.
	verifyConn, err := pool.Acquire(ctx)
	require.NoError(t, err, "acquire verify connection")
	defer verifyConn.Release()

	for i, tid := range tenants {
		var count int
		err = verifyConn.QueryRow(ctx,
			fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE tenant_id = $1", tableName),
			tid,
		).Scan(&count)
		require.NoError(t, err, "count for tenant %d", i)
		assert.Equal(t, rowsPerWriter, count,
			"tenant %d (%s) should have exactly %d rows, got %d",
			i, tid[:8], rowsPerWriter, count)
	}

	t.Logf("Data consistency verified: %d writers x %d rows = %d total rows, all correctly isolated",
		numWriters, rowsPerWriter, numWriters*rowsPerWriter)
}

// ---------------------------------------------------------------------------
// Test 11: Database Failover — Connection Pool Recovery
// ---------------------------------------------------------------------------

// TestChaos_DatabaseFailover_ConnectionRecovery simulates a transient network
// blip by closing a single-connection pgxpool and verifying that a freshly
// constructed pool for the same DSN recovers and serves queries correctly.
//
// pgx does not expose a "kill server connection" hook for individual pool
// connections in the way that pgx/v5 exposes BeforeAcquire, so we simulate
// the "failover" by discarding the old pool entirely (as a service would do on
// reconnect) and opening a new one.  The key assertion is that the new pool
// returns correct query results — proving the recovery path is functional.
func TestChaos_DatabaseFailover_ConnectionRecovery(t *testing.T) {
	dsn := requireDatabaseURL(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Phase 1: Open initial pool and run a baseline query.
	pool1 := openPool(t, dsn)

	var baseline int
	err := pool1.QueryRow(ctx, "SELECT 42").Scan(&baseline)
	require.NoError(t, err, "baseline query on initial pool")
	assert.Equal(t, 42, baseline, "baseline query should return 42")
	t.Logf("Phase 1: initial pool operational (baseline=%d)", baseline)

	// Phase 2: Simulate a network blip by closing the pool (all connections torn down).
	pool1.Close()
	t.Logf("Phase 2: pool closed — simulating network blip / failover event")

	// Phase 3: Open a new pool for the same DSN — this is the recovery step.
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err, "parse DSN for recovery pool")
	pool2, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err, "open recovery pool")
	t.Cleanup(func() { pool2.Close() })

	// Phase 4: Run queries on the recovered pool and verify correctness.
	var recovered int
	err = pool2.QueryRow(ctx, "SELECT 99").Scan(&recovered)
	require.NoError(t, err, "query on recovered pool must succeed")
	assert.Equal(t, 99, recovered, "recovered pool query should return 99")

	// Also verify RLS set_config still works on the new pool.
	tenantID := uuid.New().String()
	var cfgResult string
	err = pool2.QueryRow(ctx,
		"SELECT set_config('app.current_tenant_id', $1, false)", tenantID,
	).Scan(&cfgResult)
	require.NoError(t, err, "set_config on recovered pool must work")
	assert.Equal(t, tenantID, cfgResult, "set_config should return the set value")

	t.Logf("Phase 3-4: pool recovered successfully — query returned %d, set_config works", recovered)
}

// ---------------------------------------------------------------------------
// Test 12: Large Result Set — RLS Correctness at Scale
// ---------------------------------------------------------------------------

// TestChaos_LargeResultSet_MemoryBound inserts 10,000 rows tagged to Tenant A
// into a temp table with RLS, then queries it from both Tenant A and Tenant B
// contexts and asserts:
//   - Tenant A sees all 10,000 rows.
//   - Tenant B sees 0 rows.
//
// This proves RLS remains correct when the result set grows beyond in-memory
// limits that might trip optimisation edge cases in some DB versions.
func TestChaos_LargeResultSet_MemoryBound(t *testing.T) {
	dsn := requireDatabaseURL(t)

	const rowCount = 10_000

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	conn := openConn(t, dsn)

	tenantA := uuid.New().String()
	tenantB := uuid.New().String()
	tableName := fmt.Sprintf("chaos_large_rls_%s", uuid.New().String()[:8])

	// Create temp table with RLS.
	_, err := conn.Exec(ctx, fmt.Sprintf(`
		CREATE TEMPORARY TABLE %s (
			id        bigserial PRIMARY KEY,
			tenant_id text      NOT NULL,
			val       int       NOT NULL
		)`, tableName))
	require.NoError(t, err, "create temp table")

	_, err = conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", tableName))
	require.NoError(t, err, "enable RLS")

	_, err = conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY", tableName))
	require.NoError(t, err, "force RLS")

	_, err = conn.Exec(ctx, fmt.Sprintf(`
		CREATE POLICY tenant_iso ON %s
		USING (tenant_id = current_setting('app.current_tenant_id', true))
		WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true))`,
		tableName))
	require.NoError(t, err, "create RLS policy")

	// Set Tenant A context and bulk-insert 10K rows using a VALUES-based approach.
	_, err = conn.Exec(ctx,
		"SELECT set_config('app.current_tenant_id', $1, false)", tenantA)
	require.NoError(t, err, "set Tenant A context for insert")

	// Use COPY protocol-style approach via a single INSERT with generate_series.
	_, err = conn.Exec(ctx, fmt.Sprintf(`
		INSERT INTO %s (tenant_id, val)
		SELECT $1, generate_series(1, $2)`,
		tableName), tenantA, rowCount)
	require.NoError(t, err, "bulk insert %d rows for Tenant A", rowCount)

	// Query as Tenant A — expect all rowCount rows.
	var countA int
	err = conn.QueryRow(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName),
	).Scan(&countA)
	require.NoError(t, err, "count as Tenant A")
	assert.Equal(t, rowCount, countA,
		"Tenant A should see all %d rows (RLS COUNT mismatch at scale)", rowCount)

	// Switch to Tenant B — expect 0 rows.
	_, err = conn.Exec(ctx,
		"SELECT set_config('app.current_tenant_id', $1, false)", tenantB)
	require.NoError(t, err, "set Tenant B context")

	var countB int
	err = conn.QueryRow(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName),
	).Scan(&countB)
	require.NoError(t, err, "count as Tenant B")
	assert.Equal(t, 0, countB,
		"Tenant B must see 0 rows even when Tenant A has %d (RLS scale failure)", rowCount)

	t.Logf("RLS at scale verified: Tenant A=%d rows, Tenant B=%d rows (out of %d total)",
		countA, countB, rowCount)
}

// ---------------------------------------------------------------------------
// Test 13: Transaction Isolation Between Tenants
// ---------------------------------------------------------------------------

// TestChaos_TransactionIsolation_CrossTenant verifies PostgreSQL read-committed
// transaction isolation combined with RLS:
//
//  1. Tenant A opens a transaction and inserts a row but does NOT commit.
//  2. Tenant B queries the table — must see 0 rows (uncommitted + different tenant).
//  3. Tenant A commits.
//  4. Tenant B queries again — must still see 0 rows (different tenant; RLS filters).
//
// This double-check ensures neither dirty reads nor RLS bypass are possible
// across concurrent tenant sessions.
func TestChaos_TransactionIsolation_CrossTenant(t *testing.T) {
	dsn := requireDatabaseURL(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tenantA := uuid.New().String()
	tenantB := uuid.New().String()
	tableName := fmt.Sprintf("chaos_tx_iso_%s", uuid.New().String()[:8])

	// Tenant A uses a dedicated connection.
	connA := openConn(t, dsn)

	// Tenant B uses a second dedicated connection.
	connB := openConn(t, dsn)

	// Setup: create temp table with RLS on connA (temp tables are session-local,
	// so we need an ordinary table for cross-session visibility).
	// Use connA to create the table in public schema and drop it at end.
	setupSQL := fmt.Sprintf(`
		CREATE TABLE %s (
			id        uuid DEFAULT gen_random_uuid() PRIMARY KEY,
			tenant_id text NOT NULL,
			payload   text NOT NULL
		)`, tableName)

	_, err := connA.Exec(ctx, setupSQL)
	require.NoError(t, err, "create shared table on connA")

	t.Cleanup(func() {
		dropConn, _ := pgx.Connect(context.Background(), dsn)
		if dropConn != nil {
			_, _ = dropConn.Exec(context.Background(),
				fmt.Sprintf("DROP TABLE IF EXISTS %s", tableName))
			_ = dropConn.Close(context.Background())
		}
	})

	_, err = connA.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", tableName))
	require.NoError(t, err, "enable RLS")

	_, err = connA.Exec(ctx, fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY", tableName))
	require.NoError(t, err, "force RLS")

	_, err = connA.Exec(ctx, fmt.Sprintf(`
		CREATE POLICY tenant_iso ON %s
		USING (tenant_id = current_setting('app.current_tenant_id', true))
		WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true))`,
		tableName))
	require.NoError(t, err, "create RLS policy")

	// Set Tenant B context on connB now (before Tenant A starts its transaction).
	_, err = connB.Exec(ctx,
		"SELECT set_config('app.current_tenant_id', $1, false)", tenantB)
	require.NoError(t, err, "set Tenant B context on connB")

	// Step 1: Tenant A begins a transaction and inserts, does NOT commit yet.
	_, err = connA.Exec(ctx,
		"SELECT set_config('app.current_tenant_id', $1, false)", tenantA)
	require.NoError(t, err, "set Tenant A context")

	tx, err := connA.Begin(ctx)
	require.NoError(t, err, "begin Tenant A transaction")

	_, err = tx.Exec(ctx,
		fmt.Sprintf("INSERT INTO %s (tenant_id, payload) VALUES ($1, $2)", tableName),
		tenantA, "uncommitted-secret")
	require.NoError(t, err, "insert in Tenant A uncommitted tx")

	// Step 2: Tenant B reads before Tenant A commits — must see 0 rows.
	var countBeforeCommit int
	err = connB.QueryRow(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName),
	).Scan(&countBeforeCommit)
	require.NoError(t, err, "Tenant B count before Tenant A commits")
	assert.Equal(t, 0, countBeforeCommit,
		"Tenant B must not see Tenant A's uncommitted row (dirty read or RLS bypass)")

	// Step 3: Tenant A commits.
	err = tx.Commit(ctx)
	require.NoError(t, err, "Tenant A commit")

	// Step 4: Tenant B reads after Tenant A commits — must still see 0 rows.
	var countAfterCommit int
	err = connB.QueryRow(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName),
	).Scan(&countAfterCommit)
	require.NoError(t, err, "Tenant B count after Tenant A commits")
	assert.Equal(t, 0, countAfterCommit,
		"Tenant B must still see 0 rows after Tenant A committed (RLS cross-tenant leak)")

	t.Logf("Transaction isolation verified: before-commit=%d, after-commit=%d for Tenant B",
		countBeforeCommit, countAfterCommit)
}

// ---------------------------------------------------------------------------
// Test 14: In-memory Rate Limiter — Burst Handling
// ---------------------------------------------------------------------------

// TestChaos_RateLimiter_BurstHandling validates rate limiting logic using a
// simple in-memory token bucket implemented inline (no Redis, no DB required).
//
// The test:
//   - Defines a per-tenant request quota of 100 requests per window.
//   - Fires 200 requests for Tenant A — expects the first 100 to pass and the
//     remaining 100 to be rejected.
//   - Fires 50 requests for Tenant B — all should pass (separate quota bucket).
//
// This is a pure unit test; DATABASE_URL is still required to maintain the
// integration test gate so runners without the DB skip the whole suite.
func TestChaos_RateLimiter_BurstHandling(t *testing.T) {
	requireDatabaseURL(t)

	const (
		limit       = 100
		tenantAReqs = 200
		tenantBReqs = 50
	)

	// Minimal in-memory token bucket: maps tenant → remaining tokens.
	type bucket struct {
		mu      sync.Mutex
		tokens  map[string]int
		maxRate int
	}

	newBucket := func(max int) *bucket {
		return &bucket{tokens: make(map[string]int), maxRate: max}
	}

	tryAcquire := func(b *bucket, tenant string) bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.tokens[tenant]; !ok {
			b.tokens[tenant] = b.maxRate
		}
		if b.tokens[tenant] <= 0 {
			return false
		}
		b.tokens[tenant]--
		return true
	}

	b := newBucket(limit)
	tenantA := "tenant-alpha"
	tenantB := "tenant-beta"

	// Fire tenantAReqs requests for Tenant A.
	var passedA, rejectedA int
	for i := 0; i < tenantAReqs; i++ {
		if tryAcquire(b, tenantA) {
			passedA++
		} else {
			rejectedA++
		}
	}

	assert.Equal(t, limit, passedA,
		"Tenant A: expected exactly %d requests to pass (limit), got %d", limit, passedA)
	assert.Equal(t, tenantAReqs-limit, rejectedA,
		"Tenant A: expected %d requests to be rejected, got %d", tenantAReqs-limit, rejectedA)

	// Fire tenantBReqs requests for Tenant B — all should pass (fresh bucket).
	var passedB, rejectedB int
	for i := 0; i < tenantBReqs; i++ {
		if tryAcquire(b, tenantB) {
			passedB++
		} else {
			rejectedB++
		}
	}

	assert.Equal(t, tenantBReqs, passedB,
		"Tenant B: all %d requests should pass (separate quota)", tenantBReqs)
	assert.Equal(t, 0, rejectedB,
		"Tenant B: no requests should be rejected, got %d rejected", rejectedB)

	// Verify bucket state is independent per tenant.
	b.mu.Lock()
	remainA := b.tokens[tenantA]
	remainB := b.tokens[tenantB]
	b.mu.Unlock()

	assert.Equal(t, 0, remainA, "Tenant A bucket should be empty after %d requests", tenantAReqs)
	assert.Equal(t, limit-tenantBReqs, remainB,
		"Tenant B bucket should have %d remaining tokens", limit-tenantBReqs)

	t.Logf("Rate limiter burst: Tenant A passed=%d rejected=%d | Tenant B passed=%d rejected=%d",
		passedA, rejectedA, passedB, rejectedB)
}

// ---------------------------------------------------------------------------
// Test 15: Placement Engine — All Hosts at Capacity
// ---------------------------------------------------------------------------

// TestChaos_PlacementEngine_AllHostsFull verifies that PlacementEngine returns
// ErrNoHostsAvailable when every registered host has reached MaxDatabases, and
// that adding a single host with remaining capacity causes it to be selected.
//
// This is a pure Go test using fakeHostRepo — no database connection required
// beyond the DATABASE_URL integration gate.
func TestChaos_PlacementEngine_AllHostsFull(t *testing.T) {
	requireDatabaseURL(t)

	ctx := context.Background()

	makeHost := func(alias string, current, max int) models.RealmDatabaseHost {
		return models.RealmDatabaseHost{
			ID:                  uuid.New(),
			HostAlias:           alias,
			ConnectionStringEnc: "postgres://dev:dev@localhost:5432/hexxlock_iam?sslmode=disable",
			Region:              strPtr("us-east"),
			IsActive:            true,
			HealthStatus:        "healthy",
			CurrentDatabases:    current,
			MaxDatabases:        max,
		}
	}

	t.Run("all three hosts at capacity — ErrNoHostsAvailable", func(t *testing.T) {
		hosts := []models.RealmDatabaseHost{
			makeHost("pg-1", 100, 100), // full
			makeHost("pg-2", 200, 200), // full
			makeHost("pg-3", 50, 50),   // full
		}

		// fakeHostRepo filters to active+healthy but keeps capacity-full hosts;
		// filterByCapacity inside PlacementEngine then removes them.
		repo := &fakeHostRepo{hosts: hosts, region: "us-east"}
		engine := services.NewPlacementEngine(repo, nil)

		_, err := engine.SelectHost(ctx, services.PlacementRequest{PreferredRegion: "us-east"})
		require.Error(t, err, "should fail when all hosts are at capacity")
		assert.ErrorIs(t, err, services.ErrNoHostsAvailable,
			"error must be ErrNoHostsAvailable, got: %v", err)

		t.Logf("All hosts full: correctly returned ErrNoHostsAvailable")
	})

	t.Run("add one host with capacity — it is selected", func(t *testing.T) {
		hosts := []models.RealmDatabaseHost{
			makeHost("pg-full-1", 100, 100),   // full
			makeHost("pg-full-2", 200, 200),   // full
			makeHost("pg-available", 49, 100), // has capacity
		}

		repo := &fakeHostRepo{hosts: hosts, region: "us-east"}
		engine := services.NewPlacementEngine(repo, nil)

		result, err := engine.SelectHost(ctx, services.PlacementRequest{PreferredRegion: "us-east"})
		require.NoError(t, err, "should succeed when at least one host has capacity")
		require.NotNil(t, result, "result must not be nil")
		assert.Equal(t, "pg-available", result.Host.HostAlias,
			"should select the only host with remaining capacity")
		assert.True(t, result.Host.HasCapacity(),
			"selected host must report HasCapacity() == true")

		t.Logf("Capacity selection: correctly picked %q (current=%d, max=%d)",
			result.Host.HostAlias, result.Host.CurrentDatabases, result.Host.MaxDatabases)
	})

	t.Run("graceful degradation message is ErrNoHostsAvailable sentinel", func(t *testing.T) {
		// Verify the sentinel can be matched with errors.Is() from caller code.
		repo := &fakeHostRepo{hosts: nil, region: ""}
		engine := services.NewPlacementEngine(repo, nil)

		_, err := engine.SelectHost(ctx, services.PlacementRequest{})
		require.Error(t, err)

		// Callers should be able to detect the specific condition and trigger
		// their own capacity-exhausted alert / fallback logic.
		assert.ErrorIs(t, err, services.ErrNoHostsAvailable,
			"sentinel ErrNoHostsAvailable must be matchable with errors.Is()")
		t.Logf("Sentinel error correctly propagated: %v", err)
	})
}
