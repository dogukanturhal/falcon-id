// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// TestBootSmoke_RoutesRegisterWithoutPanic boots falcon-id's REAL
// production wiring (initInfrastructure -> initRepositories ->
// initServices -> initHandlers -> validateHandlerWiring ->
// registerRoutes -- the exact call sequence cmd/main.go's main() uses,
// minus the schema-dependent bootstrapX seed calls, IAM self-
// registration, and starting the actual HTTP listener/background
// tasks) against a throwaway Postgres + Redis, and asserts the whole
// route tree -- including the new R1 platform-plane JIT elevation +
// break-glass + platform-roles groups -- registers without a gin
// panic (e.g. a colliding wildcard/param route, which gin panics on at
// registration time, not at request time).
//
// Gated on BOOT_SMOKE_DATABASE_URL / BOOT_SMOKE_REDIS_URL. Run via:
//
//	BOOT_SMOKE_DATABASE_URL=postgres://test:test@127.0.0.1:<port>/test?sslmode=disable \
//	BOOT_SMOKE_REDIS_URL=redis://127.0.0.1:<port>/0 \
//	GOWORK=off go test ./cmd/... -run TestBootSmoke -v -count=1
func TestBootSmoke_RoutesRegisterWithoutPanic(t *testing.T) {
	dbURL := os.Getenv("BOOT_SMOKE_DATABASE_URL")
	redisURL := os.Getenv("BOOT_SMOKE_REDIS_URL")
	if dbURL == "" || redisURL == "" {
		t.Skip("BOOT_SMOKE_DATABASE_URL and BOOT_SMOKE_REDIS_URL are required for the boot smoke test")
	}
	// Seed an isolated real realm so protected routes reach the auth gate
	// instead of stopping at the bare-DB fixture's missing-realm error.
	ctx := context.Background()
	seed, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Close()
	schema := "boot_smoke_" + uuid.New().String()[:8]
	if _, err := seed.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = seed.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") }()
	if _, err := seed.Exec(ctx, fmt.Sprintf(`CREATE TABLE %[1]s.realms(id uuid PRIMARY KEY,slug text,display_name text,type text,status text,database_connection_id uuid,schema_name text,settings jsonb,branding jsonb,features jsonb,max_tenants int,max_users_per_tenant int,max_total_users int,created_at timestamptz DEFAULT now(),updated_at timestamptz DEFAULT now(),created_by uuid);
 CREATE TABLE %[1]s.realm_tenants(realm_id uuid,tenant_id uuid);
 INSERT INTO %[1]s.realms(id,slug,display_name,type,status,settings,branding,features) VALUES(gen_random_uuid(),'default','Boot smoke','shared','active','{}','{}','{}');`, schema)); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	dbURL = parsed.String()

	// Minimal env for config.LoadConfig's fail-fast validation
	// (validateSecurityConfig: DATABASE_URL/CONTROL_PLANE_DATABASE_URL/
	// REDIS_URL are always required, regardless of environment).
	// CONTROL_PLANE_DATABASE_URL points at the same throwaway Postgres --
	// connectControlPlaneDB degrades to a warning-only nil on connect
	// failure, but the config validator itself requires the URL string to
	// be non-empty.
	t.Setenv("DATABASE_URL", dbURL)
	t.Setenv("CONTROL_PLANE_DATABASE_URL", dbURL)
	t.Setenv("REDIS_URL", redisURL)
	t.Setenv("JWT_SECRET", "boot-smoke-test-jwt-secret-32-characters-minimum!!")
	t.Setenv("EMAIL_HASH_KEY", "boot-smoke-test-email-hash-key-32-chars!!")
	t.Setenv("TOKEN_HASH_SALT", "boot-smoke-test-token-hash-salt-32-chars!!")
	t.Setenv("ENCRYPTION_KEY", "boot-smoke-test-encryption-key32")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("SPICEDB_ENABLED", "false")
	t.Setenv("VAULT_ENABLED", "false")
	// OnboardingSlug/OnboardingStatus are feature-gated on these S2S
	// creds (see cmd/services.go); without them, initHandlers leaves
	// those two nil and validateHandlerWiring's fail-fast check
	// (correctly) treats that as an unintentional gap rather than a
	// registered optional exemption -- unrelated to this change, so we
	// just supply throwaway values to let the full handler set build.
	t.Setenv("SERVICE_CLIENT_ID", "boot-smoke-test-client-id")
	t.Setenv("SERVICE_CLIENT_SECRET", "boot-smoke-test-client-secret")
	t.Setenv("IAM_SERVICE_URL", "http://127.0.0.1:8010")

	infra, err := initInfrastructure()
	if err != nil {
		t.Fatalf("initInfrastructure: %v", err)
	}
	defer infra.Close()

	repositories.SetEmailHashKey(infra.Config.EmailHashKey)

	repos := initRepositories(infra)
	services := initServices(repos, infra)
	if services.RoleRevokeDrainer == nil {
		t.Fatal("durable role revoke drainer missing from production service wiring")
	}
	handlers := initHandlers(services, repos, infra)

	// validateHandlerWiring / registerRoutes are the two places a bad
	// wiring change (nil handler behind a route group, or two routes
	// colliding at the gin radix-tree level) would panic. Recover
	// explicitly so a panic here fails this test with a clear message
	// instead of crashing the whole `go test` process.
	var router interface {
		ServeHTTP(http.ResponseWriter, *http.Request)
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("registerRoutes (or validateHandlerWiring) panicked: %v", r)
			}
		}()
		validateHandlerWiring(handlers)
		router = registerRoutes(handlers, services, repos, infra)
	}()

	// Sanity: the engine actually serves a known route, proving
	// registerRoutes returned a live, usable *gin.Engine rather than
	// panicking silently into a half-built one.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /health after full route registration: got %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	// The seat usage/downgrade notice route remains S2S-authenticated.
	seatRec := httptest.NewRecorder()
	router.ServeHTTP(seatRec, httptest.NewRequest(http.MethodGet, "/internal/v1/tenants/00000000-0000-0000-0000-000000000001/seat-limit", nil))
	if seatRec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous seat-limit read: got %d, want 401", seatRec.Code)
	}
	// Exercise a real HTTP listener as well as the in-process route tree.
	server := httptest.NewServer(router)
	defer server.Close()
	for path, want := range map[string]int{"/health": http.StatusOK, "/internal/v1/tenants/00000000-0000-0000-0000-000000000001/seat-limit": http.StatusUnauthorized} {
		request, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "localhost" // Use the seeded default realm, not a pod-IP subdomain.
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Errorf("live boot listener %s: got %d, want %d", path, response.StatusCode, want)
		}
	}
	// authorize/simulate + effective-permissions (spec 23 §7) must be in the
	// route table. (An anonymous request cannot assert 401 here: the realm
	// middleware needs the schema this bare Postgres does not have.)
	engine, ok := router.(*gin.Engine)
	if !ok {
		t.Fatalf("registerRoutes returned %T, want *gin.Engine", router)
	}
	registered := map[string]bool{}
	for _, r := range engine.Routes() {
		registered[r.Method+" "+r.Path] = true
	}
	for _, want := range []string{
		"GET /oauth/login",
		"GET /oauth/logout",
		"POST /api/v1/auth/mfa/complete",
		"POST /api/v1/auth/mfa/switch-method",
		"POST /api/v1/authorize/simulate",
		"GET /api/v1/authorize/effective-permissions",
		"POST /api/v1/authorize/batch",
		"POST /api/v1/authorization/lookup-subjects",
		"POST /api/v1/authorization/check-batch",
		"GET /internal/v1/tenants/:id/approval-membership-summary",
		"GET /internal/v1/tenants/:id/approval-members/:user_id",
	} {
		if !registered[want] {
			t.Errorf("route %q not registered", want)
		}
	}
	t.Logf("boot smoke OK: full route tree (including platform-plane JIT/break-glass/platform-roles groups) registered without a gin panic; GET /health -> %d", rec.Code)
}
