// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// -----------------------------------------------------------------------
// Handler/route-level tests for the platform-plane JIT elevation +
// break-glass + platform-roles groups (R1 lead-review gap: these three
// route groups previously only had service-layer tests; nothing exercised
// the real gin router with the real ServiceAuth/RequireScope/
// RequireActorAuth/RequirePlatformInternalActor middleware chain that
// registerInternalAPIRoutes wires in cmd/routes_admin.go).
// -----------------------------------------------------------------------

// jitFakeServiceLookup is a local stand-in for
// middleware.ServicePrincipalLookup, mirroring service_auth_test.go's
// mockServiceLookup (unexported in package middleware, so not reusable
// from here).
type jitFakeServiceLookup struct {
	keys  map[string]*rsa.PublicKey
	slugs map[string]string
}

func (l *jitFakeServiceLookup) LookupPublicKey(_ context.Context, keyID string) (*rsa.PublicKey, string, error) {
	key, ok := l.keys[keyID]
	if !ok {
		return nil, "", fmt.Errorf("key not found: %s", keyID)
	}
	return key, l.slugs[keyID], nil
}

func jitGenerateTestServiceKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	hash := sha256.Sum256(pubDER)
	kid := base64.RawURLEncoding.EncodeToString(hash[:12])
	return key, kid
}

// jitCreateServiceJWT signs a service-principal JWT with an optional
// space-separated scope claim, mirroring the shape
// middleware.validateServiceJWT expects (RS256, kid header, aud
// "falcon-id" for an externally-registered kid).
func jitCreateServiceJWT(t *testing.T, key *rsa.PrivateKey, kid, scope string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":   "acmeapp-bff",
		"aud":   "falcon-id",
		"scope": scope,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// jitNoopTokenRepo/jitNoopUserRepo satisfy TokenService's narrow
// tokenTokenRepository/tokenUserRepository interfaces structurally
// (unexported interface types in package services -- satisfying them by
// method set alone, no name needed). Never actually invoked: the legacy
// HS256 access-token validation path (parseLegacyClaims) reads only the
// JWT's own claims, no repo lookups.
type jitNoopTokenRepo struct{}

func (jitNoopTokenRepo) CleanupExpiredPasswordResets(_ context.Context) (int64, error) { return 0, nil }
func (jitNoopTokenRepo) CreatePasswordReset(_ context.Context, _ *models.PasswordReset) error {
	return nil
}
func (jitNoopTokenRepo) GetPasswordReset(_ context.Context, _ string) (*models.PasswordReset, error) {
	return nil, fmt.Errorf("not implemented")
}
func (jitNoopTokenRepo) MarkPasswordResetUsed(_ context.Context, _ uuid.UUID) error { return nil }
func (jitNoopTokenRepo) InvalidateUserPasswordResets(_ context.Context, _ uuid.UUID) error {
	return nil
}

type jitNoopUserRepo struct{}

func (jitNoopUserRepo) GetByID(_ context.Context, _ uuid.UUID) (*models.User, error) {
	return nil, fmt.Errorf("not implemented")
}
func (jitNoopUserRepo) GetUserRoles(_ context.Context, _ uuid.UUID) ([]models.Role, error) {
	return nil, nil
}
func (jitNoopUserRepo) GetUserPermissions(_ context.Context, _ uuid.UUID) ([]models.Permission, error) {
	return nil, nil
}
func (jitNoopUserRepo) Update(_ context.Context, _ *models.User) error { return nil }

// jitRouterTestConfig builds a *config.Config sufficient for
// AuthMiddleware.RequireActorAuth's HS256 fallback path (mirrors
// auth_test.go's authTestConfig, unexported in package middleware).
func jitRouterTestConfig() *config.Config {
	return &config.Config{
		JWTSecret:              "jit-router-test-secret-32-characters-min",
		JWTIssuer:               "hexxlock-services",
		AccessTokenExpiry:       time.Hour,
		JWTHMACFallbackEnabled: true,
	}
}

// jitBuildActorToken signs an HS256 session access token for the
// X-Actor-Assertion header, matching the claim shape
// TokenService.ValidateAccessTokenWithContext's legacy-claims path reads.
func jitBuildActorToken(t *testing.T, cfg *config.Config, userID, tenantID uuid.UUID) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":         cfg.JWTIssuer,
		"aud":         "hexxlock-services",
		"sub":         userID.String(),
		"user_id":     userID.String(),
		"tenant_id":   tenantID.String(),
		"username":    "jit-test-actor",
		"email":       "jit-test-actor@example.com",
		"roles":       []string{},
		"permissions": []string{},
		"session_id":  uuid.New().String(),
		"iat":         time.Now().Unix(),
		"exp":         time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(cfg.JWTSecret))
	require.NoError(t, err)
	return signed
}

// jitPlatformJITTestHarness bundles everything a test needs to drive
// requests through the real registerInternalAPIRoutes wiring.
type jitPlatformJITTestHarness struct {
	router  *gin.Engine
	cfg     *config.Config
	svcKey  *rsa.PrivateKey
	svcKid  string
}

// newJITPlatformRouter builds the real gin engine for the
// /internal/v1/jit-elevations, /internal/v1/break-glass and
// /internal/v1/platform-roles groups by calling the actual
// registerInternalAPIRoutes production wiring function from
// cmd/routes_admin.go -- not a hand-rolled reimplementation of the
// middleware chain. extractTenant, when true, additionally mounts the
// real middleware.ExtractTenant() ahead of the internal routes (as
// cmd/routes.go's applyGlobalMiddleware does in production), needed only
// by the "no X-Tenant-ID required" exemption test.
func newJITPlatformRouter(t *testing.T, svc *services.PlatformJITService, extractTenant bool) *jitPlatformJITTestHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()

	if extractTenant {
		router.Use(middleware.ExtractTenant())
	}

	key, kid := jitGenerateTestServiceKey(t)
	lookup := &jitFakeServiceLookup{
		keys:  map[string]*rsa.PublicKey{kid: &key.PublicKey},
		slugs: map[string]string{kid: "acmeapp-bff"},
	}
	serviceAuthMW := middleware.NewServiceAuthMiddleware(lookup, "")

	cfg := jitRouterTestConfig()
	tokenSvc := services.NewTokenService(cfg, jitNoopTokenRepo{}, jitNoopUserRepo{})
	authMW := middleware.NewAuthMiddleware(tokenSvc, cfg)

	jitHandler := handlers.NewPlatformJITHandler(svc, zap.NewNop())
	hs := &Handlers{PlatformJIT: jitHandler}

	registerInternalAPIRoutes(router, hs, authMW, nil, nil, serviceAuthMW)

	return &jitPlatformJITTestHarness{router: router, cfg: cfg, svcKey: key, svcKid: kid}
}

func (h *jitPlatformJITTestHarness) do(t *testing.T, method, path, serviceScope, actorAssertion string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequestWithContext(context.Background(), method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if serviceScope != "__none__" {
		req.Header.Set("Authorization", "Bearer "+jitCreateServiceJWT(t, h.svcKey, h.svcKid, serviceScope))
	}
	if actorAssertion != "" {
		req.Header.Set("X-Actor-Assertion", actorAssertion)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

// jitSetupRouterTestDB is the cmd-package counterpart of
// internal/services/platform_jit_postgres_integration_test.go's
// setupPlatformJITTestDB (unexported there, package services -- not
// importable from package main), duplicated here for the router-level
// tests that need a real DB-backed PlatformJITService (self-approval and
// the happy-path "reaches the handler" case both perform real
// request/approve DB writes).
func jitSetupRouterTestDB(t *testing.T) (svc *services.PlatformJITService, pool *pgxpool.Pool, cleanup func()) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-jit-postgres-tests.sh")
	}

	ctx := context.Background()
	schema := "platform_jit_router_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)

	cleanup = func() {
		p.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	}

	_, err = p.Exec(ctx, `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE iam_tenants (id uuid PRIMARY KEY);
CREATE TABLE iam_users (id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES iam_tenants(id));
-- Migration 0016 GRANTs to the prod app role; roles are cluster-wide, so
-- create it idempotently and tolerate a concurrent creator.
DO $$ BEGIN
  CREATE ROLE falcon_id_app NOLOGIN;
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
`)
	if err != nil {
		cleanup()
		t.Fatalf("stub schema: %v", err)
	}

	migrationSQL, err := os.ReadFile("../internal/migrations/0016_iam_platform_roles_jit_elevations.sql")
	if err != nil {
		cleanup()
		t.Fatalf("read migration 0016: %v", err)
	}
	if _, err := p.Exec(ctx, string(migrationSQL)); err != nil {
		cleanup()
		t.Fatalf("apply migration 0016: %v", err)
	}

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	_, err = p.Exec(ctx, `INSERT INTO iam_tenants (id) VALUES ($1)`, internalTenantID)
	if err != nil {
		cleanup()
		t.Fatalf("seed tenant: %v", err)
	}

	r := repositories.NewPlatformElevationRepository(p)
	sp := &jitRouterFakeSpiceDB{}
	s := services.NewPlatformJITService(r, r, sp, nil, zap.NewNop())

	return s, p, cleanup
}

// jitRouterFakeSpiceDB satisfies services' unexported platformSpiceDBClient
// interface structurally, same rationale as jitNoopTokenRepo above.
type jitRouterFakeSpiceDB struct{}

func (f *jitRouterFakeSpiceDB) WritePlatformElevation(_ context.Context, _ uuid.UUID, _ string, _ time.Time) (string, error) {
	return "fake-zed-token", nil
}
func (f *jitRouterFakeSpiceDB) DeletePlatformElevation(_ context.Context, _ uuid.UUID, _ string) (string, error) {
	return "fake-zed-token", nil
}

func jitSeedUser(t *testing.T, pool *pgxpool.Pool, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(), `INSERT INTO iam_users (id, tenant_id) VALUES ($1,$2)`, id, tenantID)
	require.NoError(t, err)
	return id
}

// (a) No service token at all -> 401, for every group.
func TestPlatformJITRouter_NoToken_Returns401(t *testing.T) {
	// No DB needed: ServiceAuth() rejects before the handler (or even
	// RequireScope) runs.
	sp := &jitRouterFakeSpiceDB{}
	svc := services.NewPlatformJITService(repositories.NewPlatformElevationRepository(nil), nil, sp, nil, zap.NewNop())
	h := newJITPlatformRouter(t, svc, false)

	paths := []struct{ method, path string }{
		{http.MethodPost, "/internal/v1/jit-elevations"},
		{http.MethodPost, "/internal/v1/break-glass"},
		{http.MethodPost, "/internal/v1/platform-roles"},
		{http.MethodGet, "/internal/v1/platform-roles"},
	}
	for _, p := range paths {
		req := httptest.NewRequestWithContext(context.Background(), p.method, p.path, bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		require.Equalf(t, http.StatusUnauthorized, rec.Code, "%s %s body=%s", p.method, p.path, rec.Body.String())
	}
}

// (b) A valid service token WITHOUT the platform:jit-elevations scope ->
// 403 insufficient_scope.
func TestPlatformJITRouter_WrongScope_Returns403InsufficientScope(t *testing.T) {
	sp := &jitRouterFakeSpiceDB{}
	svc := services.NewPlatformJITService(repositories.NewPlatformElevationRepository(nil), nil, sp, nil, zap.NewNop())
	h := newJITPlatformRouter(t, svc, false)

	rec := h.do(t, http.MethodPost, "/internal/v1/jit-elevations", "some:other-scope", "", map[string]interface{}{
		"role_key":         "platform_support",
		"reason":           "test",
		"duration_seconds": 60,
	})
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "insufficient_scope", body["error"])
}

// (c) Correct scope + a valid actor assertion reaches the real handler
// and completes a real DB-backed request. Requires TEST_DATABASE_URL.
func TestPlatformJITRouter_CorrectScopeAndActor_ReachesHandler(t *testing.T) {
	svc, pool, cleanup := jitSetupRouterTestDB(t)
	defer cleanup()

	h := newJITPlatformRouter(t, svc, false)
	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	requester := jitSeedUser(t, pool, internalTenantID)
	actorToken := "Bearer " + jitBuildActorToken(t, h.cfg, requester, internalTenantID)

	rec := h.do(t, http.MethodPost, "/internal/v1/jit-elevations", "platform:jit-elevations", actorToken, map[string]interface{}{
		"role_key":         "platform_support",
		"reason":           "router test happy path",
		"duration_seconds": 60,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var elevation map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &elevation))
	require.Equal(t, "pending", elevation["status"])
	require.Equal(t, requester.String(), elevation["requester_id"])
}

// (d) Approving a JIT elevation using the SAME actor identity as the
// requester is rejected at the API layer -- not merely deep inside the
// service -- proving the two-person rule is enforced end-to-end through
// the real router/middleware chain, not just via a direct service-layer
// unit test. Requires TEST_DATABASE_URL.
func TestPlatformJITRouter_SelfApproval_Returns403(t *testing.T) {
	svc, pool, cleanup := jitSetupRouterTestDB(t)
	defer cleanup()

	h := newJITPlatformRouter(t, svc, false)
	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	requester := jitSeedUser(t, pool, internalTenantID)
	requesterAssertion := "Bearer " + jitBuildActorToken(t, h.cfg, requester, internalTenantID)

	createRec := h.do(t, http.MethodPost, "/internal/v1/jit-elevations", "platform:jit-elevations", requesterAssertion, map[string]interface{}{
		"role_key":         "platform_admin",
		"reason":           "router test self-approval",
		"duration_seconds": 300,
	})
	require.Equal(t, http.StatusCreated, createRec.Code, createRec.Body.String())
	var created map[string]interface{}
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &created))
	elevationID := created["id"].(string)

	// Same actor (the requester) attempts to approve their own request.
	approveRec := h.do(t, http.MethodPost, "/internal/v1/jit-elevations/"+elevationID+"/approve", "platform:jit-elevations", requesterAssertion, nil)
	require.Equal(t, http.StatusForbidden, approveRec.Code, approveRec.Body.String())
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(approveRec.Body.Bytes(), &body))
	require.Equal(t, "self_approval_not_allowed", body["error"])
}

// (e) A direct standing-role grant for a non-viewer platform role is
// rejected 403 platform_role_not_standing_assignable at the handler,
// through the real router -- no DB required, since GrantStandingRole
// rejects before any DB write (see platform_jit_service.go).
func TestPlatformJITRouter_StandingGrantNonViewer_Returns403(t *testing.T) {
	sp := &jitRouterFakeSpiceDB{}
	svc := services.NewPlatformJITService(repositories.NewPlatformElevationRepository(nil), nil, sp, nil, zap.NewNop())
	h := newJITPlatformRouter(t, svc, false)

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	actorID := uuid.New()
	actorAssertion := "Bearer " + jitBuildActorToken(t, h.cfg, actorID, internalTenantID)

	rec := h.do(t, http.MethodPost, "/internal/v1/platform-roles", "platform:jit-elevations", actorAssertion, map[string]interface{}{
		"user_id":  uuid.New().String(),
		"role_key": "platform_admin",
	})
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "platform_role_not_standing_assignable", body["error"])
}

// (f) No X-Tenant-ID header is required on any of the three platform-plane
// groups even in production, proving the middleware.tenant.go
// publicEndpoints exemption actually covers the bare create paths (this
// test would have failed before the trailing-slash/missing-entry fix in
// this same change: the bare POST paths didn't match the
// "/internal/v1/jit-elevations/" (trailing slash) prefix, and
// "/internal/v1/platform-roles" had no entry at all).
func TestPlatformJITRouter_NoTenantHeaderRequired_InProduction(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")

	svc, pool, cleanup := jitSetupRouterTestDB(t)
	defer cleanup()
	h := newJITPlatformRouter(t, svc, true /* mount ExtractTenant() */)

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	actor := jitSeedUser(t, pool, internalTenantID)
	targetUser := jitSeedUser(t, pool, internalTenantID)
	actorAssertion := "Bearer " + jitBuildActorToken(t, h.cfg, actor, internalTenantID)

	cases := []struct {
		method, path string
		body         interface{}
	}{
		{http.MethodPost, "/internal/v1/jit-elevations", map[string]interface{}{"role_key": "platform_admin", "reason": "x", "duration_seconds": 60}},
		{http.MethodPost, "/internal/v1/break-glass", map[string]interface{}{"role_key": "platform_admin", "reason": "x", "duration_seconds": 60}},
		{http.MethodPost, "/internal/v1/platform-roles", map[string]interface{}{"user_id": targetUser.String(), "role_key": "platform_viewer"}},
		{http.MethodGet, "/internal/v1/platform-roles", nil},
	}
	for _, tc := range cases {
		rec := h.do(t, tc.method, tc.path, "platform:jit-elevations", actorAssertion, tc.body)
		// No X-Tenant-ID header was set anywhere above. In production,
		// ExtractTenant() aborts with 400 "Tenant context required" for
		// any NON-exempt /internal/* path missing that header -- assert
		// we never see that specific rejection (whatever status the
		// handler/service itself returns for these bodies is fine and
		// exercised by the other tests above).
		require.NotEqual(t, http.StatusBadRequest, rec.Code, "%s %s unexpectedly blocked by ExtractTenant: %s", tc.method, tc.path, rec.Body.String())
		var body map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err == nil {
			require.NotEqual(t, "Tenant context required", body["error"], "%s %s: %s", tc.method, tc.path, rec.Body.String())
		}
	}
}

// --------------------------------------------------------------------
// R1 lead-review follow-up: GET list routes for /internal/v1/
// jit-elevations and /internal/v1/break-glass (filters: status,
// requester_id; paginated), plus a read-only audit endpoint over the
// append-only transitions hash chain
// (GET /internal/v1/jit-elevations/:id/transitions). Same
// platformJITAuth chain and error shape as the POST routes above, so
// (g)/(h) mirror (a)/(b) for the new routes, and (i)/(j)/(k) are
// DB-backed end-to-end coverage via the real router.
// --------------------------------------------------------------------

// (g) No service token at all on any new GET route -> 401.
func TestPlatformJITRouter_ListRoutes_NoToken_Returns401(t *testing.T) {
	sp := &jitRouterFakeSpiceDB{}
	svc := services.NewPlatformJITService(repositories.NewPlatformElevationRepository(nil), nil, sp, nil, zap.NewNop())
	h := newJITPlatformRouter(t, svc, false)

	paths := []string{
		"/internal/v1/jit-elevations",
		"/internal/v1/break-glass",
		"/internal/v1/jit-elevations/" + uuid.New().String() + "/transitions",
	}
	for _, p := range paths {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, p, bytes.NewReader(nil))
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		require.Equalf(t, http.StatusUnauthorized, rec.Code, "GET %s body=%s", p, rec.Body.String())
	}
}

// (h) Valid service token WITHOUT platform:jit-elevations scope on any
// new GET route -> 403 insufficient_scope, same as the POST routes.
func TestPlatformJITRouter_ListRoutes_WrongScope_Returns403(t *testing.T) {
	sp := &jitRouterFakeSpiceDB{}
	svc := services.NewPlatformJITService(repositories.NewPlatformElevationRepository(nil), nil, sp, nil, zap.NewNop())
	h := newJITPlatformRouter(t, svc, false)

	paths := []string{
		"/internal/v1/jit-elevations",
		"/internal/v1/break-glass",
		"/internal/v1/jit-elevations/" + uuid.New().String() + "/transitions",
	}
	for _, p := range paths {
		rec := h.do(t, http.MethodGet, p, "some:other-scope", "", nil)
		require.Equalf(t, http.StatusForbidden, rec.Code, "GET %s body=%s", p, rec.Body.String())
	}
}

// (i) DB-backed: GET /internal/v1/jit-elevations returns only the
// non-break-glass rows the caller created, filterable by status and
// requester_id, and paginated via page/page_size. Requires
// TEST_DATABASE_URL.
func TestPlatformJITRouter_ListElevations_FiltersAndPaginates(t *testing.T) {
	svc, pool, cleanup := jitSetupRouterTestDB(t)
	defer cleanup()
	h := newJITPlatformRouter(t, svc, false)

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	requesterA := jitSeedUser(t, pool, internalTenantID)
	requesterB := jitSeedUser(t, pool, internalTenantID)
	assertionA := "Bearer " + jitBuildActorToken(t, h.cfg, requesterA, internalTenantID)
	assertionB := "Bearer " + jitBuildActorToken(t, h.cfg, requesterB, internalTenantID)

	// Two pending requests from A (different role_key each, since
	// idx_iam_jit_elevations_one_open_per_subject uniquely constrains
	// (requester_id, role_key, tenant_scope) — same requester can hold
	// two concurrent open requests as long as the role differs), one
	// from B.
	for _, roleKey := range []string{"platform_support", "platform_billing"} {
		rec := h.do(t, http.MethodPost, "/internal/v1/jit-elevations", "platform:jit-elevations", assertionA, map[string]interface{}{
			"role_key":         roleKey,
			"reason":           "list-test A",
			"duration_seconds": 60,
		})
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	}
	rec := h.do(t, http.MethodPost, "/internal/v1/jit-elevations", "platform:jit-elevations", assertionB, map[string]interface{}{
		"role_key":         "platform_support",
		"reason":           "list-test B",
		"duration_seconds": 60,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	// Unfiltered list sees all 3, none of them break-glass.
	listRec := h.do(t, http.MethodGet, "/internal/v1/jit-elevations", "platform:jit-elevations", assertionA, nil)
	require.Equal(t, http.StatusOK, listRec.Code, listRec.Body.String())
	var listBody models.ElevationListResponse
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &listBody))
	require.Equal(t, 3, listBody.Total)
	require.Len(t, listBody.Elevations, 3)
	for _, e := range listBody.Elevations {
		require.False(t, e.IsBreakGlass)
	}

	// requester_id filter narrows to just B's row.
	filteredRec := h.do(t, http.MethodGet, "/internal/v1/jit-elevations?requester_id="+requesterB.String(), "platform:jit-elevations", assertionA, nil)
	require.Equal(t, http.StatusOK, filteredRec.Code, filteredRec.Body.String())
	var filteredBody models.ElevationListResponse
	require.NoError(t, json.Unmarshal(filteredRec.Body.Bytes(), &filteredBody))
	require.Equal(t, 1, filteredBody.Total)
	require.Equal(t, requesterB, filteredBody.Elevations[0].RequesterID)

	// status filter: everything is still pending.
	statusRec := h.do(t, http.MethodGet, "/internal/v1/jit-elevations?status=pending", "platform:jit-elevations", assertionA, nil)
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	var statusBody models.ElevationListResponse
	require.NoError(t, json.Unmarshal(statusRec.Body.Bytes(), &statusBody))
	require.Equal(t, 3, statusBody.Total)

	// page_size=1 paginates: page 1 and page 2 each return one row, page
	// total stays 3, total_pages reflects the page size.
	page1Rec := h.do(t, http.MethodGet, "/internal/v1/jit-elevations?page=1&page_size=1", "platform:jit-elevations", assertionA, nil)
	require.Equal(t, http.StatusOK, page1Rec.Code, page1Rec.Body.String())
	var page1Body models.ElevationListResponse
	require.NoError(t, json.Unmarshal(page1Rec.Body.Bytes(), &page1Body))
	require.Len(t, page1Body.Elevations, 1)
	require.Equal(t, 3, page1Body.Total)
	require.Equal(t, 3, page1Body.TotalPages)

	page2Rec := h.do(t, http.MethodGet, "/internal/v1/jit-elevations?page=2&page_size=1", "platform:jit-elevations", assertionA, nil)
	require.Equal(t, http.StatusOK, page2Rec.Code, page2Rec.Body.String())
	var page2Body models.ElevationListResponse
	require.NoError(t, json.Unmarshal(page2Rec.Body.Bytes(), &page2Body))
	require.Len(t, page2Body.Elevations, 1)
	require.NotEqual(t, page1Body.Elevations[0].ID, page2Body.Elevations[0].ID)
}

// (j) DB-backed: GET /internal/v1/break-glass only ever returns
// is_break_glass=true rows, even when standing elevations exist too —
// proves the two GET routes don't leak into each other. Requires
// TEST_DATABASE_URL.
func TestPlatformJITRouter_ListBreakGlass_OnlyReturnsBreakGlassRows(t *testing.T) {
	svc, pool, cleanup := jitSetupRouterTestDB(t)
	defer cleanup()
	h := newJITPlatformRouter(t, svc, false)

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	requester := jitSeedUser(t, pool, internalTenantID)
	assertion := "Bearer " + jitBuildActorToken(t, h.cfg, requester, internalTenantID)

	standingRec := h.do(t, http.MethodPost, "/internal/v1/jit-elevations", "platform:jit-elevations", assertion, map[string]interface{}{
		"role_key":         "platform_support",
		"reason":           "standing, not break-glass",
		"duration_seconds": 60,
	})
	require.Equal(t, http.StatusCreated, standingRec.Code, standingRec.Body.String())

	// Different role_key than the standing request above — same
	// requester can't hold two concurrent open requests for the SAME
	// (requester_id, role_key, tenant_scope), per
	// idx_iam_jit_elevations_one_open_per_subject.
	bgRec := h.do(t, http.MethodPost, "/internal/v1/break-glass", "platform:jit-elevations", assertion, map[string]interface{}{
		"role_key":         "platform_billing",
		"reason":           "incident, break-glass",
		"duration_seconds": 60,
	})
	require.Equal(t, http.StatusCreated, bgRec.Code, bgRec.Body.String())

	listRec := h.do(t, http.MethodGet, "/internal/v1/break-glass", "platform:jit-elevations", assertion, nil)
	require.Equal(t, http.StatusOK, listRec.Code, listRec.Body.String())
	var listBody models.ElevationListResponse
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &listBody))
	require.Equal(t, 1, listBody.Total)
	require.True(t, listBody.Elevations[0].IsBreakGlass)

	elevListRec := h.do(t, http.MethodGet, "/internal/v1/jit-elevations", "platform:jit-elevations", assertion, nil)
	require.Equal(t, http.StatusOK, elevListRec.Code, elevListRec.Body.String())
	var elevListBody models.ElevationListResponse
	require.NoError(t, json.Unmarshal(elevListRec.Body.Bytes(), &elevListBody))
	require.Equal(t, 1, elevListBody.Total)
	require.False(t, elevListBody.Elevations[0].IsBreakGlass)
}

// (k) DB-backed: GET /internal/v1/jit-elevations/:id/transitions returns
// the append-only audit trail in order, and the hash chain is intact
// (each row's prev_hash equals the previous row's entry_hash, first
// row's prev_hash is ""). Requires TEST_DATABASE_URL.
func TestPlatformJITRouter_ListTransitions_ReturnsHashChainInOrder(t *testing.T) {
	svc, pool, cleanup := jitSetupRouterTestDB(t)
	defer cleanup()
	h := newJITPlatformRouter(t, svc, false)

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	requester := jitSeedUser(t, pool, internalTenantID)
	approver := jitSeedUser(t, pool, internalTenantID)
	requesterAssertion := "Bearer " + jitBuildActorToken(t, h.cfg, requester, internalTenantID)
	approverAssertion := "Bearer " + jitBuildActorToken(t, h.cfg, approver, internalTenantID)

	createRec := h.do(t, http.MethodPost, "/internal/v1/jit-elevations", "platform:jit-elevations", requesterAssertion, map[string]interface{}{
		"role_key":         "platform_support",
		"reason":           "transitions audit test",
		"duration_seconds": 300,
	})
	require.Equal(t, http.StatusCreated, createRec.Code, createRec.Body.String())
	var created map[string]interface{}
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &created))
	elevationID := created["id"].(string)

	approveRec := h.do(t, http.MethodPost, "/internal/v1/jit-elevations/"+elevationID+"/approve", "platform:jit-elevations", approverAssertion, nil)
	require.Equal(t, http.StatusOK, approveRec.Code, approveRec.Body.String())

	activateRec := h.do(t, http.MethodPost, "/internal/v1/jit-elevations/"+elevationID+"/activate", "platform:jit-elevations", requesterAssertion, nil)
	require.Equal(t, http.StatusOK, activateRec.Code, activateRec.Body.String())

	txRec := h.do(t, http.MethodGet, "/internal/v1/jit-elevations/"+elevationID+"/transitions", "platform:jit-elevations", requesterAssertion, nil)
	require.Equal(t, http.StatusOK, txRec.Code, txRec.Body.String())
	var txBody models.TransitionListResponse
	require.NoError(t, json.Unmarshal(txRec.Body.Bytes(), &txBody))
	require.Equal(t, 3, txBody.Total) // requested, approved, activated
	require.Len(t, txBody.Transitions, 3)

	// Newest first per ListTransitions' ORDER BY occurred_at DESC — walk
	// it oldest-first to verify the chain.
	oldestFirst := []*models.PlatformElevationTransition{
		txBody.Transitions[2], txBody.Transitions[1], txBody.Transitions[0],
	}
	require.Equal(t, "pending", oldestFirst[0].ToStatus, "to_status carries the elevation's status, not the action name")
	require.Equal(t, "approved", oldestFirst[1].ToStatus)
	require.Equal(t, "active", oldestFirst[2].ToStatus)
	require.Equal(t, "", oldestFirst[0].PrevHash, "first transition in the chain has no predecessor")
	for i := 1; i < len(oldestFirst); i++ {
		require.Equal(t, oldestFirst[i-1].EntryHash, oldestFirst[i].PrevHash, "transition %d's prev_hash must equal transition %d's entry_hash", i, i-1)
		require.NotEmpty(t, oldestFirst[i].EntryHash)
	}

	// A different elevation gets its own independent, unrelated chain.
	// Different role_key: the first elevation is still 'active', and
	// idx_iam_jit_elevations_one_open_per_subject uniquely constrains
	// (requester_id, role_key, tenant_scope) while status is
	// pending/approved/active.
	otherRec := h.do(t, http.MethodPost, "/internal/v1/jit-elevations", "platform:jit-elevations", requesterAssertion, map[string]interface{}{
		"role_key":         "platform_billing",
		"reason":           "second elevation, separate chain",
		"duration_seconds": 300,
	})
	require.Equal(t, http.StatusCreated, otherRec.Code, otherRec.Body.String())
	var otherCreated map[string]interface{}
	require.NoError(t, json.Unmarshal(otherRec.Body.Bytes(), &otherCreated))
	otherID := otherCreated["id"].(string)

	otherTxRec := h.do(t, http.MethodGet, "/internal/v1/jit-elevations/"+otherID+"/transitions", "platform:jit-elevations", requesterAssertion, nil)
	require.Equal(t, http.StatusOK, otherTxRec.Code, otherTxRec.Body.String())
	var otherTxBody models.TransitionListResponse
	require.NoError(t, json.Unmarshal(otherTxRec.Body.Bytes(), &otherTxBody))
	require.Equal(t, 1, otherTxBody.Total)
	require.NotEqual(t, txBody.Transitions[0].ElevationID, otherTxBody.Transitions[0].ElevationID)
}
