// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"net/http"
	// Side-effect import: registers /debug/pprof/* on the package-level
	// http.DefaultServeMux. We bind the pprof listener to a SEPARATE
	// http.Server below (see startPprofServer) so the profiling surface
	// never shares a listener with public OAuth traffic — gated behind
	// FALCON_PPROF_ENABLED env + a Linkerd AuthzPolicy that allows only
	// platform-admin SAs at the cluster networking layer.
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/platform-shared/mtls"
)

// @title Falcon ID API
// @version 1.0.0
// @description Falcon ID — Identity & Access Management for Hexxlock Technologies. Provides authentication, authorization, user management, role-based access control, multi-factor authentication, social login, SAML/OIDC federation, and compliance features.
// @contact.name Hexxlock API Support
// @contact.email api-support@hexxlock.com
// @host falcon.hexxlock.com
// @BasePath /api/v1
// @schemes http https
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Bearer token authentication. Format: "Bearer {token}"
func main() {
	infra, err := initInfrastructure()
	if err != nil {
		fmt.Printf("Failed to initialize infrastructure: %v\n", err)
		os.Exit(1)
	}
	defer infra.Close()
	defer logger.Sync()

	// Wire the package-level email-hash HMAC key BEFORE any repo
	// initialization or query path runs. The key is required for
	// UserRepository.{GetByEmail,GetByEmailGlobal,Create,Update}
	// (computeEmailHash); without it, every email lookup uses an
	// empty HMAC key and every Update path that doesn't explicitly
	// re-populate user.Email computes HMAC-SHA256("", "") and
	// rewrites the row's stored hash to the same well-known
	// constant — breaking discover for every user that hits the
	// path. RequireEmailHashKey fails-fast so a misconfigured
	// deployment surfaces at startup, not at the first login
	// attempt hours later.
	repositories.SetEmailHashKey(infra.Config.EmailHashKey)
	if err := repositories.RequireEmailHashKey(); err != nil {
		logger.Fatal("EMAIL_HASH_KEY not configured", zap.Error(err))
	}

	repos := initRepositories(infra)

	services := initServices(repos, infra)

	// Seed-data bootstrap order matters:
	//   1. bootstrapPlatformRealm — ensures the WellKnownRealmPlatform row
	//      exists in `realms`. Required because keystone manages the table
	//      structure but not row data; the platform admin cannot be created
	//      until the realm it lives in exists.
	//   2. bootstrapPlatformRealmTenant — maps the exampletenant tenant
	//      (HexxlockInternalTenantID) to the platform realm in
	//      `realm_tenants`. Required so realm-aware code (RLS, OAuth token
	//      issuance per-realm context, RealmService.GetTenantRealm) resolves
	//      tenant_id → realm_id correctly; without it, requests silently
	//      fall back to DefaultRealmID and Sprint-1 #5's wrong-realm class
	//      reproduces. Idempotent + skips on operator-driven re-mapping.
	//   3. bootstrapProvisionerOAuthClient — ensures the
	//      `svc-serviceclient-provisioner` row in iam_oauth_clients,
	//      sourced from FALCON_PROVISIONER_CLIENT_ID/SECRET env vars
	//      (Vault-backed via ExternalSecret). Crossplane per-service
	//      Jobs auth as this client; without the row, the entire
	//      ServiceClientClaim provisioning chain breaks at the head.
	//      Independent of the realm/admin chain — safe to run before
	//      either, but kept in this position to keep all seed steps
	//      grouped. Per memory internal engineering notes
	//      — survives falcon-id-pg fresh-initdb without operator
	//      intervention (replaces the legacy bash bootstrap-job.yaml's
	//      create flow, which is blocked by risk-MFA login interrupt
	//      + Vault policy gaps).
	//   4. bootstrapAdminUser — refuses to run if the platform realm row
	//      is missing (FI!137 fail-closed gate).
	//   5. bootstrapOAuthClientSLOSeed — patches the SLO endpoint
	//      columns (backchannel_logout_uri, frontchannel_logout_uri,
	//      *_session_required) + NIST AAL2 token lifetimes onto every
	//      first-party OAuth client. ENRICHES existing rows owned by
	//      the per-service Crossplane Job; never creates rows. Restores
	//      the seed lost in the 2026-05-07 fresh-initdb regression
	//      (docs/audits/2026-05-10-slo-bcl-fcl-regression.md). Runs
	//      after bootstrapProvisionerOAuthClient so the matrix can
	//      assume the provisioner row already exists.
	// All bootstrap steps are idempotent and safe to call on every restart.
	bootstrapPlatformRealm(repos)
	bootstrapPlatformRealmTenant(repos)
	// The SHARED realm holds every self-service customer as a logical tenant
	// (Auth0/Keycloak "Organizations" model). Signup auto-assigns new tenants
	// to it (models.DefaultRealmID), so it must exist before signups complete.
	bootstrapSharedRealm(repos)
	bootstrapProvisionerOAuthClient(repos)
	bootstrapAdminUser(services, repos)
	bootstrapOAuthClientSLOSeed(repos)
	// bootstrapConsumerTenant — shared B2C tenant for personal (gmail /
	// outlook / etc.) signups. Replaces the legacy per-user "personal-
	// XXXX" tenant model in signup_service.provisionTenant; without
	// this row, personal account signups would fail at signup-complete
	// time with a clear FK / not-found error from the tenant lookup.
	bootstrapConsumerTenant(repos)
	// Map the consumer tenant into the shared realm (after both rows exist),
	// so personal signups resolve a realm at user-creation time.
	bootstrapConsumerRealmTenant(repos)
	// bootstrapConsumerRole — `consumer_user` role scoped to the
	// consumer tenant; assigned at signup completion (see
	// services.PostSignupProvisioner). Backs frontend conditional
	// rendering + SOC consumer-vs-admin filtering. Fail-fast on
	// missing — same posture as the tenant bootstrap.
	bootstrapConsumerRole(repos)

	// Register before routes can serve. A background registration left freshly
	// deployed invitation/team routes behind permissions that did not exist yet.
	if services.Permission != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := selfRegisterPermissions(ctx, services.Permission)
		cancel()
		if err != nil {
			logger.Fatal("IAM self-registration failed; refusing to serve protected routes", zap.Error(err))
		}
	}

	handlers := initHandlers(services, repos, infra)
	// Fail fast on any handler that is nil but not deliberately
	// feature-gated (see cmd/handler_wiring.go) — a nil handler behind a
	// route registrar's `if handlers.X == nil { return }` guard 404s
	// silently in production with no log line, which is exactly what
	// happened to the invitations/roles surface (t-team-seats, 2026-09-10).
	validateHandlerWiring(handlers)
	router := registerRoutes(handlers, services, repos, infra)
	srv := buildHTTPServer(infra.Config.ServicePort, router)
	applyMTLSConfig(srv)

	go startServer(srv)
	pprofSrv := startPprofServer()

	backgroundTasks := startBackgroundTasks(services, repos, infra)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")
	backgroundTasks.Stop(services)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", zap.Error(err))
	}

	if pprofSrv != nil {
		if err := pprofSrv.Shutdown(ctx); err != nil {
			logger.Warn("pprof listener forced to shutdown", zap.Error(err))
		}
	}

	shutdownTracing(ctx, infra)
	logger.Info("Server exited")
}

// startPprofServer binds the Go runtime profiling endpoints on a
// dedicated listener (default :6060) so they cannot share a port or
// router with the public OAuth surface. Returns nil when disabled.
//
// Tier-1 layered defenses on top of the side-effect-only http.pprof
// registration:
//
//  1. Off-by-default — set FALCON_PPROF_ENABLED=true to enable. The
//     chart turns this on for in-cluster falcon-id pods only.
//  2. Separate listener (default :6060) so any misconfiguration on
//     the public listener (cookies, CORS, allow-list) cannot expose
//     pprof.
//  3. The chart ships a Linkerd Server + AuthzPolicy gating :6060 to
//     a fixed allow-list of operator ServiceAccounts (see
//     templates/server-pprof.yaml + templates/authorizationpolicy-pprof.yaml).
//     Without that AuthzPolicy in place the port returns
//     PermissionDenied at the proxy layer regardless of what the
//     application does.
//  4. The Service template does NOT publish :6060 — port-forward is
//     the supported access path so reaching pprof requires kubectl
//     credentials AND the AuthzPolicy SA bind.
//
// We deliberately do not register pprof on the same gin router used
// by /oauth/authorize because (a) gin middleware would mutate the
// request context in ways the runtime/pprof handler doesn't expect,
// and (b) the public router's CORS/CSRF/rate-limit middleware would
// run on profiling requests.
func startPprofServer() *http.Server {
	if os.Getenv("FALCON_PPROF_ENABLED") != "true" {
		return nil
	}
	addr := os.Getenv("FALCON_PPROF_ADDR")
	if addr == "" {
		addr = ":6060"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           http.DefaultServeMux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      120 * time.Second, // pprof CPU profiles can take 30s+
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	go func() {
		logger.Info("pprof listener starting", zap.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("pprof listener exited", zap.Error(err))
		}
	}()
	return srv
}

// buildHTTPServer constructs the HTTP server with security-hardened timeouts.
// ReadHeaderTimeout prevents Slowloris attacks; MaxHeaderBytes guards against
// excessively large headers consuming memory.
func buildHTTPServer(port string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}
}

// applyMTLSConfig applies mTLS server TLS configuration when mTLS is enabled.
func applyMTLSConfig(srv *http.Server) {
	mtlsCfg := mtls.ConfigFromEnv()
	if mtlsCfg.Mode == mtls.ModeDisabled {
		return
	}
	tlsConfig, tlsErr := mtls.NewServerTLSConfig(mtlsCfg)
	if tlsErr != nil {
		logger.Warn("mTLS server config failed, starting without TLS", zap.Error(tlsErr))
		return
	}
	if tlsConfig != nil {
		srv.TLSConfig = tlsConfig
	}
}

// startServer starts the HTTP server, switching to TLS when a TLSConfig is present.
func startServer(srv *http.Server) {
	logger.Info("Server starting", zap.String("address", srv.Addr))
	var serveErr error
	if srv.TLSConfig != nil {
		serveErr = srv.ListenAndServeTLS("", "")
	} else {
		serveErr = srv.ListenAndServe()
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		logger.Fatal("Failed to start server", zap.Error(serveErr))
	}
}

// selfRegisterPermissions registers falcon-id's own IAM permissions via PermissionService.
// Same flow that external services use via POST /internal/permissions/register.
func selfRegisterPermissions(ctx context.Context, permSvc *services.PermissionService) error {
	req := &models.RegisterModuleRequest{
		Module: "iam",
		Permissions: []models.PermissionDefinition{
			{Resource: "users", Actions: []string{"create", "read", "update", "delete", "unlock", "reset_password", "impersonate", "manage_mfa", "send_email", "bulk_operations"}, Description: "User identity management"},
			{Resource: "roles", Actions: []string{"create", "read", "update", "delete", "assign"}, Description: "Role-based access control"},
			{Resource: "permissions", Actions: []string{"read", "manage", "register"}, Description: "Permission definitions"},
			{Resource: "groups", Actions: []string{"create", "read", "update", "delete", "manage_members", "manage_roles"}, Description: "User group management"},
			{Resource: "sessions", Actions: []string{"read", "manage"}, Description: "Active session management"},
			{Resource: "tenants", Actions: []string{"create", "read", "update", "delete", "configure", "manage_members"}, Description: "Tenant lifecycle management"},
			{Resource: "invitations", Actions: []string{"read", "create", "delete"}, Description: "Tenant team invitations"},
			{Resource: "service_accounts", Actions: []string{"read"}, Description: "Tenant service account visibility"},
			{Resource: "service_principals", Actions: []string{"read"}, Description: "Tenant service principal visibility"},
			{Resource: "realms", Actions: []string{"create", "read", "update", "delete", "configure"}, Description: "Realm configuration"},
			{Resource: "oauth-clients", Actions: []string{"create", "read", "update", "delete", "rotate_secret"}, Description: "OIDC/OAuth client registration"},
			{Resource: "api-keys", Actions: []string{"create", "read", "update", "delete", "rotate"}, Description: "API key management"},
			{Resource: "audit-logs", Actions: []string{"read", "export"}, Description: "Security audit trail"},
			{Resource: "mfa", Actions: []string{"configure", "enforce", "reset"}, Description: "Multi-factor authentication policies"},
			{Resource: "saml", Actions: []string{"create", "read", "update", "delete", "configure"}, Description: "SAML identity provider federation"},
			{Resource: "ldap", Actions: []string{"create", "read", "update", "delete", "configure", "sync"}, Description: "LDAP/Active Directory integration"},
			{Resource: "scim", Actions: []string{"configure", "read"}, Description: "SCIM provisioning"},
			{Resource: "password-policies", Actions: []string{"read", "configure"}, Description: "Password strength and rotation policies"},
		},
	}
	_, err := permSvc.RegisterModule(ctx, req)
	return err
}

// shutdownTracing gracefully shuts down the OpenTelemetry tracer provider if one is configured.
func shutdownTracing(ctx context.Context, infra *Infrastructure) {
	if infra.TracerProvider == nil {
		return
	}
	if err := infra.TracerProvider.Shutdown(ctx); err != nil {
		logger.Error("Failed to shutdown tracing", zap.Error(err))
	}
}
