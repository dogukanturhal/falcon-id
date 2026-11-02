// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.uber.org/zap"

	_ "github.com/dogukanturhal/falcon-id/docs"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/shared/database"
	sharedmiddleware "github.com/dogukanturhal/falcon-id/internal/shared/middleware"
	sharedtracing "github.com/dogukanturhal/falcon-id/internal/shared/tracing"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	// Permission strings (duplicated 3+ times)
	permCoreUsersRead        = "core:users:read"
	permCoreUsersUpdate      = "core:users:update"
	permCoreRolesRead        = "core:roles:read"
	permCorePermsRead        = "core:permissions:read"
	permIAMUsersRead         = "iam:users:read"
	permIAMUsersCreate       = "iam:users:create"
	permIAMUsersUpdate       = "iam:users:update"
	permIAMUsersDelete       = "iam:users:delete"
	scopeTeamsRead           = "iam:teams:read" // service-token scope for the internal team-scope route
	permIAMInvitationsRead   = "iam:invitations:read"
	permIAMInvitationsCreate = "iam:invitations:create"
	permIAMInvitationsDelete = "iam:invitations:delete"
	// WO#20 developer access (tenant API keys, webhooks).
	permIAMAPIKeysRead   = "iam:api_keys:read"
	permIAMAPIKeysManage = "iam:api_keys:manage"
	// ADR-A10 SoD rule matrix + violation report
	// (23-authorization-rbac-abac-rebac.md §8.3, 17-module-account.md §5.1/
	// §5.2): tenant admin manages their SoD rule additions/overrides and
	// reviews detected violations.
	permAccountSoDManage = "account:sod:manage"

	// Health status strings
	statusHealthy   = "healthy"
	statusUnhealthy = "unhealthy"
)

// registerRoutes sets up all HTTP routes and middleware.
func registerRoutes(handlers *Handlers, services *Services, repos *Repositories, infra *Infrastructure) *gin.Engine {
	cfg := infra.Config

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Gin engine-level trusted proxies. Without this, `c.ClientIP()` falls
	// back to the raw TCP socket peer (the APISIX/Linkerd pod IP at
	// 10.42.x.x) instead of parsing X-Forwarded-For. This bricked the
	// trusted-devices feature on 2026-05-11: every session/device row
	// recorded the cluster Pod CIDR IP as the "client IP", making the
	// enrollment_token IP-binding ineffective (memo:
	// internal engineering notes) AND making
	// the "Trusted devices" UI list show internal pod IPs. APISIX's
	// real-ip plugin already populates X-Forwarded-For upstream; this
	// line tells Gin to TRUST that header from the configured proxy
	// CIDRs. Same pattern is already applied to rate-limit middleware
	// (line ~130) — engine-level was the gap that broke c.ClientIP()
	// in every other handler.
	if len(cfg.TrustedProxies) > 0 {
		if err := router.SetTrustedProxies(cfg.TrustedProxies); err != nil {
			logger.Fatal("router.SetTrustedProxies failed", zap.Error(err))
		}
		logger.Info("Gin engine trusted proxies configured",
			zap.Strings("proxies", cfg.TrustedProxies))
	}

	authMiddleware, authRateLimiter, mw := buildMiddlewares(services, infra, repos, cfg)

	// DPoP (RFC 9449) wiring. Resource-server enforcement lives inside
	// RequireAuth; issue-side binding lives in the token-endpoint
	// handlers (login, refresh, MFA complete). Both sides share the
	// same DPoPMiddleware instance so JTI replay detection is consistent
	// across token-issuance and resource-access paths. Feature-flagged
	// by DPOP_ENABLED.
	dpopMW := initDPoPMiddleware(infra, cfg)
	if dpopMW != nil {
		authMiddleware.SetDPoPMiddleware(dpopMW)
		handlers.Auth.SetDPoPMiddleware(dpopMW)
	}
	var dataPlanePool *pgxpool.Pool
	if infra.DB != nil {
		dataPlanePool = infra.DB.Pool
	}
	applyGlobalMiddleware(router, handlers, cfg, authMiddleware, mw.IPFilter, mw.RateLimit, mw.APIKey, dataPlanePool, services.OriginRegistry)

	isNonProd := cfg.Environment != "production" && cfg.Environment != "staging"
	if isNonProd {
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	registerHealthRoutes(router, infra)
	registerMetricsRoutes(router, cfg)
	registerAPIRoutes(router, handlers, APIRouteMiddlewares{
		Auth:            authMiddleware,
		SCIM:            mw.SCIM,
		Internal:        mw.Internal,
		APIKey:          mw.APIKey,
		AuthRateLimiter: authRateLimiter,
		ServiceAuth:     mw.ServiceAuth,
	})
	registerOAuthRoutes(router, handlers, authMiddleware, dpopMW, cfg.OAuthTokenPerUserClientIDs, authRateLimiter)
	registerSAMLRoutes(router, handlers, authMiddleware)
	registerSAMLSPRoutes(router, handlers, authMiddleware)
	registerSCIMRoutes(router, handlers, mw.SCIM)
	registerProductRoutes(router, handlers, authMiddleware, authRateLimiter)
	registerStubTenantRoutes(router, handlers, authMiddleware)

	router.GET("/.well-known/ssf-configuration", handlers.SSF.GetConfiguration)
	logger.Info("SSF well-known discovery endpoint registered")

	registerBackchannelLogout(router, handlers)
	registerCAERoutes(router, handlers, authMiddleware)

	return router
}

// routeMiddlewares groups secondary middleware so buildMiddlewares can return them as one value.
type routeMiddlewares struct {
	IPFilter    *middleware.IPFilterMiddleware
	RateLimit   *middleware.RateLimitMiddleware
	APIKey      *middleware.APIKeyAuthMiddleware
	SCIM        *middleware.SCIMAuthMiddleware
	Internal    *middleware.InternalAuthMiddleware
	ServiceAuth *middleware.ServiceAuthMiddleware
}

// buildMiddlewares constructs all middleware required by registerRoutes.
func buildMiddlewares(services *Services, infra *Infrastructure, repos *Repositories, cfg *config.Config) (
	*middleware.AuthMiddleware,
	*middleware.AuthRateLimiter,
	routeMiddlewares,
) {
	authMiddleware := middleware.NewAuthMiddleware(services.Token, cfg)
	authMiddleware.SetAuthorizationEngine(services.AuthzEngine)
	if services.TenantStatusGate != nil {
		authMiddleware.SetTenantSuspensionChecker(services.TenantStatusGate)
	}
	if infra.SessionCache != nil {
		authMiddleware.SetSessionCache(infra.SessionCache)
	}
	// 2026-05-17 — wire iam_sessions DB repo so RequireFreshAuth can fall
	// back to session.authenticated_at when the JWT auth_time claim is
	// missing/stale. Closes the "user stuck behind step-up after
	// successful MFA verification" trap (their cookie still has the old
	// JWT but session.authenticated_at was bumped at step-up time).
	// See middleware/auth.go::RequireFreshAuth doc for the full rationale.
	if repos.Session != nil {
		authMiddleware.SetSessionRepository(repos.Session)
	}
	// SSO-cookie path re-checks account status (disabled/deleted/locked users).
	if repos.User != nil {
		authMiddleware.SetIdpUserLookup(repos.User)
	}
	if repos.Session != nil {
		authMiddleware.SetIdpSessionReader(repos.Session)
	}
	// 2026-05-26 — wire iam_step_up_verifications repo so
	// RequireFreshAuthForAction can pass when an in-place step-up
	// (POST /api/v1/auth/mfa/step-up/verify) for the same action has
	// recently completed. Enables the canonical in-place step-up
	// modal pattern (Auth0 / Google / Okta) instead of forcing the
	// disruptive full OAuth redirect dance for sensitive mutations
	// like /mfa/disable, /password/change, /sessions/:id, etc.
	if repos.StepUpVerification != nil {
		authMiddleware.SetStepUpRepository(repos.StepUpVerification)
	}
	// Session activity tracking — fire-and-forget per-request touch with a
	// Redis-gated 60s throttle so idle-timeout enforcement (checked on
	// refresh in token_service_validation.go) has an accurate LastActivityAt.
	// Required because the SDK's /heartbeat call is not load-bearing —
	// background tabs may be throttled by the browser and skip beats.
	if infra.RedisClient != nil {
		tracker := middleware.NewSessionActivityTracker(
			repos.Session,
			infra.RedisClient,
			0, // default 60s throttle window
		)
		authMiddleware.SetActivityTracker(tracker)
	}

	rateLimitMiddleware := middleware.NewRateLimitMiddleware(services.RateLimit)
	if len(cfg.TrustedProxies) > 0 {
		rateLimitMiddleware.SetTrustedProxies(cfg.TrustedProxies)
		logger.Info("Configured trusted proxies for rate limiting", zap.Strings("proxies", cfg.TrustedProxies))
	} else {
		logger.Warn("No trusted proxies configured - X-Forwarded-For headers will not be used")
	}

	authRateLimiterConfig := middleware.DefaultAuthRateLimiterConfig()
	if cfg.Environment == "development" {
		authRateLimiterConfig = middleware.DevAuthRateLimiterConfig()
	}
	authRateLimiter := middleware.NewAuthRateLimiter(authRateLimiterConfig, infra.RateLimiter)
	if len(cfg.TrustedProxies) > 0 {
		authRateLimiter.SetTrustedProxies(cfg.TrustedProxies)
	}
	logger.Info("Tiered auth rate limiter initialized",
		zap.Int("per_ip_max", authRateLimiterConfig.PerIP.MaxRequests),
		zap.Duration("per_ip_window", authRateLimiterConfig.PerIP.Window),
		zap.Int("per_account_max", authRateLimiterConfig.PerAccount.MaxRequests),
		zap.Duration("per_account_window", authRateLimiterConfig.PerAccount.Window),
		zap.Int("global_max", authRateLimiterConfig.Global.MaxRequests),
		zap.Duration("global_window", authRateLimiterConfig.Global.Window),
		zap.Bool("redis_backed", infra.RateLimiter != nil),
	)

	serviceAuthMiddleware := buildServiceAuthMiddleware(services, cfg)

	mw := routeMiddlewares{
		IPFilter:    middleware.NewIPFilterMiddleware(services.IPRule),
		RateLimit:   rateLimitMiddleware,
		APIKey:      middleware.NewAPIKeyAuthMiddleware(services.APIKey),
		SCIM:        middleware.NewSCIMAuthMiddleware(services.SCIM),
		Internal:    middleware.NewInternalAuthMiddleware(cfg.InternalAPIKey),
		ServiceAuth: serviceAuthMiddleware,
	}
	return authMiddleware, authRateLimiter, mw
}

// buildServiceAuthMiddleware builds the composite service-to-service auth middleware.
// It checks KeyManager DB keys first (rotation-aware), then falls back to the service principal registry.
func buildServiceAuthMiddleware(services *Services, cfg *config.Config) *middleware.ServiceAuthMiddleware {
	keyMgr := services.KeyManager
	spLookup := middleware.NewServicePrincipalLookupAdapter(func(ctx context.Context, keyID string) (string, string, error) {
		if keyMgr != nil {
			if pubKey, err := keyMgr.PublicKey(keyID); err == nil {
				if pubPEM, pemErr := marshalPublicKeyToPEM(pubKey); pemErr == nil {
					return pubPEM, "oauth-client", nil
				}
			}
		}
		sp, err := services.ServicePrincipal.GetByKeyID(ctx, keyID)
		if err != nil {
			return "", "", err
		}
		return sp.PublicKeyPEM, sp.Slug, nil
	})
	oauthKeyID, oauthPubKey := services.OAuthProvider.SigningKeyInfo()
	compositeLookup := middleware.NewCompositeKeyLookup(oauthKeyID, oauthPubKey, spLookup).
		WithOAuthKeyResolver(services.OAuthProvider.LookupSigningPublicKey)
	return middleware.NewServiceAuthMiddleware(compositeLookup, cfg.InternalAPIKey)
}

// initDPoPMiddleware initializes the DPoP middleware when Redis is available.
// Returns nil when the dependencies aren't wired or when the feature flag is
// off — callers must handle both cases (the resulting chain is additive, so
// nil just means "no DPoP enforcement").
func initDPoPMiddleware(infra *Infrastructure, cfg *config.Config) *middleware.DPoPMiddleware {
	if !cfg.DPoPEnabled {
		logger.Info("DPoP middleware disabled via DPOP_ENABLED=false")
		return nil
	}
	if infra.RedisClient == nil {
		logger.Warn("DPoP enabled but Redis unavailable — refusing to enforce without replay protection")
		return nil
	}
	logger.Info("DPoP middleware enabled (RFC 9449)")
	return middleware.NewDPoPMiddleware(infra.RedisClient.Redis(), logger.Log)
}

// applyGlobalMiddleware applies the ordered middleware stack to the router.
func applyGlobalMiddleware(
	router *gin.Engine,
	handlers *Handlers,
	cfg *config.Config,
	authMiddleware *middleware.AuthMiddleware,
	ipFilter *middleware.IPFilterMiddleware,
	rateLimitMW *middleware.RateLimitMiddleware,
	apiKeyMW *middleware.APIKeyAuthMiddleware,
	dataPlanePool *pgxpool.Pool,
	originRegistry *middleware.DynamicOriginRegistry,
) {
	router.Use(middleware.CorrelationID())
	if cfg.OTLPEndpoint != "" {
		router.Use(sharedtracing.GinMiddleware(cfg.ServiceName))
	}
	if cfg.MetricsEnabled {
		router.Use(middleware.PrometheusMetrics())
	}
	router.Use(middleware.RequestLogger())
	router.Use(sharedmiddleware.Recovery())
	router.Use(sharedmiddleware.ErrorHandler())
	router.Use(sharedmiddleware.APISecurityHeaders(cfg.Environment == "development"))
	// Stage 3: originRegistry adds tenant-registry-derived origins on top
	// of DefaultCORSConfig()'s static list and the existing wildcard-
	// subdomain patterns. A nil/never-refreshed registry contributes
	// nothing — see DynamicOriginRegistry's fail-closed doc comment.
	router.Use(middleware.CORSWithRegistry(middleware.DefaultCORSConfig(), originRegistry))
	router.Use(middleware.ExtractTenant())
	router.Use(middleware.PresentIdpSession())
	// RealmMiddleware.ExtractRealm resolves realm_id BEFORE auth so it is
	// available (a) to RLSMiddleware below for authenticated requests whose
	// JWT claims don't carry a realm (legacy/v0 tokens), and (b) to the
	// pre-auth session-blacklist DB-fallback bootstrap path
	// (TokenService.checkSessionActiveInDB), which needs realm context to
	// satisfy iam_sessions' realm-only RLS policy without any tenant
	// context. Previously constructed (cmd/handlers.go) but never
	// registered — same "wired but never mounted" gap RLSMiddleware had.
	// Nil-safe: realm architecture is opt-in via RealmEnabled.
	if handlers.RealmMiddleware != nil {
		router.Use(handlers.RealmMiddleware.ExtractRealm())
	}
	router.Use(ipFilter.IPFilter())
	router.Use(rateLimitMW.RateLimit())
	router.Use(apiKeyMW.APIKeyAuth())
	// OptionalAuth runs BEFORE CSRF so the CSRFMiddleware's per-session
	// validateToken path has the user/session context populated. This
	// matches the tier-1 industry pattern documented for every major
	// web framework (Spring Security FilterChain order, Django
	// `MIDDLEWARE` ordering convention, Rails ActionController callback
	// order, gorilla/csrf README "place after session middleware"):
	// session/auth establishment is a prerequisite for the
	// synchronizer-token CSRF defense. Without this ordering, the
	// CSRF middleware ran on every state-changing POST with no user
	// in context, fell through to a double-submit cookie path that
	// nothing else in the codebase set, and 403'd every browser
	// session-cookie POST. OptionalAuth is the right placement
	// (not RequireAuth) because pre-auth endpoints like /login,
	// /password/forgot, etc. must still pass through without a token.
	router.Use(authMiddleware.OptionalAuth())
	if handlers.CSRFMiddleware != nil {
		router.Use(handlers.CSRFMiddleware.CSRF())
	}
	// RLSMiddleware MUST run after both ExtractTenant/OptionalAuth (which
	// populate "tenant_id") and RealmMiddleware.ExtractRealm (which
	// populates "realm_id"), and before any handler runs. It opens the
	// request-scoped transaction, sets+verifies the RLS GUCs via SET LOCAL,
	// and stores the *pgx.Tx in gin context under "pgx_tx".
	//
	// SCOPE AS OF THIS COMMIT: registering this middleware makes the GUCs
	// genuinely set (and read-back-verified) on the request's transaction.
	// It does NOT, by itself, make every repository query run inside that
	// transaction — repositories query their own injected *pgxpool.Pool
	// directly unless explicitly converted to consume "pgx_tx" via
	// WithDB(tx). See internal/repositories/withdb.go and the repositories
	// enumerated in the RLS enforcement report for exactly which
	// repositories were converted alongside this change.
	if dataPlanePool != nil {
		router.Use(database.RLSMiddleware(dataPlanePool))
	}
}

// registerBackchannelLogout registers the back-channel logout receive endpoint when the handler is wired.
func registerBackchannelLogout(router *gin.Engine, handlers *Handlers) {
	if handlers.BackchannelLogout != nil {
		router.POST("/api/v1/oauth/backchannel-logout", handlers.BackchannelLogout.Receive)
		logger.Info("Back-channel logout receive endpoint registered")
		return
	}
	logger.Warn("BackchannelLogout handler not wired — /api/v1/oauth/backchannel-logout endpoint disabled")
}

// registerSSFStreamRoutes registers authenticated SSF stream management routes.
// Agent 1E. The SSF well-known discovery endpoint is registered separately (unauthenticated).
func registerSSFStreamRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	if handlers.SSF == nil {
		return
	}
	ssf := api.Group("/ssf/streams")
	ssf.Use(authMiddleware.RequireAuth())
	{
		ssf.POST("", handlers.SSF.CreateStream)
		ssf.GET("", handlers.SSF.ListStreams)
		ssf.GET("/:id", handlers.SSF.GetStream)
		ssf.PUT("/:id", handlers.SSF.UpdateStream)
		ssf.DELETE("/:id", handlers.SSF.DeleteStream)
	}
}

// registerCAERoutes registers Continuous Access Evaluation Protocol endpoints.
func registerCAERoutes(router *gin.Engine, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	// SSE stream for authenticated clients (resource servers / apps)
	caeAuth := router.Group("/api/v1/cae")
	caeAuth.Use(authMiddleware.RequireAuth())
	{
		caeAuth.GET("/events", handlers.CAE.StreamEvents)
	}

	// Evaluation endpoint for service-to-service calls (service auth or internal)
	router.POST("/api/v1/cae/evaluate", handlers.CAE.EvaluateToken)
	logger.Info("CAE (Continuous Access Evaluation) routes registered")
}

// registerHealthRoutes registers health check endpoints.
//
// Three endpoints, three different jobs:
//
//   - /health           — process-alive ping. Cheapest possible. Used by
//     anything that just needs to know the gin server hasn't crashed.
//     NOT wired to liveness probe — process-alive is necessary but not
//     sufficient for a live IdP (the 2026-05-01 outage proved a process
//     can stay alive while every OAuth call short-circuits in 200µs).
//
//   - /health/ready     — kubelet readiness. Pings every dependency
//     (data-plane DB, control-plane DB, Redis). Any unhealthy backend
//     flips healthy=false → 503 → the Service drains traffic from this
//     pod. Tier-1 fail-close: previous behaviour only flipped healthy on
//     data-plane failure, leaving half-broken pods (e.g. Redis-down,
//     DBs-up) serving traffic; this revision treats every hard
//     dependency as load-bearing.
//
//   - /health/live-deep — kubelet liveness. Runs an actual SQL statement
//     against the application's hot table (iam_oauth_clients) so a pod
//     with a poisoned pgxpool — connections idle but unable to run
//     statements, the failure mode behind the 2026-05-01 outage — is
//     detected and restarted by the kubelet. Bound by a 5s context
//     timeout: the kubelet's livenessProbe.timeoutSeconds is the outer
//     budget, but a shorter handler-side deadline keeps the probe
//     deterministic regardless of probe config.
func registerHealthRoutes(router *gin.Engine, infra *Infrastructure) {
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": statusHealthy, "service": "iam"})
	})

	// Readiness handler shared by `/health/ready` (canonical, used by
	// kubelet readinessProbe) and `/ready` (Kubernetes-convention alias
	// reachable through the public APISIX route — falcon-id-customer-
	// discovery in the GitOps repository lists `/ready` alongside
	// /.well-known/* and /health/*. Without an alias, every probe to
	// /ready returned 404, polluting access logs and tripping any
	// external monitor that follows the k8s convention).
	//
	// Public allow-listing in middleware/tenant.go and tenant_ownership.go
	// already lists `/ready` — only the handler registration was
	// missing. Verified live 2026-05-09: in-cluster probe to
	// http://falcon-id-falcon-id.falcon-id.svc/ready returned 404 in
	// 4ms; /health/ready returned 200 with full dependency JSON.
	readyHandler := func(c *gin.Context) {
		// Draining (SIGTERM received): fail readiness without touching
		// dependencies so the Service/gateway stop routing here.
		if draining.Load() {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "draining"})
			return
		}
		status := gin.H{"status": "ready"}
		healthy := true

		// Check data plane database
		if err := infra.DB.Health(c.Request.Context()); err != nil {
			status["data_plane_database"] = statusUnhealthy
			healthy = false
			logger.Error("Health check: data plane DB unhealthy", zap.Error(err))
		} else {
			status["data_plane_database"] = statusHealthy
		}

		// Check control plane database. Treated as load-bearing: the
		// control plane stores tenant + realm metadata that every
		// authenticated request resolves through. A pod that can't
		// reach it is functionally down regardless of data-plane
		// health.
		if infra.ControlPlaneDB != nil {
			if err := infra.ControlPlaneDB.Health(c.Request.Context()); err != nil {
				status["control_plane_database"] = statusUnhealthy
				healthy = false
				logger.Error("Health check: control plane DB unhealthy", zap.Error(err))
			} else {
				status["control_plane_database"] = statusHealthy
			}
		} else {
			status["control_plane_database"] = "disabled"
		}

		// Check Redis. Treated as load-bearing: rate limiting,
		// session cache, token blacklist, IdP SSO sessions and CSRF
		// state all live in Redis. A pod whose Redis connection is
		// broken degrades silently to fail-open on rate limits and
		// loses CSRF protection — fail closed at the readiness gate
		// instead.
		if infra.RedisClient != nil {
			if err := infra.RedisClient.Health(c.Request.Context()); err != nil {
				status["redis"] = statusUnhealthy
				healthy = false
				logger.Error("Health check: Redis unhealthy", zap.Error(err))
			} else {
				status["redis"] = statusHealthy
			}
		} else {
			status["redis"] = "disabled"
		}

		if !healthy {
			status["status"] = "not ready"
			c.JSON(http.StatusServiceUnavailable, status)
			return
		}
		c.JSON(http.StatusOK, status)
	}
	router.GET("/health/ready", readyHandler)
	router.GET("/ready", readyHandler)

	router.GET("/health/live-deep", func(c *gin.Context) {
		// Bound the probe to 5s independent of the kubelet's
		// timeoutSeconds so a slow PG doesn't cascade into a hung
		// liveness handler that blocks the kubelet's probe queue.
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		if err := infra.DB.LiveDeep(ctx); err != nil {
			logger.Error("Live-deep check: iam_oauth_clients probe failed", zap.Error(err))
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": statusUnhealthy,
				"check":  "iam_oauth_clients_count",
				"error":  err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": statusHealthy, "check": "iam_oauth_clients_count"})
	})
}

// registerMetricsRoutes registers Prometheus metrics endpoint.
func registerMetricsRoutes(router *gin.Engine, cfg *config.Config) {
	if cfg.MetricsEnabled {
		router.GET("/metrics", gin.WrapH(promhttp.Handler()))
		logger.Info("Prometheus metrics endpoint enabled at /metrics")
	}
}

// APIRouteMiddlewares groups all middleware dependencies required by registerAPIRoutes.
// This struct exists solely to reduce the parameter count of registerAPIRoutes
// and keep the function signature within the project's linting threshold.
type APIRouteMiddlewares struct {
	Auth            *middleware.AuthMiddleware
	SCIM            *middleware.SCIMAuthMiddleware
	Internal        *middleware.InternalAuthMiddleware
	APIKey          *middleware.APIKeyAuthMiddleware
	AuthRateLimiter *middleware.AuthRateLimiter
	ServiceAuth     *middleware.ServiceAuthMiddleware
}

// registerAPIRoutes registers all /api routes (both v1 and deprecated).
func registerAPIRoutes(router *gin.Engine, handlers *Handlers, mw APIRouteMiddlewares) {
	authMiddleware := mw.Auth
	authRateLimiter := mw.AuthRateLimiter

	apiv1 := router.Group("/api/v1")
	registerVersionedRoutes(apiv1, handlers, authMiddleware, authRateLimiter)
	logger.Info("v1 API routes registered at /api/v1/*")

	// Backward-compatible /api/* routes — will be removed in v2.0.0.
	api := router.Group("/api")
	registerVersionedRoutes(api, handlers, authMiddleware, authRateLimiter)
	logger.Warn("Deprecated /api/* routes registered for backward compatibility (will be removed in v2.0.0)")

	registerDomainStubRoutes(router, handlers, authMiddleware)
	registerInternalAPIRoutes(router, handlers, authMiddleware, mw.Internal, mw.APIKey, mw.ServiceAuth)
}

// registerVersionedRoutes registers the complete set of resource routes on a given router group.
// Used for both the versioned /api/v1 prefix and the deprecated /api prefix.
func registerVersionedRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware, authRateLimiter *middleware.AuthRateLimiter) {
	registerAuthRoutes(api, handlers, authMiddleware, authRateLimiter)
	registerTenantRoutes(api, handlers, authMiddleware, authRateLimiter)
	registerDeveloperRoutes(api, handlers, authMiddleware)
	registerRealmRoutes(api, handlers, authMiddleware)
	registerUserRoutes(api, handlers, authMiddleware)
	registerRoleRoutes(api, handlers, authMiddleware)
	registerPermissionRoutes(api, handlers, authMiddleware)
	registerRoleTemplateRoutes(api, handlers, authMiddleware)
	registerAuthorizationRoutes(api, handlers, authMiddleware)
	registerSocialAuthRoutes(api, handlers)
	registerAdminRoutes(api, handlers, authMiddleware)
	registerPlatformAdminRoutes(api, handlers, authMiddleware, authRateLimiter)
	registerCatalogRoutes(api, handlers)
	registerQuotaRoutes(api, handlers, authMiddleware)
	registerInfrastructureStubRoutes(api, handlers, authMiddleware)
	registerManagedIdentityRoutes(api, handlers, authMiddleware, authRateLimiter)
	registerWorkloadIdentityRoutes(api, handlers, authMiddleware)
	registerServicePrincipalAdminRoutes(api, handlers, authMiddleware)
	registerSSFStreamRoutes(api, handlers, authMiddleware)
	registerGDPRDeletionRequestRoutes(api, handlers, authMiddleware)
}

// registerDomainStubRoutes registers stub handlers for domain/Cloudflare management.
// In production, APISIX would route /api/domains/platform/* to the domain-management
// service. These stubs serve empty responses so the platform-admin frontend doesn't break.
func registerDomainStubRoutes(router *gin.Engine, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	domains := router.Group("/api/domains/platform")
	domains.Use(authMiddleware.RequireAuth(), authMiddleware.RequirePlatformAdmin())
	{
		domains.GET("/status", handlers.Stub.GetCloudflareStatus)
		domains.GET("/zones", handlers.Stub.ListCloudflareZones)
		domains.GET("/zones/:zone_id", handlers.Stub.GetCloudflareZone)
		domains.GET("/dns-records", handlers.Stub.ListCloudflareDNSRecords)
		domains.GET("/zones/:zone_id/dns-records", handlers.Stub.ListCloudflareDNSRecords)
		domains.POST("/dns-records", handlers.Stub.CreateCloudflareDNSRecord)
		domains.PUT("/dns-records/:id", handlers.Stub.UpdateCloudflareDNSRecord)
		domains.DELETE("/dns-records/:id", handlers.Stub.DeleteCloudflareDNSRecord)
		domains.GET("/custom-hostnames", handlers.Stub.ListCloudflareCustomHostnames)
		domains.GET("/zones/:zone_id/custom-hostnames", handlers.Stub.ListCloudflareCustomHostnames)
		domains.POST("/custom-hostnames", handlers.Stub.CreateCloudflareCustomHostname)
		domains.DELETE("/custom-hostnames/:id", handlers.Stub.DeleteCloudflareCustomHostname)
		domains.POST("/custom-hostnames/:id/refresh", handlers.Stub.RefreshCloudflareCustomHostname)
		domains.GET("/subdomains", handlers.Stub.ListCloudflareSubdomains)
		domains.POST("/subdomains", handlers.Stub.CreateCloudflareSubdomain)
		domains.DELETE("/subdomains/:id", handlers.Stub.DeleteCloudflareSubdomain)
	}
}

// registerAuthRoutes registers authentication routes.
// SECURITY: Tiered rate limiting is applied to sensitive authentication endpoints
// to prevent brute force, credential stuffing, and DDoS attacks.
func registerAuthRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware, authRateLimiter *middleware.AuthRateLimiter) {
	authRL := authRateLimiter.Middleware()
	auth := api.Group("/auth")
	registerPublicAuthRoutes(auth, handlers, authRL)

	authProtected := api.Group("/auth")
	authProtected.Use(authMiddleware.RequireAuth())
	registerProtectedAuthRoutes(authProtected, handlers, authRateLimiter, authMiddleware)
}

// registerPublicAuthRoutes registers unauthenticated auth endpoints.
func registerPublicAuthRoutes(auth *gin.RouterGroup, handlers *Handlers, authRL gin.HandlerFunc) {
	auth.POST("/login", authRL, handlers.Auth.Login)
	auth.POST("/mfa/complete", authRL, handlers.Auth.CompleteMFALogin)
	auth.POST("/mfa/switch-method", authRL, handlers.Auth.SwitchMFALoginMethod)
	// WebAuthn-as-MFA challenge surface (2026-05-26). When a user has a
	// passkey enrolled and no code-based factor, /api/v1/auth/login
	// returns mfa_method="webauthn" + session_id; the frontend then
	// drives navigator.credentials.get() via these two endpoints to
	// satisfy the second factor without falling back to email-OTP.
	// Mirrors Microsoft Entra / Auth0 / Okta canonical UX. Uses the
	// same authRL envelope as /login + /mfa/complete since this is the
	// final mile of the same brute-force-attack surface.
	auth.POST("/mfa/webauthn/begin", authRL, handlers.Auth.BeginMFAWebAuthn)
	auth.POST("/mfa/webauthn/finish", authRL, handlers.Auth.FinishMFAWebAuthn)
	// Registration-interrupt enrollment endpoints (NIST SP 800-63B-4 §5.1):
	// gated by the enrollment_token alone (ip+ua-bound, 10-min TTL); same
	// rate-limit envelope as /login since both are anti-brute-force surfaces.
	auth.POST("/mfa/enrollment/init", authRL, handlers.Auth.MFAEnrollmentInit)
	auth.POST("/mfa/enrollment/verify", authRL, handlers.Auth.MFAEnrollmentVerify)
	// Grace-period "Remind me later" — only effectual when the realm's
	// security policy has mfa_grace_period_days > 0 AND
	// mfa_enrollment_max_skips > 0. Otherwise the service-level budget
	// check rejects with 401 and the client falls back to the hard-block UI.
	auth.POST("/mfa/enrollment/skip", authRL, handlers.Auth.MFAEnrollmentSkip)
	// WebAuthn registration-interrupt enrollment — used by the
	// admin-passkey-required policy gate. Auth is via the
	// enrollment_token (header for /finish, body for /begin); rate-limit
	// envelope matches the TOTP / email enrollment routes.
	auth.POST("/mfa/enrollment/webauthn/begin", authRL, handlers.Auth.MFAEnrollmentWebAuthnBegin)
	auth.POST("/mfa/enrollment/webauthn/finish", authRL, handlers.Auth.MFAEnrollmentWebAuthnFinish)
	auth.POST("/refresh", handlers.Auth.Refresh)
	auth.Any("/validate", handlers.Auth.Validate)
	auth.GET("/email/verify-token", handlers.MFA.VerifyEmailByToken)
	auth.POST("/password/forgot", authRL, handlers.Auth.ForgotPassword)
	auth.POST("/password/reset", authRL, handlers.Auth.ResetPassword)
	auth.GET("/social-providers", handlers.Auth.GetEnabledSocialProviders)
	// Public listing of social/SAML/LDAP authentication methods for a
	// tenant. Called by the login UI's BFF on first paint to decide
	// which buttons to render. No auth (the response is intentionally
	// limited to public-safe IDP fields per LoginMethodsResponse), no
	// authRL — the handler's fallback short-circuits to local-auth-only
	// when state is unavailable, and the data exposed is the same set
	// already reachable via /discover for any email + the tenant slug.
	// Memory: internal engineering notes
	// (same forgot-to-wire pattern that bit /platform/security/threats).
	auth.GET("/login-methods", handlers.Auth.GetLoginMethods)
	if handlers.AvatarUpload != nil {
		auth.GET("/users/:id/avatar", handlers.AvatarUpload.GetUserAvatar)
	}
	auth.POST("/magic-link/request", authRL, handlers.MagicLink.RequestMagicLink)
	auth.POST("/magic-link/verify", authRL, handlers.MagicLink.VerifyMagicLink)
	auth.GET("/magic-link/verify", authRL, handlers.MagicLink.VerifyMagicLinkFromQuery)
	auth.GET("/validate-invitation", handlers.Invitation.ValidateInvitation)
	auth.POST("/setup-account", authRL, handlers.Invitation.SetupAccount)
	// HRD is an enumeration vector — registered email can be probed by
	// observing email_known:true/false in the response. authRL adds a
	// tiered limiter (per-IP 30/min, per-account 60/hr, global 1000/min)
	// keyed off the auth_discover EndpointOverride. Strict-default would
	// be 5/min/IP — too tight for the legitimate keystroke-debounced
	// frontend lookup, hence the dedicated override. Pair with the
	// negative-cache + timing-smoothing in DiscoverService.
	auth.POST("/discover", authRL, handlers.Discover.Discover)
	auth.POST("/realm-discovery", handlers.RealmDiscovery.Discover)
	auth.POST("/signup", authRL, handlers.Signup.InitiateSignup)
	auth.GET("/signup/check-username", authRL, handlers.Signup.CheckUsername)
	auth.GET("/signup/check-slug", authRL, handlers.Signup.CheckSlug)
	auth.GET("/signup/suggest-slug", authRL, handlers.Signup.SuggestSlug)
	auth.GET("/signup/password-policy", authRL, handlers.Signup.PasswordPolicy)
	auth.POST("/signup/verify-email", authRL, handlers.Signup.VerifySignupEmail)
	auth.POST("/signup/complete", authRL, handlers.Signup.CompleteSignup)
	// Team invitation onboarding: token-scoped, no session. The invitation
	// token is the credential; both routes sit behind the auth rate limiter.
	if handlers.TeamInvitation != nil {
		auth.GET("/invitations/preview", authRL, handlers.TeamInvitation.PreviewInvitation)
		auth.POST("/invitations/register", authRL, handlers.TeamInvitation.RegisterFromInvitation)
	}
	if handlers.WebAuthn != nil {
		auth.POST("/webauthn/login/begin", authRL, handlers.WebAuthn.BeginAuthentication)
		auth.POST("/webauthn/login/finish", authRL, handlers.WebAuthn.FinishAuthentication)
		auth.POST("/webauthn/conditional/begin", authRL, handlers.WebAuthn.BeginConditionalLogin)
		auth.POST("/webauthn/conditional/complete", authRL, handlers.WebAuthn.CompleteConditionalLogin)
	}
}

// registerProtectedAuthRoutes registers authenticated session endpoints.
func registerProtectedAuthRoutes(authProtected *gin.RouterGroup, handlers *Handlers, authRateLimiter *middleware.AuthRateLimiter, authMiddleware *middleware.AuthMiddleware) {
	// RFC 9470 step-up gate for sensitive operations. 5-minute window
	// matches the de-facto industry default (Okta's "step-up assurance"
	// timeout, AWS Console's "re-authentication for sensitive change"
	// window) — short enough that a stolen long-lived cookie cannot be
	// silently used to change credentials, long enough that an active
	// user doesn't get re-prompted mid-workflow.
	freshAuth := authMiddleware.RequireFreshAuth(5 * time.Minute)
	authProtected.GET("/csrf-token", handlers.Auth.GetCSRFToken)
	authProtected.POST("/logout", handlers.Auth.Logout)
	// /derive-token was removed in Phase 3 (mig 233). The handler is kept
	// registered to return a deterministic 410 Gone + Deprecation header
	// for any straggling clients; per-RP refresh-token issuance now flows
	// through /oauth/authorize + /oauth/token (the BFF internal OIDC dance).
	authProtected.POST("/derive-token", handlers.Auth.DeriveTokenForSession)
	authProtected.GET("/me", handlers.Auth.Me)
	authProtected.PUT("/profile", handlers.Auth.UpdateProfile)
	// GDPR Art. 17 / KVKK Art. 7 right-to-erasure flow. Schedule + Cancel
	// live under /users/me/* alongside profile / sessions so the accounts
	// BFF proxies uniformly. Deletion is deferred by a 30-day grace
	// window (services/auth_account_deletion_service.go); the row is
	// not purged until after the window elapses. Step-up (`freshAuth`)
	// is REQUIRED on schedule — a destructive operation should not fire
	// from a stale tab, and even with the in-service password check we
	// want the user to have re-authenticated recently.
	authProtected.POST("/users/me/delete-account", freshAuth, handlers.Auth.DeleteMyAccount)
	authProtected.POST("/users/me/cancel-deletion", handlers.Auth.CancelMyDeletion)
	// Self-service organization memberships — the canonical B2B IAM
	// model (Clerk / WorkOS / Auth0 Organizations) exposes user-scoped
	// membership reads at /me. Admin-scoped CRUD continues under
	// /api/v1/admin/organizations.
	if handlers.Organization != nil {
		authProtected.GET("/me/organizations", handlers.Organization.GetMyOrganizations)
	}
	if handlers.AvatarUpload != nil {
		authProtected.GET("/avatar", handlers.AvatarUpload.GetMyAvatar)
		authProtected.POST("/avatar", handlers.AvatarUpload.UploadMyAvatar)
		authProtected.DELETE("/avatar", handlers.AvatarUpload.DeleteMyAvatar)
	}
	authProtected.POST("/password/change", freshAuth, handlers.Auth.ChangePassword)
	authProtected.GET("/sessions", handlers.Auth.GetSessions)
	authProtected.DELETE("/sessions/:id", freshAuth, handlers.Auth.RevokeSession)
	authProtected.GET("/login-history", handlers.Auth.GetLoginHistory)
	// Tier-1 risk-event audit feed for the user's own account. Powers
	// accounts.hexxlock.com's "Sign-in security events" section — Google-
	// style visibility into MFA-challenged + blocked logins.
	if handlers.Risk != nil {
		authProtected.GET("/me/risk-events", handlers.Risk.GetMyLoginEvents)
	}
	authProtected.POST("/heartbeat", handlers.Auth.Heartbeat)
	if handlers.PermissionStream != nil {
		authProtected.GET("/permissions/stream", handlers.PermissionStream.Stream)
	}
	authProtected.GET("/available-contexts", handlers.Context.GetAvailableContexts)
	authProtected.POST("/switch-context", handlers.Context.SwitchContext)
	registerDeviceRoutes(authProtected, handlers)
	registerDeviceFingerprintRoutes(authProtected, handlers, freshAuth)
	registerAuditRoutes(authProtected, handlers, freshAuth)
	registerMFARoutes(authProtected, handlers, authRateLimiter, authMiddleware)
	registerOnboardingVerifyRoutes(authProtected, handlers, authRateLimiter)
	registerOnboardingSlugRoute(authProtected, handlers)
	registerOnboardingStatusRoute(authProtected, handlers)
	registerEmailRoutes(authProtected, handlers)
	registerMyAPIKeyRoutes(authProtected, handlers)
	registerMyOAuthConsentRoutes(authProtected, handlers)
	registerGDPRConsentRoutes(authProtected, handlers)
	registerLinkedAccountsRoutes(authProtected, handlers)
	registerImpersonationRoutes(authProtected, handlers)
	if handlers.WebAuthn != nil {
		registerWebAuthnProtectedRoutes(authProtected, handlers, freshAuth)
	}
	registerWitnessRoutes(authProtected, handlers, authMiddleware.RequirePlatformAdmin())
	if handlers.Delegation != nil {
		registerDelegationRoutes(authProtected, handlers)
	}
}

// registerDeviceRoutes registers device management routes.
func registerDeviceRoutes(authProtected *gin.RouterGroup, handlers *Handlers) {
	devices := authProtected.Group("/devices")
	{
		devices.GET("", handlers.Device.ListDevices)
		devices.GET("/:id", handlers.Device.GetDevice)
		devices.POST("/:id/trust", handlers.Device.TrustDevice)
		devices.DELETE("/:id/trust", handlers.Device.UntrustDevice)
		devices.PUT("/:id/rename", handlers.Device.RenameDevice)
		devices.DELETE("/:id", handlers.Device.DeleteDevice)
	}
}

// registerDeviceFingerprintRoutes registers user-self-service for the
// richer-signal iam_device_fingerprints store. Distinct from
// registerDeviceRoutes (simpler iam_user_devices). Trust + Revoke gate on
// freshAuth (RFC 9470).
func registerDeviceFingerprintRoutes(authProtected *gin.RouterGroup, handlers *Handlers, freshAuth gin.HandlerFunc) {
	if handlers.DeviceFingerprint == nil {
		return
	}
	fps := authProtected.Group("/fingerprints")
	{
		fps.GET("", handlers.DeviceFingerprint.ListDeviceFingerprints)
		fps.POST("/:id/trust", freshAuth, handlers.DeviceFingerprint.TrustDeviceFingerprint)
		fps.DELETE("/:id", freshAuth, handlers.DeviceFingerprint.RevokeDeviceFingerprint)
	}
}

// registerAuditRoutes registers the tenant-admin user-facing audit surface
// — log query + WORM archive management. Archive endpoints return 503
// until AuditArchiverService is wired; freshAuth gate on
// ArchiveTenantLogs + VerifyArchiveIntegrity (RFC 9470).
func registerAuditRoutes(authProtected *gin.RouterGroup, handlers *Handlers, freshAuth gin.HandlerFunc) {
	if handlers.Audit == nil {
		return
	}
	audit := authProtected.Group("/audit")
	{
		audit.GET("/logs", handlers.Audit.GetAuditLogs)
		audit.GET("/export", handlers.Audit.ExportAuditReport)
		audit.GET("/archives", handlers.Audit.GetArchiveMetadata)
		audit.POST("/archive", freshAuth, handlers.Audit.ArchiveTenantLogs)
		audit.POST("/archives/:batch_id/verify", freshAuth, handlers.Audit.VerifyArchiveIntegrity)
	}
}

// registerMFARoutes registers MFA routes.
// SECURITY: Rate limiting is applied to code verification and setup endpoints
// to prevent brute-force attacks on MFA codes.
func registerMFARoutes(authProtected *gin.RouterGroup, handlers *Handlers, authRateLimiter *middleware.AuthRateLimiter, authMW *middleware.AuthMiddleware) {
	authRL := authRateLimiter.Middleware()

	// Action-scoped step-up gates. Each carries a unique action string
	// so an in-place step-up verification for one resource (e.g. MFA
	// disable) cannot silently authorize a different one (e.g. push
	// device unregister). When the iam_step_up_verifications repo is
	// wired (cmd/routes.go) the frontend can satisfy these via the
	// in-place step-up modal (POST /mfa/step-up/verify) instead of
	// being redirected through the full OAuth dance.
	freshAuthMFADisable := authMW.RequireFreshAuthForAction(5*time.Minute, "mfa.disable")
	freshAuthPushUnregister := authMW.RequireFreshAuthForAction(5*time.Minute, "mfa.push.unregister")

	mfa := authProtected.Group("/mfa")
	{
		mfa.POST("/setup/totp", authRL, handlers.MFA.SetupTOTP)
		mfa.POST("/setup/totp/verify", authRL, handlers.MFA.VerifyTOTPSetup)
		mfa.POST("/setup/email", authRL, handlers.MFA.EnableEmailMFA)
		// MFA disable paths are RFC 9470 step-up gated: a stolen
		// long-lived session must not be silently usable to remove the
		// user's second factor. The freshAuth gate (AAL2 within 300s)
		// is the SOLE canonical authorization. Both password and OTP
		// code in the body are OPTIONAL — when supplied they are
		// verified hard as defense-in-depth (legacy clients, ops
		// break-glass). Step-up may have completed via WebAuthn, in
		// which case there is no OTP value the frontend could pass.
		// Forcing a second prompt would be double-prompt UX disaster.
		// This matches Auth0 / Okta / Entra. Compensating controls
		// outside this gate: SSF/CAE emission, 7-year WORM audit,
		// email-on-factor-removal. See models.MFADisableRequest.
		//
		// Uses RequireFreshAuthForAction("mfa.disable") so the
		// in-place step-up modal (POST /mfa/step-up/verify) satisfies
		// freshness without forcing a full OAuth re-login round-trip.
		mfa.POST("/disable", authRL, freshAuthMFADisable, handlers.MFA.DisableMFA)
		mfa.POST("/disable/totp", authRL, freshAuthMFADisable, handlers.MFA.DisableTOTP)
		mfa.POST("/disable/email", authRL, freshAuthMFADisable, handlers.MFA.DisableEmailMFA)
		mfa.GET("/status", handlers.MFA.GetMFAStatus)
		mfa.PUT("/preferred-method", handlers.MFA.SetPreferredMFAMethod)
		mfa.POST("/backup-codes", authRL, handlers.MFA.GenerateBackupCodes)
		mfa.GET("/backup-codes", handlers.MFA.GetBackupCodesCount)
		mfa.POST("/send-code", authRL, handlers.MFA.SendMFACode)
		mfa.POST("/verify", authRL, handlers.MFA.VerifyMFACode)
		mfa.POST("/step-up/verify", authRL, handlers.MFA.VerifyStepUp)

		// Push-notification MFA endpoints. Defined in internal/handlers/
		// push_mfa_handler.go since 2026-04-XX but never wired up here.
		// The accounts.hexxlock.com Security page calls GET .../mfa/push/
		// devices on load — without these routes registered, every
		// security-page visit gets a global 404 banner. Fix landed
		// 2026-05-12 alongside the trusted-proxies SetTrustedProxies()
		// gap (same MR). Rate-limit the challenge endpoints (mirror
		// totp/email setup discipline).
		if handlers.PushMFA != nil {
			push := mfa.Group("/push")
			{
				push.POST("/register", authRL, handlers.PushMFA.RegisterDevice)
				// Unregistering a push device removes a phishing-resistant
				// factor — RFC 9470 step-up gated for the same reason as
				// /mfa/disable. Uses RequireFreshAuthForAction with a
				// distinct action so step-up for MFA disable doesn't
				// silently authorize push-device removal.
				push.DELETE("/devices/:id", freshAuthPushUnregister, handlers.PushMFA.UnregisterDevice)
				push.GET("/devices", handlers.PushMFA.ListDevices)
				push.POST("/challenge", authRL, handlers.PushMFA.InitiateChallenge)
				push.POST("/respond", authRL, handlers.PushMFA.RespondToChallenge)
				push.GET("/challenge/:id/status", handlers.PushMFA.GetChallengeStatus)
			}
		}
	}
}

// registerOnboardingVerifyRoutes registers the AcmeWeb onboarding wizard's
// contact-verification endpoints ("Add your mobile number" / "Confirm
// your mobile number" steps in the Brevo-mirrored flow). SECURITY: rate
// limited via the same authRL envelope as the MFA send-code/verify
// endpoints above — these are OTP endpoints and must not be brute-
// forceable. Deliberately separate from registerMFARoutes: these call
// MFAService's email-OTP primitives directly and must NOT be gated on
// MFAEnabled (a fresh signup has not enabled MFA and must not be
// required to in order to finish onboarding). See
// internal/handlers/onboarding_verify_handler.go and
// internal/services/mfa_service_onboarding_verify.go for why email,
// not SMS.
func registerOnboardingVerifyRoutes(authProtected *gin.RouterGroup, handlers *Handlers, authRateLimiter *middleware.AuthRateLimiter) {
	if handlers.OnboardingVerify == nil {
		return
	}
	authRL := authRateLimiter.Middleware()

	onboarding := authProtected.Group("/onboarding")
	{
		onboarding.POST("/verify/send", authRL, handlers.OnboardingVerify.SendCode)
		onboarding.POST("/verify/confirm", authRL, handlers.OnboardingVerify.Confirm)
	}
}

// registerOnboardingSlugRoute registers the onboarding wizard's
// subdomain-slug confirmation step. Mounted only when
// Handlers.OnboardingSlug is non-nil — nil means outbound S2S creds to
// tenant-management weren't configured at boot (see
// buildTenantManagementSlugUpdaterHTTPClient in cmd/services.go), so the
// route is skipped entirely rather than mounted behind a handler that
// would always 500.
func registerOnboardingSlugRoute(authProtected *gin.RouterGroup, handlers *Handlers) {
	if handlers.OnboardingSlug == nil {
		return
	}
	authProtected.PATCH("/onboarding/slug", handlers.OnboardingSlug.ConfirmSlug)
}

// registerOnboardingStatusRoute registers the onboarding wizard's
// entry-time re-entry-guard read. Mounted only when
// Handlers.OnboardingStatus is non-nil — nil means outbound S2S creds to
// tenant-management weren't configured at boot (see
// buildTenantManagementStatusReaderHTTPClient in cmd/services.go), so the
// route is skipped entirely rather than mounted behind a handler that
// would always fail. Any authenticated user may call this — it always
// answers for the caller's own tenant (see OnboardingStatusHandler).
func registerOnboardingStatusRoute(authProtected *gin.RouterGroup, handlers *Handlers) {
	if handlers.OnboardingStatus == nil {
		return
	}
	authProtected.GET("/onboarding/status", handlers.OnboardingStatus.GetStatus)
}

// registerEmailRoutes registers email verification routes.
func registerEmailRoutes(authProtected *gin.RouterGroup, handlers *Handlers) {
	email := authProtected.Group("/email")
	{
		email.POST("/send-verification", handlers.MFA.SendVerificationEmail)
		email.POST("/verify", handlers.MFA.VerifyEmail)
		email.GET("/status", handlers.MFA.GetEmailVerificationStatus)
	}
}

// registerMyAPIKeyRoutes registers self-service API key routes.
func registerMyAPIKeyRoutes(authProtected *gin.RouterGroup, handlers *Handlers) {
	myAPIKeys := authProtected.Group("/api-keys")
	{
		myAPIKeys.GET("", handlers.APIKey.ListMyAPIKeys)
		myAPIKeys.POST("", handlers.APIKey.CreateMyAPIKey)
		myAPIKeys.POST("/:id/revoke", handlers.APIKey.RevokeMyAPIKey)
	}
}

// registerMyOAuthConsentRoutes registers self-service OAuth consent routes.
func registerMyOAuthConsentRoutes(authProtected *gin.RouterGroup, handlers *Handlers) {
	myOAuthConsents := authProtected.Group("/oauth-consents")
	{
		myOAuthConsents.GET("", handlers.OAuthProvider.GetMyConsents)
		myOAuthConsents.DELETE("/:client_id", handlers.OAuthProvider.RevokeMyConsent)
	}
}

// registerGDPRConsentRoutes registers GDPR consent management routes.
func registerGDPRConsentRoutes(authProtected *gin.RouterGroup, handlers *Handlers) {
	gdprConsents := authProtected.Group("/consents")
	{
		gdprConsents.GET("", handlers.Consent.GetUserConsents)
		gdprConsents.GET("/types", handlers.Consent.GetConsentTypes)
		gdprConsents.GET("/history", handlers.Consent.GetConsentHistory)
		// Detailed history includes prior consent versions + the IP /
		// user-agent that recorded each transition, for the user's
		// own privacy-record export (GDPR Art. 15 right of access).
		// /history (above) is the summary view; this is the deep one.
		gdprConsents.GET("/history/detailed", handlers.Consent.GetConsentHistoryDetailed)
		gdprConsents.GET("/pending", handlers.Consent.CheckPendingConsents)
		gdprConsents.POST("/bulk", handlers.Consent.BulkUpdateConsents)
		gdprConsents.POST("/:type", handlers.Consent.UpdateConsent)
		gdprConsents.POST("/id/:id", handlers.Consent.UpdateConsentByID)
	}
}

// registerLinkedAccountsRoutes registers self-service social-account
// link/unlink routes (post-auth). The pre-auth `/auth/social/*`
// authorize+callback flow stays in registerSocialAuthRoutes; this is
// the user-management side: a logged-in user attaching/detaching
// Google/Apple/etc. credentials from their Falcon-ID account.
//
// LinkAccount runs an authorisation-code exchange against the social
// provider on the user's behalf, so the per-account state mutation is
// effectively a credential addition — sensitive enough to keep behind
// the standard authenticated session, but not a step-up trigger
// (linking does not lower account security; unlinking is bounded by
// the requirement that the user still has at least one auth method).
func registerLinkedAccountsRoutes(authProtected *gin.RouterGroup, handlers *Handlers) {
	if handlers.SocialAuth == nil {
		return
	}
	accounts := authProtected.Group("/accounts")
	{
		accounts.GET("", handlers.SocialAuth.ListLinkedAccounts)
		accounts.POST("/:provider/link", handlers.SocialAuth.LinkAccount)
		accounts.DELETE("/:provider", handlers.SocialAuth.UnlinkAccount)
	}
}

// registerGDPRDeletionRequestRoutes registers the deletion-request
// lifecycle endpoints that operate on an existing `iam_deletion_requests`
// row by its primary key (as opposed to the user-scoped
// /users/:id/delete which creates one).
//
// Cancel is owner-or-tenant-admin: a user who scheduled their own
// deletion can pull it back during the 30-day grace window; a tenant
// admin can rescind on the user's behalf (e.g. mis-clicked from an
// admin console). The handler does its own owner-or-admin check; the
// route adds a `gdpr_deletion_cancel` step-up bucket so a stolen
// long-lived cookie alone cannot silently undo a regret-deletion.
//
// Legal-hold set + remove are PLATFORM-ADMIN gated at the route layer
// (defense-in-depth on top of the handler's currentUserIsAdmin
// check) PLUS a dedicated `gdpr_legal_hold` step-up bucket. A legal
// hold is a regulatory-compliance assertion (litigation hold, KVKK
// audit-trail-preserve, SOX) — operationally distinct from ordinary
// admin actions and worth its own step-up metrics + bucket sizing.
//
// All three routes require an authenticated session.
func registerGDPRDeletionRequestRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	if handlers.GDPR == nil {
		return
	}
	dr := api.Group("/deletion-requests")
	dr.Use(authMiddleware.RequireAuth())
	{
		cancelStepUp := handlers.StepUpMiddleware.RequireStepUp("gdpr_deletion_cancel", 5*time.Minute)
		legalHoldStepUp := handlers.StepUpMiddleware.RequireStepUp("gdpr_legal_hold", 5*time.Minute)

		dr.POST("/:id/cancel", cancelStepUp, handlers.GDPR.CancelDeletion)
		dr.POST("/:id/legal-hold",
			authMiddleware.RequireRole("admin", "platform_admin"),
			legalHoldStepUp,
			handlers.GDPR.SetLegalHold)
		dr.DELETE("/:id/legal-hold",
			authMiddleware.RequireRole("admin", "platform_admin"),
			legalHoldStepUp,
			handlers.GDPR.RemoveLegalHold)
	}
}

// registerImpersonationRoutes registers impersonation routes.
func registerImpersonationRoutes(authProtected *gin.RouterGroup, handlers *Handlers) {
	impersonation := authProtected.Group("/impersonation")
	{
		impersonation.GET("/status", handlers.Impersonation.GetImpersonationStatus)
		impersonation.POST("/end", handlers.Impersonation.EndImpersonation)
	}
}

// registerTenantRoutes registers tenant routes.
func registerTenantRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware, authRateLimiter *middleware.AuthRateLimiter) {
	tenant := api.Group("/tenant")
	tenant.Use(authMiddleware.RequireAuth())
	{
		tenant.GET("", handlers.Tenant.GetCurrentTenant)
		tenant.PUT("/settings", handlers.Tenant.UpdateTenantSettings)
		tenant.GET("/usage", handlers.Tenant.GetTenantUsage)
		tenant.GET("/usage/history", handlers.Tenant.GetUsageHistory)
		tenant.GET("/plan-limits", handlers.Tenant.GetPlanLimits)
		tenant.GET("/feature-flags", handlers.Tenant.GetTenantFeatureFlags)
		tenant.GET("/feature-flags/overrides", handlers.Tenant.GetTenantFeatureFlagOverrides)
		tenant.GET("/connection-info", handlers.Tenant.GetTenantConnectionInfo)
		tenant.GET("/provisioning/status", handlers.ProductInstance.GetProvisioningStatus)

		// Fail-closed tenant module entitlements (the product roadmap §4.1).
		// Tenant is derived exclusively from the session/JWT via
		// authMiddleware.RequireAuth() above -- never from a header.
		if handlers.Entitlement != nil {
			tenant.GET("/entitlements", handlers.Entitlement.GetTenantEntitlements)
		}
	}

	// Phase 2: General settings page (MR 1) + Team page (MR 2)
	tenants := api.Group("/tenants")
	tenants.Use(authMiddleware.RequireAuth())
	{
		// GET/PATCH /api/v1/tenants/me/settings — timezone + default sender domain
		tenants.GET("/me/settings", handlers.TenantSettings.GetSettings)
		tenants.PATCH("/me/settings", handlers.TenantSettings.PatchSettings)

		// Authoritative seat ledger for the authenticated tenant.
		if handlers.SeatLimit != nil {
			tenants.GET("/me/seats", handlers.SeatLimit.GetTenantSeats)
		}
		// GET /api/v1/tenants/me/users — paginated human inventory with roles;
		// status=active filters before pagination, all (default) permits recovery.
		tenants.GET("/me/users", authMiddleware.RequirePermission(permIAMUsersRead), handlers.TeamInvitation.ListTenantUsers)
		// Tenant-admin CRUD over teams (organizations with org_type=team).
		if handlers.TenantTeam != nil {
			tenants.GET("/me/teams", authMiddleware.RequirePermission(permIAMUsersRead), handlers.TenantTeam.List)
			tenants.POST("/me/teams", authMiddleware.RequirePermission(permIAMUsersUpdate), handlers.TenantTeam.Create)
			tenants.GET("/me/teams/:id", authMiddleware.RequirePermission(permIAMUsersRead), handlers.TenantTeam.Get)
			tenants.PATCH("/me/teams/:id", authMiddleware.RequirePermission(permIAMUsersUpdate), handlers.TenantTeam.Update)
			tenants.DELETE("/me/teams/:id", authMiddleware.RequirePermission(permIAMUsersUpdate), handlers.TenantTeam.Delete)
			tenants.GET("/me/teams/:id/members", authMiddleware.RequirePermission(permIAMUsersRead), handlers.TenantTeam.ListMembers)
			tenants.POST("/me/teams/:id/members", authMiddleware.RequirePermission(permIAMUsersUpdate), handlers.TenantTeam.AddMember)
			tenants.PATCH("/me/teams/:id/members/:user_id", authMiddleware.RequirePermission(permIAMUsersUpdate), handlers.TenantTeam.UpdateMember)
			tenants.DELETE("/me/teams/:id/members/:user_id", authMiddleware.RequirePermission(permIAMUsersUpdate), handlers.TenantTeam.RemoveMember)
		}
		tenants.GET("/me/service-accounts", authMiddleware.RequirePermission("iam:service_accounts:read"), handlers.TeamInvitation.ListTenantServiceAccounts)
		tenants.GET("/me/service-principals", authMiddleware.RequirePermission("iam:service_principals:read"), handlers.TeamInvitation.ListTenantServicePrincipals)
		// GET /api/v1/tenants/me/external-members — seat-free accountants
		// invited from their own partner tenant (seat_class=external).
		tenants.GET("/me/external-members", authMiddleware.RequirePermission(permIAMUsersRead), handlers.TeamInvitation.ListExternalMembers)
		// R6 WP-23: seat-free shop-floor kiosk users (seat_class=kiosk), counted against the kiosk_users quota.
		tenants.POST("/me/kiosk-users", authMiddleware.RequirePermission(permIAMUsersCreate), handlers.TeamInvitation.ProvisionKioskUser)
		tenants.DELETE("/me/kiosk-users/:id", authMiddleware.RequirePermission(permIAMUsersDelete), handlers.TeamInvitation.RevokeKioskUser)
	}

	// ADR-A10 SoD rule matrix + violation report (BFF surface,
	// 23-authorization-rbac-abac-rebac.md §8.3, 17-module-account.md
	// §5.1/§5.2). Tenant-admin gated; tenant is sourced from the session
	// JWT by authMiddleware.RequireAuth() (never a client-supplied value)
	// exactly like the /tenants/me/* group above.
	account := api.Group("/account")
	account.Use(authMiddleware.RequireAuth())
	{
		account.GET("/sod-rules", authMiddleware.RequirePermission(permAccountSoDManage), handlers.SoD.ListRules)
		account.POST("/sod-rules", authMiddleware.RequirePermission(permAccountSoDManage), handlers.SoD.CreateRule)
		account.PATCH("/sod-rules/:id", authMiddleware.RequirePermission(permAccountSoDManage), handlers.SoD.UpdateRule)
		account.GET("/sod-violations", authMiddleware.RequirePermission(permAccountSoDManage), handlers.SoD.ListViolations)
	}

	// Phase 2: Team invitations
	invitations := api.Group("/invitations")
	invitations.Use(authMiddleware.RequireAuth())
	{
		inviteStepUp := authMiddleware.RequireFreshAuthForAction(5*time.Minute, "tenant.team_invitations")
		invitations.POST("", authMiddleware.RequirePermission(permIAMInvitationsCreate), inviteStepUp, handlers.TeamInvitation.CreateInvitation)
		invitations.GET("", authMiddleware.RequirePermission(permIAMInvitationsRead), handlers.TeamInvitation.ListInvitations)
		invitations.DELETE("/:id", authMiddleware.RequirePermission(permIAMInvitationsDelete), authMiddleware.RequireFreshAuthForAction(5*time.Minute, "tenant.team_invitations"), handlers.TeamInvitation.RevokeInvitation)
		invitations.POST("/:id/actions/resend", authMiddleware.RequirePermission(permIAMInvitationsCreate), inviteStepUp, handlers.TeamInvitation.ResendInvitation)
		invitations.POST("/accept", handlers.TeamInvitation.AcceptInvitation)
		invitations.POST("/decline", handlers.TeamInvitation.DeclineInvitation)
		// Signed-in invitee flow: pending invitations addressed to the caller's
		// verified email, accepted or declined by id without the emailed token.
		// Auth-only like accept/decline above (the invitee has no permission in
		// the inviting company yet); the mutating calls are rate-limited.
		inviteeRL := authRateLimiter.Middleware()
		// GET /mine carries no per-user key and acmeweb calls it through the BFF (one
		// shared IP), so a per-IP limit would throttle every user at once; it is a
		// cheap indexed read behind RequireAuth and stays unlimited here.
		invitations.GET("/mine", handlers.TeamInvitation.ListMyInvitations)
		invitations.POST("/mine/:id/accept", inviteeRL, handlers.TeamInvitation.AcceptMyInvitation)
		invitations.POST("/mine/:id/decline", inviteeRL, handlers.TeamInvitation.DeclineMyInvitation)
	}

	// Phase 2: user role management + deactivation (team admin surface)
	// Routes are separate from the existing /users/* block to avoid
	// conflicting with the RequirePermission middleware on the existing routes.
	teamUsers := api.Group("/team/users")
	teamUsers.Use(authMiddleware.RequireAuth())
	{
		roleStepUp := authMiddleware.RequireFreshAuthForAction(5*time.Minute, "tenant.team_roles")
		membershipStepUp := authMiddleware.RequireFreshAuthForAction(5*time.Minute, "tenant.team_membership")
		teamUsers.POST("/:id/roles", authMiddleware.RequirePermission(permIAMUsersUpdate), roleStepUp, handlers.TeamInvitation.SetUserRoles)
		teamUsers.DELETE("/:id", authMiddleware.RequirePermission(permIAMUsersDelete), membershipStepUp, handlers.TeamInvitation.DeactivateUser)
		teamUsers.POST("/:id/reactivate", authMiddleware.RequirePermission(permIAMUsersDelete), membershipStepUp, handlers.TeamInvitation.ReactivateUser)
		// External (seat-free) member revocation: deletes the membership,
		// this tenant's role grants and the SpiceDB edges in one call.
		api.DELETE("/team/external-members/:id", authMiddleware.RequireAuth(), authMiddleware.RequirePermission(permIAMUsersDelete), membershipStepUp, handlers.TeamInvitation.RevokeExternalMember)
	}
}

// registerDeveloperRoutes registers the tenant API key management routes
// (WO#20). Reads need iam:api_keys:read; every mutation needs
// iam:api_keys:manage plus a fresh step-up. The handler answers 404 while
// DEVELOPER_KEYS_ENABLED / the tenant allowlist is off.
func registerDeveloperRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	if handlers.TenantAPIKey == nil {
		return
	}
	stepUp := authMiddleware.RequireFreshAuthForAction(5*time.Minute, "tenant.developer_access")
	keys := api.Group("/developer/api-keys")
	keys.Use(authMiddleware.RequireAuth())
	{
		keys.GET("", authMiddleware.RequirePermission(permIAMAPIKeysRead), handlers.TenantAPIKey.List)
		keys.GET("/:id", authMiddleware.RequirePermission(permIAMAPIKeysRead), handlers.TenantAPIKey.Get)
		keys.POST("", authMiddleware.RequirePermission(permIAMAPIKeysManage), stepUp, handlers.TenantAPIKey.Create)
		keys.POST("/:id/rotate", authMiddleware.RequirePermission(permIAMAPIKeysManage), stepUp, handlers.TenantAPIKey.Rotate)
		keys.POST("/:id/revoke", authMiddleware.RequirePermission(permIAMAPIKeysManage), stepUp, handlers.TenantAPIKey.Revoke)
		keys.DELETE("/:id", authMiddleware.RequirePermission(permIAMAPIKeysManage), stepUp, handlers.TenantAPIKey.Delete)
	}
}

// registerRealmRoutes registers realm routes.
func registerRealmRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	if handlers.Realm != nil {
		realms := api.Group("/realms")
		realms.Use(authMiddleware.RequireAuth())
		{
			realms.GET("/available", handlers.Realm.GetAvailableRealms)
			realms.POST("/switch", handlers.Realm.SwitchRealm)
			realms.GET("/current", handlers.Realm.GetCurrentRealm)
		}
	}
}

// registerUserRoutes registers user routes.
func registerUserRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	users := api.Group("/users")
	users.Use(authMiddleware.RequireAuth())
	{
		// Per-user opaque preferences (iam_users.preferences JSONB,
		// migration 0003 + Keystone bundle v0.232.254). Identity-anchored
		// per the 2026-06-02 Option C onboarding architecture: each user
		// reads/writes their own bag, tenant-id never appears in the URL
		// path. Future product BFFs (AcmeWeb welcome dialog, Hexx-Forge
		// tour, etc.) PATCH /products/{slug} to mark progress without
		// touching siblings' state. The aggregator endpoint
		// /users/me/onboarding/{product} (PR #2, v0.232.255) layers
		// derived workspace state on top.
		if handlers.UserPreferences != nil {
			users.GET("/me/preferences", handlers.UserPreferences.Get)
			users.PATCH("/me/preferences/global", handlers.UserPreferences.PatchGlobal)
			users.PATCH("/me/preferences/products/:product", handlers.UserPreferences.PatchProduct)
		}

		// Self-service account-recovery methods (recovery email today; phone
		// reserved). Owner-scoped from the session — the subject never appears
		// in the path, mirroring /me/preferences. nil when Redis is
		// unavailable (the backing service is Redis-gated for OTP storage).
		if handlers.Recovery != nil {
			// Adding/removing a recovery method is account-takeover-sensitive
			// (an attacker with a stolen cookie could plant their own recovery
			// address), so the mutations require a fresh-auth step-up. Verify
			// is already gated by the emailed one-time code, and the read is
			// harmless.
			recoveryStepUp := handlers.StepUpMiddleware.RequireStepUp("recovery_email_mutation", 5*time.Minute)
			users.GET("/me/recovery", handlers.Recovery.GetStatus)
			users.POST("/me/recovery/email", recoveryStepUp, handlers.Recovery.SetEmail)
			users.POST("/me/recovery/email/verify", handlers.Recovery.VerifyEmail)
			users.DELETE("/me/recovery/email", recoveryStepUp, handlers.Recovery.RemoveEmail)
		}

		// Peer member directory — visibility-filtered list of other members in
		// the caller's tenant (the enforcement surface for People-&-sharing
		// profile visibility). Owner/tenant-scoped from the session, no admin
		// permission (distinct from the admin /platform/tenants/:id/users).
		users.GET("/me/directory", handlers.User.ListMemberDirectory)

		stepUp := handlers.StepUpMiddleware.RequireStepUp("role_mutation", 5*time.Minute)
		// userMutationStepUp covers admin operations on a user that
		// don't fit the role-mutation bucket but still warrant a
		// fresh-MFA gate: forced password changes, account lock /
		// unlock (the latter especially — an attacker with a stolen
		// admin cookie would use it to mass-unlock recently-locked
		// accounts and replay credential-stuffing). DELETE is included
		// because user-deletion cascades through tokens, sessions,
		// audit-trail consistency, etc.
		userMutationStepUp := handlers.StepUpMiddleware.RequireStepUp("user_account_mutation", 5*time.Minute)
		users.GET("", authMiddleware.RequirePermission(permCoreUsersRead), handlers.User.List)
		users.POST("", authMiddleware.RequirePermission("core:users:create"), handlers.User.Create)
		users.GET("/:id", authMiddleware.RequirePermission(permCoreUsersRead), handlers.User.GetByID)
		users.PUT("/:id", authMiddleware.RequirePermission(permCoreUsersUpdate), handlers.User.Update)
		users.DELETE("/:id", authMiddleware.RequirePermission("core:users:delete"), userMutationStepUp, handlers.User.Delete)
		users.POST("/:id/password", authMiddleware.RequirePermission(permCoreUsersUpdate), userMutationStepUp, handlers.User.SetPassword)
		users.POST("/:id/lock", authMiddleware.RequirePermission(permCoreUsersUpdate), userMutationStepUp, handlers.User.Lock)
		users.POST("/:id/unlock", authMiddleware.RequirePermission(permCoreUsersUpdate), userMutationStepUp, handlers.User.Unlock)
		users.GET("/:id/roles", authMiddleware.RequirePermission(permCoreUsersRead), handlers.User.GetRoles)
		users.PUT("/:id/roles", authMiddleware.RequirePermission(permCoreUsersUpdate), stepUp, handlers.User.SetRoles)
		users.GET("/:id/permissions", authMiddleware.RequirePermission(permCoreUsersRead), handlers.User.GetPermissions)
		users.GET("/:id/effective-permissions", authMiddleware.RequirePermission(permCoreUsersRead), handlers.Authorization.GetEffectivePermissions)
		users.GET("/:id/risk-score", authMiddleware.RequirePermission(permCoreUsersRead), handlers.Stub.GetUserRiskScore)

		// GDPR Art. 15 + 17. The handler enforces owner-or-admin
		// authorisation inline (cross-tenant access blocked by
		// verifyUserSameTenant), so route-level RequirePermission is
		// scoped to `core:users:read` for export/status — the same gate
		// the rest of /users/:id/* uses. Delete is destructive AND
		// owner-actionable (a user deleting their own account doesn't
		// hold core:users:delete), so it gates on RequireAuth only at
		// the route, with the handler's owner-or-admin check carrying
		// the policy. freshAuth (RFC 9470) is required — matches the
		// existing /users/me/delete-account pattern: a destructive
		// operation cannot fire from a stale tab even when the
		// in-handler check passes. Export has a built-in 1-per-24h
		// rate limit in the handler, no extra middleware needed.
		gdprStepUp := handlers.StepUpMiddleware.RequireStepUp("gdpr_user_mutation", 5*time.Minute)
		if handlers.GDPR != nil {
			// Self-service export (GDPR Art. 15) — owner-scoped from the
			// session, no admin permission needed. Static `/me/export`
			// coexists with the `/:id/export` param route (same as the
			// existing /me/preferences vs /:id/* split).
			users.GET("/me/export", handlers.GDPR.ExportMyData)
			users.GET("/:id/export",
				authMiddleware.RequirePermission(permCoreUsersRead),
				handlers.GDPR.ExportUserData)
			users.DELETE("/:id/delete",
				gdprStepUp,
				handlers.GDPR.RequestDeletion)
			users.GET("/:id/deletion-status",
				authMiddleware.RequirePermission(permCoreUsersRead),
				handlers.GDPR.GetDeletionRequest)
		}
	}
}

// registerRoleRoutes registers role routes.
// Step-up MFA (5-minute freshness) is required for all mutation endpoints to
// protect against session-hijacking attacks on high-privilege operations.
func registerRoleRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	roles := api.Group("/roles")
	roles.Use(authMiddleware.RequireAuth())
	{
		stepUp := handlers.StepUpMiddleware.RequireStepUp("role_mutation", 5*time.Minute)
		roles.GET("", authMiddleware.RequirePermission(permCoreRolesRead), handlers.Role.List)
		roles.POST("", authMiddleware.RequirePermission("core:roles:create"), stepUp, handlers.Role.Create)
		roles.GET("/:id", authMiddleware.RequirePermission(permCoreRolesRead), handlers.Role.GetByID)
		roles.PUT("/:id", authMiddleware.RequirePermission("core:roles:update"), stepUp, handlers.Role.Update)
		roles.DELETE("/:id", authMiddleware.RequirePermission("core:roles:delete"), stepUp, handlers.Role.Delete)
		roles.GET("/:id/permissions", authMiddleware.RequirePermission(permCoreRolesRead), handlers.Role.GetPermissions)
		roles.PUT("/:id/permissions", authMiddleware.RequirePermission("core:roles:update"), stepUp, handlers.Role.AssignPermissions)
		// GetRoleMembers (vs the older ListRoleMembers) accepts the
		// role identifier as a UUID OR a role-name like
		// "crm:manager" — useful for the admin UI which links by
		// canonical name. Service call is identical; the difference
		// is input validation looseness. Response shape unchanged.
		roles.GET("/:id/members", authMiddleware.RequirePermission(permCoreRolesRead), handlers.Role.GetRoleMembers)
	}
}

// registerRoleTemplateRoutes registers the role-templates routes
// (the product roadmap §4.1). GET is gated the same as GET /roles
// (permCoreRolesRead) — listing the catalog is a read of role-configuration
// data. POST /:key/instantiate creates a real tenant role, so it gates on
// the same "core:roles:create" + step-up pair as POST /roles, i.e. it is a
// tenant-admin operation via the existing RequirePermission middleware
// (RequireTenantScopedAdmin doesn't fit here — there is no :tenant_id path
// param on this route; tenant comes solely from middleware.GetTenantID,
// enforced in RoleTemplateHandler.Instantiate).
func registerRoleTemplateRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	roleTemplates := api.Group("/role-templates")
	roleTemplates.Use(authMiddleware.RequireAuth())
	{
		stepUp := handlers.StepUpMiddleware.RequireStepUp("role_mutation", 5*time.Minute)
		roleTemplates.GET("", authMiddleware.RequirePermission(permCoreRolesRead), handlers.RoleTemplate.List)
		roleTemplates.POST("/:key/instantiate", authMiddleware.RequirePermission("core:roles:create"), stepUp, handlers.RoleTemplate.Instantiate)
	}
}

// registerPermissionRoutes registers permission routes.
//
// Read endpoints (List / ListModules / ListGroupedByModule /
// ListByModule / GetByID) gate on `core:permissions:read`. Bulk
// module registration (`POST /register`) keeps the
// `core:permissions:register` permission as the dedicated
// module-onboarding grant. Single-permission CRUD (Create / Update /
// Delete) is platform-grade — minting a permission row that isn't
// gated anywhere in code is a stealth-authz vector — so it gates on
// `core:permissions:register` AND step-up. The handler-side
// impersonation guard in permission_handler.go is defense-in-depth
// against a privileged-session-cookie reuse via /admin/impersonate.
func registerPermissionRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	permissions := api.Group("/permissions")
	permissions.Use(authMiddleware.RequireAuth())
	{
		permWriteStepUp := handlers.StepUpMiddleware.RequireStepUp("permission_mutation", 5*time.Minute)
		permWrite := authMiddleware.RequirePermission("core:permissions:register")

		permissions.GET("", authMiddleware.RequirePermission(permCorePermsRead), handlers.Permission.List)
		permissions.GET("/modules", authMiddleware.RequirePermission(permCorePermsRead), handlers.Permission.ListModules)
		permissions.GET("/grouped", authMiddleware.RequirePermission(permCorePermsRead), handlers.Permission.ListGroupedByModule)
		permissions.GET("/module/:module", authMiddleware.RequirePermission(permCorePermsRead), handlers.Permission.ListByModule)
		permissions.POST("/register", permWrite, handlers.Permission.RegisterModule)
		// Single-permission CRUD. The /:id parametric routes are
		// safe to interleave with /modules, /grouped, /module/:module
		// because gin's radix tree prefers static segments over
		// parametric ones at the same depth.
		permissions.GET("/:id", authMiddleware.RequirePermission(permCorePermsRead), handlers.Permission.GetByID)
		permissions.POST("", permWrite, permWriteStepUp, handlers.Permission.Create)
		permissions.PUT("/:id", permWrite, permWriteStepUp, handlers.Permission.Update)
		permissions.DELETE("/:id", permWrite, permWriteStepUp, handlers.Permission.Delete)
	}
}

// registerAuthorizationRoutes registers authorization routes.
func registerAuthorizationRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	authorize := api.Group("/authorize")
	authorize.Use(authMiddleware.RequireAuth())
	{
		authorize.POST("", handlers.Authorization.Authorize)
		authorize.POST("/batch", handlers.Authorization.AuthorizeBatch)

		// Policy simulator + effective-permissions export (spec 23 §7). Tenant
		// admins only; the handler additionally pins the target user to the
		// caller's own tenant and audits every simulation.
		authorize.POST("/simulate", authMiddleware.RequireTenantAdmin(), handlers.Authorization.Simulate)
		authorize.GET("/effective-permissions", authMiddleware.RequireTenantAdmin(), handlers.Authorization.GetEffectivePermissionsByQuery)
	}
}

// registerSocialAuthRoutes registers social authentication routes.
func registerSocialAuthRoutes(api *gin.RouterGroup, handlers *Handlers) {
	social := api.Group("/auth/social")
	{
		social.GET("/:provider/authorize", handlers.SocialAuth.GetAuthorizationURL)
		social.GET("/:provider/callback", handlers.SocialAuth.HandleCallback)
		// Apple Sign In uses form_post response mode (POST instead of GET redirect)
		social.POST("/apple/callback", handlers.SocialAuth.HandleAppleCallback)
	}

	// Account linking (authenticated)
	// Note: This needs authMiddleware but is registered outside the social group
	// This will be handled by the caller passing authMiddleware
}

// registerWebAuthnProtectedRoutes registers WebAuthn credential management routes
// for authenticated users.
func registerWebAuthnProtectedRoutes(authProtected *gin.RouterGroup, handlers *Handlers, freshAuth gin.HandlerFunc) {
	webauthn := authProtected.Group("/webauthn")
	{
		webauthn.POST("/register/begin", handlers.WebAuthn.BeginRegistration)
		webauthn.POST("/register/finish", handlers.WebAuthn.FinishRegistration)
		webauthn.GET("/credentials", handlers.WebAuthn.ListCredentials)
		// Removing a passkey is destructive to the user's phishing-resistant
		// factor inventory — RFC 9470 step-up gated.
		webauthn.DELETE("/credentials/:id", freshAuth, handlers.WebAuthn.DeleteCredential)
		// RFC 9470 step-up — session-authenticated passkey assertion that
		// elevates the current session's AMR without minting a new session.
		// Used by the /auth/mfa/challenge frontend page when the user has
		// at least one passkey enrolled (Phase 2 of tier-1 step-up MFA).
		webauthn.POST("/step-up/begin", handlers.WebAuthn.BeginStepUp)
		webauthn.POST("/step-up/finish", handlers.WebAuthn.FinishStepUp)
	}
}

// registerWitnessRoutes registers the ZTNA Path B operator enrollment witness
// endpoints (ADR 0043 §3.c.0). An operator proves they witnessed the device's
// EK public-key hash with a passkey assertion, or — for platform admins with no
// passkey — an authenticator-app code; on success Falcon-ID mints a compact JWS
// signed by the RS256 issuer key that jess verifies during TPM enrollment.
//
// All of these live behind RequireAuth (inherited from authProtected) AND
// RequirePlatformAdmin: the witness page already refused non-admins, but the
// API routes did not, so any logged-in user could mint a witness for an
// arbitrary device_uuid. Handlers re-check as defense in depth.
func registerWitnessRoutes(authProtected *gin.RouterGroup, handlers *Handlers, platformAdmin gin.HandlerFunc) {
	if handlers.WebAuthn != nil {
		wa := authProtected.Group("/webauthn")
		wa.POST("/witness/begin", platformAdmin, handlers.WebAuthn.BeginWitnessEnroll)
		wa.POST("/witness/finish", platformAdmin, handlers.WebAuthn.FinishWitnessEnroll)
	}
	if handlers.WitnessTOTP != nil {
		// Authenticator-app fallback (users with NO passkey). Further gated
		// in the service by realm policy + FALCON_WITNESS_TOTP_ENABLED.
		wt := authProtected.Group("/witness/totp")
		wt.POST("/begin", platformAdmin, handlers.WitnessTOTP.Begin)
		wt.POST("/finish", platformAdmin, handlers.WitnessTOTP.Finish)
	}
}

// registerDelegationRoutes registers user-scoped delegation routes.
func registerDelegationRoutes(authProtected *gin.RouterGroup, handlers *Handlers) {
	delegations := authProtected.Group("/delegations")
	{
		delegations.GET("", handlers.Delegation.ListMyDelegations)
		delegations.POST("", handlers.Delegation.CreateDelegation)
		delegations.GET("/:id", handlers.Delegation.GetDelegation)
		delegations.DELETE("/:id", handlers.Delegation.RevokeDelegation)
	}
}

// registerQuotaRoutes registers quota management routes (stub).
// These are called by the platform-admin frontend for quota dashboards and alerts.
func registerQuotaRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	quotas := api.Group("/quotas")
	quotas.Use(authMiddleware.RequireAuth(), authMiddleware.RequirePlatformAdmin())
	{
		quotas.GET("/dashboard/:tenant_id", handlers.Stub.GetQuotaDashboard)
		quotas.GET("/alerts", handlers.Stub.GetQuotaAlerts)
		quotas.GET("/requests", handlers.Stub.GetQuotaRequests)
		quotas.POST("/requests/:request_id/approve", handlers.Stub.ApproveQuotaRequest)
		quotas.POST("/requests/:request_id/deny", handlers.Stub.DenyQuotaRequest)
		quotas.GET("/history/:tenant_id", handlers.Stub.GetQuotaHistory)
		quotas.POST("/reconcile/:tenant_id", handlers.Stub.ReconcileQuota)
		quotas.GET("/predictions/:tenant_id", handlers.Stub.GetQuotaPredictions)
		quotas.GET("/events", handlers.Stub.GetQuotaEvents)
	}
}

// registerCatalogRoutes registers public product catalog routes (no auth required).
func registerCatalogRoutes(api *gin.RouterGroup, handlers *Handlers) {
	if handlers.Catalog == nil {
		return
	}
	catalog := api.Group("/catalog")
	{
		catalog.GET("/products", handlers.Catalog.ListProducts)
		catalog.GET("/products/:slug", handlers.Catalog.GetProduct)
	}
}

// registerManagedIdentityRoutes registers managed service identity routes.
// Admin CRUD endpoints require auth; the service self-registration endpoints are public.
func registerManagedIdentityRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware, authRateLimiter *middleware.AuthRateLimiter) {
	if handlers.ManagedIdentity == nil {
		return
	}
	// Service self-registration (no auth — authenticated by bootstrap token in body)
	// Rate-limited to prevent abuse of the public registration endpoint.
	services := api.Group("/services")
	services.Use(authRateLimiter.Middleware())
	{
		services.POST("/register", handlers.ManagedIdentity.Register)
		services.POST("/heartbeat", handlers.ManagedIdentity.Heartbeat)
	}

	// Admin bootstrap-token management (requires auth)
	adminMI := api.Group("/admin/managed-identities")
	adminMI.Use(authMiddleware.RequireAuth())
	{
		adminMI.GET("/bootstrap-tokens", handlers.ManagedIdentity.ListBootstrapTokens)
		adminMI.POST("/bootstrap-tokens", handlers.ManagedIdentity.CreateBootstrapToken)
		adminMI.DELETE("/bootstrap-tokens/:id", handlers.ManagedIdentity.DeleteBootstrapToken)
		adminMI.POST("/auto-suspend", handlers.ManagedIdentity.TriggerAutoSuspend)
	}
}

// registerWorkloadIdentityRoutes registers workload identity federation routes.
func registerWorkloadIdentityRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	if handlers.WorkloadIdentity == nil {
		return
	}
	providers := api.Group("/admin/workload-identity-providers")
	providers.Use(authMiddleware.RequireAuth())
	{
		providers.GET("", handlers.WorkloadIdentity.List)
		providers.POST("", handlers.WorkloadIdentity.Create)
		providers.GET("/:id", handlers.WorkloadIdentity.GetByID)
		providers.PUT("/:id", handlers.WorkloadIdentity.Update)
		providers.DELETE("/:id", handlers.WorkloadIdentity.Delete)
		providers.POST("/:id/test", handlers.WorkloadIdentity.Test)
	}
}

// registerServicePrincipalAdminRoutes registers service principal CRUD routes.
func registerServicePrincipalAdminRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	if handlers.ServicePrincipal == nil {
		return
	}
	sps := api.Group("/admin/service-principals")
	sps.Use(authMiddleware.RequireAuth())
	{
		sps.GET("", handlers.ServicePrincipal.List)
		sps.POST("", handlers.ServicePrincipal.Create)
		sps.GET("/:id", handlers.ServicePrincipal.GetByID)
		sps.PUT("/:id", handlers.ServicePrincipal.Update)
		sps.DELETE("/:id", handlers.ServicePrincipal.Delete)
		sps.POST("/:id/rotate-key", handlers.ServicePrincipal.RotateKey)
		sps.POST("/:id/manifest", handlers.ServicePrincipal.RegisterManifest)
	}
}

// marshalPublicKeyToPEM encodes any crypto.PublicKey to a PKIX PEM string.
// Used by the KeyManager-aware SP lookup adapter in registerRoutes to produce the
// PEM representation expected by the service auth middleware.
func marshalPublicKeyToPEM(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshalPublicKeyToPEM: %w", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return string(block), nil
}

// Continue in next file due to size...
