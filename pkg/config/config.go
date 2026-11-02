// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config provides configuration management for the IAM service.
// This service uses Viper for configuration management directly rather than
// delegating to shared config utilities. This is intentional to support
// advanced features like configuration file loading, hot-reloading, and
// complex security validation logic specific to IAM.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is an exported type.
type Config struct {
	Environment string `mapstructure:"ENVIRONMENT"`
	ServiceName string `mapstructure:"SERVICE_NAME"`
	ServicePort string `mapstructure:"SERVICE_PORT"`
	LogLevel    string `mapstructure:"LOG_LEVEL"`

	// Database - Data Plane (tenant users)
	DatabaseURL string `mapstructure:"DATABASE_URL"`

	// Database connection components used when Vault dynamic credentials are active.
	// These fields let the service build a DSN from dynamic creds + static host/port/dbname.
	DatabaseHost    string `mapstructure:"DATABASE_HOST"`
	DatabasePort    int    `mapstructure:"DATABASE_PORT"`
	DatabaseName    string `mapstructure:"DATABASE_NAME"`
	DatabaseSSLMode string `mapstructure:"DATABASE_SSL_MODE"`

	// Control Plane Database (platform admins)
	ControlPlaneDatabaseURL string `mapstructure:"CONTROL_PLANE_DATABASE_URL"`

	// Redis
	RedisURL              string        `mapstructure:"REDIS_URL"`
	RedisMaxRetries       int           `mapstructure:"REDIS_MAX_RETRIES"`
	RedisMinIdleConns     int           `mapstructure:"REDIS_MIN_IDLE_CONNS"`
	RedisConnMaxLifetime  time.Duration `mapstructure:"REDIS_CONN_MAX_LIFETIME"`
	RedisRateLimitEnabled bool          `mapstructure:"REDIS_RATE_LIMIT_ENABLED"`
	RedisSessionCacheTTL  time.Duration `mapstructure:"REDIS_SESSION_CACHE_TTL"`
	// RedisRequired makes a Redis connect failure fatal at startup. Without it
	// the service degrades to no rate limits, no session cache and no token
	// blacklist, which in production silently turns off revocation.
	RedisRequired bool `mapstructure:"REDIS_REQUIRED"`

	// Permission Cache Configuration
	PermissionCacheLocalSize      int           `mapstructure:"PERMISSION_CACHE_LOCAL_SIZE"`       // Local LRU cache size
	PermissionCacheLocalTTL       time.Duration `mapstructure:"PERMISSION_CACHE_LOCAL_TTL"`        // Local cache TTL
	PermissionCacheCheckTTL       time.Duration `mapstructure:"PERMISSION_CACHE_CHECK_TTL"`        // Redis check cache TTL
	PermissionCacheRoleMappingTTL time.Duration `mapstructure:"PERMISSION_CACHE_ROLE_MAPPING_TTL"` // Role->permissions mapping TTL

	// Observability
	OTLPEndpoint        string  `mapstructure:"OTLP_ENDPOINT"`
	TracingSamplingRate float64 `mapstructure:"TRACING_SAMPLING_RATE"`
	MetricsEnabled      bool    `mapstructure:"METRICS_ENABLED"`

	// Encryption
	EncryptionKey string `mapstructure:"ENCRYPTION_KEY"`
	EmailHashKey  string `mapstructure:"EMAIL_HASH_KEY"`

	// Token Hashing
	TokenHashSalt string `mapstructure:"TOKEN_HASH_SALT"`

	// JWT Configuration
	JWTSecret         string        `mapstructure:"JWT_SECRET"`
	JWTIssuer         string        `mapstructure:"JWT_ISSUER"`
	AccessTokenExpiry time.Duration `mapstructure:"ACCESS_TOKEN_EXPIRY"`
	SessionExpiry     time.Duration `mapstructure:"SESSION_EXPIRY"`

	// Signing-key rotation (publish before activate). See pkg/keys.
	SigningKeyPublishDelay   time.Duration `mapstructure:"SIGNING_KEY_PUBLISH_DELAY"`
	SigningKeyReloadInterval time.Duration `mapstructure:"SIGNING_KEY_RELOAD_INTERVAL"`
	SigningKeyRetireAfter    time.Duration `mapstructure:"SIGNING_KEY_RETIRE_AFTER"`
	JWKSMaxAge               time.Duration `mapstructure:"JWKS_MAX_AGE"`

	// CAEPOutboxEnabled flips the CAEP transmitter from best-effort
	// sync push (Phase 1, wave 2 default) to PG-backed transactional
	// outbox + drainer (Phase 6 ZTNA). When true:
	//   - emit() enqueues iam_caep_event_outbox rows instead of HTTP-pushing
	//   - a goroutine drainer signs + delivers with exponential backoff
	//   - at-least-once delivery; receivers may see duplicates and MUST
	//     deduplicate by `jti` (the row UUID)
	// Defaults to false to preserve wave-2 behaviour during canary.
	CAEPOutboxEnabled bool `mapstructure:"CAEP_OUTBOX_ENABLED"`

	// EmailOutboxEnabled routes NON-CREDENTIAL mail through the
	// iam_email_outbox table + drainer instead of sending it inline.
	// Same canary discipline as CAEP_OUTBOX_ENABLED: defaults to false,
	// so the pre-outbox synchronous path stays in force until an
	// operator opts in.
	//
	// This flag can NEVER affect credential mail. One-time codes,
	// password-reset and magic links are refused by MayQueue and by a
	// CHECK constraint on the table, whatever this is set to — see
	// internal/services/email_delivery_policy.go.
	EmailOutboxEnabled bool `mapstructure:"EMAIL_OUTBOX_ENABLED"`

	// DPoP (RFC 9449 — Demonstrating Proof of Possession) — sender-constrains
	// access tokens to the holder of a specific key. When enabled:
	//   - Token issuance embeds cnf.jkt when a DPoP proof accompanies the
	//     request at the token endpoint.
	//   - Resource server middleware (OptionalDPoP + VerifyTokenBinding)
	//     enforces proof-key-matches-cnf.jkt on every request carrying a
	//     DPoP-bound token.
	//   - Bare bearer tokens continue to work unchanged — the flag is purely
	//     additive, so gradual SDK rollout is safe.
	// Default OFF until the SDKs are shipped with DPoP proof generation.
	DPoPEnabled bool `mapstructure:"DPOP_ENABLED"`

	// NativeAppSchemeDomains enables RFC 8252 §7.1 private-use URI scheme
	// redirects for native clients (public + PKCE + first-party): a scheme
	// is accepted when its reversed labels equal or sit under an entry
	// (com.example.app under example.com). Empty = feature off.
	NativeAppSchemeDomains []string `mapstructure:"NATIVE_APP_SCHEME_DOMAINS"`
	// TenantExchangePublicClientIDs lists client_ids of public, PKCE,
	// first-party clients allowed to use the tenant token exchange.
	// Empty = confidential clients only.
	TenantExchangePublicClientIDs []string `mapstructure:"TENANT_EXCHANGE_PUBLIC_CLIENT_IDS"`
	// OAuthTokenPerUserClientIDs lists client_ids whose /oauth/token rate
	// limit is bucketed per end user instead of per client (multi-user BFFs
	// and public native clients). Default: acmeapp-bff.
	OAuthTokenPerUserClientIDs []string `mapstructure:"OAUTH_TOKEN_PER_USER_CLIENT_IDS"`

	// Session Security Configuration
	SessionIdleTimeout time.Duration `mapstructure:"SESSION_IDLE_TIMEOUT"` // Max inactivity before session is invalidated on refresh

	// SECURITY: SessionRotationOnRefresh generates a new session ID when tokens are refreshed
	// This prevents session fixation attacks and limits the window for session hijacking
	SessionRotationOnRefresh bool `mapstructure:"SESSION_ROTATION_ON_REFRESH"`

	// Remember-me session TTL bifurcation. SessionTTLDefault governs the
	// iam_sessions.expires_at + falcon_idp_session cookie Max-Age for
	// logins WITHOUT the "Remember me" checkbox checked — falls back to
	// SessionExpiry when SESSION_TTL_DEFAULT is unset so existing
	// deployments preserve their current short TTL (no behaviour drift).
	//
	// SessionTTLRememberMe is the extended TTL applied when the login
	// request carries `remember_me: true` (frontend checkbox). Defaults
	// to 720h (30d) so the IdP SSO cookie + DB session row survive
	// browser restarts, matching the canonical Microsoft Entra / Auth0
	// "keep me signed in" UX. Override via SESSION_TTL_REMEMBER_ME for
	// stricter compliance regimes (e.g. 168h = 7d for PCI-DSS § 8.1.8).
	//
	// IMPORTANT: long-lived sessions still flow through the SAME MFA /
	// IP-binding / device-fingerprint gates — extending the TTL does
	// NOT relax any security check. The boundary is purely cookie /
	// expires_at; every per-request middleware (session_tenant_binding,
	// RequireFreshAuth) is unchanged.
	SessionTTLDefault    time.Duration `mapstructure:"SESSION_TTL_DEFAULT"`
	SessionTTLRememberMe time.Duration `mapstructure:"SESSION_TTL_REMEMBER_ME"`

	// Trusted Device Configuration
	TrustedDeviceSessionExpiry time.Duration `mapstructure:"TRUSTED_DEVICE_SESSION_EXPIRY"` // Extended session expiry for trusted devices
	TrustDurationDays          int           `mapstructure:"TRUST_DURATION_DAYS"`           // How long a device remains trusted

	// AD Sync Configuration
	ADSyncEnabled          bool          `mapstructure:"AD_SYNC_ENABLED"`           // Enable/disable AD sync scheduler
	ADSyncDefaultInterval  time.Duration `mapstructure:"AD_SYNC_DEFAULT_INTERVAL"`  // Default sync interval if not set per provider
	ADSyncBatchSize        int           `mapstructure:"AD_SYNC_BATCH_SIZE"`        // Batch size for sync operations
	ADSyncHistoryRetention time.Duration `mapstructure:"AD_SYNC_HISTORY_RETENTION"` // How long to keep sync history

	// Password Policy
	PasswordMinLength      int  `mapstructure:"PASSWORD_MIN_LENGTH"`
	PasswordRequireUpper   bool `mapstructure:"PASSWORD_REQUIRE_UPPER"`
	PasswordRequireLower   bool `mapstructure:"PASSWORD_REQUIRE_LOWER"`
	PasswordRequireDigit   bool `mapstructure:"PASSWORD_REQUIRE_DIGIT"`
	PasswordRequireSpecial bool `mapstructure:"PASSWORD_REQUIRE_SPECIAL"`
	// PasswordBreachCheckEnabled gates the HIBP breach-password check wired
	// into signup / set-password / change-password / reset (ASVS V6 / NIST
	// 800-63B). Default true. The check already fails OPEN on any HIBP error,
	// so the only reason to disable is a fully air-gapped deployment that
	// cannot reach api.pwnedpasswords.com and wants to avoid the recurring
	// "failing open" log line on every password set.
	PasswordBreachCheckEnabled bool `mapstructure:"PASSWORD_BREACH_CHECK_ENABLED"`

	// WitnessTOTPEnabled is the global kill switch for the authenticator-app
	// (TOTP) fallback of the ZTNA device-enrollment witness. Default false:
	// first deploy ships dark. Even when true, the realm flag
	// device_witness_totp_allowed must also allow it.
	WitnessTOTPEnabled bool `mapstructure:"FALCON_WITNESS_TOTP_ENABLED"`

	// Rate Limiting
	RateLimitRequests int           `mapstructure:"RATE_LIMIT_REQUESTS"`
	RateLimitWindow   time.Duration `mapstructure:"RATE_LIMIT_WINDOW"`

	// Account Lockout
	MaxLoginAttempts int           `mapstructure:"MAX_LOGIN_ATTEMPTS"`
	LockoutDuration  time.Duration `mapstructure:"LOCKOUT_DURATION"`

	// SMTP Configuration
	SMTPHost     string `mapstructure:"SMTP_HOST"`
	SMTPPort     int    `mapstructure:"SMTP_PORT"`
	SMTPUsername string `mapstructure:"SMTP_USERNAME"`
	SMTPPassword string `mapstructure:"SMTP_PASSWORD"`
	SMTPFrom     string `mapstructure:"SMTP_FROM"`
	// SMTPFromName is the platform-level fallback display name. Left empty by
	// default deliberately: this value is used whenever a tenant has not set
	// its own smtp_from_name override (see ConfigProvider.SMTPFromName), and a
	// non-empty platform brand here would leak into every tenant's From header
	// that hasn't configured one — exactly the bug this field exists to avoid.
	SMTPFromName           string `mapstructure:"SMTP_FROM_NAME"`
	SMTPUseTLS             bool   `mapstructure:"SMTP_USE_TLS"`
	SMTPInsecureSkipVerify bool   `mapstructure:"SMTP_INSECURE_SKIP_VERIFY"` // SECURITY: Allow skipping TLS verification for internal mail relays (default: false)

	// MFA Configuration
	MFAIssuer          string        `mapstructure:"MFA_ISSUER"`
	MFATOTPDigits      int           `mapstructure:"MFA_TOTP_DIGITS"`
	MFATOTPPeriod      int           `mapstructure:"MFA_TOTP_PERIOD"`
	MFAEmailCodeTTL    time.Duration `mapstructure:"MFA_EMAIL_CODE_TTL"`
	MFABackupCodeCount int           `mapstructure:"MFA_BACKUP_CODE_COUNT"`

	// Frontend URL for verification links
	FrontendURL string `mapstructure:"FRONTEND_URL"`
	// ConsumerEmailDomain is the email domain provisioned for PERSONAL
	// accounts (like Gmail's gmail.com) — a personal signup picks a username
	// and gets <username>@<ConsumerEmailDomain>. Authoritative server-side so
	// the domain isn't duplicated in clients. Env CONSUMER_EMAIL_DOMAIN;
	// defaults to downstream.com.
	ConsumerEmailDomain string `mapstructure:"CONSUMER_EMAIL_DOMAIN"`

	// TenantApexDomain is the eTLD+1 that business-tenant subdomains hang
	// off (e.g. tenant slug "hexxlock" resolves at "hexxlock.example.com").
	// Used to build the Host/CanonicalURL passed to HostDiscoveryService.
	// RegisterVerifiedHost when the onboarding wizard confirms/changes a
	// tenant's slug. Env TENANT_APEX_DOMAIN; defaults to example.com.
	TenantApexDomain string `mapstructure:"TENANT_APEX_DOMAIN"`

	// SignupDefaultPlanCode is the subscription_plans.name assigned to a
	// tenant provisioned through self-service signup (business AND personal/
	// consumer paths — see SignupService.provisionTenant) and to the
	// self-service product-entitlement activation that follows it (see
	// PostSignupProvisioner.OnSignupComplete). Both sites read this single
	// resolved value instead of hardcoding a plan literal, so they cannot
	// drift apart. Env SIGNUP_DEFAULT_PLAN_CODE; defaults to "starter" (an
	// active plan) — "free" was retired 2026-09-10 and must never be
	// assigned to new tenants again.
	SignupDefaultPlanCode string `mapstructure:"SIGNUP_DEFAULT_PLAN_CODE"`

	// SignupDefaultAppURL is where a completed self-service signup is sent when
	// it carries no (valid) OIDC continuation, e.g. the AcmeApp app's
	// oidc-start URL. Absolute http(s) URL; empty leaves the client on its own
	// fallback. Env SIGNUP_DEFAULT_APP_URL.
	SignupDefaultAppURL string `mapstructure:"SIGNUP_DEFAULT_APP_URL"`

	// ABAC/OPA Configuration
	UseABAC          bool          `mapstructure:"USE_ABAC"`           // Global ABAC enable/disable (default: false)
	OPAPolicyPath    string        `mapstructure:"OPA_POLICY_PATH"`    // Path to Rego policy files
	OPADecisionPath  string        `mapstructure:"OPA_DECISION_PATH"`  // OPA decision path
	ABACCacheTTL     time.Duration `mapstructure:"ABAC_CACHE_TTL"`     // Policy cache TTL
	ABACFallbackRBAC bool          `mapstructure:"ABAC_FALLBACK_RBAC"` // Fall back to RBAC if OPA fails

	// Internal Service-to-Service Authentication
	InternalAPIKey string `mapstructure:"INTERNAL_API_KEY"` // Static key for internal service communication

	// Realm Configuration (Full Realm Architecture)
	RealmEnabled          bool   `mapstructure:"REALM_ENABLED"`            // Enable realm architecture
	RealmDefaultSlug      string `mapstructure:"REALM_DEFAULT_SLUG"`       // Default realm slug
	RealmSubdomainEnabled bool   `mapstructure:"REALM_SUBDOMAIN_ENABLED"`  // Extract realm from subdomain
	RealmHeaderEnabled    bool   `mapstructure:"REALM_HEADER_ENABLED"`     // Extract realm from X-Realm-Slug header
	RealmURLPrefixEnabled bool   `mapstructure:"REALM_URL_PREFIX_ENABLED"` // Support /realms/{slug}/... URL pattern

	// SpiceDB Configuration (Relationship-Based Access Control)
	SpiceDBEnabled             bool          `mapstructure:"SPICEDB_ENABLED"`               // Enable SpiceDB for authorization
	SpiceDBEndpoint            string        `mapstructure:"SPICEDB_ENDPOINT"`              // gRPC endpoint (e.g., "spicedb:50051")
	SpiceDBToken               string        `mapstructure:"SPICEDB_TOKEN"`                 // Preshared key for authentication
	SpiceDBInsecure            bool          `mapstructure:"SPICEDB_INSECURE"`              // Use insecure connection (dev only)
	SpiceDBDualWriteEnabled    bool          `mapstructure:"SPICEDB_DUAL_WRITE_ENABLED"`    // Write to both Redis and SpiceDB
	SpiceDBCacheTTL            time.Duration `mapstructure:"SPICEDB_CACHE_TTL"`             // Permission check cache TTL
	SpiceDBMaxConcurrentChecks int           `mapstructure:"SPICEDB_MAX_CONCURRENT_CHECKS"` // Max concurrent permission checks
	SpiceDBTokenV2Enabled      bool          `mapstructure:"SPICEDB_TOKEN_V2_ENABLED"`      // Generate v2 (ultra-minimal) tokens
	SpiceDBTokenV2Percentage   int           `mapstructure:"SPICEDB_TOKEN_V2_PERCENTAGE"`   // Percentage of users to get v2 tokens (canary)
	SpiceDBWatchEnabled        bool          `mapstructure:"SPICEDB_WATCH_ENABLED"`         // Enable Watch API for real-time cache invalidation

	// Trusted Proxy Configuration
	// SECURITY: Only IPs in this list are trusted for X-Forwarded-For headers
	// Common values: ["10.0.30.20"] for Traefik, ["10.0.30.30"] for APISIX
	TrustedProxies []string `mapstructure:"TRUSTED_PROXIES"` // List of trusted proxy IPs

	// SpiceDB Reconciler Configuration
	SpiceDBReconcilerEnabled  bool          `mapstructure:"SPICEDB_RECONCILER_ENABLED"`  // Enable daily PostgreSQL↔SpiceDB reconciliation
	SpiceDBReconcilerInterval time.Duration `mapstructure:"SPICEDB_RECONCILER_INTERVAL"` // Reconciliation interval

	// SAML SP (Inbound Federation) Configuration
	SAMLSPBaseURL               string        `mapstructure:"SAML_SP_BASE_URL"`               // Base URL for SP endpoints (e.g., "https://iam.hexxlock.com")
	SAMLSPClockSkew             time.Duration `mapstructure:"SAML_SP_CLOCK_SKEW"`             // Clock skew tolerance for assertion validation
	SAMLMetadataRefreshEnabled  bool          `mapstructure:"SAML_METADATA_REFRESH_ENABLED"`  // Enable background metadata auto-refresh
	SAMLMetadataRefreshInterval time.Duration `mapstructure:"SAML_METADATA_REFRESH_INTERVAL"` // Interval between metadata refresh checks

	// WebAuthn / Passkey Configuration (FIDO2)
	// RPID is the Relying Party identifier used to scope passkey credentials.
	// MUST be the eTLD+1 root (e.g. "hexxlock.com") so a credential is reusable
	// across every product subdomain. RPID is immutable per credential —
	// changing it after credentials exist invalidates them.
	WebAuthnRPID string `mapstructure:"WEBAUTHN_RP_ID"`
	// RPDisplayName is shown by the authenticator UI during ceremony prompts.
	WebAuthnRPDisplayName string `mapstructure:"WEBAUTHN_RP_DISPLAY_NAME"`
	// RPOrigins is the comma-separated list of origins (scheme + host[:port])
	// from which passkey ceremonies are permitted. MUST cover every host that
	// runs the login or accounts UI (e.g. "https://accounts.hexxlock.com,
	// https://id.hexxlock.com"). Subdomains of RPID are not auto-trusted.
	WebAuthnRPOrigins []string `mapstructure:"WEBAUTHN_RP_ORIGINS"`

	// Apple Sign In Configuration
	AppleTeamID     string `mapstructure:"APPLE_TEAM_ID"`     // Apple Developer Team ID
	AppleKeyID      string `mapstructure:"APPLE_KEY_ID"`      // Key ID for the Apple private key
	AppleServicesID string `mapstructure:"APPLE_SERVICES_ID"` // Services ID (client_id for web)
	ApplePrivateKey string `mapstructure:"APPLE_PRIVATE_KEY"` // PEM-encoded ECDSA P-256 private key

	// Asymmetric JWT Signing Configuration
	JWTSigningAlgorithm    string        `mapstructure:"JWT_SIGNING_ALGORITHM"`     // RS256 (default) or ES256
	JWTKeyRotationInterval time.Duration `mapstructure:"JWT_KEY_ROTATION_INTERVAL"` // How often to rotate signing keys (default: 90 days)
	JWTHMACFallbackEnabled bool          `mapstructure:"JWT_HMAC_FALLBACK_ENABLED"` // Accept HS256 tokens during migration (default: false)
	// JWTClockSkewLeeway is the symmetric clock-skew tolerance applied to
	// access-token time-based claim validation (exp / nbf). A disconnected or
	// drifting DDIL node whose clock runs ahead of the issuer would otherwise
	// reject a still-valid token as expired (or, if behind, as not-yet-valid);
	// this leeway (P3.3) absorbs bounded skew. Widens the acceptance window, so
	// keep it tight. Default: 60s. (SAML has its own SAML_SP_CLOCK_SKEW.)
	JWTClockSkewLeeway time.Duration `mapstructure:"JWT_CLOCK_SKEW_LEEWAY"`

	// --- DDIL degraded-mode (Phase 3) ---------------------------------------
	// Governed offline-authorization (P3.2): when SpiceDB is unreachable, serve
	// the last-known-good SIGNED, time-boxed decision within a short,
	// adversary-aware budget, then fail CLOSED. Honours a revocation epoch so a
	// role/permission change (tenant role-version bump) voids cached decisions
	// even while disconnected. See docs/2026-07-19-ddil-degraded-mode-operating-spec.md.
	DDILOfflineAuthzEnabled           bool          `mapstructure:"DDIL_OFFLINE_AUTHZ"`                    // Master toggle (default: true)
	DDILOfflineAuthzStandardBudget    time.Duration `mapstructure:"DDIL_OFFLINE_AUTHZ_STANDARD_BUDGET"`    // Standard-tier staleness budget (default: 15m)
	DDILOfflineAuthzPrivilegedBudget  time.Duration `mapstructure:"DDIL_OFFLINE_AUTHZ_PRIVILEGED_BUDGET"`  // Privileged-tier staleness budget (default: 5m)
	DDILOfflineAuthzPrivilegedModules []string      `mapstructure:"DDIL_OFFLINE_AUTHZ_PRIVILEGED_MODULES"` // Modules treated as privileged (default: iam,core,admin,platform)
	DDILOfflineAuthzClockLeeway       time.Duration `mapstructure:"DDIL_OFFLINE_AUTHZ_CLOCK_LEEWAY"`       // Skew leeway on the offline budget window (default: 0 — budget already carries margin)

	// Uniform resilience kit (P3.11): circuit-breaker + backoff-with-jitter +
	// per-attempt timeout around central-dependency calls, so a failing
	// dependency sheds load (and, for SpiceDB, composes with offline-authz)
	// instead of piling on. The Redis breaker is separate (pkg/circuitbreaker).
	SpiceDBResilienceEnabled       bool          `mapstructure:"SPICEDB_RESILIENCE_ENABLED"`        // Wrap SpiceDB checks in breaker+backoff (default: true)
	SpiceDBBreakerFailureThreshold int           `mapstructure:"SPICEDB_BREAKER_FAILURE_THRESHOLD"` // Consecutive failures before open (default: 5)
	SpiceDBBreakerResetTimeout     time.Duration `mapstructure:"SPICEDB_BREAKER_RESET_TIMEOUT"`     // Cool-down before half-open probe (default: 30s)
	SpiceDBCallTimeout             time.Duration `mapstructure:"SPICEDB_CALL_TIMEOUT"`              // Per-attempt gRPC timeout (default: 5s)
	SpiceDBMaxAttempts             int           `mapstructure:"SPICEDB_MAX_ATTEMPTS"`              // Total attempts incl. first (default: 3)

	HIBPResilienceEnabled       bool          `mapstructure:"HIBP_RESILIENCE_ENABLED"`        // Wrap HIBP range calls in breaker+backoff (default: true)
	HIBPBreakerFailureThreshold int           `mapstructure:"HIBP_BREAKER_FAILURE_THRESHOLD"` // Consecutive failures before open (default: 5)
	HIBPBreakerResetTimeout     time.Duration `mapstructure:"HIBP_BREAKER_RESET_TIMEOUT"`     // Cool-down before half-open probe (default: 30s)

	LDAPResilienceEnabled       bool          `mapstructure:"LDAP_RESILIENCE_ENABLED"`        // Wrap LDAP connect in a breaker (default: true)
	LDAPBreakerFailureThreshold int           `mapstructure:"LDAP_BREAKER_FAILURE_THRESHOLD"` // Consecutive failures before open (default: 5)
	LDAPBreakerResetTimeout     time.Duration `mapstructure:"LDAP_BREAKER_RESET_TIMEOUT"`     // Cool-down before half-open probe (default: 30s)

	// Graceful Shutdown
	// SHUTDOWN_TIMEOUT controls the total time (in seconds) allowed for the
	// process to drain connections and clean up after a SIGTERM/SIGINT.
	// The first 5 seconds are used as a load-balancer drain delay during which
	// readiness probes return 503; the remainder is given to http.Server.Shutdown.
	// Defaults to 30 seconds when unset or 0.
	ShutdownTimeout time.Duration `mapstructure:"SHUTDOWN_TIMEOUT"`

	// Read Replica Configuration
	// DATABASE_READ_REPLICA_URLS is a space/comma-separated list of PostgreSQL
	// read-replica DSNs.  When set, read-intent queries are distributed across
	// the replicas in round-robin order.  Write-intent and strong-read-intent
	// queries always go to the primary (DATABASE_URL).
	// Leave empty (default) to route all traffic to the primary.
	DatabaseReadReplicaURLs []string `mapstructure:"DATABASE_READ_REPLICA_URLS"`

	// Product Provisioning Configuration
	// PRODUCT_MIGRATIONS_PATH is the base directory containing product migration
	// SQL files. Each subdirectory maps to a product's migration_source value.
	// Example: "/app/product-migrations/crm/" contains CRM module migrations.
	// If empty, only statically registered migrations (embed.FS) are used.
	ProductMigrationsPath string `mapstructure:"PRODUCT_MIGRATIONS_PATH"`

	// Lifecycle callback URL allowlist (comma-separated list of allowed URL prefixes).
	// SSRF prevention: only URLs starting with these prefixes are allowed.
	// Example: "http://crm-service:8080,http://pm-service:8081"
	LifecycleCallbackAllowlistRaw string `mapstructure:"LIFECYCLE_CALLBACK_ALLOWLIST"`

	lifecycleCallbackAllowlistParsed []string // cached parsed result

	// Temporal workflow orchestration (optional — disabled by default).
	// When TEMPORAL_ENABLED=true, the provisioning orchestrator dispatches new
	// pending product instances to Temporal workflows instead of processing them
	// via the local PostgreSQL advisory-lock reconciliation loop.
	// The reconciliation loop remains active as a fallback in all modes.
	TemporalEnabled   bool   `mapstructure:"TEMPORAL_ENABLED"`
	TemporalHostPort  string `mapstructure:"TEMPORAL_HOST_PORT"`
	TemporalNamespace string `mapstructure:"TEMPORAL_NAMESPACE"`
	TemporalTaskQueue string `mapstructure:"TEMPORAL_TASK_QUEUE"`

	// APISIX Admin API configuration.
	// APISIXAdminURL is the base URL of the APISIX Admin API (e.g. "http://apisix:9180").
	// APISIXAdminKey is the pre-shared key sent in the X-API-KEY header.
	// When APISIXAdminURL is empty, dynamic route registration is disabled and
	// the provisioning orchestrator skips the APISIX step gracefully.
	APISIXAdminURL string `mapstructure:"APISIX_ADMIN_URL"`
	APISIXAdminKey string `mapstructure:"APISIX_ADMIN_KEY"`

	// Metering scraper endpoints.
	// PrometheusURL is the base URL of the Prometheus server used by the
	// MeteringAggregator to scrape compute (CPU-seconds) metrics per tenant
	// namespace.  Defaults to "http://prometheus:9090".
	PrometheusURL string `mapstructure:"PROMETHEUS_URL"`

	// MinIOConsoleURL is the base URL of the MinIO Console API used to list
	// bucket storage usage per tenant.  Defaults to "http://minio:9001".
	MinIOConsoleURL string `mapstructure:"MINIO_CONSOLE_URL"`

	// MinIOAccessKey and MinIOSecretKey are credentials for the MinIO Console
	// API.  Leave empty when the endpoint is reachable without authentication
	// (e.g. internal service mesh).
	MinIOAccessKey string `mapstructure:"MINIO_ACCESS_KEY"`
	MinIOSecretKey string `mapstructure:"MINIO_SECRET_KEY"`

	// MinIOEndpoint is the internal S3-compatible endpoint used by Falcon-ID to
	// generate presigned URLs.  Defaults to "minio:9000" (in-cluster address).
	MinIOEndpoint string `mapstructure:"MINIO_ENDPOINT"`

	// MinIOExternalEndpoint is the publicly-reachable endpoint embedded into
	// presigned download URLs returned to browser clients.  When empty it
	// falls back to MinIOEndpoint.  Defaults to "localhost:9000".
	MinIOExternalEndpoint string `mapstructure:"MINIO_EXTERNAL_ENDPOINT"`

	// MinIOBucket is the default bucket used for presigned-download requests
	// when the bucket cannot be derived from the object key.
	// Defaults to "hexxlock-crm".
	MinIOBucket string `mapstructure:"MINIO_BUCKET"`

	// APISIXMetricsURL is the base URL of the APISIX Prometheus metrics
	// exporter (e.g. "http://apisix:9091").  The scraper appends
	// /apisix/prometheus/metrics to this URL.  Defaults to "http://apisix:9091".
	APISIXMetricsURL string `mapstructure:"APISIX_METRICS_URL"`

	// Kafka — subscription-to-provisioning bridge.
	// When configured, Falcon-ID consumes subscription.activated events and
	// auto-provisions product instances.
	KafkaBrokers string `mapstructure:"KAFKA_BROKERS"`  // comma-separated, e.g. "kafka:9092"
	KafkaGroupID string `mapstructure:"KAFKA_GROUP_ID"` // consumer group, default "falcon-id-provisioning"

	// Tenant reverse projection (ADR 0029 Phase 1a).
	// TenantProjectionEnabled gates the Phase 1a consumer. Set to "false" to
	// disable at runtime without a code change (ops kill-switch).
	// Default: "true" — must be enabled before Phase 1b flips authoritative writes.
	TenantProjectionEnabled bool `mapstructure:"TENANT_PROJECTION_ENABLED"`

	// EntitlementSyncEnabled gates the example.tenant.modules.sync
	// consumer (the product roadmap §4.1, internal/entitlementsync). Set to
	// "false" to disable at runtime without a code change (ops
	// kill-switch) -- e.g. before <gitops-bootstrap-repo>'s
	// topic/KafkaUser and the GitOps repository' v0.232.267 MigrationBundle
	// have both rolled out (see falcon-id r1/entitlements rollout-order
	// note). Default: "true".
	EntitlementSyncEnabled bool `mapstructure:"ENTITLEMENT_SYNC_ENABLED"`
	// ModuleAccessReconcileOnStartup runs the module-access reconcile (role
	// templates + owner grants for every granting entitlement) once, shortly
	// after startup. Kill switch: MODULE_ACCESS_RECONCILE_ON_STARTUP=false.
	// Default: "true".
	ModuleAccessReconcileOnStartup bool `mapstructure:"MODULE_ACCESS_RECONCILE_ON_STARTUP"`
	// AcmeAppGrantSyncOnStartup tops up catalog permission grants on every
	// tenant's existing AcmeApp system roles shortly after startup (additive,
	// idempotent). Kill switch: ACMEAPP_GRANT_SYNC_ON_STARTUP=false.
	AcmeAppGrantSyncOnStartup bool `mapstructure:"ACMEAPP_GRANT_SYNC_ON_STARTUP"`

	// WO#20 tenant API keys (developer access). Everything is off by default:
	// DeveloperKeysEnabled gates the /api/v1/developer/api-keys routes and the
	// /oauth/token/api-key exchange; DeveloperKeysTenantAllowlist (comma-
	// separated tenant UUIDs) narrows it to a canary set, and an empty list
	// means every tenant once the flag is on (GA).
	DeveloperKeysEnabled         bool     `mapstructure:"DEVELOPER_KEYS_ENABLED"`
	DeveloperKeysTenantAllowlist []string `mapstructure:"DEVELOPER_KEYS_TENANT_ALLOWLIST"`
	// DeveloperKeysPepper is the HMAC-SHA256 pepper for tenant API key secrets.
	// Sourced from Vault via env; never logged, never in the DB. Empty disables
	// key creation and exchange (fail closed).
	DeveloperKeysPepper string `mapstructure:"DEVELOPER_KEYS_PEPPER"`
	// DeveloperKeysPeppers holds additional pepper versions ("v2=secret,
	// v3=secret" in DEVELOPER_KEYS_PEPPERS) so stored hashes made with an
	// older pepper keep verifying across a rotation. DEVELOPER_KEYS_PEPPER is
	// always version v1. DeveloperKeysPepperCurrent names the version used for
	// new hashes (default v1); stored as hash_alg "hmac-sha256:<version>".
	DeveloperKeysPeppers       map[string]string `mapstructure:"DEVELOPER_KEYS_PEPPERS"`
	DeveloperKeysPepperCurrent string            `mapstructure:"DEVELOPER_KEYS_PEPPER_CURRENT"`
	// DeveloperKeysAudience is the `aud` of API key access tokens. The public
	// API host is not final, so it is configuration, not code.
	DeveloperKeysAudience string `mapstructure:"DEVELOPER_KEYS_AUDIENCE"`
	// DeveloperKeysTokenTTL is the lifetime of an exchanged API key token.
	DeveloperKeysTokenTTL time.Duration `mapstructure:"DEVELOPER_KEYS_TOKEN_TTL"`
	// BusinessInternalURL is the in-cluster base URL of the business service,
	// used to sync API key company edges (scope iam:api-keys:sync).
	BusinessInternalURL string `mapstructure:"BUSINESS_INTERNAL_URL"`
	// TenantStatusEnabled gates the example.tenant.status consumer (tenant
	// suspension enforcement, R1-GAPS row 27, internal/tenantstatus). Kill
	// switch: TENANT_STATUS_ENABLED=false. Like the other Kafka consumers it
	// is a no-op when KAFKA_BROKERS is empty.
	TenantStatusEnabled bool `mapstructure:"TENANT_STATUS_ENABLED"`
	// OpsStrictPlatformRoles (OPS_STRICT_PLATFORM_ROLES, default false) turns
	// on the platform-admin console's strict platform-plane model. When true,
	// platform-admin authority comes ONLY from iam_platform_roles (an active
	// JIT elevation or break-glass grant): the is_platform_admin claim, the
	// checkPermissions / RequirePlatformAdmin bypass and the implicit
	// internal-tenant admin no longer follow tenant membership or the legacy
	// tenant-role platform_admin / iam_admin. The one exception is the
	// break-glass account (OpsBreakGlassEmail). When false (default) every
	// path behaves exactly as before.
	OpsStrictPlatformRoles bool `mapstructure:"OPS_STRICT_PLATFORM_ROLES"`
	// OpsBreakGlassEmail (OPS_BREAK_GLASS_EMAIL) is the single account that
	// keeps a standing platform_admin / iam_admin tenant role under
	// OPS_STRICT_PLATFORM_ROLES. Empty = the account created by
	// FALCON_ADMIN_EMAIL is the break-glass account.
	OpsBreakGlassEmail string `mapstructure:"OPS_BREAK_GLASS_EMAIL"`
	// OpsAuditConsumerEnabled (OPS_AUDIT_CONSUMER_ENABLED, default false)
	// starts the platform.ops-audit.v1 consumer that appends operator audit
	// events to platform_admin_audit_log (needs migration 0035 applied).
	OpsAuditConsumerEnabled bool `mapstructure:"OPS_AUDIT_CONSUMER_ENABLED"`
	// OpsOperatorExchangeClientIDs (OPS_OPERATOR_EXCHANGE_CLIENT_IDS, comma
	// separated) lists the confidential OAuth clients allowed to run the
	// operator token exchange (audience hexxlock-ops). Empty = exchange off.
	OpsOperatorExchangeClientIDs []string `mapstructure:"OPS_OPERATOR_EXCHANGE_CLIENT_IDS"`
	// OpsStandingAdminDirect (OPS_STANDING_ADMIN_DIRECT, default false) makes
	// the operator exchange mint standing_platform_admin for the standing
	// break-glass platform_admin, so the operator console skips reason /
	// confirmation / four-eyes friction for it (audit stays complete). false =
	// kill switch: full friction for everyone.
	OpsStandingAdminDirect bool `mapstructure:"OPS_STANDING_ADMIN_DIRECT"`
	// TenantManagementInternalURL is the in-cluster base URL of tenant-management
	// used by the cold-start bootstrap REST poll.
	// Default: http://hexxlock-platform-tenant-management.example-platform.svc.cluster.local:80
	TenantManagementInternalURL string `mapstructure:"TENANT_MANAGEMENT_INTERNAL_URL"`
	// SubscriptionManagementInternalURL is the in-cluster base URL of
	// subscription-management, used by the onboarding-completion trial-start
	// hook (see PostSignupProvisioner's TrialStarter) to call
	// POST /api/v1/internal/tenants/{id}/trial.
	// Default: http://subscription-management.example-platform.svc.cluster.local:8040
	SubscriptionManagementInternalURL string `mapstructure:"SUBSCRIPTION_MANAGEMENT_INTERNAL_URL"`

	// Outbound OAuth client_credentials creds for falcon-id-as-CLIENT to other
	// platform services. Populated from a sibling ExternalSecret driven by
	// the `falcon-id-oauth` ServiceClientClaim (XServiceClient Crossplane
	// composition). When unset, the tenantprojection bootstrap REST poll
	// falls back to an unauthenticated http.DefaultClient — appropriate for
	// dev/test where tenant-management's read endpoints are not yet
	// scope-gated. ADR 0029 follow-up handoff (G).
	ServiceClientID     string `mapstructure:"SERVICE_CLIENT_ID"`
	ServiceClientSecret string `mapstructure:"SERVICE_CLIENT_SECRET"`
	// IAMServiceURL is the in-cluster URL used to mint the
	// client_credentials access_token. Default points at falcon-id itself
	// (the OP and the calling service share a pod for tenantprojection
	// bootstrap — falcon-id's own /oauth/token is the natural choice).
	IAMServiceURL string `mapstructure:"IAM_SERVICE_URL"`

	// Bot / Fraud Detection
	// BOT_DETECTION_ENABLED gates the entire detection engine (default true).
	// BOT_DETECTION_THRESHOLD is the composite score above which requests are
	// blocked outright (default 0.7).
	// BOT_DETECTION_CHALLENGE_THRESHOLD is the score above which a challenge
	// (CAPTCHA / proof-of-work) is issued instead of an outright block (default 0.4).
	// Seat-quota enforcement (feat/seat-quota-enforcement).
	// QuotaServiceURL is the in-cluster base URL of quota-service, used by
	// UserService to check/increment/decrement the tenant's "users"
	// resource quota around iam_users writes.
	// Default: http://quota-service.example-platform.svc.cluster.local:8013
	QuotaServiceURL string `mapstructure:"QUOTA_SERVICE_URL"`
	// QuotaEnforcementEnabled gates whether UserService.Create calls
	// quota-service's MustCheckQuota before writing a new iam_users row.
	// Default: true. Ops kill-switch — set to "false" to fall back to
	// unlimited-seats behavior without a redeploy if quota-service itself
	// is unstable and wrongly blocking signups.
	QuotaEnforcementEnabled bool `mapstructure:"QUOTA_ENFORCEMENT_ENABLED"`
	// QuotaCheckFailOpen controls what happens when MustCheckQuota fails
	// for a reason OTHER than quota being exceeded (quota-service network
	// error, 5xx, timeout): false (default) fails closed — the create is
	// denied — because silently granting unlimited seats during a
	// quota-service outage is the worse failure mode for a paid seat
	// limit. Set to "true" to fail open instead if quota-service
	// instability starts blocking all signups; this is a real
	// availability/correctness tradeoff, not a default anyone should
	// flip casually — see falcon-id!<TBD> MR description.
	QuotaCheckFailOpen bool `mapstructure:"QUOTA_CHECK_FAIL_OPEN"`

	// SeatQuotaReconcilerEnabled/Interval (feat/seat-quota-reconciler).
	// Seats are a STOCK (a current count), not a FLOW like
	// email_sends_monthly: the synchronous IncrementUsage/DecrementUsage
	// calls around UserService.Create/Delete above drift permanently the
	// moment any write path skips them (a direct DB write, a partially
	// failed bulk operation, historical drift predating a working
	// service-auth scope, a tenant merge). This periodic reconciler
	// recounts real active seats per tenant straight from iam_users (the
	// only authoritative source of tenant users on the platform) and
	// writes the absolute value to quota-service via
	// POST /api/v1/quota/admin/reconcile, self-correcting any drift
	// between runs — mirrors hexxlock/business's
	// ContactsQuotaReconcilerService for the "contacts" resource.
	// Default: enabled, hourly (same cadence as the contacts precedent —
	// seat counts do not need real-time reconciliation given the
	// synchronous check/increment/decrement path above already covers
	// the common create/delete case).
	SeatQuotaReconcilerEnabled   bool          `mapstructure:"SEAT_QUOTA_RECONCILER_ENABLED"`
	SeatQuotaReconcilerInterval  time.Duration `mapstructure:"SEAT_QUOTA_RECONCILER_INTERVAL"`
	EmployeeAccessExpiryInterval time.Duration `mapstructure:"EMPLOYEE_ACCESS_EXPIRY_INTERVAL"`

	BotDetectionEnabled            bool    `mapstructure:"BOT_DETECTION_ENABLED"`
	BotDetectionThreshold          float64 `mapstructure:"BOT_DETECTION_THRESHOLD"`
	BotDetectionChallengeThreshold float64 `mapstructure:"BOT_DETECTION_CHALLENGE_THRESHOLD"`
}

// envStringSlice reads a comma-separated env var and returns it as a
// []string with each element trimmed of whitespace and empty entries
// dropped.
//
// Why this exists: viper.GetStringSlice() returns a SINGLE-element slice
// containing the entire comma-joined string when the value comes from
// an env var (it only splits on commas when reading from YAML/TOML/JSON
// config files). The result is that something like
// `WEBAUTHN_RP_ORIGINS="https://a,https://b"` becomes
// []string{"https://a,https://b"} — one element — rather than
// []string{"https://a","https://b"}. Downstream consumers that exact-
// match against the slice (notably go-webauthn's origin validation)
// then reject every legitimate value past the first joined-in entry.
//
// This helper makes the env-var → []string split explicit and
// idempotent. Use it for every viper-backed slice that may be sourced
// from an env var: TRUSTED_PROXIES, WEBAUTHN_RP_ORIGINS,
// DATABASE_READ_REPLICA_URLS, etc.
//
// Refs:
//   - https://github.com/spf13/viper/issues/380
//   - https://github.com/spf13/viper/issues/112
//   - falcon-id pre-fix passkey FinishRegistration: "Error validating
//     origin" failure logged 2026-05-19, every assertion rejected
//     because RPOrigins was a 1-element slice.
func envStringSlice(key string) []string {
	raw := viper.GetString(key)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// parseVersionedSecrets parses "v2=secret,v3=secret" into a version->secret map.
// Entries without a version, secret or "=" are ignored.
func parseVersionedSecrets(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		version, secret, ok := strings.Cut(strings.TrimSpace(part), "=")
		version, secret = strings.TrimSpace(version), strings.TrimSpace(secret)
		if ok && version != "" && secret != "" {
			out[version] = secret
		}
	}
	return out
}

// DeveloperKeyPeppers returns every configured API key pepper by version
// (DEVELOPER_KEYS_PEPPER is v1; DEVELOPER_KEYS_PEPPERS adds more) and the
// version new hashes use. The current version is v1 unless
// DEVELOPER_KEYS_PEPPER_CURRENT says otherwise; if it has no pepper, the
// returned current pepper is missing and callers must fail closed.
func (c *Config) DeveloperKeyPeppers() (peppers map[string]string, current string) {
	peppers = map[string]string{}
	for v, s := range c.DeveloperKeysPeppers {
		peppers[v] = s
	}
	if c.DeveloperKeysPepper != "" {
		if _, taken := peppers["v1"]; !taken {
			peppers["v1"] = c.DeveloperKeysPepper
		}
	}
	current = c.DeveloperKeysPepperCurrent
	if current == "" {
		current = "v1"
	}
	return peppers, current
}

// LoadConfig is an exported function.
func LoadConfig() (*Config, error) {
	// SECURITY: Environment must be explicitly set - no default
	// This prevents accidental production deployment with development settings
	viper.SetDefault("ENVIRONMENT", "")
	viper.SetDefault("SERVICE_NAME", "falcon-id")
	viper.SetDefault("SERVICE_PORT", "8010")
	viper.SetDefault("LOG_LEVEL", "info")

	// SECURITY: No defaults for database credentials - must be explicitly configured
	viper.SetDefault("DATABASE_URL", "")
	viper.SetDefault("CONTROL_PLANE_DATABASE_URL", "")

	// Database connection components for Vault dynamic credential mode.
	// When VAULT_DATABASE_ENABLED=true the service builds the DSN from these
	// fields plus the dynamic username/password returned by Vault.
	viper.SetDefault("DATABASE_HOST", "postgres")
	viper.SetDefault("DATABASE_PORT", 5432)
	viper.SetDefault("DATABASE_NAME", "hexxlock_iam")
	viper.SetDefault("DATABASE_SSL_MODE", "disable")

	viper.SetDefault("REDIS_URL", "")
	viper.SetDefault("REDIS_MAX_RETRIES", 3)
	viper.SetDefault("REDIS_REQUIRED", false)
	viper.SetDefault("REDIS_MIN_IDLE_CONNS", 5)
	viper.SetDefault("REDIS_CONN_MAX_LIFETIME", 30*time.Minute)
	viper.SetDefault("REDIS_RATE_LIMIT_ENABLED", true)
	// SECURITY: Session cache TTL must be aligned with SESSION_EXPIRY, not ACCESS_TOKEN_EXPIRY.
	// The cache stores session context that v1/v2 tokens depend on for every authenticated request.
	// If this TTL is shorter than the refresh cycle, requests fail with "session not found."
	// The TTL is refreshed on every cache read (sliding window) so active sessions never expire
	// from cache prematurely. Security boundaries are enforced by:
	//   - Refresh token expiry (7d / 30d trusted)
	//   - Session expires_at in PostgreSQL
	//   - Token blacklist / session revocation checks
	// SECURITY: Redis session TTL must be >= SESSION_IDLE_TIMEOUT so that active
	// sessions are never evicted from cache while still valid. The sliding TTL
	// in GetSessionData extends this on every read, so memory pressure is limited
	// to genuinely active sessions.
	viper.SetDefault("REDIS_SESSION_CACHE_TTL", 9*time.Hour) // idle timeout (8h) + 1h safety buffer

	// Permission cache defaults - multi-layer caching for performance
	viper.SetDefault("PERMISSION_CACHE_LOCAL_SIZE", 10000)                // 10k entries in local LRU
	viper.SetDefault("PERMISSION_CACHE_LOCAL_TTL", 30*time.Second)        // Local cache refreshes frequently
	viper.SetDefault("PERMISSION_CACHE_CHECK_TTL", 1*time.Minute)         // Permission check cache
	viper.SetDefault("PERMISSION_CACHE_ROLE_MAPPING_TTL", 15*time.Minute) // Role mappings are more stable

	// Observability defaults
	viper.SetDefault("OTLP_ENDPOINT", "")
	viper.SetDefault("TRACING_SAMPLING_RATE", 0.1)
	viper.SetDefault("METRICS_ENABLED", true)

	// SECURITY: No default for encryption key - must be explicitly configured
	viper.SetDefault("ENCRYPTION_KEY", "")
	viper.SetDefault("EMAIL_HASH_KEY", "")

	// SECURITY: No default for token hash salt - must be explicitly configured
	viper.SetDefault("TOKEN_HASH_SALT", "")

	// SECURITY: No default for JWT secret - must be explicitly configured
	viper.SetDefault("JWT_SECRET", "")
	viper.SetDefault("JWT_ISSUER", "falcon-id")
	viper.SetDefault("ACCESS_TOKEN_EXPIRY", 15*time.Minute) // SECURITY: Short-lived access tokens reduce exposure window
	viper.SetDefault("SESSION_EXPIRY", 24*time.Hour)
	// Must exceed JWKS_MAX_AGE + SIGNING_KEY_RELOAD_INTERVAL so every cache and replica knows a key before it signs.
	viper.SetDefault("SIGNING_KEY_PUBLISH_DELAY", 75*time.Minute)
	viper.SetDefault("SIGNING_KEY_RELOAD_INTERVAL", 60*time.Second)
	viper.SetDefault("SIGNING_KEY_RETIRE_AFTER", 24*time.Hour) // rotated key stays in JWKS this long (>= longest JWT lifetime + margin)
	viper.SetDefault("JWKS_MAX_AGE", 300*time.Second)
	viper.SetDefault("SESSION_IDLE_TIMEOUT", 8*time.Hour) // 8 hours of inactivity before session is invalidated
	viper.SetDefault("DPOP_ENABLED", false)               // RFC 9449 — enable after SDK client proof generation ships
	// SECURITY: Enable session rotation by default to prevent session fixation attacks
	viper.SetDefault("SESSION_ROTATION_ON_REFRESH", true)

	// Remember-me TTL bifurcation. SESSION_TTL_DEFAULT intentionally has
	// NO viper.SetDefault so the unset state is detectable in Load() and
	// can be aliased to SessionExpiry — preserving any operator override
	// of SESSION_EXPIRY without requiring a paired SESSION_TTL_DEFAULT
	// edit. Operators who want a SHORTER short-TTL than the existing
	// SESSION_EXPIRY (e.g. 8h for high-security tenants while keeping the
	// extended remember-me path on 30d) can set SESSION_TTL_DEFAULT
	// explicitly and it will take precedence.
	viper.SetDefault("SESSION_TTL_REMEMBER_ME", 30*24*time.Hour) // 30d — overridable via SESSION_TTL_REMEMBER_ME for stricter regimes (PCI-DSS § 8.1.8 = 7d / 168h)

	// Trusted device settings - extended expiry for "Remember Me" sessions
	viper.SetDefault("TRUSTED_DEVICE_SESSION_EXPIRY", 30*24*time.Hour) // 30 days for trusted device sessions
	viper.SetDefault("TRUST_DURATION_DAYS", 30)                        // Device trust lasts 30 days

	// AD Sync Defaults - disabled by default
	viper.SetDefault("AD_SYNC_ENABLED", false)
	viper.SetDefault("AD_SYNC_DEFAULT_INTERVAL", 1*time.Hour)
	viper.SetDefault("AD_SYNC_BATCH_SIZE", 100)
	viper.SetDefault("AD_SYNC_HISTORY_RETENTION", 30*24*time.Hour) // 30 days

	// SECURITY: Strong password policy defaults (NIST SP 800-63B compliant)
	viper.SetDefault("PASSWORD_MIN_LENGTH", 12)
	viper.SetDefault("PASSWORD_REQUIRE_UPPER", true)
	viper.SetDefault("PASSWORD_REQUIRE_LOWER", true)
	viper.SetDefault("PASSWORD_REQUIRE_DIGIT", true)
	viper.SetDefault("PASSWORD_REQUIRE_SPECIAL", true)
	viper.SetDefault("PASSWORD_BREACH_CHECK_ENABLED", true)
	viper.SetDefault("FALCON_WITNESS_TOTP_ENABLED", false)

	viper.SetDefault("RATE_LIMIT_REQUESTS", 100)
	viper.SetDefault("RATE_LIMIT_WINDOW", time.Minute)

	viper.SetDefault("MAX_LOGIN_ATTEMPTS", 5)
	viper.SetDefault("LOCKOUT_DURATION", 30*time.Minute)

	// SMTP Defaults — empty by default; production SMTP config lives in the database
	// via ConfigProvider (iam_tenant_configs table) and is resolved per-tenant.
	// Static env vars serve as a system-wide fallback when no tenant config exists.
	viper.SetDefault("SMTP_HOST", "")
	viper.SetDefault("SMTP_PORT", 0)
	viper.SetDefault("SMTP_USERNAME", "")
	viper.SetDefault("SMTP_PASSWORD", "")
	viper.SetDefault("SMTP_FROM", "")
	viper.SetDefault("SMTP_USE_TLS", true)
	viper.SetDefault("SMTP_INSECURE_SKIP_VERIFY", false)

	// MFA Defaults
	viper.SetDefault("MFA_ISSUER", "Falcon ID")
	viper.SetDefault("MFA_TOTP_DIGITS", 6)
	viper.SetDefault("MFA_TOTP_PERIOD", 30)
	viper.SetDefault("MFA_EMAIL_CODE_TTL", 10*time.Minute)
	viper.SetDefault("MFA_BACKUP_CODE_COUNT", 10)

	// Frontend URL
	viper.SetDefault("FRONTEND_URL", "http://localhost:3000")

	// ABAC/OPA Defaults - disabled by default
	viper.SetDefault("USE_ABAC", false)
	viper.SetDefault("OPA_POLICY_PATH", "./policies")
	viper.SetDefault("OPA_DECISION_PATH", "falcon/authz/allow")
	viper.SetDefault("ABAC_CACHE_TTL", 5*time.Minute)
	viper.SetDefault("ABAC_FALLBACK_RBAC", true)

	// Realm Configuration Defaults
	viper.SetDefault("REALM_ENABLED", true)            // Enable by default for new architecture
	viper.SetDefault("REALM_DEFAULT_SLUG", "default")  // Default realm slug
	viper.SetDefault("REALM_SUBDOMAIN_ENABLED", true)  // Extract realm from subdomain
	viper.SetDefault("REALM_HEADER_ENABLED", true)     // Extract realm from header
	viper.SetDefault("REALM_URL_PREFIX_ENABLED", true) // Support /realms/{slug}/... URLs

	// SpiceDB Configuration Defaults - enabled by default (primary authorization engine)
	viper.SetDefault("SPICEDB_ENABLED", true)              // SpiceDB is the primary authorization engine
	viper.SetDefault("SPICEDB_ENDPOINT", "spicedb:50051")  // Default gRPC endpoint
	viper.SetDefault("SPICEDB_TOKEN", "")                  // Must be configured explicitly
	viper.SetDefault("SPICEDB_INSECURE", true)             // Insecure in development
	viper.SetDefault("SPICEDB_DUAL_WRITE_ENABLED", true)   // Always dual-write to keep SpiceDB in sync
	viper.SetDefault("SPICEDB_CACHE_TTL", 30*time.Second)  // Permission check cache TTL
	viper.SetDefault("SPICEDB_MAX_CONCURRENT_CHECKS", 100) // Rate limit concurrent checks
	viper.SetDefault("SPICEDB_TOKEN_V2_ENABLED", true)     // v2 tokens enabled
	viper.SetDefault("SPICEDB_TOKEN_V2_PERCENTAGE", 100)   // All users get v2 tokens
	viper.SetDefault("SPICEDB_WATCH_ENABLED", true)        // Watch API for real-time cache invalidation

	// SECURITY: Trusted Proxy Defaults
	// In production: MUST be explicitly configured (e.g., "10.0.30.20,10.0.30.30" for Traefik+APISIX)
	// In development: Empty list means X-Forwarded-For is never trusted
	viper.SetDefault("TRUSTED_PROXIES", []string{})

	// SAML SP (Inbound Federation) Defaults
	viper.SetDefault("SAML_SP_BASE_URL", "")                        // Must be configured for SAML SP
	viper.SetDefault("SAML_SP_CLOCK_SKEW", 2*time.Minute)           // 2-minute tolerance
	viper.SetDefault("SAML_METADATA_REFRESH_ENABLED", false)        // Disabled by default
	viper.SetDefault("SAML_METADATA_REFRESH_INTERVAL", 1*time.Hour) // Check every hour

	// Apple Sign In Defaults - must be configured when Apple provider is enabled
	viper.SetDefault("APPLE_TEAM_ID", "")
	viper.SetDefault("APPLE_KEY_ID", "")
	viper.SetDefault("APPLE_SERVICES_ID", "")
	viper.SetDefault("APPLE_PRIVATE_KEY", "")

	// Asymmetric JWT Signing Defaults
	viper.SetDefault("JWT_SIGNING_ALGORITHM", "RS256")             // RS256 for broad compatibility
	viper.SetDefault("JWT_KEY_ROTATION_INTERVAL", 90*24*time.Hour) // 90-day rotation cycle
	viper.SetDefault("JWT_HMAC_FALLBACK_ENABLED", false)           // Accept HS256 during migration
	viper.SetDefault("JWT_CLOCK_SKEW_LEEWAY", 60*time.Second)      // DDIL P3.3: clock-skew tolerance on exp/nbf

	// DDIL degraded-mode (Phase 3) defaults — budgets from the operating spec.
	viper.SetDefault("DDIL_OFFLINE_AUTHZ", true)                                         // Governed offline-authz ON by default
	viper.SetDefault("DDIL_OFFLINE_AUTHZ_STANDARD_BUDGET", 15*time.Minute)               // Standard tier: 15m
	viper.SetDefault("DDIL_OFFLINE_AUTHZ_PRIVILEGED_BUDGET", 5*time.Minute)              // Privileged tier: 5m
	viper.SetDefault("DDIL_OFFLINE_AUTHZ_PRIVILEGED_MODULES", "iam,core,admin,platform") // Privileged modules (comma-separated)
	viper.SetDefault("DDIL_OFFLINE_AUTHZ_CLOCK_LEEWAY", 0)                               // Strict; budget carries the margin

	// DDIL resilience (P3.11) defaults — mirror the shared resilient kit defaults.
	viper.SetDefault("SPICEDB_RESILIENCE_ENABLED", true)
	viper.SetDefault("SPICEDB_BREAKER_FAILURE_THRESHOLD", 5)
	viper.SetDefault("SPICEDB_BREAKER_RESET_TIMEOUT", 30*time.Second)
	viper.SetDefault("SPICEDB_CALL_TIMEOUT", 5*time.Second)
	viper.SetDefault("SPICEDB_MAX_ATTEMPTS", 3)
	viper.SetDefault("HIBP_RESILIENCE_ENABLED", true)
	viper.SetDefault("HIBP_BREAKER_FAILURE_THRESHOLD", 5)
	viper.SetDefault("HIBP_BREAKER_RESET_TIMEOUT", 30*time.Second)
	viper.SetDefault("LDAP_RESILIENCE_ENABLED", true)
	viper.SetDefault("LDAP_BREAKER_FAILURE_THRESHOLD", 5)
	viper.SetDefault("LDAP_BREAKER_RESET_TIMEOUT", 30*time.Second)

	// SpiceDB Reconciler Defaults - safety net for PostgreSQL↔SpiceDB consistency
	viper.SetDefault("SPICEDB_RECONCILER_ENABLED", true)          // Enabled by default
	viper.SetDefault("SPICEDB_RECONCILER_INTERVAL", 24*time.Hour) // Daily reconciliation

	// Graceful shutdown timeout (total; 5s drain + remainder for http.Server.Shutdown)
	viper.SetDefault("SHUTDOWN_TIMEOUT", 30*time.Second)

	// Read replica URLs — empty by default (all traffic to primary)
	viper.SetDefault("DATABASE_READ_REPLICA_URLS", []string{})

	// Product provisioning — empty by default (only static registry used)
	viper.SetDefault("PRODUCT_MIGRATIONS_PATH", "")

	// Temporal workflow orchestration — disabled by default.
	// Enable only when a Temporal server is available in the deployment.
	viper.SetDefault("TEMPORAL_ENABLED", false)
	viper.SetDefault("TEMPORAL_HOST_PORT", "temporal:7233")
	viper.SetDefault("TEMPORAL_NAMESPACE", "hexxlock-provisioning")
	viper.SetDefault("TEMPORAL_TASK_QUEUE", "provisioning-tasks")

	// APISIX Admin API — disabled by default (empty URL = route registration skipped).
	// Set APISIX_ADMIN_URL and APISIX_ADMIN_KEY to enable dynamic route registration
	// during product instance provisioning.
	viper.SetDefault("APISIX_ADMIN_URL", "")
	viper.SetDefault("APISIX_ADMIN_KEY", "")

	// Metering scraper endpoints — each has a sensible in-cluster default.
	// Defaults are FQDN-form (svc.cluster.local) because falcon-id never
	// runs in the same namespace as these dependencies; bare short-names
	// fail cross-namespace DNS resolution silently. The previous
	// `minio:9000` default produced a startup warning storm and broke
	// avatar bucket creation across every deploy until this change
	// (discovered 2026-05-01).
	viper.SetDefault("PROMETHEUS_URL", "http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090")
	viper.SetDefault("MINIO_CONSOLE_URL", "http://example-prod-console.minio-tenant.svc.cluster.local:9090")
	// MINIO_ACCESS_KEY / MINIO_SECRET_KEY have no default by design.
	// The previous defaults (`hexxlock` / `hexxlock_minio_dev_2024`) were
	// dev-only credentials that silently shipped to every environment;
	// any non-dev MinIO admin returned `SignatureDoesNotMatch (HTTP 403)`
	// which the avatar bucket bootstrap downgraded to a startup warning,
	// so the breakage was invisible until a user attempted upload (live
	// since at least 2026-05-01). Empty string here means viper.Get*
	// returns "" unless the chart projects the env var via
	// ExternalSecret — fail-closed.
	viper.SetDefault("MINIO_ACCESS_KEY", "")
	viper.SetDefault("MINIO_SECRET_KEY", "")
	viper.SetDefault("MINIO_ENDPOINT", "minio.minio-tenant.svc.cluster.local:80")
	viper.SetDefault("MINIO_EXTERNAL_ENDPOINT", "localhost:9000")
	viper.SetDefault("MINIO_BUCKET", "hexxlock-crm")
	viper.SetDefault("APISIX_METRICS_URL", "http://apisix:9091")

	// Bot / Fraud Detection
	viper.SetDefault("BOT_DETECTION_ENABLED", true)
	viper.SetDefault("BOT_DETECTION_THRESHOLD", 0.7)
	viper.SetDefault("BOT_DETECTION_CHALLENGE_THRESHOLD", 0.4)

	// Tenant reverse projection (ADR 0029 Phase 1a).
	// Default true — must be enabled before Phase 1b flips authoritative writes.
	// Ops kill-switch: set TENANT_PROJECTION_ENABLED=false without redeploying.
	viper.SetDefault("TENANT_PROJECTION_ENABLED", true)
	viper.SetDefault("ENTITLEMENT_SYNC_ENABLED", true)
	viper.SetDefault("MODULE_ACCESS_RECONCILE_ON_STARTUP", true)
	viper.SetDefault("ACMEAPP_GRANT_SYNC_ON_STARTUP", true)
	viper.SetDefault("DEVELOPER_KEYS_ENABLED", false)
	viper.SetDefault("DEVELOPER_KEYS_AUDIENCE", "https://api.example.com")
	viper.SetDefault("DEVELOPER_KEYS_TOKEN_TTL", 600*time.Second)
	viper.SetDefault("TENANT_STATUS_ENABLED", true)
	viper.SetDefault("OPS_STRICT_PLATFORM_ROLES", false)
	viper.SetDefault("OPS_AUDIT_CONSUMER_ENABLED", false)
	viper.SetDefault("OPS_STANDING_ADMIN_DIRECT", false)
	viper.SetDefault("TENANT_MANAGEMENT_INTERNAL_URL", "http://hexxlock-platform-tenant-management.example-platform.svc.cluster.local:80")
	viper.SetDefault("SUBSCRIPTION_MANAGEMENT_INTERNAL_URL", "http://subscription-management.example-platform.svc.cluster.local:8040")
	// Outbound OAuth (ADR 0029 follow-up G) — empty by default; production
	// overlay sets these via the falcon-id-oauth ServiceClientClaim →
	// ExternalSecret pipeline.
	viper.SetDefault("SERVICE_CLIENT_ID", "")
	viper.SetDefault("SERVICE_CLIENT_SECRET", "")
	viper.SetDefault("IAM_SERVICE_URL", "")

	// Seat-quota enforcement (feat/seat-quota-enforcement).
	viper.SetDefault("QUOTA_SERVICE_URL", "http://quota-service.example-platform.svc.cluster.local:8013")
	viper.SetDefault("QUOTA_ENFORCEMENT_ENABLED", true)
	viper.SetDefault("QUOTA_CHECK_FAIL_OPEN", false)
	viper.SetDefault("SEAT_QUOTA_RECONCILER_ENABLED", true)
	viper.SetDefault("SEAT_QUOTA_RECONCILER_INTERVAL", time.Hour)
	viper.SetDefault("EMPLOYEE_ACCESS_EXPIRY_INTERVAL", 15*time.Minute)

	viper.AutomaticEnv()

	config := &Config{}

	config.Environment = viper.GetString("ENVIRONMENT")
	config.ServiceName = viper.GetString("SERVICE_NAME")
	config.ServicePort = viper.GetString("SERVICE_PORT")
	config.LogLevel = viper.GetString("LOG_LEVEL")

	config.DatabaseURL = viper.GetString("DATABASE_URL")
	config.DatabaseHost = viper.GetString("DATABASE_HOST")
	config.DatabasePort = viper.GetInt("DATABASE_PORT")
	config.DatabaseName = viper.GetString("DATABASE_NAME")
	config.DatabaseSSLMode = viper.GetString("DATABASE_SSL_MODE")
	config.ControlPlaneDatabaseURL = viper.GetString("CONTROL_PLANE_DATABASE_URL")
	config.RedisURL = viper.GetString("REDIS_URL")
	config.RedisMaxRetries = viper.GetInt("REDIS_MAX_RETRIES")
	config.RedisRequired = viper.GetBool("REDIS_REQUIRED")
	config.RedisMinIdleConns = viper.GetInt("REDIS_MIN_IDLE_CONNS")
	config.RedisConnMaxLifetime = viper.GetDuration("REDIS_CONN_MAX_LIFETIME")
	config.RedisRateLimitEnabled = viper.GetBool("REDIS_RATE_LIMIT_ENABLED")
	config.RedisSessionCacheTTL = viper.GetDuration("REDIS_SESSION_CACHE_TTL")

	// Permission cache
	config.PermissionCacheLocalSize = viper.GetInt("PERMISSION_CACHE_LOCAL_SIZE")
	config.PermissionCacheLocalTTL = viper.GetDuration("PERMISSION_CACHE_LOCAL_TTL")
	config.PermissionCacheCheckTTL = viper.GetDuration("PERMISSION_CACHE_CHECK_TTL")
	config.PermissionCacheRoleMappingTTL = viper.GetDuration("PERMISSION_CACHE_ROLE_MAPPING_TTL")

	// Observability
	config.OTLPEndpoint = viper.GetString("OTLP_ENDPOINT")
	config.TracingSamplingRate = viper.GetFloat64("TRACING_SAMPLING_RATE")
	config.MetricsEnabled = viper.GetBool("METRICS_ENABLED")

	// Encryption
	config.EncryptionKey = viper.GetString("ENCRYPTION_KEY")
	config.EmailHashKey = viper.GetString("EMAIL_HASH_KEY")

	// Token hash salt
	config.TokenHashSalt = viper.GetString("TOKEN_HASH_SALT")

	config.JWTSecret = viper.GetString("JWT_SECRET")
	config.JWTIssuer = viper.GetString("JWT_ISSUER")
	config.AccessTokenExpiry = viper.GetDuration("ACCESS_TOKEN_EXPIRY")
	config.SessionExpiry = viper.GetDuration("SESSION_EXPIRY")
	config.SigningKeyPublishDelay = viper.GetDuration("SIGNING_KEY_PUBLISH_DELAY")
	config.SigningKeyReloadInterval = viper.GetDuration("SIGNING_KEY_RELOAD_INTERVAL")
	config.SigningKeyRetireAfter = viper.GetDuration("SIGNING_KEY_RETIRE_AFTER")
	config.JWKSMaxAge = viper.GetDuration("JWKS_MAX_AGE")
	config.SessionIdleTimeout = viper.GetDuration("SESSION_IDLE_TIMEOUT")
	// Remember-me TTL bifurcation. SessionTTLDefault falls back to
	// SessionExpiry when SESSION_TTL_DEFAULT is unset — this preserves
	// pre-feature behaviour (no operator action required to keep the
	// existing short TTL after upgrade). SessionTTLRememberMe defaults
	// to 720h (30d) via viper.SetDefault below.
	config.SessionTTLDefault = viper.GetDuration("SESSION_TTL_DEFAULT")
	if config.SessionTTLDefault == 0 {
		config.SessionTTLDefault = config.SessionExpiry
	}
	config.SessionTTLRememberMe = viper.GetDuration("SESSION_TTL_REMEMBER_ME")
	config.DPoPEnabled = viper.GetBool("DPOP_ENABLED")
	config.NativeAppSchemeDomains = envStringSlice("NATIVE_APP_SCHEME_DOMAINS")
	config.TenantExchangePublicClientIDs = envStringSlice("TENANT_EXCHANGE_PUBLIC_CLIENT_IDS")
	config.OAuthTokenPerUserClientIDs = envStringSlice("OAUTH_TOKEN_PER_USER_CLIENT_IDS")
	if len(config.OAuthTokenPerUserClientIDs) == 0 {
		config.OAuthTokenPerUserClientIDs = []string{"acmeapp-bff"}
	}
	config.CAEPOutboxEnabled = viper.GetBool("CAEP_OUTBOX_ENABLED")
	config.EmailOutboxEnabled = viper.GetBool("EMAIL_OUTBOX_ENABLED")

	// Trusted device settings
	config.TrustedDeviceSessionExpiry = viper.GetDuration("TRUSTED_DEVICE_SESSION_EXPIRY")
	config.TrustDurationDays = viper.GetInt("TRUST_DURATION_DAYS")

	// AD Sync
	config.ADSyncEnabled = viper.GetBool("AD_SYNC_ENABLED")
	config.ADSyncDefaultInterval = viper.GetDuration("AD_SYNC_DEFAULT_INTERVAL")
	config.ADSyncBatchSize = viper.GetInt("AD_SYNC_BATCH_SIZE")
	config.ADSyncHistoryRetention = viper.GetDuration("AD_SYNC_HISTORY_RETENTION")

	config.PasswordMinLength = viper.GetInt("PASSWORD_MIN_LENGTH")
	config.PasswordRequireUpper = viper.GetBool("PASSWORD_REQUIRE_UPPER")
	config.PasswordRequireLower = viper.GetBool("PASSWORD_REQUIRE_LOWER")
	config.PasswordRequireDigit = viper.GetBool("PASSWORD_REQUIRE_DIGIT")
	config.PasswordRequireSpecial = viper.GetBool("PASSWORD_REQUIRE_SPECIAL")
	config.PasswordBreachCheckEnabled = viper.GetBool("PASSWORD_BREACH_CHECK_ENABLED")
	config.WitnessTOTPEnabled = viper.GetBool("FALCON_WITNESS_TOTP_ENABLED")

	config.RateLimitRequests = viper.GetInt("RATE_LIMIT_REQUESTS")
	config.RateLimitWindow = viper.GetDuration("RATE_LIMIT_WINDOW")

	config.MaxLoginAttempts = viper.GetInt("MAX_LOGIN_ATTEMPTS")
	config.LockoutDuration = viper.GetDuration("LOCKOUT_DURATION")

	// SMTP
	config.SMTPHost = viper.GetString("SMTP_HOST")
	config.SMTPPort = viper.GetInt("SMTP_PORT")
	config.SMTPUsername = viper.GetString("SMTP_USERNAME")
	config.SMTPPassword = viper.GetString("SMTP_PASSWORD")
	config.SMTPFrom = viper.GetString("SMTP_FROM")
	config.SMTPFromName = viper.GetString("SMTP_FROM_NAME")
	config.SMTPUseTLS = viper.GetBool("SMTP_USE_TLS")
	config.SMTPInsecureSkipVerify = viper.GetBool("SMTP_INSECURE_SKIP_VERIFY")

	// MFA
	config.MFAIssuer = viper.GetString("MFA_ISSUER")
	config.MFATOTPDigits = viper.GetInt("MFA_TOTP_DIGITS")
	config.MFATOTPPeriod = viper.GetInt("MFA_TOTP_PERIOD")
	config.MFAEmailCodeTTL = viper.GetDuration("MFA_EMAIL_CODE_TTL")
	config.MFABackupCodeCount = viper.GetInt("MFA_BACKUP_CODE_COUNT")

	// Frontend
	config.FrontendURL = viper.GetString("FRONTEND_URL")
	config.ConsumerEmailDomain = viper.GetString("CONSUMER_EMAIL_DOMAIN")
	if config.ConsumerEmailDomain == "" {
		config.ConsumerEmailDomain = "downstream.com"
	}
	config.TenantApexDomain = viper.GetString("TENANT_APEX_DOMAIN")
	if config.TenantApexDomain == "" {
		config.TenantApexDomain = "example.com"
	}
	config.SignupDefaultPlanCode = viper.GetString("SIGNUP_DEFAULT_PLAN_CODE")
	if config.SignupDefaultPlanCode == "" {
		config.SignupDefaultPlanCode = "starter"
	}
	config.SignupDefaultAppURL = strings.TrimSpace(viper.GetString("SIGNUP_DEFAULT_APP_URL"))

	// ABAC/OPA
	config.UseABAC = viper.GetBool("USE_ABAC")
	config.OPAPolicyPath = viper.GetString("OPA_POLICY_PATH")
	config.OPADecisionPath = viper.GetString("OPA_DECISION_PATH")
	config.ABACCacheTTL = viper.GetDuration("ABAC_CACHE_TTL")
	config.ABACFallbackRBAC = viper.GetBool("ABAC_FALLBACK_RBAC")

	// Internal Service-to-Service Authentication
	config.InternalAPIKey = viper.GetString("INTERNAL_API_KEY")

	// Realm Configuration
	config.RealmEnabled = viper.GetBool("REALM_ENABLED")
	config.RealmDefaultSlug = viper.GetString("REALM_DEFAULT_SLUG")
	config.RealmSubdomainEnabled = viper.GetBool("REALM_SUBDOMAIN_ENABLED")
	config.RealmHeaderEnabled = viper.GetBool("REALM_HEADER_ENABLED")
	config.RealmURLPrefixEnabled = viper.GetBool("REALM_URL_PREFIX_ENABLED")

	// SpiceDB Configuration
	config.SpiceDBEnabled = viper.GetBool("SPICEDB_ENABLED")
	config.SpiceDBWatchEnabled = viper.GetBool("SPICEDB_WATCH_ENABLED")
	config.SpiceDBEndpoint = viper.GetString("SPICEDB_ENDPOINT")
	config.SpiceDBToken = viper.GetString("SPICEDB_TOKEN")
	config.SpiceDBInsecure = viper.GetBool("SPICEDB_INSECURE")
	config.SpiceDBDualWriteEnabled = viper.GetBool("SPICEDB_DUAL_WRITE_ENABLED")
	config.SpiceDBCacheTTL = viper.GetDuration("SPICEDB_CACHE_TTL")
	config.SpiceDBMaxConcurrentChecks = viper.GetInt("SPICEDB_MAX_CONCURRENT_CHECKS")
	config.SpiceDBTokenV2Enabled = viper.GetBool("SPICEDB_TOKEN_V2_ENABLED")
	config.SpiceDBTokenV2Percentage = viper.GetInt("SPICEDB_TOKEN_V2_PERCENTAGE")

	// Trusted Proxies
	// viper.GetStringSlice doesn't split comma-separated env-var values into
	// multiple slice elements (it only does that for YAML/JSON config). Use
	// our env-aware helper that always re-splits.
	config.TrustedProxies = envStringSlice("TRUSTED_PROXIES")

	// SAML SP Configuration
	config.SAMLSPBaseURL = viper.GetString("SAML_SP_BASE_URL")
	config.SAMLSPClockSkew = viper.GetDuration("SAML_SP_CLOCK_SKEW")
	config.SAMLMetadataRefreshEnabled = viper.GetBool("SAML_METADATA_REFRESH_ENABLED")
	config.SAMLMetadataRefreshInterval = viper.GetDuration("SAML_METADATA_REFRESH_INTERVAL")

	// WebAuthn / Passkey Configuration
	config.WebAuthnRPID = viper.GetString("WEBAUTHN_RP_ID")
	config.WebAuthnRPDisplayName = viper.GetString("WEBAUTHN_RP_DISPLAY_NAME")
	// viper.GetStringSlice doesn't split comma-separated env-var values
	// (single-element slice with the joined string), which makes
	// go-webauthn's `Error validating origin` fail for every legitimate
	// origin past the first. Use envStringSlice so the comma-separated
	// env var actually becomes the multi-element []string{} the library
	// expects.
	config.WebAuthnRPOrigins = envStringSlice("WEBAUTHN_RP_ORIGINS")

	// Dev convenience default. Passkeys are gated on RP config being present
	// (cmd/services.go builds WebAuthnService only when RPID + origins are
	// set), so an unconfigured local stack silently has passkeys disabled and
	// every /webauthn route 404s. Production/staging MUST set these explicitly
	// to the real domain — we never default there. In any other environment,
	// when RPID is unset, default to localhost so passkeys work in the local
	// stack with no per-launch env plumbing: RP ID "localhost" matches any
	// http://localhost:<port> origin, and the origins list covers the local
	// frontend apps (accounts is where passkeys are managed) + the gateway /
	// OAuth issuer. Any explicit WEBAUTHN_RP_* env still wins — we only fill
	// fields left empty.
	if config.WebAuthnRPID == "" &&
		config.Environment != "" &&
		config.Environment != "production" &&
		config.Environment != "staging" {
		config.WebAuthnRPID = "localhost"
		if config.WebAuthnRPDisplayName == "" {
			config.WebAuthnRPDisplayName = "HexxLock (dev)"
		}
		if len(config.WebAuthnRPOrigins) == 0 {
			// The local frontend apps live on fixed ports that aren't otherwise
			// in config, so they're listed explicitly (accounts is where
			// passkeys are managed; login is where they're used). FRONTEND_URL
			// is unioned in (deduped) so a custom local config is also covered.
			origins := []string{
				"http://localhost:3002",  // accounts portal (passkey management)
				"http://localhost:3015",  // login app
				"http://localhost:3010",  // acmeweb
				"http://localhost:18090", // local gateway / OAuth issuer
			}
			if u := strings.TrimRight(strings.TrimSpace(config.FrontendURL), "/"); u != "" {
				seen := false
				for _, o := range origins {
					if o == u {
						seen = true
						break
					}
				}
				if !seen {
					origins = append(origins, u)
				}
			}
			config.WebAuthnRPOrigins = origins
		}
	}

	// Apple Sign In Configuration
	config.AppleTeamID = viper.GetString("APPLE_TEAM_ID")
	config.AppleKeyID = viper.GetString("APPLE_KEY_ID")
	config.AppleServicesID = viper.GetString("APPLE_SERVICES_ID")
	config.ApplePrivateKey = viper.GetString("APPLE_PRIVATE_KEY")

	// Asymmetric JWT Signing
	config.JWTSigningAlgorithm = viper.GetString("JWT_SIGNING_ALGORITHM")
	config.JWTKeyRotationInterval = viper.GetDuration("JWT_KEY_ROTATION_INTERVAL")
	config.JWTHMACFallbackEnabled = viper.GetBool("JWT_HMAC_FALLBACK_ENABLED")
	config.JWTClockSkewLeeway = viper.GetDuration("JWT_CLOCK_SKEW_LEEWAY")

	// DDIL degraded-mode (Phase 3)
	config.DDILOfflineAuthzEnabled = viper.GetBool("DDIL_OFFLINE_AUTHZ")
	config.DDILOfflineAuthzStandardBudget = viper.GetDuration("DDIL_OFFLINE_AUTHZ_STANDARD_BUDGET")
	config.DDILOfflineAuthzPrivilegedBudget = viper.GetDuration("DDIL_OFFLINE_AUTHZ_PRIVILEGED_BUDGET")
	// viper.GetStringSlice doesn't split comma-separated env values; use the
	// env-aware splitter (falls back to the default string set above when unset).
	config.DDILOfflineAuthzPrivilegedModules = envStringSlice("DDIL_OFFLINE_AUTHZ_PRIVILEGED_MODULES")
	config.DDILOfflineAuthzClockLeeway = viper.GetDuration("DDIL_OFFLINE_AUTHZ_CLOCK_LEEWAY")

	// DDIL resilience (P3.11)
	config.SpiceDBResilienceEnabled = viper.GetBool("SPICEDB_RESILIENCE_ENABLED")
	config.SpiceDBBreakerFailureThreshold = viper.GetInt("SPICEDB_BREAKER_FAILURE_THRESHOLD")
	config.SpiceDBBreakerResetTimeout = viper.GetDuration("SPICEDB_BREAKER_RESET_TIMEOUT")
	config.SpiceDBCallTimeout = viper.GetDuration("SPICEDB_CALL_TIMEOUT")
	config.SpiceDBMaxAttempts = viper.GetInt("SPICEDB_MAX_ATTEMPTS")
	config.HIBPResilienceEnabled = viper.GetBool("HIBP_RESILIENCE_ENABLED")
	config.HIBPBreakerFailureThreshold = viper.GetInt("HIBP_BREAKER_FAILURE_THRESHOLD")
	config.HIBPBreakerResetTimeout = viper.GetDuration("HIBP_BREAKER_RESET_TIMEOUT")
	config.LDAPResilienceEnabled = viper.GetBool("LDAP_RESILIENCE_ENABLED")
	config.LDAPBreakerFailureThreshold = viper.GetInt("LDAP_BREAKER_FAILURE_THRESHOLD")
	config.LDAPBreakerResetTimeout = viper.GetDuration("LDAP_BREAKER_RESET_TIMEOUT")

	// SpiceDB Reconciler Configuration
	config.SpiceDBReconcilerEnabled = viper.GetBool("SPICEDB_RECONCILER_ENABLED")
	config.SpiceDBReconcilerInterval = viper.GetDuration("SPICEDB_RECONCILER_INTERVAL")

	// Graceful Shutdown
	config.ShutdownTimeout = viper.GetDuration("SHUTDOWN_TIMEOUT")

	// Read Replica URLs (optional; empty slice means all traffic goes to primary)
	config.DatabaseReadReplicaURLs = envStringSlice("DATABASE_READ_REPLICA_URLS")

	// Product Provisioning
	config.ProductMigrationsPath = viper.GetString("PRODUCT_MIGRATIONS_PATH")
	config.LifecycleCallbackAllowlistRaw = viper.GetString("LIFECYCLE_CALLBACK_ALLOWLIST")
	// Pre-parse the allowlist
	if config.LifecycleCallbackAllowlistRaw != "" {
		for _, prefix := range strings.Split(config.LifecycleCallbackAllowlistRaw, ",") {
			trimmed := strings.TrimSpace(prefix)
			if trimmed != "" {
				config.lifecycleCallbackAllowlistParsed = append(config.lifecycleCallbackAllowlistParsed, trimmed)
			}
		}
	}

	// Temporal Workflow Orchestration
	config.TemporalEnabled = viper.GetBool("TEMPORAL_ENABLED")
	config.TemporalHostPort = viper.GetString("TEMPORAL_HOST_PORT")
	config.TemporalNamespace = viper.GetString("TEMPORAL_NAMESPACE")
	config.TemporalTaskQueue = viper.GetString("TEMPORAL_TASK_QUEUE")

	// APISIX Admin API
	config.APISIXAdminURL = viper.GetString("APISIX_ADMIN_URL")
	config.APISIXAdminKey = viper.GetString("APISIX_ADMIN_KEY")

	// Metering scraper endpoints
	config.PrometheusURL = viper.GetString("PROMETHEUS_URL")
	config.MinIOConsoleURL = viper.GetString("MINIO_CONSOLE_URL")
	config.MinIOAccessKey = viper.GetString("MINIO_ACCESS_KEY")
	config.MinIOSecretKey = viper.GetString("MINIO_SECRET_KEY")
	config.MinIOEndpoint = viper.GetString("MINIO_ENDPOINT")
	config.MinIOExternalEndpoint = viper.GetString("MINIO_EXTERNAL_ENDPOINT")
	config.MinIOBucket = viper.GetString("MINIO_BUCKET")
	config.APISIXMetricsURL = viper.GetString("APISIX_METRICS_URL")

	// Kafka
	config.KafkaBrokers = viper.GetString("KAFKA_BROKERS")
	config.KafkaGroupID = viper.GetString("KAFKA_GROUP_ID")
	if config.KafkaGroupID == "" {
		config.KafkaGroupID = "falcon-id-provisioning"
	}

	// Bot / Fraud Detection
	config.BotDetectionEnabled = viper.GetBool("BOT_DETECTION_ENABLED")
	config.BotDetectionThreshold = viper.GetFloat64("BOT_DETECTION_THRESHOLD")
	config.BotDetectionChallengeThreshold = viper.GetFloat64("BOT_DETECTION_CHALLENGE_THRESHOLD")

	// Tenant reverse projection (ADR 0029 Phase 1a).
	config.TenantProjectionEnabled = viper.GetBool("TENANT_PROJECTION_ENABLED")
	config.EntitlementSyncEnabled = viper.GetBool("ENTITLEMENT_SYNC_ENABLED")
	config.ModuleAccessReconcileOnStartup = viper.GetBool("MODULE_ACCESS_RECONCILE_ON_STARTUP")
	config.AcmeAppGrantSyncOnStartup = viper.GetBool("ACMEAPP_GRANT_SYNC_ON_STARTUP")
	config.DeveloperKeysEnabled = viper.GetBool("DEVELOPER_KEYS_ENABLED")
	config.DeveloperKeysTenantAllowlist = envStringSlice("DEVELOPER_KEYS_TENANT_ALLOWLIST")
	config.DeveloperKeysPepper = viper.GetString("DEVELOPER_KEYS_PEPPER")
	config.DeveloperKeysPeppers = parseVersionedSecrets(viper.GetString("DEVELOPER_KEYS_PEPPERS"))
	config.DeveloperKeysPepperCurrent = viper.GetString("DEVELOPER_KEYS_PEPPER_CURRENT")
	config.DeveloperKeysAudience = viper.GetString("DEVELOPER_KEYS_AUDIENCE")
	config.DeveloperKeysTokenTTL = viper.GetDuration("DEVELOPER_KEYS_TOKEN_TTL")
	config.BusinessInternalURL = viper.GetString("BUSINESS_INTERNAL_URL")
	config.TenantStatusEnabled = viper.GetBool("TENANT_STATUS_ENABLED")
	config.OpsStrictPlatformRoles = viper.GetBool("OPS_STRICT_PLATFORM_ROLES")
	config.OpsBreakGlassEmail = strings.TrimSpace(viper.GetString("OPS_BREAK_GLASS_EMAIL"))
	config.OpsAuditConsumerEnabled = viper.GetBool("OPS_AUDIT_CONSUMER_ENABLED")
	config.OpsStandingAdminDirect = viper.GetBool("OPS_STANDING_ADMIN_DIRECT")
	config.OpsOperatorExchangeClientIDs = envStringSlice("OPS_OPERATOR_EXCHANGE_CLIENT_IDS")
	config.TenantManagementInternalURL = viper.GetString("TENANT_MANAGEMENT_INTERNAL_URL")
	config.SubscriptionManagementInternalURL = viper.GetString("SUBSCRIPTION_MANAGEMENT_INTERNAL_URL")

	// Outbound OAuth client_credentials for cross-service calls (ADR 0029 G).
	config.ServiceClientID = viper.GetString("SERVICE_CLIENT_ID")
	config.ServiceClientSecret = viper.GetString("SERVICE_CLIENT_SECRET")
	config.IAMServiceURL = viper.GetString("IAM_SERVICE_URL")

	config.QuotaServiceURL = viper.GetString("QUOTA_SERVICE_URL")
	config.QuotaEnforcementEnabled = viper.GetBool("QUOTA_ENFORCEMENT_ENABLED")
	config.QuotaCheckFailOpen = viper.GetBool("QUOTA_CHECK_FAIL_OPEN")
	config.SeatQuotaReconcilerEnabled = viper.GetBool("SEAT_QUOTA_RECONCILER_ENABLED")
	config.SeatQuotaReconcilerInterval = viper.GetDuration("SEAT_QUOTA_RECONCILER_INTERVAL")
	config.EmployeeAccessExpiryInterval = viper.GetDuration("EMPLOYEE_ACCESS_EXPIRY_INTERVAL")

	// SECURITY: Validate configuration before returning
	if err := validateSecurityConfig(config); err != nil {
		return nil, fmt.Errorf("LoadConfig: %w", err)
	}

	return config, nil
}

// validateSecurityConfig validates that all required security configuration is present.
// This function enforces secure defaults and prevents startup with insecure configuration.
func validateSecurityConfig(config *Config) error {
	// SECURITY: Environment must be explicitly set
	if config.Environment == "" {
		return fmt.Errorf("ENVIRONMENT must be explicitly set (development, staging, or production)")
	}

	isProduction := config.Environment == "production" || config.Environment == "staging"

	// SECURITY: Database URLs are always required
	if config.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if config.ControlPlaneDatabaseURL == "" {
		return fmt.Errorf("CONTROL_PLANE_DATABASE_URL is required")
	}
	if config.RedisURL == "" {
		return fmt.Errorf("REDIS_URL is required")
	}

	// SECURITY: Critical secrets must be configured in production
	if isProduction {
		return validateProductionSecrets(config)
	}
	return applyDevSecretDefaults(config)
}

// validateProductionSecrets enforces that all required secrets are set and meet minimum strength
// requirements in production/staging environments.
func validateProductionSecrets(config *Config) error {
	if config.JWTSecret == "" {
		return fmt.Errorf("JWT_SECRET is required in %s environment", config.Environment)
	}
	if err := validateJWTSecret(config.JWTSecret); err != nil {
		return fmt.Errorf("JWT_SECRET validation failed in %s environment: %w", config.Environment, err)
	}
	if config.EncryptionKey == "" {
		return fmt.Errorf("ENCRYPTION_KEY is required in %s environment", config.Environment)
	}
	if len(config.EncryptionKey) != 32 {
		return fmt.Errorf("ENCRYPTION_KEY must be exactly 32 bytes in %s environment", config.Environment)
	}
	if config.TokenHashSalt == "" {
		return fmt.Errorf("TOKEN_HASH_SALT is required in %s environment", config.Environment)
	}
	if config.InternalAPIKey == "" {
		return fmt.Errorf("INTERNAL_API_KEY is required in %s environment", config.Environment)
	}
	if len(config.InternalAPIKey) < 32 {
		return fmt.Errorf("INTERNAL_API_KEY must be at least 32 characters in %s environment", config.Environment)
	}
	// SECURITY: TRUSTED_PROXIES must be explicitly configured in production
	// Rate limiting relies on correct client IP extraction, which requires trusted proxy configuration
	if len(config.TrustedProxies) == 0 {
		return fmt.Errorf("TRUSTED_PROXIES is required in %s environment for secure rate limiting (e.g., TRUSTED_PROXIES=10.0.30.20,10.0.30.30)", config.Environment)
	}
	// SECURITY: SpiceDB must use TLS in production/staging
	if config.SpiceDBEnabled && config.SpiceDBInsecure {
		return fmt.Errorf("SPICEDB_INSECURE must be false in %s environment when SpiceDB is enabled", config.Environment)
	}
	return nil
}

// applyDevSecretDefaults auto-generates missing secrets for development environments, printing warnings.
func applyDevSecretDefaults(config *Config) error {
	// SECURITY: JWT_SECRET requires explicit opt-in for auto-generation in development
	if config.JWTSecret == "" {
		allowAutoSecret := os.Getenv("ALLOW_AUTO_JWT_SECRET") == "true"
		if allowAutoSecret {
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "╔═══════════════════════════════════════════════════════════════╗\n")
			fmt.Fprintf(os.Stderr, "║  WARNING: AUTO-GENERATING JWT_SECRET FOR DEVELOPMENT         ║\n")
			fmt.Fprintf(os.Stderr, "║                                                               ║\n")
			fmt.Fprintf(os.Stderr, "║  • Tokens will NOT persist across service restarts           ║\n")
			fmt.Fprintf(os.Stderr, "║  • All users will be logged out on restart                   ║\n")
			fmt.Fprintf(os.Stderr, "║  • DO NOT use auto-generated secrets in production           ║\n")
			fmt.Fprintf(os.Stderr, "║                                                               ║\n")
			fmt.Fprintf(os.Stderr, "║  Set JWT_SECRET explicitly or disable ALLOW_AUTO_JWT_SECRET  ║\n")
			fmt.Fprintf(os.Stderr, "╚═══════════════════════════════════════════════════════════════╝\n")
			fmt.Fprintf(os.Stderr, "\n")
			var err error
			config.JWTSecret, err = generateSecureDevSecret()
			if err != nil {
				return fmt.Errorf("failed to generate JWT_SECRET: %w", err)
			}
		} else {
			return fmt.Errorf("JWT_SECRET is required. Set JWT_SECRET environment variable or set ALLOW_AUTO_JWT_SECRET=true for development (not recommended)")
		}
	}
	// ENCRYPTION_KEY and TOKEN_HASH_SALT can be auto-generated with warning
	if config.EncryptionKey == "" {
		fmt.Fprintf(os.Stderr, "WARNING: ENCRYPTION_KEY not set - generating secure random value (encrypted data will not persist across restarts)\n")
		encKey, err := generateSecureDevSecret()
		if err != nil {
			return fmt.Errorf("failed to generate ENCRYPTION_KEY: %w", err)
		}
		if len(encKey) > 32 {
			config.EncryptionKey = encKey[:32]
		} else {
			config.EncryptionKey = encKey
		}
	}
	if config.TokenHashSalt == "" {
		fmt.Fprintf(os.Stderr, "WARNING: TOKEN_HASH_SALT not set - generating secure random value\n")
		var err error
		config.TokenHashSalt, err = generateSecureDevSecret()
		if err != nil {
			return fmt.Errorf("failed to generate TOKEN_HASH_SALT: %w", err)
		}
	}
	return nil
}

// generateSecureDevSecret generates a cryptographically secure random secret for development only.
// SECURITY: Uses crypto/rand for secure random generation with minimum 32 bytes of entropy.
// This ensures development can still work without explicit configuration,
// but the secrets are different on each startup (sessions won't persist).
func generateSecureDevSecret() (string, error) {
	// Generate 32 bytes (256 bits) of secure random data
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate secure random bytes: %w", err)
	}

	// Encode to base64 for use as a string secret (results in 44 characters)
	return base64.StdEncoding.EncodeToString(randomBytes), nil
}

// validateJWTSecret validates that the JWT secret meets security requirements.
// Requirements:
// - Minimum 32 characters length
// - Minimum Shannon entropy of 3.5 bits per character
// - Not a common weak pattern
// - No sequential or keyboard patterns
func validateJWTSecret(secret string) error {
	if len(secret) < 32 {
		return fmt.Errorf("must be at least 32 characters (got %d)", len(secret))
	}

	// Calculate Shannon entropy
	entropy := calculateShannonEntropy(secret)
	if entropy < 3.5 {
		return fmt.Errorf("insufficient entropy: Shannon entropy %.2f bits/char is below minimum 3.5", entropy)
	}

	// Check for common weak patterns
	weakPatterns := []string{
		"12345678901234567890123456789012",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"secret_key_change_me_in_production",
		"your-256-bit-secret",
		"super_secret_key_please_change_in_prod",
		"development_jwt_secret_not_for_prod",
		"changeme",
		"password",
	}
	lowerSecret := strings.ToLower(secret)
	for _, pattern := range weakPatterns {
		if strings.Contains(lowerSecret, pattern) {
			return fmt.Errorf("detected common weak secret pattern")
		}
	}

	// Check for sequential patterns (e.g., "abcdefgh", "12345678")
	if hasSequentialPattern(secret, 6) {
		return fmt.Errorf("detected sequential character pattern")
	}

	// Check for keyboard patterns (e.g., "qwerty", "asdfgh")
	if hasKeyboardPattern(secret) {
		return fmt.Errorf("detected keyboard pattern")
	}

	// Check for repeated substrings
	if hasRepeatedSubstring(secret, 4) {
		return fmt.Errorf("detected repeated substring pattern")
	}

	return nil
}

// calculateShannonEntropy calculates the Shannon entropy (bits per character) of a string.
// Higher entropy indicates more randomness/unpredictability.
func calculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}

	// Calculate entropy: -sum(p * log2(p))
	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * log2(p)
		}
	}

	return entropy
}

// log2 calculates log base 2
func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Using natural log: log2(x) = ln(x) / ln(2)
	return ln(x) / 0.6931471805599453 // ln(2)
}

// ln approximates natural logarithm using Taylor series
func ln(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// For x close to 1, use Taylor series
	// For larger/smaller x, normalize to [0.5, 2] range
	result := 0.0
	for x > 2.0 {
		x /= 2.718281828459045 // e
		result += 1.0
	}
	for x < 0.5 {
		x *= 2.718281828459045
		result -= 1.0
	}
	// Taylor series for ln(1+y) where y = x-1
	y := x - 1.0
	term := y
	for i := 1; i <= 50; i++ {
		result += term / float64(i)
		term *= -y
	}
	return result
}

// hasSequentialPattern checks if the string contains sequential characters
func hasSequentialPattern(s string, minLength int) bool {
	if len(s) < minLength {
		return false
	}

	consecutive := 1
	ascending := 1
	descending := 1
	runes := []rune(s)

	for i := 1; i < len(runes); i++ {
		diff := int(runes[i]) - int(runes[i-1])

		switch diff {
		case 1:
			ascending++
			descending = 1
		case -1:
			descending++
			ascending = 1
		case 0:
			consecutive++
		default:
			ascending = 1
			descending = 1
			consecutive = 1
		}

		if ascending >= minLength || descending >= minLength || consecutive >= minLength {
			return true
		}
	}

	return false
}

// hasKeyboardPattern checks for common keyboard row patterns
func hasKeyboardPattern(s string) bool {
	keyboardPatterns := []string{
		"qwerty", "qwertz", "azerty",
		"asdfgh", "zxcvbn",
		"qazwsx", "1qaz2wsx",
		"!@#$%^", "123qwe",
		"qweasd", "ytrewq",
	}

	lowerS := strings.ToLower(s)
	for _, pattern := range keyboardPatterns {
		if strings.Contains(lowerS, pattern) {
			return true
		}
	}

	return false
}

// LifecycleCallbackAllowlist returns the parsed list of allowed URL prefixes
// for product lifecycle callbacks (SSRF prevention).
func (c *Config) LifecycleCallbackAllowlist() []string {
	return c.lifecycleCallbackAllowlistParsed
}

// hasRepeatedSubstring checks if any substring of minLength or more is repeated
func hasRepeatedSubstring(s string, minLength int) bool {
	if len(s) < minLength*2 {
		return false
	}

	// Check for repeated substrings
	for length := minLength; length <= len(s)/2; length++ {
		seen := make(map[string]int)
		for i := 0; i <= len(s)-length; i++ {
			substr := s[i : i+length]
			seen[substr]++
			if seen[substr] >= 2 {
				return true
			}
		}
	}

	return false
}
