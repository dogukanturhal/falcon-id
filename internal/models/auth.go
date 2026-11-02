// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// LoginRequest for authentication
type LoginRequest struct {
	Username           string `json:"username" binding:"required,min=1,max=255"`
	Password           string `json:"password" binding:"required,min=1,max=1024"`
	TenantID           string `json:"tenant_id" binding:"omitempty,max=36"`           // Tenant UUID (legacy, prefer tenant_slug)
	TenantSlug         string `json:"tenant_slug" binding:"omitempty,max=100"`        // Tenant slug for resolution (e.g., "bilenlegez")
	RealmID            string `json:"realm_id,omitempty" binding:"omitempty,max=255"` // Realm context for multi-realm authentication
	MFACode            string `json:"mfa_code,omitempty" binding:"omitempty,max=20"`
	PreferredMFAMethod string `json:"preferred_mfa_method,omitempty" binding:"omitempty,oneof=totp email"` // Used when switching MFA methods during login
	RememberMe         bool   `json:"remember_me,omitempty"`                                               // Trust this device for extended session
	DeviceID           string `json:"device_id,omitempty" binding:"omitempty,max=255"`                     // Client-generated device identifier
	ClientID           string `json:"client_id,omitempty" binding:"omitempty,max=255"`                     // OAuth client_id for audience-scoped tokens
	IdentityProviderID string `json:"identity_provider_id,omitempty" binding:"omitempty,max=36"`           // Explicit IdP for LDAP login
}

// LoginResponse returned after successful authentication
type LoginResponse struct {
	AccessToken  string        `json:"access_token,omitempty"`
	RefreshToken string        `json:"refresh_token,omitempty"`
	TokenType    string        `json:"token_type,omitempty"`
	ExpiresIn    int64         `json:"expires_in,omitempty"`
	User         *UserResponse `json:"user,omitempty"`
	// Realm context fields
	RealmID   string `json:"realm_id,omitempty"`   // The realm this session belongs to
	RealmSlug string `json:"realm_slug,omitempty"` // URL-safe realm identifier
	RealmType string `json:"realm_type,omitempty"` // platform, enterprise, shared, partner, sandbox
	// MFA Challenge fields (returned when MFA is required)
	RequiresMFA         bool     `json:"requires_mfa,omitempty"`
	MFAMethod           string   `json:"mfa_method,omitempty"`            // Preferred/selected method: "totp" or "email"
	AvailableMFAMethods []string `json:"available_mfa_methods,omitempty"` // List of available methods if multiple
	SessionID           string   `json:"session_id,omitempty"`            // Temporary session for MFA verification
	MaskedEmail         string   `json:"masked_email,omitempty"`
	MFAExpiresIn        int64    `json:"mfa_expires_in,omitempty"`
	ResendAfterSeconds  int64    `json:"resend_after_seconds,omitempty"`
	// MFA Enrollment fields (returned when risk-based MFA fires for an
	// unenrolled user — registration-interrupt pattern, mirrors Microsoft
	// Entra ID Protection / Okta enrollment policies / Auth0 Require MFA
	// Enrollment / Keycloak Required Actions). Mutually exclusive with the
	// MFA challenge fields above: either the user has MFA enrolled and we
	// challenge, or they don't and we interrupt to make them enrol before
	// any session is issued. NIST SP 800-63B-4 §5.1 requires authenticators
	// to be bound before AAL2 use, so we never send an unverifiable code to
	// an unenrolled mailbox.
	RequiresMFAEnrollment bool     `json:"requires_mfa_enrollment,omitempty"`
	EnrollmentToken       string   `json:"enrollment_token,omitempty"`      // Opaque, single-use, ip+ua-bound. Only valid on /auth/mfa/enrollment/{init,verify}.
	EnrollmentMethods     []string `json:"enrollment_methods,omitempty"`    // Methods the user may enrol via on this interrupt: "totp", "email"
	EnrollmentExpiresIn   int64    `json:"enrollment_expires_in,omitempty"` // Seconds until enrollment_token expires
	// Grace-period fields (migration 235). Populated only when the realm's
	// mfa_grace_period_days > 0 AND the user is currently in their grace
	// window. When the window has expired (or never existed), the skip
	// button MUST NOT be rendered — frontend reads MFAEnrollmentCanSkip
	// as the authoritative gate. MFAEnrollmentDeadline is RFC3339-encoded
	// so the UI can render a real-time countdown.
	MFAEnrollmentDeadline       *time.Time `json:"mfa_enrollment_deadline,omitempty"`
	MFAEnrollmentSkipsRemaining int        `json:"mfa_enrollment_skips_remaining,omitempty"`
	MFAEnrollmentCanSkip        bool       `json:"mfa_enrollment_can_skip,omitempty"`
	// Risk assessment fields
	RiskScore    int      `json:"risk_score,omitempty"`
	RiskLevel    string   `json:"risk_level,omitempty"`
	RiskWarnings []string `json:"risk_warnings,omitempty"`
	IsNewDevice  bool     `json:"is_new_device,omitempty"`
	// Device trust fields
	IsTrustedDevice  bool  `json:"is_trusted_device,omitempty"`  // Whether this device is now trusted
	RefreshExpiresIn int64 `json:"refresh_expires_in,omitempty"` // Refresh token expiry in seconds
	// IsRememberMeSession is true when the login was completed with
	// `remember_me: true` and the resulting iam_sessions row was created
	// with the extended TTL (Config.SessionTTLRememberMe). The HTTP
	// handler reads this to set the falcon_idp_session cookie's
	// Max-Age to the same horizon, keeping the cookie and DB row in
	// lock-step. Omitted (false) for default short-TTL logins so the
	// cookie stays a browser-session cookie (clears on browser close).
	IsRememberMeSession bool `json:"is_remember_me_session,omitempty"`
}

// RefreshRequest for token refresh
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required,min=1,max=4096"`
}

// RefreshResponse returned after token refresh
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// LogoutRequest for logout
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token,omitempty" binding:"omitempty,max=4096"`
	AllDevices   bool   `json:"all_devices,omitempty"`
}

// PasswordChangeRequest for password change
type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,min=1,max=1024"`
	NewPassword     string `json:"new_password" binding:"required,min=8,max=1024"`
}

// PasswordResetRequest for initiating password reset
type PasswordResetRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// PasswordResetConfirmRequest for completing password reset
type PasswordResetConfirmRequest struct {
	Token       string `json:"token" binding:"required,min=1,max=512"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=1024"`
}

// MFASetupRequest for enabling MFA
type MFASetupRequest struct {
	Type string `json:"type" binding:"required,oneof=totp sms email"`
}

// MFASetupResponse returned when setting up MFA
type MFASetupResponse struct {
	Secret        string   `json:"secret,omitempty"`
	QRCode        string   `json:"qr_code,omitempty"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

// MFAVerifyRequest for verifying MFA
type MFAVerifyRequest struct {
	Code string `json:"code" binding:"required,min=1,max=20"`
}

// MFADisableRequest for disabling MFA.
//
// Both Password AND Code are OPTIONAL. The /mfa/disable* endpoints
// are gated by the RFC 9470 freshAuth middleware (see cmd/routes.go),
// which is the canonical authorization signal: the user has proven
// AAL2 freshness within the last 300s. This matches the Auth0 / Okta /
// Microsoft Entra pattern — step-up alone is sufficient for sensitive
// mutations; a second password or factor-OTP prompt is not required.
//
// Why neither field can be required:
//   - Passkey-only / social-SSO users have no local password
//   - Step-up may have completed via WebAuthn (no OTP value the
//     frontend could pass through to this call)
//   - Forcing the frontend to prompt for an additional OTP after
//     step-up = double-prompt UX disaster
//
// When either field IS supplied, the service layer still verifies it
// hard (defense-in-depth for legacy clients and ops break-glass).
//
// Compensating controls:
//   - All MFA-disable events emit SSF/CAE signals (downstream RPs
//     receive a real-time revocation hint).
//   - WORM audit log records every MFA mutation for 7 years.
//   - Email/notification on factor removal lets the legit user
//     detect anomalous disables.
type MFADisableRequest struct {
	Password string `json:"password,omitempty" binding:"omitempty,min=1,max=1024"`
	Code     string `json:"code,omitempty"     binding:"omitempty,min=1,max=20"`
}

// Claims represents JWT token claims
type Claims struct {
	Issuer                 string     `json:"iss"`
	Subject                string     `json:"sub"`
	TenantID               uuid.UUID  `json:"tenant_id"`
	UserID                 uuid.UUID  `json:"user_id"`
	Username               string     `json:"username"`
	Email                  string     `json:"email"`
	Roles                  []string   `json:"roles"`
	Permissions            []string   `json:"permissions"`
	SessionID              uuid.UUID  `json:"session_id"`
	IssuedAt               int64      `json:"iat"`
	ExpiresAt              int64      `json:"exp"`
	NotBefore              int64      `json:"nbf"`
	ImpersonatorID         *uuid.UUID `json:"impersonator_id,omitempty"`
	ImpersonationSessionID *uuid.UUID `json:"impersonation_session_id,omitempty"`

	// Realm fields for Full Realm Architecture
	RealmID   uuid.UUID `json:"realm_id"`             // The realm this user belongs to
	RealmSlug string    `json:"realm_slug,omitempty"` // URL-safe realm identifier
	RealmType string    `json:"realm_type,omitempty"` // platform, enterprise, shared, partner, sandbox
	Scope     string    `json:"scope,omitempty"`      // "tenant" for tenant users (vs "platform" for platform admins)

	// Platform admin flag - computed server-side based on tenant membership
	// SECURITY: This claim is authoritative - frontend should use this instead of checking slugs
	IsPlatformAdmin bool `json:"is_platform_admin,omitempty"`

	// CnfJKT is the DPoP proof key thumbprint extracted from the cnf.jkt claim (RFC 9449).
	// When non-empty the token is DPoP-bound and every resource request MUST include a
	// matching DPoP proof signed by the corresponding private key.
	// Middleware should copy this value to the Gin context key "token_cnf_jkt" so that
	// VerifyTokenBinding can compare it against the validated proof's JKT.
	CnfJKT string `json:"cnf_jkt,omitempty"`

	// CnfSpiffe is the SPIFFE URI extracted from the cnf.spiffe claim — a
	// RFC 7800-style sender-binding stamped on tokens issued via the RFC
	// 8693 :jwt token-exchange grant (IAP→BFF bridge). When non-empty,
	// resource servers MUST verify the incoming Linkerd `l5d-client-id`
	// header matches this value before honouring the token. Mismatch =
	// token replay attempt from a different workload; reject with 403.
	// Empty = no SPIFFE binding (token was issued by a non-mesh path or
	// a non-:jwt grant); fall back to bearer semantics.
	CnfSpiffe string `json:"cnf_spiffe,omitempty"`

	// AuthTime is the Unix timestamp of the original authentication event
	// (RFC 9470 §3 / OIDC Core §2 `auth_time`). Carried forward across
	// access-token refreshes so RequireFreshAuth gates can enforce
	// "authentication within the last N minutes" without re-querying the
	// session row. Issued by the token service at first token mint.
	AuthTime int64 `json:"auth_time,omitempty"`

	// Actor carries the RFC 8693 §4.1 `act` claim — the party that
	// requested the token exchange (typically a BFF acting on behalf of
	// the subject). Non-nil when the access token was issued via the
	// urn:ietf:params:oauth:grant-type:token-exchange grant with a JWT
	// subject_token (the IAP→BFF bridge). Receivers MUST NOT use the
	// actor for access-control decisions per §4.1 — it is audit metadata
	// only. The auth middleware emits a structured log line carrying
	// subject + actor.sub + actor.iss + actor.client_id so SIEM can
	// reconstruct the full delegation chain on every authorised request.
	Actor *TokenActor `json:"act,omitempty"`
}

// TokenActor mirrors the structure RFC 8693 §4.1 puts in the `act`
// claim. All three sub-fields are optional per the spec, but Falcon-ID
// always populates Sub + ClientID + Iss when emitting one (see
// oauth_provider_service_tokens.go:148-156).
type TokenActor struct {
	// Sub identifies the calling party (the BFF's client_id when the
	// grant was token-exchange:jwt). Receivers SHOULD log this for
	// attribution but MUST NOT use it as a sole authorisation input.
	Sub string `json:"sub,omitempty"`
	// ClientID is the OAuth client_id of the BFF that performed the
	// exchange. Same value as Sub for client_credentials-style actors;
	// emitted separately so SIEM rules can filter on client_id without
	// re-parsing sub heuristics.
	ClientID string `json:"client_id,omitempty"`
	// Iss is the issuer URL of the subject_token (e.g. Talon's IAP
	// issuer). Receivers MAY enforce a per-environment allowlist of
	// upstream IAP issuers to detect mis-routed token-exchanges.
	Iss string `json:"iss,omitempty"`
}

// IsImpersonated returns true if this token represents an impersonated session
func (c *Claims) IsImpersonated() bool {
	return c.ImpersonatorID != nil
}

// AuthMethod identifies how a CurrentUser was authenticated for the
// current request. Handlers and middleware (RequireFreshAuth, audit
// loggers, step-up gates) read this to make security-graded decisions:
// e.g. a DPoP-bound access token is stronger than a 7-day IdP session
// cookie, so high-privilege operations may insist on AuthMethodAccessToken.
type AuthMethod string

const (
	// AuthMethodAccessToken means the request carried a validated OAuth
	// access token (optionally DPoP-bound). Short-lived; sender-constrained
	// when DPoP is in use.
	AuthMethodAccessToken AuthMethod = "access_token"
	// AuthMethodIdpSession means the request was authenticated via the
	// falcon_idp_session cookie alone (no access token). Long-lived (7d
	// TTL), HttpOnly/Secure/SameSite, but NOT sender-constrained. Used by
	// first-party IdP UI calls during mid-OAuth-flow states (e.g. the
	// /auth/mfa/enrollment page calls /auth/csrf-token and /auth/mfa/status
	// before any access token is issued). Mirrors Keycloak / Auth0 / Okta
	// session-cookie semantics for first-party endpoints.
	AuthMethodIdpSession AuthMethod = "idp_session"
)

// CurrentUser represents the authenticated user context
type CurrentUser struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
	SessionID   uuid.UUID `json:"session_id"`

	// Realm fields
	RealmID   uuid.UUID `json:"realm_id"`
	RealmSlug string    `json:"realm_slug"`
	RealmType string    `json:"realm_type"`

	// Platform admin flag - computed server-side
	IsPlatformAdmin bool `json:"is_platform_admin"`

	// PlatformAuthorityVerified is set by the auth middleware ONLY when
	// OPS_STRICT_PLATFORM_ROLES is on and iam_platform_roles (an active
	// platform_admin elevation) or the break-glass account vouches for this
	// principal. It replaces the legacy tenant-role (platform_admin /
	// iam_admin) check in the platform-admin gates. Never serialised and
	// never read from a token.
	PlatformAuthorityVerified bool `json:"-"`

	// AuthMethod records how this principal was identified for the
	// current request. Set by setAuthContext (access_token path) and
	// resolveIdpSessionCookie (idp_session path). Empty for unauthenticated
	// contexts. Drives step-up / RequireFreshAuth decisions: cookie-only
	// callers cannot satisfy gates that require AuthMethodAccessToken.
	AuthMethod AuthMethod `json:"auth_method,omitempty"`

	// AuthTime is the Unix timestamp of the original authentication
	// event for the current principal — i.e. when the user typed their
	// password (and optionally MFA). RFC 9470 §3 calls this `auth_time`;
	// OIDC Core §2 makes it a standard ID-token claim. Stable across
	// access-token refreshes within a session. Powers RequireFreshAuth
	// gates on sensitive endpoints (password change, MFA disable,
	// session revocation): "the user must have authenticated within the
	// last N minutes".
	AuthTime int64 `json:"auth_time,omitempty"`
}

// IsPlatformTenant checks if the user belongs to the exampletenant platform tenant
func (u *CurrentUser) IsPlatformTenant() bool {
	return u.TenantID.String() == HexxlockInternalTenantID
}

// HasPermission checks if the user has a specific permission
func (u *CurrentUser) HasPermission(permission string) bool {
	for _, p := range u.Permissions {
		if p == permission || p == "*" {
			return true
		}
		// Check wildcard permissions (e.g., "core:users:*" matches "core:users:read")
		if matchWildcard(p, permission) {
			return true
		}
	}
	return false
}

// HasRole checks if the user has a specific role
func (u *CurrentUser) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the user has any of the specified permissions
func (u *CurrentUser) HasAnyPermission(permissions ...string) bool {
	for _, p := range permissions {
		if u.HasPermission(p) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the user has all specified permissions
func (u *CurrentUser) HasAllPermissions(permissions ...string) bool {
	for _, p := range permissions {
		if !u.HasPermission(p) {
			return false
		}
	}
	return true
}

func matchWildcard(pattern, permission string) bool {
	// Enhanced wildcard matching supporting patterns like:
	// - "core:users:*" matches "core:users:read", "core:users:write"
	// - "core:*:read" matches "core:users:read", "core:roles:read"
	// - "*:users:*" matches "core:users:read", "admin:users:write"
	// - "core:*" matches "core:users", "core:roles" (2-part patterns)

	// Split both by colon delimiter
	patternParts := strings.Split(pattern, ":")
	permParts := strings.Split(permission, ":")

	// Handle trailing wildcard with prefix matching (e.g., "core:users:*" or "core:*")
	// This allows patterns with fewer parts than the permission
	if len(patternParts) > 0 && patternParts[len(patternParts)-1] == "*" {
		// If pattern ends with *, it can match any number of additional parts
		if len(permParts) < len(patternParts)-1 {
			return false
		}
		// Check all parts before the final *
		for i := 0; i < len(patternParts)-1; i++ {
			if patternParts[i] != "*" && patternParts[i] != permParts[i] {
				return false
			}
		}
		return true
	}

	// For non-trailing wildcards, parts count must match exactly
	if len(patternParts) != len(permParts) {
		return false
	}

	// Compare each part - "*" matches any single part
	for i, p := range patternParts {
		if p != "*" && p != permParts[i] {
			return false
		}
	}
	return true
}

// AuditLog represents an audit entry
type AuditLog struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	TenantID     uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	UserID       *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	Username     *string    `json:"username,omitempty" db:"username"`
	TargetUserID *uuid.UUID `json:"target_user_id,omitempty" db:"target_user_id"`

	Action       string     `json:"action" db:"action"`
	ResourceType *string    `json:"resource_type,omitempty" db:"resource_type"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty" db:"resource_id"`

	Details   map[string]interface{} `json:"details,omitempty" db:"details"`
	IPAddress *string                `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent *string                `json:"user_agent,omitempty" db:"user_agent"`
	// CountryCode is the ISO 3166-1 alpha-2 country code Cloudflare
	// reported for the originating client (CF-IPCountry header).
	// Sanitized by middleware.ClientCountry — two upper-case A–Z
	// letters or NULL. Backed by varchar(2) column in iam_audit_log
	// (platform migration v0.232.245).
	CountryCode *string `json:"country_code,omitempty" db:"country_code"`

	Success      bool    `json:"success" db:"success"`
	ErrorMessage *string `json:"error_message,omitempty" db:"error_message"`

	// Archive and retention fields
	Archived        bool       `json:"archived" db:"archived"`
	ArchiveDate     *time.Time `json:"archive_date,omitempty" db:"archive_date"`
	ArchiveLocation *string    `json:"archive_location,omitempty" db:"archive_location"`
	CorrelationID   *uuid.UUID `json:"correlation_id,omitempty" db:"correlation_id"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// AuditArchiveMetadata represents metadata for archived audit log batches
type AuditArchiveMetadata struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	TenantID          uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ArchiveBatchID    uuid.UUID  `json:"archive_batch_id" db:"archive_batch_id"`
	StartDate         time.Time  `json:"start_date" db:"start_date"`
	EndDate           time.Time  `json:"end_date" db:"end_date"`
	RecordCount       int64      `json:"record_count" db:"record_count"`
	S3Bucket          string     `json:"s3_bucket" db:"s3_bucket"`
	S3Key             string     `json:"s3_key" db:"s3_key"`
	S3ETag            *string    `json:"s3_etag,omitempty" db:"s3_etag"`
	FileSizeBytes     *int64     `json:"file_size_bytes,omitempty" db:"file_size_bytes"`
	CompressionType   string     `json:"compression_type" db:"compression_type"`
	Encrypted         bool       `json:"encrypted" db:"encrypted"`
	ObjectLockEnabled bool       `json:"object_lock_enabled" db:"object_lock_enabled"`
	ObjectLockUntil   *time.Time `json:"object_lock_until,omitempty" db:"object_lock_until"`
	ChecksumSHA256    *string    `json:"checksum_sha256,omitempty" db:"checksum_sha256"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	CreatedBy         *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// AuditArchiveMetadataResponse is the API response for archive metadata
type AuditArchiveMetadataResponse struct {
	ID                uuid.UUID `json:"id"`
	TenantID          uuid.UUID `json:"tenant_id"`
	ArchiveBatchID    uuid.UUID `json:"archive_batch_id"`
	StartDate         time.Time `json:"start_date"`
	EndDate           time.Time `json:"end_date"`
	RecordCount       int64     `json:"record_count"`
	S3Bucket          string    `json:"s3_bucket"`
	S3Key             string    `json:"s3_key"`
	FileSizeMB        float64   `json:"file_size_mb"`
	CompressionType   string    `json:"compression_type"`
	Encrypted         bool      `json:"encrypted"`
	ObjectLockEnabled bool      `json:"object_lock_enabled"`
	CreatedAt         time.Time `json:"created_at"`
}

// PermissionChangeEvent represents a permission or role change event
type PermissionChangeEvent struct {
	UserID         uuid.UUID              `json:"user_id"`
	TargetUserID   uuid.UUID              `json:"target_user_id"`
	ChangeType     string                 `json:"change_type"` // role_assigned, role_revoked, permission_granted, permission_revoked
	RoleID         *uuid.UUID             `json:"role_id,omitempty"`
	RoleName       *string                `json:"role_name,omitempty"`
	PermissionID   *uuid.UUID             `json:"permission_id,omitempty"`
	PermissionName *string                `json:"permission_name,omitempty"`
	Details        map[string]interface{} `json:"details,omitempty"`
	IPAddress      string                 `json:"ip_address"`
	CorrelationID  *uuid.UUID             `json:"correlation_id,omitempty"`
}

// AuditLogResponse is an exported type.
type AuditLogResponse struct {
	ID           uuid.UUID              `json:"id"`
	TenantID     uuid.UUID              `json:"tenant_id"`
	UserID       *uuid.UUID             `json:"user_id,omitempty"`
	Username     *string                `json:"username,omitempty"`
	Action       string                 `json:"action"`
	ResourceType *string                `json:"resource_type,omitempty"`
	ResourceID   *uuid.UUID             `json:"resource_id,omitempty"`
	Details      map[string]interface{} `json:"details,omitempty"`
	IPAddress    *string                `json:"ip_address,omitempty"`
	UserAgent    *string                `json:"user_agent,omitempty"`
	Success      bool                   `json:"success"`
	ErrorMessage *string                `json:"error_message,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// AuditLogListResponse is an exported type.
type AuditLogListResponse struct {
	Logs       []AuditLogResponse `json:"logs"`
	Total      int64              `json:"total"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	TotalPages int                `json:"total_pages"`
}

// MFALoginResponse returned when MFA is required
type MFALoginResponse struct {
	RequiresMFA bool   `json:"requires_mfa"`
	MFAMethod   string `json:"mfa_method"` // "totp" or "email"
	SessionID   string `json:"session_id"` // Temporary session for MFA verification
	Message     string `json:"message"`
}

// MFAStatusResponse for getting MFA status
type MFAStatusResponse struct {
	Enabled          bool     `json:"enabled"`
	Method           string   `json:"method,omitempty"`           // Preferred method: "totp" or "email"
	TOTPEnabled      bool     `json:"totp_enabled"`               // Is authenticator app enabled
	EmailEnabled     bool     `json:"email_enabled"`              // Is email MFA enabled
	AvailableMethods []string `json:"available_methods"`          // List of enabled methods
	PreferredMethod  string   `json:"preferred_method,omitempty"` // User's preferred method
	BackupCodesCount int      `json:"backup_codes_count"`
	MaskedEmail      string   `json:"masked_email,omitempty"`
	EmailCodeTTL     int64    `json:"email_code_ttl_seconds,omitempty"`
	PasskeyAvailable bool     `json:"passkey_available"`
}

// EmailVerificationStatus for email verification status
type EmailVerificationStatus struct {
	Email               string     `json:"email"`
	IsVerified          bool       `json:"is_verified"`
	PendingVerification bool       `json:"pending_verification"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
}

// SendEmailCodeRequest for requesting email MFA code
type SendEmailCodeRequest struct {
	SessionID string `json:"session_id,omitempty" binding:"omitempty,max=255"` // For login flow
}

// VerifyMFARequest for verifying MFA during login
type VerifyMFARequest struct {
	SessionID string `json:"session_id" binding:"required,min=1,max=255"`
	Code      string `json:"code" binding:"required,min=1,max=20"`
	CodeType  string `json:"code_type,omitempty" binding:"omitempty,oneof=totp email backup"` // "totp", "email", or "backup"
}

// SelectMFAMethodRequest for selecting MFA method during login
type SelectMFAMethodRequest struct {
	SessionID string `json:"session_id" binding:"required,min=1,max=255"`
	// webauthn (passkey-as-MFA, Phase A.2 2026-05-26) is a valid switch
	// target. The handler-level oneof is just a pre-filter; AuthService
	// .SwitchMFALoginMethod is the real gate — it rejects switching to a
	// method the user can't actually use (e.g. webauthn without an enrolled
	// credential) via getAvailableMFAMethods membership. Omitting webauthn
	// here made the MFA picker's "verify with a passkey" choice 400 with
	// "Invalid request" before ever reaching that check.
	Method string `json:"method" binding:"required,oneof=totp email webauthn"` // Selected method
}

// MFACompleteRequest for completing MFA verification during login (session-based, no password)
type MFACompleteRequest struct {
	SessionID  string `json:"session_id" binding:"required,uuid"`
	MFACode    string `json:"mfa_code" binding:"required,min=1,max=20"`
	RememberMe bool   `json:"remember_me,omitempty"`
	DeviceID   string `json:"device_id,omitempty" binding:"omitempty,max=255"`
}

// MFASessionData stores the MFA session data in Redis (TTL: 5 minutes)
type MFASessionData struct {
	UserID     string `json:"user_id"`
	TenantID   string `json:"tenant_id"`
	TenantSlug string `json:"tenant_slug"`
	IPAddress  string `json:"ip_address"`
	UserAgent  string `json:"user_agent"`
	AuthMethod string `json:"auth_method,omitempty"` // "password", "sso", "saml" — tracks origin for audit trail
	ClientID   string `json:"client_id,omitempty"`   // OAuth client_id for audience-scoped tokens (persists through MFA flow)
	CreatedAt  int64  `json:"created_at"`
	MFAMethod  string `json:"mfa_method,omitempty"`
}

// MFAEnrollmentSession stores the registration-interrupt enrollment session in
// Redis (TTL: 10 minutes). Issued by the Login flow when risk-based MFA fires
// for a user without an enrolled authenticator, then consumed by
// /api/v1/auth/mfa/enrollment/{init,verify}. Bound to the originating IP and a
// hash of the User-Agent — rebind misses fail closed and emit
// auth.mfa.enrollment_token_misuse to the security audit log.
//
// Never accepted by /oauth/authorize, /oauth/token, or any resource endpoint —
// the only use is the two enrollment routes above. On successful verify the
// session is deleted (one-time-use); init may be called multiple times within
// the TTL so the user can switch between TOTP and email.
type MFAEnrollmentSession struct {
	UserID     string `json:"user_id"`
	TenantID   string `json:"tenant_id"`
	TenantSlug string `json:"tenant_slug"`
	IPAddress  string `json:"ip_address"`
	// UserAgentHash is sha256(UserAgent) hex; we don't store the raw UA to
	// keep the Redis blob bounded and avoid PII drift across replicas.
	UserAgentHash string `json:"user_agent_hash"`
	ClientID      string `json:"client_id,omitempty"` // OAuth client_id for audience scoping on the post-enrollment session
	// RiskScore + RiskLevel are snapshotted from the assessment that
	// triggered the interrupt, so the verify-side audit log can correlate
	// back to the original risk signals without re-querying the scorer.
	RiskScore int    `json:"risk_score,omitempty"`
	RiskLevel string `json:"risk_level,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

// MFAEnrollmentInitRequest is the body for POST /api/v1/auth/mfa/enrollment/init.
// Sent by the unauthenticated enrollment page after the user picks TOTP or
// email; the server validates the enrollment_token (ip+ua-bound, 10-min TTL)
// and returns the method-specific bootstrap material.
type MFAEnrollmentInitRequest struct {
	EnrollmentToken string `json:"enrollment_token" binding:"required,min=1,max=255"`
	Method          string `json:"method" binding:"required,oneof=totp email"`
}

// MFAEnrollmentInitResponse carries TOTP-specific or email-specific bootstrap
// material back to the unauthenticated enrollment page. For TOTP, the QR/secret
// are included so the user can register with their authenticator app; for
// email, only Message is set (the actual code is delivered out-of-band via
// SMTP and verified on the next call).
type MFAEnrollmentInitResponse struct {
	Method      string `json:"method"`
	Secret      string `json:"secret,omitempty"`       // TOTP only
	QRCode      string `json:"qr_code,omitempty"`      // TOTP only — base64 PNG
	ManualEntry string `json:"manual_entry,omitempty"` // TOTP only
	Message     string `json:"message,omitempty"`
	ExpiresIn   int64  `json:"expires_in,omitempty"` // Seconds until enrollment_token expires
}

// MFAEnrollmentSkipRequest is the body for POST /api/v1/auth/mfa/enrollment/skip.
// Used when a realm's mfa_grace_period_days is configured AND
// mfa_enrollment_max_skips > 0 AND the user clicks "Remind me later" on
// the enrollment interrupt. The server atomically increments the
// per-user skip count under SQL-level locks (no read-modify-write race),
// gated on deadline > now AND mfa_enabled = false. On success, the
// enrollment session is consumed and a normal authenticated session +
// token pair are issued — same shape as CompleteMFALogin /
// MFAEnrollmentVerifyResponse so the BFF can plumb cookies + redirect
// uniformly. Pre-auth route (no IdP session yet); CSRF allowlisted same
// as the other /mfa/enrollment/* routes — enrollment_token's ip+ua
// binding is the canonical anti-CSRF replacement (matches
// internal engineering notes pattern).
type MFAEnrollmentSkipRequest struct {
	EnrollmentToken string `json:"enrollment_token" binding:"required,min=1,max=255"`
	RememberMe      bool   `json:"remember_me,omitempty"`
	DeviceID        string `json:"device_id,omitempty" binding:"omitempty,max=255"`
}

// MFAEnrollmentVerifyRequest is the body for POST /api/v1/auth/mfa/enrollment/verify.
// Submits the user-entered code; on success the user's MFA flags flip
// (mfa_enabled=true + the method-specific flag), the enrollment session is
// deleted (one-time-use), backup codes are generated, and a normal
// authenticated session + token pair are issued — same shape as
// CompleteMFALogin so the BFF can plumb cookies + redirect_url uniformly.
type MFAEnrollmentVerifyRequest struct {
	EnrollmentToken string `json:"enrollment_token" binding:"required,min=1,max=255"`
	Method          string `json:"method" binding:"required,oneof=totp email"`
	Code            string `json:"code" binding:"required,min=1,max=20"`
	RememberMe      bool   `json:"remember_me,omitempty"`
	DeviceID        string `json:"device_id,omitempty" binding:"omitempty,max=255"`
}

// SetPreferredMFARequest for setting user's preferred MFA method
type SetPreferredMFARequest struct {
	Method string `json:"method" binding:"required,oneof=totp email"` // Preferred method
}

// SetUserMFARequest for admin to enable/disable MFA for a user
type SetUserMFARequest struct {
	Enabled bool   `json:"enabled"`
	Method  string `json:"method,omitempty" binding:"omitempty,oneof=totp email"` // "totp" or "email", defaults to "email" if enabling
}

// MFAPendingSetup represents a pending MFA setup awaiting verification
type MFAPendingSetup struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	Secret    string    `json:"secret"`
	MFAType   string    `json:"mfa_type"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// MFAEmailCode represents a one-time email verification code for MFA
type MFAEmailCode struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	CodeHash  string     `json:"code_hash"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// RecoveryCode represents an MFA recovery/backup code
type RecoveryCode struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	CodeHash  string     `json:"code_hash"`
	CreatedAt time.Time  `json:"created_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
}

// LDAPProvider is an alias for IdentityProvider used in LDAP contexts
type LDAPProvider = IdentityProvider

// EmailVerification represents an email verification record for MFA
type EmailVerification struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	Email      string     `json:"email"`
	Code       string     `json:"code"`
	ExpiresAt  time.Time  `json:"expires_at"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}
