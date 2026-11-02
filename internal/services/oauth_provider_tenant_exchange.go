// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/tenantstatus"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// Tenant token exchange (R3 guest, LD-R3-GUEST-1/2): an RFC 8693 exchange on
// /oauth/token that turns the caller's access token for one tenant into a
// short-lived access token for another tenant the same user holds an ACTIVE
// iam_user_memberships row in. This is how an external accountant whose home
// tenant is their own practice opens a client tenant's app: the client tenant
// subdomain only accepts a token whose tenant_id matches it.
//
// Request: grant_type=urn:ietf:params:oauth:grant-type:token-exchange,
// subject_token=<access token>, subject_token_type=...:access_token,
// target_tenant_id=<uuid>, confidential client authentication.
//
// The token is minted by generateTokens like every other /oauth/token grant
// (same signer, audience, products/suspension handling); the exchange only
// swaps the tenant, scopes the roles claim to that tenant, adds
// membership_kind and caps the lifetime. No refresh token is returned.

const (
	// tokenExchangeGrantType is the RFC 8693 grant_type a client must be
	// registered for to use the legacy access_token narrowing exchange.
	tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

	// TenantExchangeTargetParam is the RFC 8693 §2.1 extension parameter
	// naming the tenant the caller wants a token for.
	TenantExchangeTargetParam = "target_tenant_id"

	// tenantExchangeAccessTokenTTL caps the exchanged token's lifetime. The
	// client re-exchanges (and the membership is re-checked) when it expires.
	tenantExchangeAccessTokenTTL = 10 * time.Minute

	// Per-user limit: switching tenants is a human action; anything faster
	// is a script probing tenant ids.
	tenantExchangeRateLimit       = 10
	tenantExchangeRateWindow      = time.Minute
	tenantExchangeRateBlock       = 5 * time.Minute
	tenantExchangeMembershipClaim = "membership_kind"
)

// ErrTenantExchangeRateLimited is returned when a user exceeds the per-user
// tenant exchange limit. The handler maps it to HTTP 429.
var ErrTenantExchangeRateLimited = errors.New("tenant exchange rate limit exceeded")

// tenantExchangeMembershipStore resolves the user's membership in the target
// tenant (repositories.UserMembershipRepository satisfies it).
type tenantExchangeMembershipStore interface {
	ResolveTenantExchange(ctx context.Context, userID, tenantID uuid.UUID) (*models.TenantExchangeMembership, error)
}

// tenantExchangeLastUsedStore is the optional membership bookkeeping hook
// (repositories.UserMembershipRepository satisfies it).
type tenantExchangeLastUsedStore interface {
	TouchLastUsed(ctx context.Context, tenantID, userID uuid.UUID) error
}

// tenantExchangeRateLimiter is the per-user limiter (*redis.RateLimiter).
type tenantExchangeRateLimiter interface {
	Check(ctx context.Context, key string, limit int, window time.Duration, blockDuration time.Duration) (*redispkg.RateLimitResult, error)
}

// SetTenantExchange wires the tenant token exchange. With a nil store the
// exchange is disabled and every target_tenant_id request is refused. A nil
// limiter disables the per-user limit (tests).
func (s *OAuthProviderService) SetTenantExchange(store tenantExchangeMembershipStore, limiter tenantExchangeRateLimiter) {
	s.tenantExchangeStore = store
	s.tenantExchangeLimiter = limiter
}

// tenantExchangeGrant is what TenantTokenExchange hands generateTokens
// through ctx.
type tenantExchangeGrant struct {
	MembershipKind models.SeatClass
	RoleNames      []string
	// SubjectExp is the subject token's exp. The exchanged token never
	// outlives it, so a chain of exchanges cannot extend a session.
	SubjectExp time.Time
}

const ctxKeyTenantExchange contextKey = "oauth_tenant_exchange"

func withTenantExchangeGrant(ctx context.Context, g tenantExchangeGrant) context.Context {
	return context.WithValue(ctx, ctxKeyTenantExchange, g)
}

func tenantExchangeGrantFromContext(ctx context.Context) (tenantExchangeGrant, bool) {
	g, ok := ctx.Value(ctxKeyTenantExchange).(tenantExchangeGrant)
	return g, ok
}

// applyTenantExchangeClaims rewrites the subject claims of a tenant-exchange
// token: roles become the target tenant's role names only (the generic
// effective-roles lookup spans every tenant the user has roles in; emitted
// only when the roles scope is granted and the client allows it), groups
// are dropped (group paths are not tenant-scoped either), and
// membership_kind marks external (guest) tokens.
func applyTenantExchangeClaims(claims jwt.MapClaims, g tenantExchangeGrant, rolesAllowed bool) {
	delete(claims, OIDCScopeGroups)
	delete(claims, OIDCScopeRoles)
	if rolesAllowed && len(g.RoleNames) > 0 {
		claims[OIDCScopeRoles] = append([]string(nil), g.RoleNames...)
	}
	claims[tenantExchangeMembershipClaim] = string(g.MembershipKind)
}

// tenantExchangeDenied is the single client-facing reason for every
// membership/tenant refusal, so the response never tells a caller whether a
// tenant id exists or merely has no membership for them.
const tenantExchangeDenied = "invalid_target: no active membership in the requested tenant"

// TenantTokenExchange implements the tenant token exchange described at the
// top of this file. Checks, in order:
//
//  1. exchange enabled; confidential client; subject_token_type access_token;
//     requested_token_type empty or access_token; target is a UUID and not a
//     protected platform tenant.
//  2. subject_token signature + expiry (ValidateAccessToken), then the
//     iam_oauth_tokens row: present, not revoked, user-bound, and issued to
//     THIS client. The JWT's sub/client_id must agree with the row. A
//     DPoP-bound subject token needs a proof for the same key.
//  3. user active and not locked; per-user rate limit.
//  4. membership: active, seat_class member or external; tenant status
//     active or trial (suspension is also enforced by generateTokens).
//
//nolint:gocyclo // sequential validation gates, kept in one place on purpose.
func (s *OAuthProviderService) TenantTokenExchange(
	ctx context.Context,
	client *models.OAuthClient,
	subjectToken, subjectTokenType, requestedTokenType, targetTenant string,
	requestedScopes []string,
) (*models.OAuthTokenResponse, error) {
	const accessTokenType = "urn:ietf:params:oauth:token-type:access_token"

	if s.tenantExchangeStore == nil {
		return nil, errors.New("invalid_request: tenant token exchange is not enabled on this server")
	}
	if client == nil {
		return nil, errors.New("unauthorized_client: tenant token exchange requires a confidential client")
	}
	// Public clients (native apps) only when explicitly allowlisted AND
	// PKCE-required + first-party; every later check still applies.
	if client.IsPublic && !s.tenantExchangePublicClientAllowed(client) {
		return nil, errors.New("unauthorized_client: tenant token exchange requires a confidential client")
	}
	// Public path: the client must also be registered for the token-exchange
	// grant, like the generic exchange. (Confidential clients are not
	// checked here: existing BFF registrations may predate the grant type.)
	if client.IsPublic && !s.containsString(client.GrantTypes, tokenExchangeGrantType) {
		return nil, errors.New("unauthorized_client: token-exchange grant is not allowed for this client")
	}
	if subjectTokenType != accessTokenType {
		return nil, errors.New("invalid_request: tenant token exchange requires subject_token_type access_token")
	}
	if requestedTokenType != "" && requestedTokenType != accessTokenType {
		return nil, fmt.Errorf("invalid_request: requested_token_type %q is not supported (only access_token)", requestedTokenType)
	}
	targetTenantID, err := uuid.Parse(targetTenant)
	if err != nil || targetTenantID == uuid.Nil {
		return nil, errors.New("invalid_request: target_tenant_id must be a tenant UUID")
	}
	// Platform tenants are never exchange targets: a token whose tenant_id
	// is the Hexxlock internal tenant carries platform_admin.
	if tenantstatus.IsProtected(targetTenantID) {
		return nil, errors.New(tenantExchangeDenied)
	}

	claims, vErr := s.ValidateAccessToken(subjectToken)
	if vErr != nil {
		return nil, errors.New("invalid_grant: subject_token is invalid or expired")
	}
	row, err := s.clientRepo.GetOAuthTokenByHash(ctx, s.hashSecret(subjectToken))
	if err != nil || row == nil {
		return nil, errors.New("invalid_grant: subject_token not found in token store (revoked or never issued)")
	}
	if row.IsRevoked {
		return nil, errors.New("invalid_grant: subject_token has been revoked")
	}
	if row.UserID == nil {
		return nil, errors.New("invalid_grant: subject_token is not bound to a user")
	}
	if row.ClientID != client.ID {
		return nil, errors.New("invalid_grant: subject_token was not issued to this client")
	}
	if sub, _ := claims["sub"].(string); sub != row.UserID.String() {
		return nil, errors.New("invalid_grant: subject_token subject mismatch")
	}
	if cid, _ := claims["client_id"].(string); cid != client.ClientID {
		return nil, errors.New("invalid_grant: subject_token was not issued to this client")
	}
	if jkt := subjectTokenJKT(claims); jkt != "" && jkt != dpopJKTFromContext(ctx) {
		return nil, errors.New("invalid_grant: subject_token is DPoP-bound; a proof for the same key is required")
	}

	user, err := s.userRepo.GetByID(ctx, *row.UserID)
	if err != nil || user == nil {
		return nil, errors.New("invalid_grant: subject_token user not found")
	}
	if !user.IsActive || user.IsLocked {
		return nil, errors.New("invalid_grant: user is not active")
	}
	homeTenantID := user.TenantID

	if s.tenantExchangeLimiter != nil {
		res, lErr := s.tenantExchangeLimiter.Check(ctx, "tenant_exchange:"+user.ID.String(),
			tenantExchangeRateLimit, tenantExchangeRateWindow, tenantExchangeRateBlock)
		if lErr != nil {
			logger.Warn("tenant exchange rate limit check failed", zap.Error(lErr))
		} else if !res.Allowed {
			s.auditTenantExchange(ctx, homeTenantID, user.ID, client, targetTenantID, "", false, "rate_limited")
			return nil, ErrTenantExchangeRateLimited
		}
	}

	m, err := s.tenantExchangeStore.ResolveTenantExchange(ctx, user.ID, targetTenantID)
	if err != nil {
		return nil, fmt.Errorf("server_error: membership lookup failed: %w", err)
	}
	if reason := tenantExchangeRefusal(m); reason != "" {
		// Denials are audited in the caller's HOME tenant: the target id is
		// caller-chosen, and writing into an arbitrary tenant's audit log
		// would let anyone spam it.
		s.auditTenantExchange(ctx, homeTenantID, user.ID, client, targetTenantID, "", false, reason)
		return nil, errors.New(tenantExchangeDenied)
	}

	// Owner/admin of a company other than the home one needs MFA (operator
	// decision 2026-10-13). Login enforces it only for the tenant signed in
	// to, so without this gate an exchange would reach a joined company's
	// admin role with a password-only session. The home tenant is excluded:
	// its own sign-in policy already applied and a switch back must not fail.
	// The role check also covers RequiresInvitedAdminMFA (invited membership
	// holding owner/admin), which is a strict subset of it.
	subjectAMR := claimStrings(claims["amr"])
	if targetTenantID != homeTenantID && tenantExchangeHoldsAdminRole(m.RoleNames) && !HasMFAFactor(subjectAMR) {
		s.auditTenantExchange(ctx, homeTenantID, user.ID, client, targetTenantID, m.SeatClass, false, "mfa_step_up_required")
		return nil, errors.New("insufficient_user_authentication: multi-factor authentication is required for an owner or admin role in the requested tenant")
	}

	// Scopes: subject's scopes, optionally narrowed (RFC 8693 §2.1: never
	// wider than the subject token).
	scopes := append([]string(nil), row.Scopes...)
	if len(requestedScopes) > 0 {
		allowed := make(map[string]bool, len(row.Scopes))
		for _, sc := range row.Scopes {
			allowed[sc] = true
		}
		narrowed := make([]string, 0, len(requestedScopes))
		for _, sc := range requestedScopes {
			if sc != "" && allowed[sc] {
				narrowed = append(narrowed, sc)
			}
		}
		if len(narrowed) == 0 {
			return nil, errors.New("invalid_scope: requested scope not a subset of subject_token scope")
		}
		scopes = narrowed
	}
	if s.cfg.DPoPEnabled && scopeRequiresDPoP(scopes) && dpopJKTFromContext(ctx) == "" {
		return nil, ErrDPoPRequired
	}

	// The token is for the same person in the target tenant. Copy, never
	// mutate the repository's user value.
	target := *user
	target.TenantID = targetTenantID

	var subjectExp time.Time
	if exp, expErr := claims.GetExpirationTime(); expErr == nil && exp != nil {
		subjectExp = exp.Time
	}
	exCtx := withTenantExchangeGrant(ctx, tenantExchangeGrant{
		MembershipKind: m.SeatClass,
		RoleNames:      m.RoleNames,
		SubjectExp:     subjectExp,
	})
	exCtx = WithTokenExchangeActor(exCtx, TokenExchangeActor{
		ActorSub:      client.ClientID,
		ActorClientID: client.ClientID,
	})
	// The subject token's amr is carried forward so a later exchange (or any
	// resource server) still sees how the person actually authenticated.
	resp, err := s.generateTokens(exCtx, client, &target, scopes, nil, nil, subjectAMR, row.IdpSessionID)
	if err != nil {
		if errors.Is(err, ErrTenantSuspended) {
			s.auditTenantExchange(ctx, homeTenantID, user.ID, client, targetTenantID, m.SeatClass, false, "tenant_suspended")
		}
		return nil, err
	}
	// Exchange is not a login: no refresh token, no ID token.
	resp.RefreshToken = ""
	resp.IDToken = ""
	resp.TenantID = targetTenantID.String()
	resp.TenantSlug = m.TenantSlug
	resp.MembershipKind = string(m.SeatClass)

	// Best-effort bookkeeping: the last company the person worked in picks the
	// default when they hold more than one active membership. A failure never
	// affects the token that was just issued.
	if toucher, ok := s.tenantExchangeStore.(tenantExchangeLastUsedStore); ok {
		if tErr := toucher.TouchLastUsed(ctx, targetTenantID, user.ID); tErr != nil {
			logger.Warn("tenant exchange: failed to stamp membership last_used_at", zap.Error(tErr))
		}
	}

	s.auditTenantExchange(ctx, targetTenantID, user.ID, client, targetTenantID, m.SeatClass, true, "")
	if homeTenantID != targetTenantID {
		s.auditTenantExchange(ctx, homeTenantID, user.ID, client, targetTenantID, m.SeatClass, true, "")
	}
	return resp, nil
}

// tenantExchangeRefusal returns the audit reason a membership does not allow
// an exchange, or "" when it does.
func tenantExchangeRefusal(m *models.TenantExchangeMembership) string {
	switch {
	case m == nil:
		return "no_membership"
	case m.Status != models.UserMembershipStatusActive:
		return "membership_inactive"
	case m.SeatClass != models.SeatClassMember && m.SeatClass != models.SeatClassExternal:
		return "membership_kind_not_allowed"
	case m.TenantStatus != "active" && m.TenantStatus != "trial":
		return "tenant_not_active"
	}
	return ""
}

// tenantExchangeHoldsAdminRole reports whether any role name is a role that
// requires MFA (same owner/admin set as team-invitation onboarding).
func tenantExchangeHoldsAdminRole(roleNames []string) bool {
	for _, n := range roleNames {
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "owner", "admin":
			return true
		}
	}
	return false
}

// claimStrings reads a JWT claim that is a string array.
func claimStrings(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		return append([]string(nil), t...)
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

// subjectTokenJKT returns the RFC 9449 cnf.jkt of a validated token, or "".
func subjectTokenJKT(claims jwt.MapClaims) string {
	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		return ""
	}
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

// auditTenantExchange records one exchange decision. Tokens are never part
// of the event.
func (s *OAuthProviderService) auditTenantExchange(
	ctx context.Context,
	auditTenantID, userID uuid.UUID,
	client *models.OAuthClient,
	targetTenantID uuid.UUID,
	kind models.SeatClass,
	success bool,
	reason string,
) {
	if s.auditService == nil {
		return
	}
	action, severity := "oauth.tenant_exchange.issued", SecuritySeverityLow
	if !success {
		action, severity = "oauth.tenant_exchange.denied", SecuritySeverityMedium
	}
	uid := userID
	details := map[string]interface{}{
		"client_id":        client.ClientID,
		"grant_type":       "token-exchange",
		"target_tenant_id": targetTenantID.String(),
	}
	if kind != "" {
		details["membership_kind"] = string(kind)
	}
	if reason != "" {
		details["reason"] = reason
	}
	if success {
		details["access_token_lifetime"] = tenantExchangeLifetime(client)
	}
	s.auditService.LogSecurityEvent(ctx, &SecurityAuditEvent{
		TenantID:    auditTenantID,
		UserID:      &uid,
		IPAddress:   requestIPFromContext(ctx),
		Category:    SecurityCategoryAuthentication,
		Severity:    severity,
		Action:      action,
		Description: fmt.Sprintf("Tenant token exchange for tenant %s via client %s", targetTenantID, client.ClientID),
		Details:     details,
		Blocked:     !success,
	})
}

// tenantExchangeLifetime is the access-token lifetime (seconds) of a tenant
// exchange token: the client's own lifetime, capped.
func tenantExchangeLifetime(client *models.OAuthClient) int {
	capSec := int(tenantExchangeAccessTokenTTL / time.Second)
	if client.AccessTokenLifetime > 0 && client.AccessTokenLifetime < capSec {
		return client.AccessTokenLifetime
	}
	return capSec
}

// tenantExchangePublicClientAllowed reports whether a public client may use
// the tenant exchange: PKCE-required, first-party and listed in
// TENANT_EXCHANGE_PUBLIC_CLIENT_IDS.
func (s *OAuthProviderService) tenantExchangePublicClientAllowed(client *models.OAuthClient) bool {
	if s.cfg == nil || !client.RequirePKCE || !client.IsFirstParty {
		return false
	}
	for _, id := range s.cfg.TenantExchangePublicClientIDs {
		if id == client.ClientID {
			return true
		}
	}
	return false
}

// nativeAppSchemeDomains returns the configured private-use scheme allowlist.
func (s *OAuthProviderService) nativeAppSchemeDomains() []string {
	if s.cfg == nil {
		return nil
	}
	return s.cfg.NativeAppSchemeDomains
}
