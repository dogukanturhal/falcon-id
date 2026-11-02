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
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// Operator token exchange (platform-admin console, P0): an RFC 8693 exchange
// on /oauth/token that turns a Hexxlock operator's own access token into a
// short-lived assertion for the operator plane, sent by the console BFF as
// X-Actor-Assertion and verified by platform-shared/operatorauth.
//
// Request: grant_type=urn:ietf:params:oauth:grant-type:token-exchange,
// subject_token=<operator access token>, subject_token_type=...:access_token,
// audience=hexxlock-ops, confidential client authentication (the client id
// must be listed in OPS_OPERATOR_EXCHANGE_CLIENT_IDS; empty = disabled).
//
// The token deliberately has NO `roles` claim: the operator's normal access
// token carries standing tenant roles (platform_admin / iam_admin), which is
// exactly the bypass this token replaces. What it carries instead:
//
//	sub, user_id, email   the operator
//	tid, tenant_id        the internal tenant (checked here, again by receivers)
//	platform_roles        iam_platform_roles rows in force now (standing viewer
//	                      plus roles backed by an active elevation / break-glass)
//	ops_perms             ops:<domain>:<verb> permissions SpiceDB grants on
//	                      hxl_platform:hexxlock to that user right now
//	elev_id               the active elevation backing the elevated roles
//	auth_time, amr        carried from the subject token (step-up evidence)
//
// TTL is 5 minutes and never beyond the subject token's own expiry. No
// refresh token. The token is not stored (no iam_oauth_tokens row); its short
// life is the revocation story, and the BFF re-mints on demand.
const (
	// OperatorTokenAudience is the aud of operator assertions.
	OperatorTokenAudience = "hexxlock-ops"

	operatorExchangeTTL       = 5 * time.Minute
	operatorExchangeRateLimit = 60
)

// opsPermissionSource computes ops_perms (*spicedb.Client satisfies it).
type opsPermissionSource interface {
	PlatformOpsPermissions(ctx context.Context, userID uuid.UUID) ([]string, error)
}

// standingRoleWriter is the optional SpiceDB capability that writes an
// uncaveated (standing) hxl_platform relationship (*spicedb.Client has it).
type standingRoleWriter interface {
	WritePlatformStandingRole(ctx context.Context, userID uuid.UUID, roleKey string) (string, error)
}

// ensureStandingBreakGlassAdmin mirrors the break-glass account's standing
// platform_admin row into hxl_platform before ops_perms is computed.
// ActiveRolesFor already honours that row, but ops_perms come from SpiceDB,
// where only elevations write relationships - so the master admin got a
// token with platform_admin and an empty ops_perms, and every console page
// asked for elevation. Done on every exchange (idempotent TOUCH) rather
// than once at startup because revoking or expiring an elevation deletes
// the same admin relationship.
func (s *OAuthProviderService) ensureStandingBreakGlassAdmin(ctx context.Context, user *models.User) (bool, error) {
	w, ok := s.opsPerms.(standingRoleWriter)
	if !ok {
		return false, nil
	}
	standing, err := s.platformAuthority.HoldsStandingBreakGlassAdmin(ctx, user.ID, user.Email)
	if err != nil || !standing {
		return false, err
	}
	if _, err = w.WritePlatformStandingRole(ctx, user.ID, string(models.PlatformRoleAdmin)); err != nil {
		return false, err
	}
	return true, nil
}

// SetPlatformAuthority wires the strict platform-role model (is_platform_admin
// claim derivation and the operator exchange's role lookup).
func (s *OAuthProviderService) SetPlatformAuthority(pa *PlatformAuthority) { s.platformAuthority = pa }

// SetOperatorExchange wires the SpiceDB permission source. With a nil source
// the operator exchange is disabled.
func (s *OAuthProviderService) SetOperatorExchange(perms opsPermissionSource) { s.opsPerms = perms }

func (s *OAuthProviderService) operatorExchangeClientAllowed(client *models.OAuthClient) bool {
	if s.cfg == nil || client == nil {
		return false
	}
	for _, id := range s.cfg.OpsOperatorExchangeClientIDs {
		if id == client.ClientID {
			return true
		}
	}
	return false
}

// OperatorTokenExchange implements the operator token exchange described at
// the top of this file.
//
//nolint:gocyclo // sequential validation gates, kept in one place on purpose.
func (s *OAuthProviderService) OperatorTokenExchange(
	ctx context.Context,
	client *models.OAuthClient,
	subjectToken, subjectTokenType, requestedTokenType string,
) (*models.OAuthTokenResponse, error) {
	const accessTokenType = "urn:ietf:params:oauth:token-type:access_token"

	if s.opsPerms == nil || s.platformAuthority == nil {
		return nil, errors.New("invalid_request: operator token exchange is not enabled on this server")
	}
	if client == nil || client.IsPublic || !s.operatorExchangeClientAllowed(client) {
		return nil, errors.New("unauthorized_client: operator token exchange is not allowed for this client")
	}
	if subjectTokenType != accessTokenType {
		return nil, errors.New("invalid_request: operator token exchange requires subject_token_type access_token")
	}
	if requestedTokenType != "" && requestedTokenType != accessTokenType {
		return nil, fmt.Errorf("invalid_request: requested_token_type %q is not supported (only access_token)", requestedTokenType)
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
	// An impersonation token is somebody else acting as the operator.
	if imp, _ := claims["impersonator_id"].(string); imp != "" {
		return nil, errors.New("access_denied: impersonated sessions cannot obtain operator tokens")
	}

	user, err := s.userRepo.GetByID(ctx, *row.UserID)
	if err != nil || user == nil {
		return nil, errors.New("invalid_grant: subject_token user not found")
	}
	if !user.IsActive || user.IsLocked {
		return nil, errors.New("invalid_grant: user is not active")
	}
	if user.TenantID.String() != models.HexxlockInternalTenantID {
		s.auditOperatorExchange(ctx, user, client, false, "not_internal_tenant", nil)
		return nil, errors.New("access_denied: operator tokens are only issued to Hexxlock internal accounts")
	}

	if s.tenantExchangeLimiter != nil {
		res, lErr := s.tenantExchangeLimiter.Check(ctx, "operator_exchange:"+user.ID.String(),
			operatorExchangeRateLimit, tenantExchangeRateWindow, tenantExchangeRateBlock)
		if lErr != nil {
			logger.Warn("operator exchange rate limit check failed", zap.Error(lErr))
		} else if !res.Allowed {
			s.auditOperatorExchange(ctx, user, client, false, "rate_limited", nil)
			return nil, ErrTenantExchangeRateLimited
		}
	}

	roles, err := s.platformAuthority.ActiveRolesFor(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("server_error: platform role lookup failed: %w", err)
	}
	if len(roles) == 0 {
		s.auditOperatorExchange(ctx, user, client, false, "no_platform_role", nil)
		return nil, errors.New("access_denied: no active platform role")
	}
	standing, err := s.ensureStandingBreakGlassAdmin(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("server_error: standing admin sync failed: %w", err)
	}
	// standing_platform_admin tells the operator services to skip reason /
	// confirmation / second-approver friction for the break-glass admin. It is
	// only minted when OPS_STANDING_ADMIN_DIRECT is on; absent = full friction.
	standingDirect := standing && s.cfg != nil && s.cfg.OpsStandingAdminDirect
	perms, err := s.opsPerms.PlatformOpsPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("server_error: permission lookup failed: %w", err)
	}
	if perms == nil {
		perms = []string{}
	}
	var elevID string
	if ref, eErr := s.platformAuthority.LatestActiveElevation(ctx, user.ID); eErr != nil {
		return nil, fmt.Errorf("server_error: elevation lookup failed: %w", eErr)
	} else if ref != nil {
		elevID = ref.ID.String()
	}

	now := time.Now().UTC()
	exp := now.Add(operatorExchangeTTL)
	if subExp, expErr := claims.GetExpirationTime(); expErr == nil && subExp != nil && subExp.Time.Before(exp) {
		exp = subExp.Time
	}
	if !exp.After(now) {
		return nil, errors.New("invalid_grant: subject_token is invalid or expired")
	}

	tokenClaims := jwt.MapClaims{
		"iss":            s.getIssuer(),
		"aud":            []string{OperatorTokenAudience},
		"sub":            user.ID.String(),
		"user_id":        user.ID.String(),
		"email":          user.Email,
		"tid":            user.TenantID.String(),
		"tenant_id":      user.TenantID.String(),
		"client_id":      client.ClientID,
		"gty":            "operator_exchange",
		"platform_roles": roles,
		"ops_perms":      perms,
		"amr":            claimStrings(claims["amr"]),
		"iat":            now.Unix(),
		"nbf":            now.Unix(),
		"exp":            exp.Unix(),
		"jti":            uuid.New().String(),
	}
	if elevID != "" {
		tokenClaims["elev_id"] = elevID
	}
	if standingDirect {
		tokenClaims["standing_platform_admin"] = true
	}
	if at, ok := claims["auth_time"].(float64); ok && at > 0 {
		tokenClaims["auth_time"] = int64(at)
	}
	if sid, _ := claims["sid"].(string); sid != "" {
		tokenClaims["sid"] = sid
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	signKey, signKid := s.signingKey()
	tok.Header["kid"] = signKid
	signed, err := tok.SignedString(signKey)
	if err != nil {
		return nil, fmt.Errorf("server_error: failed to sign operator token: %w", err)
	}

	s.auditOperatorExchange(ctx, user, client, true, "", map[string]interface{}{
		"platform_roles":          strings.Join(roles, ","),
		"ops_perm_count":          len(perms),
		"elevation_id":            elevID,
		"standing_platform_admin": standingDirect,
	})
	return &models.OAuthTokenResponse{
		AccessToken: signed,
		TokenType:   "Bearer",
		ExpiresIn:   int64(exp.Sub(now) / time.Second),
	}, nil
}

// auditOperatorExchange records one exchange decision. Tokens are never part
// of the event.
func (s *OAuthProviderService) auditOperatorExchange(
	ctx context.Context,
	user *models.User,
	client *models.OAuthClient,
	success bool,
	reason string,
	extra map[string]interface{},
) {
	if s.auditService == nil || user == nil {
		return
	}
	action, severity := "oauth.operator_exchange.issued", SecuritySeverityLow
	if !success {
		action, severity = "oauth.operator_exchange.denied", SecuritySeverityMedium
	}
	details := map[string]interface{}{
		"client_id":  client.ClientID,
		"grant_type": "token-exchange",
		"audience":   OperatorTokenAudience,
	}
	if reason != "" {
		details["reason"] = reason
	}
	for k, v := range extra {
		details[k] = v
	}
	uid := user.ID
	s.auditService.LogSecurityEvent(ctx, &SecurityAuditEvent{
		TenantID:    user.TenantID,
		UserID:      &uid,
		IPAddress:   requestIPFromContext(ctx),
		Category:    SecurityCategoryAuthentication,
		Severity:    severity,
		Action:      action,
		Description: fmt.Sprintf("Operator token exchange via client %s", client.ClientID),
		Details:     details,
		Blocked:     !success,
	})
}

// SignOpsToken signs claims with the active RS256 signing key (the key behind
// the operator exchange and the JWKS endpoint) and sets the kid header. Used
// for four-eyes approval tokens. Callers own iss/aud/exp.
func (s *OAuthProviderService) SignOpsToken(claims jwt.MapClaims) (string, error) {
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = s.getIssuer()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signKey, signKid := s.signingKey()
	tok.Header["kid"] = signKid
	return tok.SignedString(signKey)
}
