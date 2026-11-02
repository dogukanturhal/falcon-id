// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

// ValidateAccessToken validates a JWT access token and returns claims
func (s *TokenService) ValidateAccessToken(tokenString string) (*models.Claims, error) {
	return s.ValidateAccessTokenWithContext(context.Background(), tokenString)
}

// ValidateAccessTokenWithContext validates a JWT access token with context for blacklist checking.
// Supports both legacy (v0) and minimal (v1) token formats.
//
// Algorithm selection:
//   - RS256 tokens are verified with the RSA public key from the JWTKeyProvider.
//   - HS256 tokens are accepted only when JWTHMACFallbackEnabled is true (migration period).
//   - Any other algorithm is rejected.
func (s *TokenService) ValidateAccessTokenWithContext(ctx context.Context, tokenString string) (*models.Claims, error) {
	// DDIL P3.3: apply a bounded clock-skew leeway to the time-based claim
	// checks (exp / nbf). Without it, a disconnected or drifting node whose
	// clock runs ahead of the issuer rejects a still-valid token as expired
	// (or, if behind, as not-yet-valid) — a classic degraded-mode failure.
	// The window is widened symmetrically by at most jwtClockSkewLeeway().
	token, err := jwt.Parse(tokenString, s.resolveSigningKey, jwt.WithLeeway(s.jwtClockSkewLeeway()))
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	// Tenant API key tokens are signed with the same provider key but are
	// minted for the business API audience only; falcon-id is never their
	// audience, so they must not authenticate its own /api/v1/* routes.
	if typ, _ := mapClaims["type"].(string); typ == APIKeyTokenType {
		return nil, fmt.Errorf("invalid token: API key tokens are not accepted here")
	}

	claims, err := s.extractClaimsByVersion(ctx, mapClaims)
	if err != nil {
		return nil, err
	}

	if err := s.enforceBlacklist(ctx, claims); err != nil {
		return nil, err
	}

	// Tenant suspension gate (R1-GAPS row 27): an access token minted before
	// the suspension must stop working immediately, not at natural expiry.
	if err := checkTenantNotSuspended(ctx, s.tenantSuspension, claims.TenantID); err != nil {
		return nil, err
	}

	return claims, nil
}

// defaultJWTClockSkewLeeway is the fallback clock-skew tolerance used when the
// service is constructed without a config (e.g. stripped-down tests). Matches
// the JWT_CLOCK_SKEW_LEEWAY viper default.
const defaultJWTClockSkewLeeway = 60 * time.Second

// jwtClockSkewLeeway returns the configured symmetric leeway for access-token
// time-based claim validation (DDIL P3.3). A negative configured value is
// clamped to zero — leeway may only relax, never tighten, the validity window,
// so a mis-signed configuration cannot silently narrow it below the stated
// bound. An explicit zero means strict validation (no leeway).
func (s *TokenService) jwtClockSkewLeeway() time.Duration {
	if s.config == nil {
		return defaultJWTClockSkewLeeway
	}
	if s.config.JWTClockSkewLeeway < 0 {
		return 0
	}
	return s.config.JWTClockSkewLeeway
}

// resolveSigningKey is the jwt.Keyfunc used by ValidateAccessTokenWithContext.
// It selects the correct verification key based on the token's signing algorithm.
func (s *TokenService) resolveSigningKey(token *jwt.Token) (interface{}, error) {
	switch token.Method.(type) {
	case *jwt.SigningMethodRSA:
		return s.resolveRSAKey(token)
	case *jwt.SigningMethodHMAC:
		return s.resolveHMACKey()
	default:
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
}

// resolveRSAKey returns the RSA public key for RS256 verification.
// Prefers the KeyManager (rotation-aware) over the legacy JWTKeyProvider.
func (s *TokenService) resolveRSAKey(token *jwt.Token) (interface{}, error) {
	if s.keyManager != nil {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("RS256 token missing kid header")
		}
		pubKey, err := s.keyManager.PublicKey(kid)
		if err != nil {
			return nil, fmt.Errorf("unknown signing key %q: %w", kid, err)
		}
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("signing key %q is not RSA", kid)
		}
		return rsaPub, nil
	}
	if s.jwtKeyProvider == nil {
		return nil, fmt.Errorf("RS256 token received but no JWT key provider is configured")
	}
	return s.jwtKeyProvider.PublicKey(), nil
}

// resolveHMACKey returns the HMAC secret for HS256 verification.
// HS256 is only accepted when the migration fallback flag is enabled.
func (s *TokenService) resolveHMACKey() (interface{}, error) {
	if !s.config.JWTHMACFallbackEnabled {
		return nil, fmt.Errorf("HS256 tokens are no longer accepted; set JWT_HMAC_FALLBACK_ENABLED=true to re-enable during migration")
	}
	return []byte(s.config.JWTSecret), nil
}

// extractClaimsByVersion dispatches claim extraction based on the token version field.
func (s *TokenService) extractClaimsByVersion(ctx context.Context, mapClaims jwt.MapClaims) (*models.Claims, error) {
	tokenVersion := models.TokenVersionLegacy
	if v, ok := mapClaims["v"].(float64); ok {
		tokenVersion = int(v)
	}

	var claims *models.Claims
	var err error
	switch tokenVersion {
	case models.TokenVersionSpiceDB:
		claims, err = s.extractSpiceDBClaims(ctx, mapClaims)
	case models.TokenVersionMinimal:
		claims, err = s.extractMinimalClaims(ctx, mapClaims)
	default:
		claims = s.parseLegacyClaims(mapClaims)
	}
	if err == nil && claims != nil {
		// RFC 9449 §6 DPoP binding — if cnf.jkt is present, propagate it
		// into the domain Claims so the resource-server middleware
		// (VerifyTokenBinding) can compare against the proof's JKT.
		claims.CnfJKT = extractCnfJKT(mapClaims)
		// RFC 7800 SPIFFE binding — if cnf.spiffe is present, propagate
		// into the domain Claims so receivers can compare against the
		// inbound Linkerd `l5d-client-id` header (mesh-layer sender
		// constraint enforcement).
		claims.CnfSpiffe = extractCnfSpiffe(mapClaims)
		// RFC 9470 §6.1 / OIDC Core §2 auth_time — propagate so
		// RequireFreshAuth gates can measure elapsed time since the
		// original authentication event.
		claims.AuthTime = extractAuthTime(mapClaims)
		// RFC 8693 §4.1 `act` claim — when present, surface the
		// delegation actor so RequireAuth can emit a structured audit
		// log line. Absent → claims.Actor stays nil; receivers MUST
		// NOT fail closed on missing act.
		claims.Actor = extractActor(mapClaims)
	}
	return claims, err
}

// extractActor pulls the RFC 8693 §4.1 `act` claim out of the validated
// token's raw map. Returns nil when absent or malformed; receivers treat
// nil as "non-delegated request" — never reject solely on missing act.
// Nested act chains (act inside act) are NOT followed — §4.1.1 says
// nested actors are informational only and must not influence access
// control. We log the immediate actor only.
func extractActor(mapClaims jwt.MapClaims) *models.TokenActor {
	raw, ok := mapClaims["act"]
	if !ok {
		return nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	sub, _ := m["sub"].(string)
	clientID, _ := m["client_id"].(string)
	iss, _ := m["iss"].(string)
	if sub == "" && clientID == "" && iss == "" {
		return nil
	}
	return &models.TokenActor{Sub: sub, ClientID: clientID, Iss: iss}
}

// extractAuthTime pulls the auth_time claim out of the validated token's
// raw map. Accepts both float64 (the encoding the jwt library produces
// for JSON numbers) and int64 (defensive). Returns 0 when absent or
// malformed; RequireFreshAuth treats that as "auth time unknown, fail
// closed".
func extractAuthTime(mapClaims jwt.MapClaims) int64 {
	raw, ok := mapClaims["auth_time"]
	if !ok {
		return 0
	}
	switch v := raw.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}

// extractCnfJKT pulls the jkt out of the RFC 7800 / RFC 9449 cnf object.
// Returns "" when the claim is absent or malformed; callers treat this as
// "token is not DPoP-bound" — no enforcement, backwards compatible.
func extractCnfJKT(mapClaims jwt.MapClaims) string {
	return extractCnfField(mapClaims, "jkt")
}

// extractCnfSpiffe pulls the spiffe URI out of the cnf object. Tokens
// issued via the RFC 8693 :jwt token-exchange grant (IAP→BFF) carry
// `cnf.spiffe = <Linkerd l5d-client-id>` so receivers can detect token
// replay across workloads. Empty when the token was not SPIFFE-bound.
func extractCnfSpiffe(mapClaims jwt.MapClaims) string {
	return extractCnfField(mapClaims, "spiffe")
}

// extractCnfField is the shared lookup helper for any string-valued cnf
// member. Defensive against missing claim, wrong outer type, and wrong
// member type — all fall through to "".
func extractCnfField(mapClaims jwt.MapClaims, key string) string {
	cnfRaw, ok := mapClaims["cnf"]
	if !ok {
		return ""
	}
	cnf, ok := cnfRaw.(map[string]interface{})
	if !ok {
		return ""
	}
	v, _ := cnf[key].(string)
	return v
}

// extractSpiceDBClaims builds claims for v2 (SpiceDB) tokens.
// Only identity fields are included; permissions are resolved via SpiceDB at check time.
func (s *TokenService) extractSpiceDBClaims(ctx context.Context, mapClaims jwt.MapClaims) (*models.Claims, error) {
	sessionIDStr, ok := mapClaims["sid"].(string)
	if !ok {
		return nil, fmt.Errorf("v2 token missing session ID")
	}

	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID in v2 token: %w", err)
	}

	iss, _ := mapClaims["iss"].(string)
	sub, _ := mapClaims["sub"].(string)
	exp, _ := mapClaims["exp"].(float64)
	iat, _ := mapClaims["iat"].(float64)
	userID, _ := uuid.Parse(sub)

	var tenantID, realmID uuid.UUID
	if tid, ok := mapClaims["tid"].(string); ok {
		tenantID, _ = uuid.Parse(tid)
	}
	if rid, ok := mapClaims["rid"].(string); ok {
		realmID, _ = uuid.Parse(rid)
	}

	tokenRoles := parseStringSlice(mapClaims, "roles")

	claims := &models.Claims{
		Issuer:      iss,
		Subject:     sub,
		TenantID:    tenantID,
		UserID:      userID,
		SessionID:   sessionID,
		RealmID:     realmID,
		IssuedAt:    int64(iat),
		ExpiresAt:   int64(exp),
		NotBefore:   int64(iat),
		Roles:       tokenRoles,
		Permissions: nil, // Resolved via SpiceDB
	}

	s.enrichClaimsFromSessionCache(ctx, claims, sessionID)
	return claims, nil
}

// enrichClaimsFromSessionCache populates display fields from the session cache when available.
func (s *TokenService) enrichClaimsFromSessionCache(ctx context.Context, claims *models.Claims, sessionID uuid.UUID) {
	if s.sessionCache == nil {
		return
	}
	sessionData, err := s.sessionCache.GetSessionData(ctx, sessionID)
	if err != nil || sessionData == nil {
		return
	}
	claims.Username = sessionData.Username
	claims.Email = sessionData.Email
	claims.RealmSlug = sessionData.RealmSlug
	claims.RealmType = sessionData.RealmType
	claims.IsPlatformAdmin = sessionData.IsPlatformAdmin
}

// extractMinimalClaims builds full claims for v1 (minimal) tokens by retrieving
// session data from the Redis cache. Fails closed when Redis is unavailable.
func (s *TokenService) extractMinimalClaims(ctx context.Context, mapClaims jwt.MapClaims) (*models.Claims, error) {
	sessionIDStr, ok := mapClaims["sid"].(string)
	if !ok {
		return nil, fmt.Errorf("minimal token missing session ID")
	}

	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID in token: %w", err)
	}

	if s.sessionCache == nil {
		return nil, fmt.Errorf("minimal token validation requires session cache")
	}

	sessionData, err := s.sessionCache.GetSessionData(ctx, sessionID)
	if err != nil {
		if redis.IsRedisUnavailableError(err) {
			return nil, fmt.Errorf("ValidateAccessTokenWithContext: %w", err)
		}
		return nil, fmt.Errorf("failed to retrieve session data: %w", err)
	}
	if sessionData == nil {
		return nil, fmt.Errorf("session not found or expired")
	}

	iss, _ := mapClaims["iss"].(string)
	exp, _ := mapClaims["exp"].(float64)
	iat, _ := mapClaims["iat"].(float64)

	claims := s.sessionDataToClaims(sessionData, sessionID, iss, int64(exp), int64(iat))

	overrideUUIDClaim(mapClaims, "tid", func(id uuid.UUID) { claims.TenantID = id })
	overrideUUIDClaim(mapClaims, "rid", func(id uuid.UUID) { claims.RealmID = id })
	if scp, ok := mapClaims["scp"].(string); ok {
		claims.Scope = scp
	}

	return claims, nil
}

// enforceBlacklist checks both session-level and user-level blacklists.
// SECURITY: Fail-closed — Redis unavailability results in access denial.
func (s *TokenService) enforceBlacklist(ctx context.Context, claims *models.Claims) error {
	if s.tokenBlacklist == nil || claims.SessionID == uuid.Nil {
		return nil
	}

	if err := s.checkSessionBlacklist(ctx, claims.SessionID, claims.RealmID); err != nil {
		return err
	}

	return s.checkUserBlacklist(ctx, claims.UserID)
}

// checkSessionBlacklist verifies the session has not been revoked.
// Falls back to the database when Redis returns a non-availability error.
func (s *TokenService) checkSessionBlacklist(ctx context.Context, sessionID uuid.UUID, realmID uuid.UUID) error {
	blacklisted, reason, err := s.tokenBlacklist.IsSessionBlacklisted(ctx, sessionID)
	if err == nil {
		if blacklisted {
			return fmt.Errorf("session has been revoked: %s", reason)
		}
		return nil
	}

	if redis.IsRedisUnavailableError(err) {
		logger.Error("SECURITY: Redis unavailable for session blacklist check - denying access (fail-closed)",
			zap.Error(err),
			zap.String("session_id", sessionID.String()),
		)
		return fmt.Errorf("ValidateAccessTokenWithContext: %w", err)
	}

	logger.Warn("Redis blacklist check failed with non-availability error, attempting database fallback",
		zap.Error(err),
		zap.String("session_id", sessionID.String()),
	)

	return s.checkSessionActiveInDB(ctx, sessionID, realmID)
}

// checkSessionActiveInDB performs a database fallback when Redis is unavailable.
// Fails closed when no database fallback is configured.
func (s *TokenService) checkSessionActiveInDB(ctx context.Context, sessionID uuid.UUID, realmID uuid.UUID) error {
	if s.sessionRepo == nil {
		logger.Error("SECURITY: No database fallback available for session verification - denying access",
			zap.String("session_id", sessionID.String()),
		)
		return fmt.Errorf("unable to verify session status")
	}

	// RLS bootstrap: iam_sessions' RLS policy (strict_realm_sessions) is
	// realm-scoped. realmID comes from the already signature-verified JWT's
	// `rid` claim. Without it, this lookup would run with no RLS context and
	// either (a) return zero rows under FORCE RLS — silently treating a
	// live, non-blacklisted session as inactive and denying a legitimate
	// user, or (b) once RLS is force-enabled on this table, fail closed the
	// same way. A missing/zero realmID is refused rather than silently
	// falling back to the unscoped GetByID, because that fallback is
	// exactly the shape of query this whole effort is trying to eliminate.
	if realmID == uuid.Nil {
		logger.Error("SECURITY: session blacklist DB fallback has no realm context - denying access (fail-closed)",
			zap.String("session_id", sessionID.String()),
		)
		return fmt.Errorf("unable to verify session status")
	}

	session, dbErr := s.sessionRepo.GetByIDWithRealmContext(ctx, sessionID, realmID)
	if dbErr != nil {
		logger.Error("Database session check also failed during Redis error",
			zap.Error(dbErr),
			zap.String("session_id", sessionID.String()),
		)
		return fmt.Errorf("unable to verify session status")
	}

	sessionInactive := session == nil || !session.IsActive || session.EndedAt != nil
	if sessionInactive {
		return fmt.Errorf("session is no longer active")
	}
	return nil
}

// checkUserBlacklist verifies the user's tokens have not been globally revoked.
// Non-availability errors cause fail-closed behavior; other errors are logged and skipped.
func (s *TokenService) checkUserBlacklist(ctx context.Context, userID uuid.UUID) error {
	if userID == uuid.Nil {
		return nil
	}

	userBlacklisted, err := s.tokenBlacklist.IsUserBlacklisted(ctx, userID)
	if err != nil {
		if redis.IsRedisUnavailableError(err) {
			logger.Error("SECURITY: Redis unavailable for user blacklist check - denying access (fail-closed)",
				zap.Error(err),
				zap.String("user_id", userID.String()),
			)
			return fmt.Errorf("ValidateAccessTokenWithContext: %w", err)
		}
		logger.Warn("Redis user blacklist check failed with non-availability error",
			zap.Error(err),
			zap.String("user_id", userID.String()),
		)
		return nil
	}

	if userBlacklisted {
		return fmt.Errorf("all user sessions have been revoked")
	}
	return nil
}

// parseStringSlice extracts a []string from a jwt.MapClaims key that holds []interface{}.
func parseStringSlice(mapClaims jwt.MapClaims, key string) []string {
	raw, ok := mapClaims[key].([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// overrideUUIDClaim parses a UUID string claim and calls set when parsing succeeds.
func overrideUUIDClaim(mapClaims jwt.MapClaims, key string, set func(uuid.UUID)) {
	val, ok := mapClaims[key].(string)
	if !ok {
		return
	}
	parsed, err := uuid.Parse(val)
	if err == nil {
		set(parsed)
	}
}

// CleanupExpiredTokens removes expired tokens from the database
func (s *TokenService) CleanupExpiredTokens(ctx context.Context) error {
	if _, err := s.tokenRepo.CleanupExpiredPasswordResets(ctx); err != nil {
		return fmt.Errorf("failed to cleanup password resets: %w", err)
	}
	return nil
}

// CreatePasswordResetToken generates a password reset token
func (s *TokenService) CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, ipAddress *string) (string, error) {
	// Invalidate existing password reset tokens
	if err := s.tokenRepo.InvalidateUserPasswordResets(ctx, userID); err != nil {
		return "", fmt.Errorf("failed to invalidate existing tokens: %w", err)
	}

	// Generate token
	tokenString, err := crypto.GenerateSecureToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	tokenHash, err := crypto.HashToken(tokenString)
	if err != nil {
		return "", fmt.Errorf("failed to hash token: %w", err)
	}

	reset := &models.PasswordReset{
		UserID:    userID,
		TokenHash: tokenHash,
		IPAddress: ipAddress,
		ExpiresAt: time.Now().Add(time.Hour), // 1 hour expiry
	}

	if err := s.tokenRepo.CreatePasswordReset(ctx, reset); err != nil {
		return "", fmt.Errorf("failed to store password reset: %w", err)
	}

	return tokenString, nil
}

// ValidatePasswordResetToken validates a password reset token
func (s *TokenService) ValidatePasswordResetToken(ctx context.Context, tokenString string) (*models.PasswordReset, error) {
	tokenHash, err := crypto.HashToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to hash token: %w", err)
	}

	reset, err := s.tokenRepo.GetPasswordReset(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get password reset: %w", err)
	}

	if reset == nil {
		return nil, fmt.Errorf("password reset token not found")
	}

	if reset.UsedAt != nil {
		return nil, fmt.Errorf("password reset token has been used")
	}

	if time.Now().After(reset.ExpiresAt) {
		return nil, fmt.Errorf("password reset token has expired")
	}

	return reset, nil
}

// MarkPasswordResetUsed marks a password reset token as used
func (s *TokenService) MarkPasswordResetUsed(ctx context.Context, resetID uuid.UUID) error {
	return s.tokenRepo.MarkPasswordResetUsed(ctx, resetID)
}

// parseLegacyClaims extracts claims from legacy token format (v0)
// This method handles backward compatibility with existing tokens
func (s *TokenService) parseLegacyClaims(mapClaims jwt.MapClaims) *models.Claims {
	claims := &models.Claims{}
	parseLegacyIdentity(mapClaims, claims)
	parseLegacyStringSlice(mapClaims, "roles", &claims.Roles)
	parseLegacyStringSlice(mapClaims, "permissions", &claims.Permissions)
	parseLegacyTimestamps(mapClaims, claims)
	parseLegacyImpersonation(mapClaims, claims)
	parseLegacyRealm(mapClaims, claims)
	if isPlatformAdmin, ok := mapClaims["is_platform_admin"].(bool); ok {
		claims.IsPlatformAdmin = isPlatformAdmin
	}
	return claims
}

// parseLegacyIdentity extracts identity fields from legacy JWT claims.
func parseLegacyIdentity(mapClaims jwt.MapClaims, claims *models.Claims) {
	if iss, ok := mapClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if sub, ok := mapClaims["sub"].(string); ok {
		claims.Subject = sub
	}
	if tenantID, ok := mapClaims["tenant_id"].(string); ok {
		if parsed, err := uuid.Parse(tenantID); err == nil {
			claims.TenantID = parsed
		}
	}
	// Short-form tid claim takes precedence (session fixation protection, backward compat)
	if tid, ok := mapClaims["tid"].(string); ok {
		if parsed, err := uuid.Parse(tid); err == nil {
			claims.TenantID = parsed
		}
	}
	if userID, ok := mapClaims["user_id"].(string); ok {
		if parsed, err := uuid.Parse(userID); err == nil {
			claims.UserID = parsed
		}
	}
	// OIDC access tokens issued by /oauth/token carry the user identifier
	// in the standard `sub` claim (RFC 7519 §4.1.2) and do NOT emit a
	// legacy `user_id`. Fall back to parsing `sub` when user_id was absent
	// or unparseable — otherwise any resource-server middleware that reads
	// claims.UserID (UserInfo, audit logging, admin gates) sees a zero UUID
	// and rejects the request.
	if claims.UserID == uuid.Nil {
		if sub, ok := mapClaims["sub"].(string); ok {
			if parsed, err := uuid.Parse(sub); err == nil {
				claims.UserID = parsed
			}
		}
	}
	if username, ok := mapClaims["username"].(string); ok {
		claims.Username = username
	}
	if email, ok := mapClaims["email"].(string); ok {
		claims.Email = email
	}
	if sessionID, ok := mapClaims["session_id"].(string); ok {
		if parsed, err := uuid.Parse(sessionID); err == nil {
			claims.SessionID = parsed
		}
	}
}

// parseLegacyStringSlice extracts a string slice from legacy JWT claims.
func parseLegacyStringSlice(mapClaims jwt.MapClaims, key string, dest *[]string) {
	if vals, ok := mapClaims[key].([]interface{}); ok {
		for _, v := range vals {
			if s, ok := v.(string); ok {
				*dest = append(*dest, s)
			}
		}
	}
}

// parseLegacyTimestamps extracts timestamp fields from legacy JWT claims.
func parseLegacyTimestamps(mapClaims jwt.MapClaims, claims *models.Claims) {
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}
	if exp, ok := mapClaims["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}
	if nbf, ok := mapClaims["nbf"].(float64); ok {
		claims.NotBefore = int64(nbf)
	}
}

// parseLegacyImpersonation extracts impersonation fields from legacy JWT claims.
func parseLegacyImpersonation(mapClaims jwt.MapClaims, claims *models.Claims) {
	if impersonatorID, ok := mapClaims["impersonator_id"].(string); ok {
		if parsed, err := uuid.Parse(impersonatorID); err == nil {
			claims.ImpersonatorID = &parsed
		}
	}
	if impersonationSessionID, ok := mapClaims["impersonation_session_id"].(string); ok {
		if parsed, err := uuid.Parse(impersonationSessionID); err == nil {
			claims.ImpersonationSessionID = &parsed
		}
	}
}

// parseLegacyRealm extracts realm fields from legacy JWT claims.
func parseLegacyRealm(mapClaims jwt.MapClaims, claims *models.Claims) {
	if realmID, ok := mapClaims["realm_id"].(string); ok {
		if parsed, err := uuid.Parse(realmID); err == nil {
			claims.RealmID = parsed
		}
	}
	if realmSlug, ok := mapClaims["realm_slug"].(string); ok {
		claims.RealmSlug = realmSlug
	}
	if realmType, ok := mapClaims["realm_type"].(string); ok {
		claims.RealmType = realmType
	}
	if scope, ok := mapClaims["scope"].(string); ok {
		claims.Scope = scope
	}
}

// sessionDataToClaims converts redis.SessionData to models.Claims
// This helper avoids circular dependencies between packages
func (s *TokenService) sessionDataToClaims(sessionData *redis.SessionData, sessionID uuid.UUID, issuer string, expiresAt, issuedAt int64) *models.Claims {
	claims := &models.Claims{
		Issuer:          issuer,
		Subject:         sessionData.UserID.String(),
		TenantID:        sessionData.TenantID,
		UserID:          sessionData.UserID,
		Username:        sessionData.Username,
		Email:           sessionData.Email,
		Roles:           sessionData.Roles,
		Permissions:     sessionData.Permissions,
		SessionID:       sessionID,
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
		NotBefore:       issuedAt,
		RealmID:         sessionData.RealmID,
		RealmSlug:       sessionData.RealmSlug,
		RealmType:       sessionData.RealmType,
		Scope:           "tenant", // Default scope
		IsPlatformAdmin: sessionData.IsPlatformAdmin,
	}

	if sessionData.ImpersonatorID != nil {
		claims.ImpersonatorID = sessionData.ImpersonatorID
	}
	if sessionData.ImpersonationSessionID != nil {
		claims.ImpersonationSessionID = sessionData.ImpersonationSessionID
	}

	return claims
}
