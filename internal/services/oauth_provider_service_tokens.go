// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ==================== Token Generation ====================

// oauthTokenCreator is the minimal persistence surface generateTokens needs to
// store the issued token row. In the authorization_code grant the caller passes
// the exchange transaction handle (repositories.OAuthClientTx) so the INSERT is
// atomic with the CAS that marks the code used; every other grant
// (refresh_token, client_credentials, token-exchange) passes the pooled
// repository. Both s.clientRepo and OAuthClientTx satisfy this interface.
type oauthTokenCreator interface {
	CreateOAuthToken(ctx context.Context, token *models.OAuthToken) error
}

// generateTokens mints tokens and persists the token row on the pooled
// repository. This is the path taken by the refresh_token, client_credentials
// and token-exchange grants — none of which consume an authorization code, so
// no surrounding transaction is required and their behaviour is unchanged.
func (s *OAuthProviderService) generateTokens(ctx context.Context, client *models.OAuthClient, user *models.User, scopes []string, nonce *string, authzDetails []models.AuthorizationDetail, authMethods []string, idpSessionID *uuid.UUID) (*models.OAuthTokenResponse, error) {
	return s.generateTokensWithSink(ctx, s.clientRepo, client, user, scopes, nonce, authzDetails, authMethods, idpSessionID)
}

// generateTokensWithSink is generateTokens with the token-row persistence
// target injected. The authorization_code grant threads its exchange
// transaction here (from ExchangeAuthorizationCode) so the token INSERT commits
// atomically with the code's mark-used CAS; a failure anywhere in token
// generation therefore rolls the mark-used back and leaves the code usable.
// Only the CreateOAuthToken write is transactional — the stateless JWT signing
// and the read-only claim resolvers deliberately are not (they run on other
// connections/services and hold no lock on the auth-code row).
func (s *OAuthProviderService) generateTokensWithSink(ctx context.Context, tokenSink oauthTokenCreator, client *models.OAuthClient, user *models.User, scopes []string, nonce *string, authzDetails []models.AuthorizationDetail, authMethods []string, idpSessionID *uuid.UUID) (*models.OAuthTokenResponse, error) {
	now := time.Now()
	accessTokenExpiry := now.Add(time.Duration(client.AccessTokenLifetime) * time.Second)
	refreshTokenExpiry := now.Add(time.Duration(client.RefreshTokenLifetime) * time.Second)

	// `aud` resolution — multi-audience JWT pattern (RFC 7519 §4.1.3,
	// Auth0 / Microsoft Entra / Okta in-place-transition canonical):
	//
	// Every issued OAuth access token carries an ARRAY of audiences so
	// receivers that validate against different identifiers all accept
	// the same token. This unblocks the resource-identifier migration
	// across the platform without requiring lock-step deploys of every
	// .NET / Go service.
	//
	// Default audience array members (and why each is there):
	//
	//   1. client.ClientID        — RFC 8693 §4.3 / Google-style: token is
	//                                "for" the OAuth client that requested
	//                                it. Maintains audience-confusion
	//                                defense at the client level.
	//   2. PlatformAPIAudienceURI — RFC 8707 canonical resource URI for
	//                                every HexxLock platform API. NEW. Any
	//                                receiver that migrates to URI-based
	//                                validation (Auth0 / Entra / Okta
	//                                convention) accepts this value.
	//   3. LegacyServiceMeshAud   — "hexxlock-services", the historical
	//                                hard-coded value baked into every
	//                                .NET service deployment as
	//                                Jwt__Audience. Kept during the
	//                                transition window so existing
	//                                services continue to pass validation
	//                                without per-service redeploys.
	//
	// Caller-supplied `resource` parameter (RFC 8707 §2) wins for
	// per-resource narrowing — but the legacy mesh audience stays in the
	// array so the transition is non-breaking until every receiver moves
	// to the URI form. When the migration completes we drop
	// LegacyServiceMeshAud cluster-wide.
	//
	// Implementation note: jwt.ClaimStrings serializes to a single string
	// when len == 1 and to a JSON array otherwise — both shapes are
	// RFC 7519-valid. ASP.NET Core's JwtBearerOptions.Audience matches
	// "expected value is IN the aud array", so multi-aud is transparently
	// accepted by every .NET receiver without any service-side change.
	audience := jwt.ClaimStrings{
		client.ClientID,
		PlatformAPIAudienceURI,
		LegacyServiceMeshAudience,
	}
	if resource := oauthResourceFromContext(ctx); resource != "" {
		// Explicit RFC 8707 per-resource narrowing. Caller specified
		// exactly which resource this token is for; honour it but keep
		// LegacyServiceMeshAudience so unmigrated receivers still pass.
		audience = jwt.ClaimStrings{resource, LegacyServiceMeshAudience}
	}

	// Generate access token JWT
	accessTokenClaims := jwt.MapClaims{
		"iss":       s.getIssuer(),
		"aud":       audience,
		"iat":       now.Unix(),
		"exp":       accessTokenExpiry.Unix(),
		"client_id": client.ClientID,
		"scope":     strings.Join(scopes, " "),
		"jti":       uuid.New().String(),
	}

	// RFC 7800 sender-constraining claims (cnf). We currently emit two
	// flavours and merge them under a single `cnf` object — the spec
	// allows multiple confirmation methods on the same token, but
	// today no receiver requires both simultaneously:
	//
	//   1. RFC 9449 §6 cnf.jkt — DPoP proof-key thumbprint. Populated
	//      when /oauth/token's OptionalDPoP middleware validated a proof
	//      header. Resource servers enforce the cnf-jkt-vs-proof match
	//      via RequireAuth → VerifyTokenBindingInline.
	//
	//   2. cnf.spiffe — Linkerd SPIFFE URI of the calling workload.
	//      Populated only on RFC 8693 :jwt grant exchanges (IAP→BFF
	//      bridge) because that's the only grant where the requestor
	//      provably traversed the mesh and thus has a trusted
	//      `l5d-client-id` header. Receivers cross-check the claim
	//      against their own inbound `l5d-client-id`.
	//
	// Backward-compat: when neither is set, no `cnf` is emitted —
	// legacy bearers pass through unchanged.
	cnf := map[string]string{}
	if jkt := dpopJKTFromContext(ctx); jkt != "" {
		cnf["jkt"] = jkt
	}
	if spiffe := spiffeIDFromContext(ctx); spiffe != "" {
		cnf["spiffe"] = spiffe
	}
	if len(cnf) > 0 {
		accessTokenClaims["cnf"] = cnf
	}

	if user != nil {
		accessTokenClaims["sub"] = user.ID.String()
		accessTokenClaims["tenant_id"] = user.TenantID.String()
		// `email`/`email_verified` on the access token, scope-gated — lets
		// resource servers (e.g. downstream JMAP, which keys mailboxes by email)
		// authorize from the access token without consuming the id_token
		// (audience-bound to the client; RFC 8707 anti-pattern to send to an
		// API) or a /userinfo round-trip. Mirrors the id_token email claim and
		// the tenant_id/groups/roles already emitted on the access token here.
		if s.containsString(scopes, "email") {
			accessTokenClaims["email"] = user.Email
			accessTokenClaims["email_verified"] = user.IsEmailVerified
		}
		// RFC 9470 §6.1 / OIDC Core §2 — `auth_time` is the Unix
		// timestamp of the most recent end-user authentication event,
		// and is what downstream RequireFreshAuth gates check against
		// max_age. Pre-fix `generateTokens` (the OAuth /oauth/token
		// mint path used by authorization_code + refresh_token grants)
		// silently dropped this claim — every token issued by the
		// accounts BFF code-exchange came out with no auth_time, so
		// OptionalAuth set CurrentUser.AuthTime=0 and the very next
		// /webauthn/credentials DELETE or /mfa/disable POST 401'd with
		// `insufficient_user_authentication` even after a fresh
		// password+OTP re-auth.
		//
		// The earlier !243 fix added auth_time to token_service.
		// GenerateAccessTokenV2 — that closed the /api/v1/auth/login
		// path, but the OAuth /oauth/token path uses THIS function
		// (raw jwt.MapClaims, no token_service involvement). Same bug,
		// different code path; the 6th layer of the redirect-loop
		// chain, only surfacing after !241-!246 closed the upstream
		// layers.
		//
		// Source preference:
		//   1. IdP session AuthTime (canonical — when the user
		//      actually proved identity) — looked up via the
		//      sessionCache when idpSessionID is non-nil.
		//   2. `now` fallback when the IdP session is missing
		//      (client_credentials-adjacent paths with a user_id but
		//      no idp session, e.g. service-account-impersonation
		//      exchange). Acceptable because in those paths the
		//      caller already proved identity via the token they
		//      presented; using now() means a single freshness window
		//      from token issuance.
		//
		// Wire shape: the lookup is intentionally NIL-SAFE — when
		// sessionCache isn't wired (tests, partial deployments) we
		// fall through to now() rather than failing token issuance.
		accessTokenClaims["auth_time"] = s.resolveAuthTimeForToken(ctx, idpSessionID, now)
		// Resource-server bypass flag for platform admins. Same
		// derivation rule as token_service.go:generateLegacyToken
		// (purely tenant-based, not role-based) — every user in the
		// exampletenant control-plane tenant gets the implicit
		// platform_admin scope for platform:* permission checks.
		// Without this claim, middleware.RequirePermission(c, ...)
		// falls through to SpiceDB lookup which doesn't have platform
		// scopes seeded → 403 on every /api/v1/* call from BFFs that
		// pick up their tokens via /oauth/token (incl. the IAP→BFF
		// :jwt token-exchange path). Diagnosed live 2026-05-14 as the
		// proximate cause of the admin-tier dashboard 401 cascade.
		if user.TenantID.String() == models.HexxlockInternalTenantID {
			accessTokenClaims["is_platform_admin"] = true
		}

		// Product subscription claim — mirrors what
		// token_service.generateMinimalToken does for the legacy
		// /api/v1/auth/login mint path. Without this block, JWTs minted
		// by the OAuth /oauth/token path (authorization_code +
		// refresh_token + token-exchange grants — the canonical paths
		// for centralized SSO at accounts.hexxlock.com and every product
		// app's BFF code-exchange) silently dropped the `products`
		// claim. Downstream product-entitlement middleware (mearax
		// `productSlug: 'mearax'` gate in falcon-id-client) then had no
		// source for /app/* gating decisions and bounced every user to
		// /unauthorized — the symmetric bug to the 2026-05-25 auth_time
		// drop the surrounding comment block documents.
		//
		// Shape: array of { pid, slug, plan? }, resolved from active
		// iam_product_instances rows for the user's tenant (see
		// services/product_subscription_resolver.go). Empty resolved
		// list is OMITTED — we drop the claim entirely rather than
		// emit an empty array, matching token_service behaviour and
		// minimising token size for the (still common) no-products
		// case.
		//
		// Resolver failures are LOGGED but NON-FATAL: token issuance
		// continues with no products claim. A transient DB hiccup
		// shouldn't 500 the OAuth code exchange — the downstream
		// middleware will bounce the user to /unauthorized on this
		// single request, and the next refresh-token rotation
		// (typically <30min later) re-resolves cleanly.
		if s.productSubscriptionResolver != nil {
			resolved, err := s.productSubscriptionResolver.Resolve(ctx, user.TenantID)
			if err != nil {
				logger.Warn("Failed to resolve product subscriptions for OAuth token",
					zap.Error(err),
					zap.String("tenant_id", user.TenantID.String()),
					zap.String("client_id", client.ClientID),
				)
			} else if len(resolved) > 0 {
				products := make([]map[string]any, 0, len(resolved))
				for _, pc := range resolved {
					entry := map[string]any{
						"pid":  pc.ProductID.String(),
						"slug": pc.ProductSlug,
					}
					if pc.PlanID != nil {
						entry["plan"] = *pc.PlanID
					}
					products = append(products, entry)
				}
				accessTokenClaims["products"] = products
			}
		}
	} else {
		// client_credentials grant — no end-user, but the token is still
		// bound to the client's tenant. Without these two claims,
		// resource-server middleware that calls middleware.GetTenantID(c)
		// gets uuid.Nil and admin handlers reject with HTTP 400 "tenant ID
		// not found" (root cause of the provision-svcclient-* Crossplane
		// Job 2026-04-29 incident).
		//
		// `sub` is conventionally the client_id for client_credentials
		// tokens (Auth0/Okta/Keycloak default; aligns with RFC 8693 §4.3
		// guidance for service-to-service tokens). Resource servers that
		// expect `sub` to be a UUID see a non-UUID; parseLegacyIdentity in
		// token_service_validation.go falls through with claims.UserID =
		// uuid.Nil — the correct semantic (no human user behind this call).
		//
		// Mirrors what the iam_oauth_tokens row already records for
		// client_credentials grants (TenantID: client.TenantID below);
		// before this fix the in-flight JWT silently diverged from the
		// persisted row.
		accessTokenClaims["sub"] = client.ClientID
		accessTokenClaims["tenant_id"] = client.TenantID.String()
	}

	// Embed RAR authorization_details in the access token (RFC 9396 §7).
	s.rarService.EmbedInToken(accessTokenClaims, authzDetails)

	// Emit groups/roles/amr on the access token so resource servers (APISIX,
	// Pomerium, downstream services) can authorise without an extra /userinfo
	// round-trip. Subject to the same scope + per-client allowlist gating
	// as the id_token — matches the Auth0/Okta enterprise default.
	s.emitSubjectClaims(ctx, accessTokenClaims, user, client, scopes, authMethods)

	// Emit the OIDC Session Management 1.0 §5 `sid` claim on the access
	// token (in addition to the id_token below) so resource servers and
	// the /api/auth/me poller can scope cascade-revocation by sid without
	// a /userinfo round-trip. RPs that subscribe to the
	// OIDC Front-Channel Logout 1.0 cascade key off this claim. Migration
	// 220 is the underlying storage for the value.
	if idpSessionID != nil {
		accessTokenClaims["sid"] = idpSessionID.String()
	}

	// RFC 8693 §4.1 — delegation chain. When the caller initiated an
	// OAuth Token Exchange (TokenExchangeGrant stashes the actor via
	// WithTokenExchangeActor), stamp the `act` claim so downstream
	// receivers and audit logs see "actor X acted on behalf of subject
	// Y". For exchanges where the subject_token was itself externally
	// minted (e.g. Talon IAP JWT), the inner `iss` records the upstream
	// authentication authority, preserving the full delegation chain
	// per RFC 8693 §4.1.1 example A.1.
	//
	// Self-exchange (actor == subject — i.e. a user re-issuing their
	// own token) is silently suppressed: emitting act={sub: user_id}
	// when sub is already user_id would be meaningless noise.
	if actor := tokenExchangeActorFromContext(ctx); actor.ActorSub != "" {
		if subStr, _ := accessTokenClaims["sub"].(string); subStr != actor.ActorSub {
			actClaim := map[string]any{"sub": actor.ActorSub}
			if actor.ActorClientID != "" {
				actClaim["client_id"] = actor.ActorClientID
			}
			if actor.SubjectTokenIssuer != "" {
				actClaim["iss"] = actor.SubjectTokenIssuer
			}
			accessTokenClaims["act"] = actClaim
		}
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessTokenClaims)
	accessToken.Header["kid"] = s.keyID
	accessTokenString, err := accessToken.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Refresh-token generation: canonical rotate path mints fresh
	// random bytes; the "reuse" path (Duende BFF pattern for
	// confidential first-party clients) returns the same plaintext
	// the caller already holds. The reuse plaintext is stashed by
	// RefreshTokens via WithReuseRefreshToken when
	// client.RefreshTokenRotationPolicy == "reuse" — see that
	// branch for rotation-policy semantics.
	//
	// Either way we record the hash of the issued refresh_token on the
	// new access-token row so RevokeOAuthToken's `WHERE token=$1 OR
	// refresh_token=$1` continues to cascade-revoke the whole pair.
	// Reuse therefore yields multiple iam_oauth_tokens rows sharing
	// the same refresh_token hash; lookups by refresh-token hash are
	// satisfied by any one of them (the QueryRow contract returns the
	// first row found — every reuse row carries the same validation
	// state because they all stem from the same originally-minted
	// refresh).
	var refreshTokenString string
	if reuse := reuseRefreshTokenFromContext(ctx); reuse != "" {
		refreshTokenString = reuse
	} else {
		refreshTokenBytes := make([]byte, 32)
		if _, err := rand.Read(refreshTokenBytes); err != nil {
			return nil, fmt.Errorf("failed to generate refresh token: %w", err)
		}
		refreshTokenString = base64.RawURLEncoding.EncodeToString(refreshTokenBytes)
	}

	// Store tokens
	var userID *uuid.UUID
	if user != nil {
		userID = &user.ID
	}

	// Hash both tokens for storage — never store tokens in plaintext
	refreshTokenHash := s.hashSecret(refreshTokenString)

	oauthToken := &models.OAuthToken{
		ID:           uuid.New(),
		TenantID:     client.TenantID,
		ClientID:     client.ID,
		UserID:       userID,
		TokenType:    "access_token",
		Token:        s.hashSecret(accessTokenString), // Hash full JWT — its first ~70 chars are the identical header, so slicing would collide

		Scopes:       scopes,
		RefreshToken: &refreshTokenHash,
		IsRevoked:    false,
		ExpiresAt:    refreshTokenExpiry,
		CreatedAt:    now,
		UpdatedAt:    now,
		// Preserve the amr snapshot so refresh rotations carry it forward.
		AuthMethodsUsed: append([]string(nil), authMethods...),
		// Preserve the IdP session UUID so refresh rotations emit a stable
		// `sid` claim across the session lifetime (migration 220).
		IdpSessionID: idpSessionID,
	}

	// RFC 9700 §4.14 refresh-token family (lineage). On a rotation,
	// RefreshTokens stashes the parent's family id via WithRefreshTokenFamily
	// and we inherit it so the whole lineage stays revocable as one unit. On
	// any other grant path (auth_code, client_credentials, token-exchange)
	// nothing is stashed and this token ROOTS a new family at its own id.
	if fam := refreshTokenFamilyFromContext(ctx); fam != uuid.Nil {
		famCopy := fam
		oauthToken.TokenFamilyID = &famCopy
	} else {
		idCopy := oauthToken.ID
		oauthToken.TokenFamilyID = &idCopy
	}

	// Stamp the request IP captured by the handler (via WithRequestIP) so
	// the next refresh-token grant has a baseline to compare against and
	// can publish a CAEP CAEIPChanged signal on mismatch. Empty value →
	// preserve the pre-IP-binding behavior (column stays NULL).
	if ip := requestIPFromContext(ctx); ip != "" {
		ipCopy := ip
		oauthToken.IPAddress = &ipCopy
	}

	if err := tokenSink.CreateOAuthToken(ctx, oauthToken); err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	response := &models.OAuthTokenResponse{
		AccessToken:          accessTokenString,
		TokenType:            "Bearer",
		ExpiresIn:            int64(client.AccessTokenLifetime),
		RefreshToken:         refreshTokenString,
		Scope:                strings.Join(scopes, " "),
		AuthorizationDetails: authzDetails, // nil when no RAR was requested; omitted in JSON via omitempty
	}

	// Generate ID token if openid scope is requested and user exists
	if user != nil && s.containsString(scopes, "openid") {
		idToken, err := s.generateIDToken(ctx, client, user, scopes, nonce, authMethods, idpSessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ID token: %w", err)
		}
		response.IDToken = idToken
	}

	return response, nil
}

func (s *OAuthProviderService) generateIDToken(ctx context.Context, client *models.OAuthClient, user *models.User, scopes []string, nonce *string, authMethods []string, idpSessionID *uuid.UUID) (string, error) {
	now := time.Now()
	expiry := now.Add(time.Duration(client.IDTokenLifetime) * time.Second)

	claims := jwt.MapClaims{
		"iss": s.getIssuer(),
		"sub": user.ID.String(),
		"aud": client.ClientID,
		"iat": now.Unix(),
		"exp": expiry.Unix(),
	}

	if nonce != nil && *nonce != "" {
		claims["nonce"] = *nonce
	}

	// OIDC Session Management 1.0 §5 — `sid` claim binds the id_token to
	// the OP session that produced it so OIDC Front-Channel Logout 1.0
	// receivers can scope cascade-revocation to a single browser session
	// instead of fanning out across the subject. Mirrored on the access
	// token by the caller (see generateTokens) so resource servers can
	// drive sid-keyed invalidation without a /userinfo round-trip.
	if idpSessionID != nil {
		claims["sid"] = idpSessionID.String()
	}

	// Add standard OIDC claims based on scopes
	if s.containsString(scopes, "profile") {
		if user.DisplayName != nil {
			claims["name"] = *user.DisplayName
		}
		if user.FirstName != nil {
			claims["given_name"] = *user.FirstName
		}
		if user.LastName != nil {
			claims["family_name"] = *user.LastName
		}
		claims["preferred_username"] = user.Username
	}

	if s.containsString(scopes, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = user.IsEmailVerified
	}

	// tenant_id is a non-standard private claim following the pattern used by
	// Azure Entra ID ("tid") and Okta ("tid").  Including it in every id_token
	// (not gated on a scope) lets relying parties implement tenant-aware access
	// control without an extra /userinfo round-trip.
	claims["tenant_id"] = user.TenantID.String()

	// Emit groups/roles/amr per the OIDC claim-gap design
	// (docs/oidc-claims-groups-amr.md). `amr` is emitted whenever the
	// authentication-method snapshot is non-empty; `groups` and `roles` are
	// scope-gated AND per-client allowlisted.
	s.emitSubjectClaims(ctx, claims, user, client, scopes, authMethods)

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	idToken.Header["kid"] = s.keyID
	return idToken.SignedString(s.privateKey)
}

// ==================== UserInfo ====================

// GetUserByID loads the user record by UUID. Mirror of the
// userRepo.GetByID call but exposed on the service so handlers
// (notably continueAuthorize's ACR step-up gate) don't reach into
// the repository layer directly.
func (s *OAuthProviderService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}

// UserHasAnyMFAFactor reports whether the user has at least one
// enrolled MFA factor (TOTP, email OTP, WebAuthn credential, or push
// device). It is the source-of-truth check that the OAuth step-up gate
// uses to decide between routing to /mfa (factor exists) vs
// /mfa/enrollment (no factor) after MFA-required scopes are requested.
// The denormalized users.mfa_enabled flag remains for legacy reads,
// but routing decisions MUST go through this method so they cannot
// drift if mfa_enabled is mis-set.
func (s *OAuthProviderService) UserHasAnyMFAFactor(ctx context.Context, userID uuid.UUID) (bool, error) {
	return s.userRepo.HasAnyMFAFactor(ctx, userID)
}

// GetUserInfoByID loads the user record by UUID and renders the OIDC
// UserInfo response. Callers (e.g. the /oauth/userinfo handler) only hold
// the user_id from the validated access token context — this saves them
// from reaching into the repository layer directly.
func (s *OAuthProviderService) GetUserInfoByID(ctx context.Context, userID uuid.UUID, scopes []string) (*models.UserInfoResponse, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("GetUserInfoByID: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("GetUserInfoByID: user %s not found", userID)
	}
	return s.GetUserInfo(ctx, user, scopes), nil
}

// GetUserInfo returns the user info for a valid access token
func (s *OAuthProviderService) GetUserInfo(_ context.Context, user *models.User, scopes []string) *models.UserInfoResponse {
	response := &models.UserInfoResponse{
		Sub: user.ID.String(),
	}

	if s.containsString(scopes, "profile") {
		if user.DisplayName != nil {
			response.Name = *user.DisplayName
		}
		if user.FirstName != nil {
			response.GivenName = *user.FirstName
		}
		if user.LastName != nil {
			response.FamilyName = *user.LastName
		}
		response.PreferredUsername = user.Username
		response.UpdatedAt = user.UpdatedAt.Unix()
	}

	if s.containsString(scopes, "email") {
		response.Email = user.Email
		response.EmailVerified = user.IsEmailVerified
	}

	return response
}

// ==================== OIDC Discovery ====================

// GetDiscoveryDocument returns the OIDC discovery document
func (s *OAuthProviderService) GetDiscoveryDocument() *models.OIDCDiscoveryDocument {
	issuer := s.getIssuer()

	// Auth methods accepted at /oauth/introspect and /oauth/revoke.
	// RFC 7662 §2.1 and RFC 7009 §2.1 require client authentication for
	// confidential clients on these endpoints; "none" is intentionally
	// omitted because Falcon-ID rejects public-client introspection
	// (Keycloak's confidential-only policy — public-client introspection
	// is the canonical token-fingerprinting vector).
	confidentialAuthMethods := []string{"client_secret_basic", "client_secret_post"}

	doc := &models.OIDCDiscoveryDocument{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/oauth/authorize",
		TokenEndpoint:                     issuer + "/oauth/token",
		UserinfoEndpoint:                  issuer + "/oauth/userinfo",
		JwksURI:                           issuer + "/.well-known/jwks.json",
		RevocationEndpoint:                issuer + "/oauth/revoke",
		IntrospectionEndpoint:             issuer + "/oauth/introspect",
		EndSessionEndpoint:                issuer + "/oauth/logout",
		ScopesSupported:                   []string{"openid", "profile", "email", "offline_access", OIDCScopeGroups, OIDCScopeRoles, OIDCScopeIntrospect},
		// OAuth 2.1 (IAM-04): only `code` is conformant. Implicit
		// (`token`, `id_token`, `id_token token`) and hybrid response
		// types (`code id_token`, `code token`, `code id_token token`)
		// are removed because we do not implement them and OAuth 2.1
		// BCP-225 deprecates the implicit-flow tokens-in-URL-fragment
		// pattern across the board.
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query", "fragment", "form_post"},
		GrantTypesSupported:               []string{"authorization_code", "client_credentials", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{oauthAlgRS256},
		// `tls_client_auth` per RFC 8705 §2.1 — PKI-mode mTLS client
		// authentication. Per-client opt-in via TLSClientAuthSubjectDN;
		// X-Forwarded-Client-Cert from APISIX is the wiring contract.
		// Advertised here so RPs running mTLS-only deployments can
		// auto-discover support; clients without a registered cert
		// continue to use client_secret_basic / client_secret_post.
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none", "tls_client_auth"},
		// Claims added 2026-04-21 to close the Phase B/E OIDC claim gap:
		//   groups, roles — client-gated authorization context
		//   amr           — RFC 8176 Authentication Method References
		//   tenant_id     — already emitted; advertising for honesty with consumers
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "nonce",
			"name", "given_name", "family_name", "preferred_username",
			"email", "email_verified",
			"tenant_id",
			OIDCScopeGroups, OIDCScopeRoles, "amr", "acr",
		},
		// AcrValuesSupported advertises the AAL ladder so RPs can request
		// passkey re-authentication via `acr_values=urn:hexxlock:aal3` on
		// their authorization request. AAL2 covers password+TOTP/email-OTP;
		// AAL3 is the phishing-resistant FIDO2/WebAuthn path.
		AcrValuesSupported:            []string{ACRValueAAL2, ACRValueAAL3},
		CodeChallengeMethodsSupported: []string{oauthAlgS256},

		// Conformance pack (2026-04-29) — RFC 7662/7009 + OIDC Discovery 1.0
		// fields that Auth0/Okta integration validators and the OpenID
		// Foundation conformance suite read on startup. Omitting any of
		// these forces RPs to hard-code the values in their config, so
		// every copy-paste becomes a future bug.
		IntrospectionEndpointAuthMethodsSupported: confidentialAuthMethods,
		RevocationEndpointAuthMethodsSupported:    confidentialAuthMethods,
		ClaimTypesSupported:                       []string{"normal"},
		// RFC 9101 — JAR shipped 2026-04-30 (commit 5530290). The
		// /oauth/authorize handler accepts the `request` parameter and
		// verifies it against the client's registered JWKS. Pre-fix
		// this was advertised false even though the path was wired,
		// causing FAPI 2.0 conformance probers + spec-aware RP SDKs
		// to skip JAR. `request_uri` is intentionally still false —
		// PAR is the request-by-reference pattern.
		RequestParameterSupported:                 true,
		RequestURIParameterSupported:              false,
		RequireRequestURIRegistration:             false,
		// RFC 9101 §10.5 — mirrors isSupportedJARAlg in
		// internal/services/oauth_provider_jar.go. Update both
		// in lockstep when adding a new alg.
		RequestObjectSigningAlgValuesSupported: []string{"RS256", "RS384", "RS512"},
		// RFC 9449 §5.1 — JWS algs accepted on DPoP proofs. RSA family
		// (RS / PS) and ECDSA P-256 (ES256). Mirrors what
		// pkg/dpop/dpop.go's parseJWK actually accepts.
		DPoPSigningAlgValuesSupported:         []string{"RS256", "PS256", "ES256"},
		ClaimsParameterSupported:              false,
		TLSClientCertificateBoundAccessTokens: false,
		// RFC 9207 — `iss` parameter in authorization response.
		// /oauth/authorize emits `iss=<issuer>` alongside `code` and
		// `state` so RPs can detect IdP mix-up attacks. Required by
		// FAPI 2.0 Baseline §5.4.
		AuthorizationResponseIssParameterSupported: true,
	}

	// Advertise the PAR endpoint only when the PAR store is configured (RFC 9126 §5).
	if s.parStore != nil {
		doc.PushedAuthorizationRequestEndpoint = issuer + "/oauth/par"
	}

	// OIDC Back-Channel Logout 1.0
	doc.BackchannelLogoutSupported = true
	doc.BackchannelLogoutSessionSupported = true

	// OIDC Front-Channel Logout 1.0
	// (https://openid.net/specs/openid-connect-frontchannel-1_0.html §4)
	// frontchannel_logout_session_supported=true: the OP includes `iss`
	// and `sid` query parameters in the iframe URL it renders for each
	// RP, letting RPs that registered with
	// frontchannel_logout_session_required=true scope the cascade to a
	// single browser session instead of fanning out across the subject.
	doc.FrontchannelLogoutSupported = true
	doc.FrontchannelLogoutSessionSupported = true

	return doc
}

// GetJWKS returns the JSON Web Key Set.
// When a KeyManager is wired, all active and rotated keys are returned so that
// clients can validate tokens issued before a key rotation (graceful rotation pattern).
func (s *OAuthProviderService) GetJWKS() *models.JWKSet {
	if s.keyManager != nil {
		return s.buildJWKSFromKeyManager()
	}
	return &models.JWKSet{
		Keys: []models.JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: s.keyID,
				Alg: oauthAlgRS256,
				N:   base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.publicKey.E)).Bytes()),
			},
		},
	}
}

// buildJWKSFromKeyManager assembles a JWKSet from all non-revoked keys held by
// the KeyManager. This enables graceful rotation: old tokens signed with a rotated
// key remain verifiable until the rotation window expires.
func (s *OAuthProviderService) buildJWKSFromKeyManager() *models.JWKSet {
	pubKeyInfos := s.keyManager.AllPublicKeys()
	jwkSet := &models.JWKSet{Keys: make([]models.JWK, 0, len(pubKeyInfos))}
	for _, info := range pubKeyInfos {
		rsaPub, ok := info.PublicKey.(*rsa.PublicKey)
		if !ok {
			// Skip non-RSA keys (e.g. EC keys) — only RS256 is advertised via RSA JWKs.
			continue
		}
		// Normalise algorithm label: RS256 is the standard JWA name regardless of how
		// it was stored in the DB.
		alg := info.Algorithm
		if alg == "" {
			alg = oauthAlgRS256
		}
		jwkSet.Keys = append(jwkSet.Keys, models.JWK{
			Kty: "RSA",
			Use: "sig",
			Kid: info.KeyID,
			Alg: alg,
			N:   base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPub.E)).Bytes()),
		})
	}
	return jwkSet
}

// ==================== Token Validation ====================

// ValidateAccessToken validates an access token and returns the claims
func (s *OAuthProviderService) ValidateAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// ==================== Client Authentication ====================

// AuthenticateClient authenticates a client using client_id and client_secret
func (s *OAuthProviderService) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*models.OAuthClient, error) {
	// Same error-transparency pattern as ValidateAuthorizeRequest — keep
	// the wire-level message generic for genuine "no such client_id", but
	// surface the underlying error (and structured-log it) for any other
	// failure so a stuck pgx pool or schema drift is diagnosable from
	// pod logs rather than presenting as an opaque "client not found".
	client, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, repositories.ErrOAuthClientNotFound) {
			return nil, fmt.Errorf("invalid_client: client not found")
		}
		logger.Error("OAuth client lookup failed in AuthenticateClient",
			zap.Error(err),
			zap.String("client_id", clientID),
		)
		return nil, fmt.Errorf("invalid_client: %w", err)
	}

	if !client.IsActive {
		return nil, fmt.Errorf("invalid_client: client is not active")
	}

	// Public clients don't need secret verification
	if client.IsPublic {
		return client, nil
	}

	// Verify client secret
	if !s.verifySecret(clientSecret, client.ClientSecret) {
		return nil, fmt.Errorf("invalid_client: invalid client secret")
	}

	return client, nil
}

// ==================== Consent Management ====================

// GetConsent retrieves the user's consent for a client
func (s *OAuthProviderService) GetConsent(ctx context.Context, userID, clientID uuid.UUID) (*models.OAuthConsent, error) {
	return s.clientRepo.GetConsent(ctx, userID, clientID)
}

// GrantConsent grants consent for a user to a client
func (s *OAuthProviderService) GrantConsent(ctx context.Context, userID, clientID uuid.UUID, scopes []string) error {
	consent := &models.OAuthConsent{
		ID:        uuid.New(),
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    scopes,
		GrantedAt: time.Now(),
	}
	return s.clientRepo.CreateOrUpdateConsent(ctx, consent)
}

// RevokeConsent revokes consent for a user to a client
func (s *OAuthProviderService) RevokeConsent(ctx context.Context, userID, clientID uuid.UUID) error {
	// Revoke only this user's tokens for the client (not all users' tokens)
	if err := s.clientRepo.RevokeUserClientTokens(ctx, userID, clientID); err != nil {
		return fmt.Errorf("RevokeConsent: %w", err)
	}
	return s.clientRepo.RevokeConsent(ctx, userID, clientID)
}

// GetUserConsents gets all consents for a user
func (s *OAuthProviderService) GetUserConsents(ctx context.Context, userID uuid.UUID) ([]*models.OAuthConsent, error) {
	return s.clientRepo.GetUserConsents(ctx, userID)
}

// GetUserConsentsEnriched returns the user's consents with display
// metadata (client name, logo, category, last-used) pre-joined.
// Backing call for the user-facing GET /api/v1/auth/oauth-consents.
func (s *OAuthProviderService) GetUserConsentsEnriched(ctx context.Context, userID uuid.UUID) ([]*models.OAuthConsentEnriched, error) {
	return s.clientRepo.GetUserConsentsEnriched(ctx, userID)
}

// ==================== Token Revocation (RFC 7009) ====================

// Revocation reasons emitted on the CAEP `session_revoked` event when the
// token revocation cascade runs. Receivers (Talon, future SCIM provisioners,
// downstream RPs subscribed to the SSE stream) inspect Metadata["reason"]
// to decide whether to invalidate sessions immediately or just log.
const (
	revokeReasonRPRequest  = "rp_revocation_request"
	revokeReasonRefreshCsd = "refresh_token_cascade"
)

// RevokeToken revokes an access or refresh token per RFC 7009.
//
// Conformance contract:
//
//   - The caller MUST be the confidential client that issued the token (RFC
//     7009 §2.1: "the authorization server first … verifies whether the
//     token was issued to the client making the revocation request"). When
//     callerClient.ID != tokenRow.ClientID we still return nil so the
//     handler emits 200 — RFC §2.2 forbids leaking token-existence by
//     varying the status code.
//
//   - Unknown / already-revoked / expired tokens return nil (idempotent
//     response, RFC §2.2).
//
//   - When the token is found, a CAEP `session_revoked` event is published
//     so Talon and any future SSE subscriber invalidate the local session
//     within the access-token TTL window. Best-effort — a CAEP publish
//     failure does NOT roll back the revocation.
//
//   - tokenTypeHint is honored as an OPTIMISATION hint only. The repository
//     query (`WHERE token=$1 OR refresh_token=$1`) already covers both
//     types in one round-trip, so RFC §2.1's "MUST extend its search across
//     all of its supported token types" obligation is satisfied implicitly.
func (s *OAuthProviderService) RevokeToken(ctx context.Context, callerClient *models.OAuthClient, token, _ string) error {
	if token == "" {
		return nil
	}

	// generateTokens stores hashSecret(<full token string>) on the row.
	// The earlier code truncated to first 32 chars here, which silently
	// no-op'd every /oauth/revoke call — fixed 2026-04-29.
	tokenHash := s.hashSecret(token)

	row, err := s.clientRepo.GetOAuthTokenByHash(ctx, tokenHash)
	if err != nil {
		// RFC 7009 §2.2: unknown token MUST return success (200).
		// Silent return so the caller cannot probe token existence by
		// observing HTTP status codes.
		return nil
	}

	if callerClient != nil && row.ClientID != callerClient.ID {
		// Cross-client revocation attempt. Per RFC 7009 §2.1 the request
		// "is refused" — but §2.2 forbids exposing token state. Resolve
		// the conflict the way Keycloak/Auth0 do: silently return 200
		// without performing the revoke. Audit log captures the attempt.
		return nil
	}

	if err := s.clientRepo.RevokeOAuthToken(ctx, tokenHash); err != nil {
		return fmt.Errorf("RevokeToken: %w", err)
	}

	// Emit CAEP session_revoked so SSE-subscribed RPs invalidate within
	// the AT TTL window. Best-effort — failure is logged inside the
	// publisher and does NOT roll back the DB write.
	s.publishTokenRevoked(ctx, row, revokeReasonRPRequest)

	return nil
}

// IntrospectToken implements RFC 7662 token introspection with mandatory
// revocation-store consultation (the default jwt-only validation path
// returned active=true even for tokens that had been revoked at /oauth/revoke
// or via refresh-token rotation).
//
// Conformance contract:
//
//   - Returns `{active: false}` for unknown tokens, expired tokens, revoked
//     tokens, and any token whose row's expires_at has passed (RFC 7662
//     §2.2: status code MUST be 200 in every "inactive" case).
//
//   - Per-client filter (defense vs introspection-as-discovery): a caller
//     introspecting a token issued to a *different* client gets
//     `{active: false}` UNLESS that caller holds the `oidc:introspect`
//     scope. The same-client path is always allowed, matching the Keycloak
//     and Curity reference behaviour.
//
//   - For access tokens the JWT signature is also verified to defeat tokens
//     replayed across a key rotation that have been pruned from the live
//     JWKS. JWT-validation failure → `{active: false}`.
//
// callerClient MUST be the authenticated client (post-authenticateClient).
// Public clients are rejected at the handler before reaching this method.
func (s *OAuthProviderService) IntrospectToken(ctx context.Context, token string, _ string, callerClient *models.OAuthClient) *models.OAuthIntrospectResponse {
	inactive := &models.OAuthIntrospectResponse{Active: false}
	if token == "" || callerClient == nil {
		return inactive
	}

	tokenHash := s.hashSecret(token)
	row, err := s.clientRepo.GetOAuthTokenByHash(ctx, tokenHash)
	if err != nil {
		return inactive
	}

	if row.IsRevoked || row.IsExpired() {
		return inactive
	}

	// Per-client filter — Keycloak's "audience-restricted introspection"
	// pattern: if the caller did not issue the token, they need the
	// `oidc:introspect` scope to see metadata. Otherwise we behave as if
	// the token does not exist.
	if row.ClientID != callerClient.ID && !containsScope(callerClient.Scopes, OIDCScopeIntrospect) {
		return inactive
	}

	// For access tokens (token column matched), verify the JWT signature
	// so a token whose signing key was rotated AND removed from the JWKS
	// (extremely rare, but possible during key-pinning incident response)
	// reports inactive. Refresh tokens are opaque random strings, not JWTs.
	isAccessToken := row.RefreshToken == nil || tokenHash != *row.RefreshToken

	resp := &models.OAuthIntrospectResponse{
		Active:    true,
		ClientID:  callerClient.ClientID, // canonical string client_id
		TokenType: "Bearer",
		ExpiresAt: row.ExpiresAt.Unix(),
		IssuedAt:  row.CreatedAt.Unix(),
		Issuer:    s.getIssuer(),
		Scope:     strings.Join(row.Scopes, " "),
	}

	// Resolve string client_id when caller introspects another client's
	// token via oidc:introspect — the response's `client_id` MUST be the
	// token's owner, not the caller (RFC 7662 §2.2).
	if row.ClientID != callerClient.ID {
		if owner, err := s.clientRepo.GetByID(ctx, row.ClientID); err == nil && owner != nil {
			resp.ClientID = owner.ClientID
		} else {
			// Owner lookup failed — better to omit than mislabel.
			resp.ClientID = ""
		}
	}

	if row.UserID != nil {
		resp.Subject = row.UserID.String()
	}

	if isAccessToken {
		claims, jwtErr := s.ValidateAccessToken(token)
		if jwtErr != nil {
			// Row exists and is unrevoked but JWT signature failed —
			// treat as inactive rather than leaking partial metadata.
			return inactive
		}
		// JWT claims override row-derived fields where they exist (the JWT
		// is the cryptographically authenticated source for sub/aud/iss).
		if sub, ok := claims["sub"].(string); ok && sub != "" {
			resp.Subject = sub
		}
		if iss, ok := claims["iss"].(string); ok && iss != "" {
			resp.Issuer = iss
		}
		if aud, ok := claims["aud"].(string); ok && aud != "" {
			resp.Audience = []string{aud}
		}
		if scope, ok := claims["scope"].(string); ok && scope != "" {
			resp.Scope = scope
		}
	}

	return resp
}

// publishTokenRevoked emits a CAEP session_revoked event for downstream
// receivers (Talon IAP, SSE subscribers). Wired only when SetCAEService
// has been called from the cmd/ wiring layer; missing publisher is a
// no-op so this MR remains shippable independent of the full CAEP fan-out
// stack (which is not yet wired in cmd/handlers.go).
func (s *OAuthProviderService) publishTokenRevoked(ctx context.Context, row *models.OAuthToken, reason string) {
	if s.caeService == nil || row == nil {
		return
	}
	userID := uuid.Nil
	if row.UserID != nil {
		userID = *row.UserID
	}
	_ = s.caeService.PublishEvent(ctx, CAEEvent{
		Type:      CAESessionRevoked,
		UserID:    userID,
		TenantID:  row.TenantID,
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"reason":       reason,
			"client_id":    row.ClientID.String(),
			"token_row_id": row.ID.String(),
		},
	})
}

// RevokeAllClientTokens revokes all tokens for a client
func (s *OAuthProviderService) RevokeAllClientTokens(ctx context.Context, clientID uuid.UUID) error {
	return s.clientRepo.RevokeAllClientTokens(ctx, clientID)
}

// containsScope returns true when scope is present in scopes (linear scan;
// the registered scope list per client is small).
func containsScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// ==================== Helper Functions ====================

func (s *OAuthProviderService) generateClientID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generateClientID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (s *OAuthProviderService) generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generateClientSecret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (s *OAuthProviderService) hashSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// verifySecret authenticates a presented client_secret against the stored hash.
//
// Two hash formats are supported transparently:
//
//  1. **bcrypt** (`$2a$…` / `$2b$…` / `$2y$…`) — used by callers that
//     register OAuth clients through the Crossplane ServiceClientClaim
//     provisioner Job, which hashes with bcrypt at cost 12 (matching the
//     password/app-registration path elsewhere in this codebase).
//  2. **SHA-256 base64-rawurl** — falcon-id's own admin API
//     (CreateClient / RegenerateSecret) writes this format.
//
// Branching on the stored prefix lets pre-existing clients of either origin
// authenticate against the same /oauth/token handler. bcrypt is preferred for
// new writes; the SHA-256 branch remains for backward compatibility with
// clients minted before the migration.
func (s *OAuthProviderService) verifySecret(secret, hash string) bool {
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		// bcrypt.CompareHashAndPassword is constant-time relative to the
		// presented secret length and self-rate-limits via cost-12.
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)) == nil
	}
	computed := s.hashSecret(secret)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1
}

// verifyCodeChallenge uses constant-time comparison to prevent timing side-channel attacks.
// Only S256 method is supported; "plain" is rejected for security.
func (s *OAuthProviderService) verifyCodeChallenge(challenge, verifier, method string) bool {
	if method != "" && method != oauthAlgS256 {
		return false
	}

	// S256
	hash := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	return subtle.ConstantTimeCompare([]byte(challenge), []byte(computed)) == 1
}

func (s *OAuthProviderService) containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (s *OAuthProviderService) isStandardScope(scope string) bool {
	standardScopes := []string{"openid", "profile", "email", "address", "phone", "offline_access"}
	return s.containsString(standardScopes, scope)
}

func (s *OAuthProviderService) getIssuer() string {
	issuer := os.Getenv("OAUTH_ISSUER")
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%s", s.cfg.ServicePort)
	}
	return issuer
}

// Issuer is the public accessor for the canonical OAuth issuer URL used
// across token signing, discovery, and the RFC 9207 authorization
// response `iss` parameter (handled at /oauth/authorize). Mirrors
// getIssuer so handlers can compose the auth-response redirect without
// reaching into the service's private state.
func (s *OAuthProviderService) Issuer() string {
	return s.getIssuer()
}

// ==================== End Session ====================

// EndSession validates an id_token_hint and returns the associated client and user ID.
// Used by the OIDC RP-Initiated Logout endpoint.
func (s *OAuthProviderService) EndSession(ctx context.Context, idTokenHint string) (*models.OAuthClient, *uuid.UUID, error) {
	// Parse and validate the id_token JWT
	claims, err := s.ValidateAccessToken(idTokenHint)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid id_token_hint: %w", err)
	}

	// Extract client_id from aud claim
	var clientIDStr string
	switch aud := claims["aud"].(type) {
	case string:
		clientIDStr = aud
	case []interface{}:
		if len(aud) > 0 {
			if s, ok := aud[0].(string); ok {
				clientIDStr = s
			}
		}
	}
	if clientIDStr == "" {
		return nil, nil, fmt.Errorf("id_token_hint missing aud claim")
	}

	client, err := s.clientRepo.GetByClientID(ctx, clientIDStr)
	if err != nil {
		return nil, nil, fmt.Errorf("client not found for id_token_hint: %w", err)
	}

	// Extract user_id from sub claim
	var userID *uuid.UUID
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		parsed, err := uuid.Parse(sub)
		if err == nil {
			userID = &parsed
		}
	}

	return client, userID, nil
}
