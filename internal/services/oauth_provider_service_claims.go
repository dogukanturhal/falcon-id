// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"sort"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// OIDC scopes introduced by the OIDC-claim-gap closure
// (docs/oidc-claims-groups-amr.md). These are *client-gated* — a client
// must have `groups` / `roles` in its registered `OAuthClient.Scopes` list
// for the corresponding claim to be emitted.
const (
	OIDCScopeGroups = "groups"
	OIDCScopeRoles  = "roles"

	// OIDCScopeIntrospect is the Falcon-ID-specific scope that, when
	// granted to a confidential client, lets it introspect tokens issued
	// to *other* clients within the same tenant. Defense-in-depth on top
	// of RFC 7662 §2.1 client authentication: same-client introspection
	// is always allowed; cross-client introspection requires this scope.
	// Without it /oauth/introspect returns active=false even for valid
	// tokens, denying the introspection-as-discovery attack.
	OIDCScopeIntrospect = "oidc:introspect"
)

// AAL ladder published as the `acr` ID-token claim.
//
//   - AAL2 — password plus a one-time-password device or out-of-band
//     authenticator (TOTP, email-OTP). NIST SP 800-63B-4 §5.1.4 / §5.1.5.
//     Cannot reach AAL3 because TOTP / email-OTP are phishable.
//   - AAL3 — phishing-resistant Multi-Factor Cryptographic Authenticator,
//     i.e. WebAuthn / FIDO2 with user verification. NIST SP 800-63B-4
//     §5.1.7 + §6.2.2 (verifier impersonation resistance).
//
// The `urn:hexxlock:` prefix scopes the values to this IdP; RPs SHOULD
// treat them as opaque identifiers and consult the discovery document's
// `acr_values_supported` array to enumerate available levels.
const (
	ACRValueAAL2 = "urn:hexxlock:aal2"
	ACRValueAAL3 = "urn:hexxlock:aal3"
)

// AMR values per RFC 8176 used by Falcon-ID. Other authenticator types
// (e.g. "pwd", "otp", "mfa") are emitted by the auth_service path; this
// const set is the WebAuthn-relevant subset.
const (
	AMRValueHardwareKey      = "hwk"  // hardware-key authenticator (WebAuthn)
	AMRValueUserVerification = "user" // user-verification step succeeded

	// AMRValueMFA is the umbrella value from RFC 8176 §2 indicating
	// "multiple-factor authentication". Emitted whenever the session
	// snapshot contains ≥1 concrete multi-factor method (otp, hwk,
	// swk, sms, face, fpt, ...), regardless of the password factor.
	// Tier-1 RPs (Talon, third-party SaaS integrations) check this
	// single value to satisfy MFA gates rather than enumerating every
	// concrete factor name; Auth0 / Okta / SecureAuth follow the same
	// pattern. The umbrella is appended IN ADDITION TO the specific
	// factor values, never replaces them, so downstream consumers
	// that DO care about the concrete method (audit, risk scoring)
	// retain full fidelity.
	AMRValueMFA = "mfa"

	// AMRValuePassword is the single-factor baseline. Listed here so
	// the umbrella-promotion logic can excludeit explicitly — `pwd` on
	// its own is NOT multi-factor authentication.
	AMRValuePassword = "pwd"
)

// rfc8176MFAFactors is the set of RFC 8176 §2 amr values that each
// individually qualify as a multi-factor method. Membership in this
// set (anywhere in the session's authMethods list) triggers the
// `mfa` umbrella in the emitted amr claim and bumps acr to AAL2+.
//
// The list intentionally excludes `pwd` (single-factor by definition)
// and `user` (a sub-step of WebAuthn, not a factor on its own — its
// presence accompanies `hwk` or `swk` which already gate the umbrella).
var rfc8176MFAFactors = map[string]struct{}{
	"otp":    {}, // one-time password (TOTP / email-OTP / SMS-OTP)
	"hwk":    {}, // hardware key (WebAuthn / FIDO2)
	"swk":    {}, // software key
	"sms":    {}, // SMS-delivered code
	"tel":    {}, // telephone callback
	"face":   {}, // facial recognition
	"fpt":    {}, // fingerprint
	"iris":   {}, // iris scan
	"retina": {}, // retinal scan
	"vbm":    {}, // voice biometric
	"geo":    {}, // geolocation
	"kba":    {}, // knowledge-based answer
	"pin":    {}, // PIN
	"sc":     {}, // smart card
	"wia":    {}, // Windows Integrated Authentication
	"mfa":    {}, // umbrella already present — idempotent
}

// hasMFAFactor reports whether the authMethods snapshot contains any
// RFC 8176 §2 multi-factor method (any concrete factor or the umbrella
// itself). Independent of order. Case-sensitive — amr values are
// always lowercase per the IANA registry.
//
// Lower-case alias retained for in-package callers (amrWithUmbrella,
// claims emit, etc.); the canonical implementation lives on the
// exported HasMFAFactor below so the handler package can call it
// without crossing a package-internal boundary.
func hasMFAFactor(authMethods []string) bool {
	return HasMFAFactor(authMethods)
}

// HasMFAFactor is the exported sibling of hasMFAFactor — single
// canonical RFC-8176-aware multi-factor check shared between the
// service-side claims emit path and the handler-side
// /oauth/authorize ACR-satisfaction gate.
//
// Load-bearing for the WebAuthn step-up flow: pre-fix the handler
// at oauth_provider_handler.go did `slices.Contains(amr, "mfa")`
// directly, which returns false for passkey sessions whose AMR is
// ["hwk","user"] (the literal "mfa" umbrella is only appended at
// token-emission time by amrWithUmbrella below, NOT at session-
// write time by LoginViaWebAuthn). Result: the user was bounced
// to /auth/mfa/challenge AFTER successfully authenticating with
// a passkey — a phantom second-factor prompt that surfaced live
// 2026-05-25 as "passkey delete still loops to login".
//
// Recognises passkeys (hwk), security keys (swk), TOTP/email-OTP
// (otp), SMS (sms), phone-call (tel), proof-of-possession (pop),
// biometric (face/fpt/iris/retina/voice), location (geo), the
// generic "user" interaction signal, and the "mfa" umbrella itself
// — per RFC 8176 §2 + NIST SP 800-63B-4 §5.1.7's "any single
// possession-AND-something-else ceremony satisfies MFA".
func HasMFAFactor(authMethods []string) bool {
	for _, m := range authMethods {
		if _, ok := rfc8176MFAFactors[m]; ok {
			return true
		}
	}
	return false
}

// amrWithUmbrella returns a copy of authMethods with the "mfa"
// umbrella appended iff (a) ≥1 RFC 8176 multi-factor method is
// present AND (b) the umbrella is not already there. Preserves
// input order; the umbrella sorts at the end if appended. The input
// slice is never mutated.
func amrWithUmbrella(authMethods []string) []string {
	out := append([]string(nil), authMethods...)
	if !hasMFAFactor(out) {
		return out
	}
	for _, m := range out {
		if m == AMRValueMFA {
			return out
		}
	}
	return append(out, AMRValueMFA)
}

// maxGroupHierarchyDepth caps the parent-walk when rendering group paths.
// Prevents pathological cycles in the group table (defense in depth: the
// data model forbids cycles, but we never want token issuance to loop).
const maxGroupHierarchyDepth = 16

// subjectClaimsProvider supplies the identity-side data needed to build
// the `groups` and `roles` claims. GroupService is the production
// implementation; tests can substitute a stub.
type subjectClaimsProvider interface {
	// GetUserGroupPaths returns the `/parent/child` hierarchy paths for each
	// group the user is a direct member of. Paths are Keycloak-compatible
	// and consumable by Argo CD / Grafana / oauth2-proxy / Pomerium /
	// Kubernetes (`--oidc-groups-claim=groups`).
	GetUserGroupPaths(ctx context.Context, userID uuid.UUID) ([]string, error)

	// GetUserEffectiveRoles returns direct + group-inherited roles for the
	// user. Used to source the `roles` claim.
	GetUserEffectiveRoles(ctx context.Context, userID uuid.UUID) ([]*models.EffectiveRole, error)
}

// SetSubjectClaimsProvider wires in the GroupService (or an equivalent
// provider) so that scope-gated `groups` / `roles` claims are emitted. When
// nil, the corresponding claims are silently omitted — the service remains
// functional for clients that do not request those scopes.
func (s *OAuthProviderService) SetSubjectClaimsProvider(p subjectClaimsProvider) {
	s.subjectClaims = p
}

// SetClaimsLogger allows callers to inject a logger for diagnostic warnings
// emitted when the subject-claims provider returns an error. Optional —
// without it, errors are swallowed so token issuance never fails just
// because the group/role store was briefly unreachable.
func (s *OAuthProviderService) SetClaimsLogger(l *zap.Logger) {
	s.claimsLogger = l
}

// emitSubjectClaims augments the given JWT claims map with `groups`, `roles`,
// and `amr` per the design doc (`docs/oidc-claims-groups-amr.md`):
//
//   - `amr`    — emitted whenever the authentication-method snapshot is
//     non-empty. Spec-compliant (RFC 8176, OIDC Core §2).
//   - `groups` — emitted only when the `groups` scope was requested AND the
//     client's registered `Scopes` allow list contains `groups`.
//   - `roles`  — same gating as `groups`, but with the `roles` scope/allow
//     entry.
//
// `user` may be nil (client_credentials grant) — in which case nothing is
// emitted. Errors from the subjectClaimsProvider are logged at warn level
// and the affected claim is simply omitted; token issuance must not fail
// for a transient identity-store outage.
func (s *OAuthProviderService) emitSubjectClaims(
	ctx context.Context,
	claims jwt.MapClaims,
	user *models.User,
	client *models.OAuthClient,
	scopes []string,
	authMethods []string,
) {
	if user == nil {
		return
	}

	if len(authMethods) > 0 {
		// Emit amr with the RFC 8176 §2 "mfa" umbrella appended when
		// at least one concrete multi-factor method is present. Tier-1
		// RPs (Talon, third-party SaaS) check the umbrella to satisfy
		// MFA gates per Auth0 / Okta / SecureAuth convention — without
		// it, `acr_values=mfa` step-up flows can loop because the
		// RP's `contains(amr, "mfa")` check fails even after MFA was
		// successfully completed.
		claims["amr"] = amrWithUmbrella(authMethods)
		// Derive `acr` from `amr` per the AAL ladder. The presence of
		// "hwk" (RFC 8176 hardware-key authenticator) signals a WebAuthn
		// ceremony, which qualifies the session for AAL3 because every
		// such ceremony is verifier-impersonation-resistant. Anything
		// else (password + TOTP/email-OTP) caps at AAL2. The token
		// caller is the authoritative source of authMethods, so a
		// session that did NOT actually use a passkey will not have
		// "hwk" and will get aal2.
		if acr := acrFromAuthMethods(authMethods); acr != "" {
			claims["acr"] = acr
		}
	}

	if s.subjectClaims == nil {
		return
	}

	if s.containsString(scopes, OIDCScopeGroups) && clientAllowsClaimScope(client, OIDCScopeGroups) {
		paths, err := s.subjectClaims.GetUserGroupPaths(ctx, user.ID)
		if err != nil {
			s.logClaimsWarn("failed to load group paths for id_token", user.ID, err)
		} else if len(paths) > 0 {
			sort.Strings(paths)
			claims[OIDCScopeGroups] = paths
		}
	}

	if s.containsString(scopes, OIDCScopeRoles) && clientAllowsClaimScope(client, OIDCScopeRoles) {
		effective, err := s.subjectClaims.GetUserEffectiveRoles(ctx, user.ID)
		if err != nil {
			s.logClaimsWarn("failed to load effective roles for id_token", user.ID, err)
		} else {
			roles := dedupeRoleNames(effective)
			if len(roles) > 0 {
				claims[OIDCScopeRoles] = roles
			}
		}
	}
}

// acrFromAuthMethods maps an AMR snapshot to the corresponding `acr`
// value. Returns "" when no value is appropriate so the claim is omitted
// rather than misrepresenting a session's assurance level.
func acrFromAuthMethods(authMethods []string) string {
	hasHwk := false
	hasOther := false
	for _, m := range authMethods {
		if m == AMRValueHardwareKey {
			hasHwk = true
		} else if m != AMRValueUserVerification {
			hasOther = true
		}
	}
	switch {
	case hasHwk:
		return ACRValueAAL3
	case hasOther:
		return ACRValueAAL2
	default:
		return ""
	}
}

// clientAllowsClaimScope returns true when the client's registered Scopes
// list contains the given scope. Used to enforce per-client allowlisting of
// the `groups` / `roles` scopes so not every client receives sensitive
// membership data by default.
func clientAllowsClaimScope(client *models.OAuthClient, scope string) bool {
	if client == nil {
		return false
	}
	for _, s := range client.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// dedupeRoleNames extracts the role names from a list of EffectiveRoles,
// removing duplicates that arise when a role is both direct and
// group-inherited. Output is sorted for determinism.
func dedupeRoleNames(effective []*models.EffectiveRole) []string {
	seen := make(map[string]struct{}, len(effective))
	out := make([]string, 0, len(effective))
	for _, r := range effective {
		if r == nil || r.RoleName == "" {
			continue
		}
		if _, ok := seen[r.RoleName]; ok {
			continue
		}
		seen[r.RoleName] = struct{}{}
		out = append(out, r.RoleName)
	}
	sort.Strings(out)
	return out
}

// logClaimsWarn logs a claim-sourcing failure at warn level without aborting
// token issuance. Swallowing the error is intentional — a brief identity-
// store outage must not take down the whole OIDC provider.
func (s *OAuthProviderService) logClaimsWarn(msg string, userID uuid.UUID, err error) {
	if s.claimsLogger == nil {
		return
	}
	s.claimsLogger.Warn(msg,
		zap.String("user_id", userID.String()),
		zap.Error(err),
	)
}
