// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FAPI 2.0 Baseline Profile self-conformance suite.
//
// Source spec: https://openid.net/specs/fapi-2_0-baseline.html
//
// These tests assert the protocol-level invariants the OpenID Foundation
// FAPI 2.0 conformance suite probes when validating an authorization
// server. Running them locally on every push catches regressions that
// the OIDF suite would only catch at certification re-runs (months
// apart). Each test cites the specific spec section it pins so a
// future maintainer can find the rationale without reading source.
//
// Coverage matrix (FAPI 2.0 Baseline §4 + §5):
//
//   §4.3.1.1   PAR endpoint advertised when implemented        — TestDiscovery_PAREndpointAdvertised
//   §4.3.1.2   PKCE S256 supported                            — TestDiscovery_PKCES256Supported
//   §4.3.2     `iss` parameter advertised (RFC 9207)          — TestDiscovery_AuthorizationResponseIssAdvertised
//   §5.3.2.1   `request` parameter advertised (RFC 9101 JAR)  — TestDiscovery_JARAdvertised
//   §5.3.3     DPoP advertised when implemented (RFC 9449)    — TestDiscovery_DPoPAlgsAdvertised
//   §5.4       `code` is the only response_type               — TestDiscovery_OnlyCodeResponseType
//   §5.5       Implicit + ROPC grants rejected at registration — TestValidateGrants_RejectsImplicitAndROPC
//   §5.5       JAR algs whitelist is closed (no `none`)       — TestJARAlgs_RejectsNone
//   §5.6       Strong ID-token signing alg (no `none`/`HS*`)  — TestDiscovery_NoNoneOrHSAlgs
//
// The suite is organised so a CI failure points directly at the §
// of the spec that broke. If a future test is added, follow the
// pattern: assert one invariant, name the file by spec section,
// cite the section in the test doc-comment.

// TestDiscovery_PAREndpointAdvertised — FAPI 2.0 §4.3.1.1.
//
// Pushed Authorization Request endpoint MUST be advertised in the
// discovery document when the AS implements PAR (RFC 9126). The
// presence of `pushed_authorization_request_endpoint` is what tells
// FAPI 2.0-compliant RP SDKs to use PAR; without it they fall back
// to plain /authorize. We hide the field when parStore is nil so the
// advertisement stays honest with implementation state.
func TestDiscovery_PAREndpointAdvertised(t *testing.T) {
	svc := newTestOAuthService(t)
	// Wire an in-memory PAR store so the AS is PAR-capable for this
	// assertion. newTestOAuthService leaves parStore unset by default
	// because most tests don't exercise PAR; flipping the global
	// fixture would risk false positives elsewhere.
	svc.SetPARStore(newMemPARStore())
	doc := svc.GetDiscoveryDocument()

	require.NotNil(t, svc.parStore, "PAR store must be wired for this assertion")
	assert.NotEmpty(t, doc.PushedAuthorizationRequestEndpoint,
		"FAPI 2.0 §4.3.1.1: pushed_authorization_request_endpoint MUST be advertised when PAR is implemented")
	assert.Contains(t, doc.PushedAuthorizationRequestEndpoint, "/oauth/par",
		"PAR endpoint URL must point at /oauth/par")
}

// TestDiscovery_PAREndpointHiddenWhenNotConfigured — the inverse: when
// the PAR store is not wired, the endpoint MUST NOT be advertised.
// Honest discovery prevents probers from hitting an unimplemented
// surface and getting confusing errors.
func TestDiscovery_PAREndpointHiddenWhenNotConfigured(t *testing.T) {
	svc := newTestOAuthService(t) // parStore deliberately unset
	require.Nil(t, svc.parStore, "test fixture pre-condition: parStore must start unset")
	doc := svc.GetDiscoveryDocument()
	assert.Empty(t, doc.PushedAuthorizationRequestEndpoint,
		"PAR endpoint must NOT be advertised when no PAR store is wired")
}

// TestDiscovery_PKCES256Supported — FAPI 2.0 §4.3.1.2.
//
// All authorization-code requests MUST be PKCE-protected with the
// S256 method. The discovery doc MUST advertise S256 in
// code_challenge_methods_supported so RP SDKs pick the right method.
// `plain` is intentionally rejected by FAPI 2.0 because it offers no
// channel-binding protection.
func TestDiscovery_PKCES256Supported(t *testing.T) {
	svc := newTestOAuthService(t)
	doc := svc.GetDiscoveryDocument()
	assert.Contains(t, doc.CodeChallengeMethodsSupported, "S256",
		"FAPI 2.0 §4.3.1.2: code_challenge_methods_supported MUST include S256")
	assert.NotContains(t, doc.CodeChallengeMethodsSupported, "plain",
		"FAPI 2.0 §4.3.1.2: plain PKCE method must not be advertised — it offers no binding")
}

// TestDiscovery_AuthorizationResponseIssAdvertised — RFC 9207, FAPI 2.0
// Baseline §5.4.
//
// `authorization_response_iss_parameter_supported: true` tells RP
// SDKs that the AS emits `iss=<issuer>` on the authorize redirect,
// which lets the RP detect the IdP mix-up attack (where the attacker
// tricks an honest RP into sending the auth code received from a
// malicious IdP to the honest IdP's /token endpoint). Without the
// advertisement, RP SDKs that DO support the check skip it.
func TestDiscovery_AuthorizationResponseIssAdvertised(t *testing.T) {
	svc := newTestOAuthService(t)
	doc := svc.GetDiscoveryDocument()
	assert.True(t, doc.AuthorizationResponseIssParameterSupported,
		"RFC 9207 / FAPI 2.0 §5.4: authorization_response_iss_parameter_supported MUST be true")
}

// TestDiscovery_JARAdvertised — RFC 9101, FAPI 2.0 §5.3.2.1.
//
// JWT-Secured Authorization Request (`request` parameter) shipped in
// commit 5530290. The discovery doc MUST advertise both the
// `request_parameter_supported` flag and a non-empty
// `request_object_signing_alg_values_supported` list. Without the
// alg list, FAPI 2.0 spec-aware RP SDKs refuse to send signed
// requests because they have no declared-supported alg to pick.
func TestDiscovery_JARAdvertised(t *testing.T) {
	svc := newTestOAuthService(t)
	doc := svc.GetDiscoveryDocument()
	assert.True(t, doc.RequestParameterSupported,
		"RFC 9101 / FAPI 2.0 §5.3.2.1: request_parameter_supported MUST be true (JAR shipped)")
	assert.NotEmpty(t, doc.RequestObjectSigningAlgValuesSupported,
		"RFC 9101 §10.5: request_object_signing_alg_values_supported MUST be advertised when JAR is implemented")
	// The advertised list MUST mirror what VerifyJARRequestObject
	// actually accepts. Drift here is exactly the bug class FAPI 2.0
	// conformance probers catch.
	for _, alg := range doc.RequestObjectSigningAlgValuesSupported {
		assert.True(t, isSupportedJARAlg(alg),
			"discovery advertises %q but VerifyJARRequestObject does not accept it — drift", alg)
	}
	assert.NotContains(t, doc.RequestObjectSigningAlgValuesSupported, "none",
		"RFC 9101 §10.5: alg=none MUST NEVER be advertised (defeats signature)")
	assert.NotContains(t, doc.RequestObjectSigningAlgValuesSupported, "HS256",
		"FAPI 2.0 §5.6: HMAC algs MUST NOT be advertised on a public IdP (key-as-secret antipattern)")
}

// TestDiscovery_DPoPAlgsAdvertised — RFC 9449 §5.1, FAPI 2.0 §5.3.3.
//
// When the AS supports DPoP, it MUST advertise the JWS algs it accepts
// on DPoP proofs. Falcon-ID accepts proofs whose JWK kty is RSA (RS*)
// or EC P-256 (ES256). Spec-aware RP SDKs read this list to pick a
// proof signing key.
func TestDiscovery_DPoPAlgsAdvertised(t *testing.T) {
	svc := newTestOAuthService(t)
	doc := svc.GetDiscoveryDocument()
	assert.NotEmpty(t, doc.DPoPSigningAlgValuesSupported,
		"RFC 9449 §5.1: dpop_signing_alg_values_supported MUST be advertised when DPoP is implemented")
	// Hardened algs only — none of "none"/HS*.
	for _, alg := range doc.DPoPSigningAlgValuesSupported {
		assert.True(t,
			alg == "RS256" || alg == "RS384" || alg == "RS512" ||
				alg == "PS256" || alg == "PS384" || alg == "PS512" ||
				alg == "ES256" || alg == "ES384" || alg == "ES512",
			"DPoP advertised alg %q must be a strong asymmetric JWS alg (no `none`/HMAC/RSA1_5)", alg)
	}
}

// TestDiscovery_OnlyCodeResponseType — FAPI 2.0 §5.4.
//
// FAPI 2.0 Baseline mandates the authorization-code grant only. The
// discovery doc MUST advertise just `code`; advertising `token` or
// `id_token` would invite RPs to use the implicit flow, which OAuth
// 2.1 BCP-225 deprecates outright.
func TestDiscovery_OnlyCodeResponseType(t *testing.T) {
	svc := newTestOAuthService(t)
	doc := svc.GetDiscoveryDocument()
	assert.Equal(t, []string{"code"}, doc.ResponseTypesSupported,
		"FAPI 2.0 §5.4: response_types_supported MUST be exactly [code]")
	for _, rt := range doc.ResponseTypesSupported {
		for _, part := range strings.Fields(rt) {
			assert.NotEqual(t, "token", part, "implicit-flow `token` response part MUST NOT appear")
			assert.NotEqual(t, "id_token", part, "implicit-flow `id_token` response part MUST NOT appear")
		}
	}
}

// TestValidateGrants_RejectsImplicitAndROPC — FAPI 2.0 §5.5 / OAuth
// 2.1 BCP-225 §10.
//
// The service-layer validator MUST refuse to register a client whose
// grant_types includes `implicit` or `password` (ROPC). This is the
// guard at the registration boundary; the runtime guard at /oauth/token
// (switch default → unsupported_grant_type) is the second layer.
func TestValidateGrants_RejectsImplicitAndROPC(t *testing.T) {
	svc := newTestOAuthService(t)

	cases := []struct {
		name   string
		grants []string
		want   string
	}{
		{"implicit alone", []string{"implicit"}, "implicit"},
		{"ROPC alone", []string{"password"}, "Resource Owner Password Credentials"},
		{"implicit mixed with code", []string{"authorization_code", "implicit"}, "implicit"},
		{"ROPC mixed with code", []string{"authorization_code", "password"}, "Resource Owner"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.validateOAuth21GrantsAndResponses(tc.grants, []string{"code"})
			require.Error(t, err, "FAPI 2.0 §5.5: registration MUST reject deprecated grant_type")
			assert.Contains(t, err.Error(), tc.want,
				"error must clearly identify the rejected grant for operator clarity")
		})
	}
}

// TestValidateResponseTypes_RejectsImplicitFragments — FAPI 2.0 §5.4.
//
// Composite response_types ("code id_token", "code token id_token")
// implicitly include implicit-flow token return and MUST be rejected.
// `code` alone is the only conformant value.
func TestValidateResponseTypes_RejectsImplicitFragments(t *testing.T) {
	svc := newTestOAuthService(t)

	cases := []struct {
		name string
		rt   []string
	}{
		{"plain token", []string{"token"}},
		{"plain id_token", []string{"id_token"}},
		{"hybrid code id_token", []string{"code id_token"}},
		{"hybrid code token", []string{"code token"}},
		{"hybrid code id_token token", []string{"code id_token token"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.validateOAuth21GrantsAndResponses([]string{"authorization_code"}, tc.rt)
			require.Error(t, err, "FAPI 2.0 §5.4: implicit-fragment response_type MUST be rejected")
			assert.Contains(t, err.Error(), "implicit-flow",
				"error must mention implicit-flow for operator clarity")
		})
	}
}

// TestJARAlgs_RejectsNone — RFC 9101 §10.5 / FAPI 2.0 §5.6.
//
// The JAR verifier MUST close the alg=none + alg=HS* footguns. The
// implementation does this via `jwt.WithValidMethods([]string{allowedAlg})`
// at parse time AND via `isSupportedJARAlg` at the entry-point check.
// This test pins both.
func TestJARAlgs_RejectsNone(t *testing.T) {
	for _, bad := range []string{"none", "HS256", "HS384", "HS512", ""} {
		t.Run(bad, func(t *testing.T) {
			assert.False(t, isSupportedJARAlg(bad),
				"isSupportedJARAlg must reject %q (FAPI 2.0 §5.6 / RFC 9101 §10.5)", bad)
		})
	}
}

// TestDiscovery_NoNoneOrHSAlgs — FAPI 2.0 §5.6.
//
// `none` and HMAC algs (HS256/384/512) MUST NEVER appear in the
// discovery doc's signing-alg lists for a public IdP. `none` defeats
// signature verification entirely; HS* makes the signing key a
// shared-secret which a public IdP fundamentally cannot have.
func TestDiscovery_NoNoneOrHSAlgs(t *testing.T) {
	svc := newTestOAuthService(t)
	doc := svc.GetDiscoveryDocument()

	all := append([]string{}, doc.IDTokenSigningAlgValuesSupported...)
	all = append(all, doc.RequestObjectSigningAlgValuesSupported...)
	all = append(all, doc.DPoPSigningAlgValuesSupported...)

	for _, alg := range all {
		assert.NotEqual(t, "none", alg,
			"FAPI 2.0 §5.6: alg=none MUST NEVER appear in any advertised list")
		assert.False(t, strings.HasPrefix(alg, "HS"),
			"FAPI 2.0 §5.6: HMAC alg %q MUST NOT appear in a public IdP discovery doc", alg)
	}
}

// TestDiscovery_GrantTypesSupported_NoLegacy — FAPI 2.0 §5.5.
//
// `grant_types_supported` MUST NOT include `implicit` or `password`
// (ROPC). Falcon-ID retains `authorization_code`, `client_credentials`,
// and `refresh_token` — the OAuth 2.1 conformant set.
func TestDiscovery_GrantTypesSupported_NoLegacy(t *testing.T) {
	svc := newTestOAuthService(t)
	doc := svc.GetDiscoveryDocument()
	for _, g := range doc.GrantTypesSupported {
		assert.NotEqual(t, "implicit", g,
			"FAPI 2.0 §5.5: grant_types_supported MUST NOT include implicit")
		assert.NotEqual(t, "password", g,
			"FAPI 2.0 §5.5: grant_types_supported MUST NOT include password (ROPC)")
	}
}
