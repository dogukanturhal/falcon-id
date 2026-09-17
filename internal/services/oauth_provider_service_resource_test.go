// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the multi-audience emission policy on OAuth tokens
// (see services/audience.go for the migration rationale).
//
// Before 2026-05-30: `aud` was a single string — either the
// RFC 8707 `resource` parameter when supplied, otherwise the OAuth
// client_id (Google-style "token is for this client").
//
// After 2026-05-30: `aud` is always an ARRAY containing the platform's
// shared identifiers + the per-resource narrowing. The migration
// transitions every .NET / Go service in the mesh off the legacy
// hard-coded `hexxlock-services` audience onto the canonical
// `PlatformAPIAudienceURI` (= "https://api.hexxlock.com") without
// requiring lock-step deploys.
//
// `aud` SHAPE CONTRACTS (locked 2026-05-30):
//
//   No resource supplied:
//     aud = [client_id, PlatformAPIAudienceURI, LegacyServiceMeshAudience]
//
//   Resource supplied (RFC 8707 §2):
//     aud = [resource, LegacyServiceMeshAudience]
//     — client_id is dropped because the caller has been explicit about
//       the target resource; LegacyServiceMeshAudience stays for the
//       transition window so unmigrated receivers still accept.
//
// When every receiver has migrated and `Jwt__Audience: hexxlock-services`
// is removed from all service deployments, `LegacyServiceMeshAudience`
// is dropped from these arrays too (and from services/audience.go).

// audSlice unwraps a `claims["aud"]` value into a string slice regardless
// of whether the JWT library serialised it as a single string or an
// array. RFC 7519 §4.1.3 permits both shapes; here we always emit an
// array but the helper is defensive in case a code path drops to single
// string in future.
func audSlice(t *testing.T, claims map[string]interface{}) []string {
	t.Helper()
	raw, ok := claims["aud"]
	require.True(t, ok, "claims must contain `aud`")
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			require.True(t, ok, "aud array entries must be strings (got %T)", item)
			out = append(out, s)
		}
		return out
	default:
		t.Fatalf("unexpected aud type %T", raw)
		return nil
	}
}

func TestGenerateTokens_Resource_OverridesAudClaim(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	ctx := WithOAuthResource(context.Background(), "https://api.hexxlock.com/v1")

	resp, err := svc.generateTokens(
		ctx,
		client, user,
		[]string{"openid"}, nil, nil,
		[]string{"pwd"},
		nil,
	)
	require.NoError(t, err)
	require.NotEmpty(t, resp.AccessToken)

	claims := decodeJWTUnverified(t, resp.AccessToken)
	aud := audSlice(t, claims)

	assert.Contains(t, aud, "https://api.hexxlock.com/v1",
		"explicit RFC 8707 resource MUST appear in aud")
	assert.Contains(t, aud, LegacyServiceMeshAudience,
		"LegacyServiceMeshAudience MUST stay in aud during the migration window")
	assert.NotContains(t, aud, client.ClientID,
		"when caller supplies an explicit resource, client_id MUST NOT be added (caller has narrowed the target)")
}

func TestGenerateTokens_Resource_AbsentEmitsDefaultMultiAud(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	// No resource in context — the default multi-aud array applies.
	resp, err := svc.generateTokens(
		context.Background(),
		client, user,
		[]string{"openid"}, nil, nil,
		[]string{"pwd"},
		nil,
	)
	require.NoError(t, err)

	claims := decodeJWTUnverified(t, resp.AccessToken)
	aud := audSlice(t, claims)

	assert.Contains(t, aud, client.ClientID,
		"client_id MUST be in aud — audience-confusion defence at the client level")
	assert.Contains(t, aud, PlatformAPIAudienceURI,
		"PlatformAPIAudienceURI MUST be in aud — NEW canonical resource identifier")
	assert.Contains(t, aud, LegacyServiceMeshAudience,
		"LegacyServiceMeshAudience MUST be in aud during the migration window")
}

func TestGenerateTokens_Resource_EmptyContextValueIsIgnored(t *testing.T) {
	// WithOAuthResource intentionally short-circuits on "" so a
	// caller that passes an empty form value doesn't override `aud`
	// with an empty string. The aud array must then match the
	// no-resource case exactly.
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	ctx := WithOAuthResource(context.Background(), "") // no-op

	resp, err := svc.generateTokens(
		ctx,
		client, user,
		[]string{"openid"}, nil, nil,
		[]string{"pwd"},
		nil,
	)
	require.NoError(t, err)

	claims := decodeJWTUnverified(t, resp.AccessToken)
	aud := audSlice(t, claims)

	assert.Contains(t, aud, client.ClientID,
		"empty resource MUST behave identically to no resource — client_id present")
	assert.Contains(t, aud, PlatformAPIAudienceURI,
		"empty resource MUST behave identically to no resource — PlatformAPIAudienceURI present")
	assert.Contains(t, aud, LegacyServiceMeshAudience,
		"empty resource MUST behave identically to no resource — LegacyServiceMeshAudience present")
}
