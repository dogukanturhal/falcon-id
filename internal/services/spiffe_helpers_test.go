// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ============================================================================
// ParseSPIFFETrustDomain
// ============================================================================

func TestParseSPIFFETrustDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		spiffeID   string
		wantDomain string
		wantErrSub string // non-empty means we expect an error containing this substring
	}{
		{
			name:       "simple trust domain and path",
			spiffeID:   "spiffe://example.com/workload/api-server",
			wantDomain: "example.com",
		},
		{
			name:       "trust domain with port",
			spiffeID:   "spiffe://spire.internal:8443/ns/default/sa/frontend",
			wantDomain: "spire.internal:8443",
		},
		{
			name:       "deeply nested workload path",
			spiffeID:   "spiffe://prod.example.com/k8s/ns/payments/sa/checkout",
			wantDomain: "prod.example.com",
		},
		{
			name:       "empty string",
			spiffeID:   "",
			wantErrSub: "must not be empty",
		},
		{
			name:       "wrong scheme",
			spiffeID:   "https://example.com/workload",
			wantErrSub: `scheme must be "spiffe"`,
		},
		{
			name:       "missing trust domain",
			spiffeID:   "spiffe:///workload/path",
			wantErrSub: "trust domain (authority) must not be empty",
		},
		{
			name:       "no workload path",
			spiffeID:   "spiffe://example.com",
			wantErrSub: "workload path",
		},
		{
			name:       "root path only",
			spiffeID:   "spiffe://example.com/",
			wantErrSub: "workload path",
		},
		{
			name:       "upper-case trust domain",
			spiffeID:   "spiffe://Example.COM/workload/api",
			wantErrSub: "lower-case",
		},
		{
			name:       "query string present",
			spiffeID:   "spiffe://example.com/workload?foo=bar",
			wantErrSub: "query string",
		},
		{
			name:       "fragment present",
			spiffeID:   "spiffe://example.com/workload#section",
			wantErrSub: "fragment",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseSPIFFETrustDomain(tc.spiffeID)
			if tc.wantErrSub != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrSub)
				assert.Empty(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantDomain, got)
			}
		})
	}
}

// ============================================================================
// ValidateSPIFFEID
// ============================================================================

func TestValidateSPIFFEID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		spiffeID   string
		wantErrSub string
	}{
		// Valid IDs
		{
			name:     "minimal valid id",
			spiffeID: "spiffe://td.example/svc",
		},
		{
			name:     "multi-segment workload path",
			spiffeID: "spiffe://example.com/ns/default/sa/api",
		},
		{
			name:     "trust domain with port",
			spiffeID: "spiffe://trust.internal:9090/workload",
		},
		{
			name:     "subdomain trust domain",
			spiffeID: "spiffe://spire.prod.example.com/frontend",
		},
		// Invalid IDs
		{
			name:       "empty string",
			spiffeID:   "",
			wantErrSub: "must not be empty",
		},
		{
			name:       "scheme is http not spiffe",
			spiffeID:   "http://example.com/workload",
			wantErrSub: `scheme must be "spiffe"`,
		},
		{
			name:       "scheme is urn",
			spiffeID:   "urn:example:workload",
			wantErrSub: `scheme must be "spiffe"`,
		},
		{
			name:       "missing authority",
			spiffeID:   "spiffe:///path/workload",
			wantErrSub: "trust domain (authority) must not be empty",
		},
		{
			name:       "no path after trust domain",
			spiffeID:   "spiffe://example.com",
			wantErrSub: "workload path",
		},
		{
			name:       "path is bare slash",
			spiffeID:   "spiffe://example.com/",
			wantErrSub: "workload path",
		},
		{
			name:       "upper-case host",
			spiffeID:   "spiffe://EXAMPLE.COM/workload",
			wantErrSub: "lower-case",
		},
		{
			name:       "mixed-case host",
			spiffeID:   "spiffe://Spire.Example.com/workload",
			wantErrSub: "lower-case",
		},
		{
			name:       "query string",
			spiffeID:   "spiffe://example.com/workload?key=val",
			wantErrSub: "query string",
		},
		{
			name:       "fragment",
			spiffeID:   "spiffe://example.com/workload#anchor",
			wantErrSub: "fragment",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateSPIFFEID(tc.spiffeID)
			if tc.wantErrSub != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrSub)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// TrustDomainFromIssuer
// ============================================================================

func TestTrustDomainFromIssuer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		issuerURL string
		want      string
	}{
		{
			name:      "plain https host",
			issuerURL: "https://spire.example.com",
			want:      "spire.example.com",
		},
		{
			name:      "https host with port",
			issuerURL: "https://spire.example.com:8443",
			want:      "spire.example.com:8443",
		},
		{
			name:      "https host with trailing path",
			issuerURL: "https://spire.example.com/oidc",
			want:      "spire.example.com",
		},
		{
			name:      "http scheme (non-production)",
			issuerURL: "http://localhost:8443",
			want:      "localhost:8443",
		},
		{
			name:      "empty string returns empty",
			issuerURL: "",
			want:      "",
		},
		{
			name:      "host-only no scheme fallback",
			issuerURL: "spire.example.com",
			want:      "spire.example.com",
		},
		{
			name:      "host with path no scheme fallback",
			issuerURL: "spire.example.com/some/path",
			want:      "spire.example.com",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := TrustDomainFromIssuer(tc.issuerURL)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ============================================================================
// DefaultBundleEndpoint
// ============================================================================

func TestDefaultBundleEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		trustDomain string
		want        string
	}{
		{
			name:        "simple domain",
			trustDomain: "example.com",
			want:        "https://example.com/.well-known/jwks.json",
		},
		{
			name:        "domain with port",
			trustDomain: "spire.internal:8443",
			want:        "https://spire.internal:8443/.well-known/jwks.json",
		},
		{
			name:        "subdomain",
			trustDomain: "trust.prod.example.com",
			want:        "https://trust.prod.example.com/.well-known/jwks.json",
		},
		{
			name:        "empty string produces minimal url",
			trustDomain: "",
			want:        "https:///.well-known/jwks.json",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := DefaultBundleEndpoint(tc.trustDomain)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ============================================================================
// validateSPIFFEClaims (via TokenExchangeService)
// ============================================================================

func TestValidateSPIFFEClaims(t *testing.T) {
	t.Parallel()

	// Build a minimal TokenExchangeService — validateSPIFFEClaims only uses
	// the helper functions and the provider struct; no repo/logger calls are made.
	svc := &TokenExchangeService{}

	audienceVal := "falcon-id"

	providerBase := &models.WorkloadIdentityProvider{
		ProviderType: models.ProviderTypeSPIFFE,
		IssuerURL:    "https://spire.example.com",
	}

	providerWithAudience := &models.WorkloadIdentityProvider{
		ProviderType:  models.ProviderTypeSPIFFE,
		IssuerURL:     "https://spire.example.com",
		AudienceMatch: &audienceVal,
	}

	tests := []struct {
		name       string
		provider   *models.WorkloadIdentityProvider
		claims     map[string]interface{}
		wantErrSub string
	}{
		// Passing cases
		{
			name:     "valid SPIFFE ID matching trust domain",
			provider: providerBase,
			claims: map[string]interface{}{
				"sub": "spiffe://spire.example.com/ns/default/sa/api",
			},
		},
		{
			name:     "valid with string audience claim",
			provider: providerWithAudience,
			claims: map[string]interface{}{
				"sub": "spiffe://spire.example.com/workload/backend",
				"aud": audienceVal,
			},
		},
		{
			name:     "valid with slice audience claim",
			provider: providerWithAudience,
			claims: map[string]interface{}{
				"sub": "spiffe://spire.example.com/workload/backend",
				"aud": []interface{}{"falcon-id", "other"},
			},
		},
		// Failing cases
		{
			name:       "missing sub claim",
			provider:   providerBase,
			claims:     map[string]interface{}{},
			wantErrSub: "missing sub claim",
		},
		{
			name:     "sub is not a SPIFFE ID",
			provider: providerBase,
			claims: map[string]interface{}{
				"sub": "system:serviceaccount:default:api",
			},
			wantErrSub: "invalid SPIFFE ID",
		},
		{
			name:     "trust domain mismatch",
			provider: providerBase,
			claims: map[string]interface{}{
				"sub": "spiffe://other.example.com/workload/api",
			},
			wantErrSub: "does not match provider trust domain",
		},
		{
			name:     "missing aud when audience_match configured",
			provider: providerWithAudience,
			claims: map[string]interface{}{
				"sub": "spiffe://spire.example.com/workload/api",
				// no "aud" key
			},
			wantErrSub: "aud claim missing",
		},
		{
			name:     "empty string aud when audience_match configured",
			provider: providerWithAudience,
			claims: map[string]interface{}{
				"sub": "spiffe://spire.example.com/workload/api",
				"aud": "",
			},
			wantErrSub: "aud claim is empty",
		},
		{
			name:     "empty slice aud when audience_match configured",
			provider: providerWithAudience,
			claims: map[string]interface{}{
				"sub": "spiffe://spire.example.com/workload/api",
				"aud": []interface{}{},
			},
			wantErrSub: "aud claim is empty",
		},
		{
			name:     "invalid SPIFFE ID in sub — no workload path",
			provider: providerBase,
			claims: map[string]interface{}{
				"sub": "spiffe://spire.example.com",
			},
			wantErrSub: "invalid SPIFFE ID",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := svc.validateSPIFFEClaims(tc.provider, tc.claims)
			if tc.wantErrSub != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrSub)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// resolveJWKSURL — SPIFFE branch
// ============================================================================

func TestResolveJWKSURL_SPIFFE(t *testing.T) {
	t.Parallel()

	svc := &TokenExchangeService{}

	t.Run("derives bundle endpoint from issuer when jwks_endpoint absent", func(t *testing.T) {
		t.Parallel()
		p := &models.WorkloadIdentityProvider{
			ProviderType: models.ProviderTypeSPIFFE,
			IssuerURL:    "https://spire.example.com",
		}
		got := svc.resolveJWKSURL(p)
		assert.Equal(t, "https://spire.example.com/.well-known/jwks.json", got)
	})

	t.Run("uses explicit jwks_endpoint when provided", func(t *testing.T) {
		t.Parallel()
		endpoint := "https://spire.example.com/bundle/jwt"
		p := &models.WorkloadIdentityProvider{
			ProviderType: models.ProviderTypeSPIFFE,
			IssuerURL:    "https://spire.example.com",
			JWKSEndpoint: &endpoint,
		}
		got := svc.resolveJWKSURL(p)
		assert.Equal(t, endpoint, got)
	})

	t.Run("non-SPIFFE provider still uses OIDC discovery path", func(t *testing.T) {
		t.Parallel()
		p := &models.WorkloadIdentityProvider{
			ProviderType: models.ProviderTypeKubernetes,
			IssuerURL:    "https://kubernetes.default.svc",
		}
		got := svc.resolveJWKSURL(p)
		assert.Equal(t, "https://kubernetes.default.svc/.well-known/jwks.json", got)
	})
}
