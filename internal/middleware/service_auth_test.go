// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensure mockUsageRecorder satisfies the ServicePrincipalUsageRecorder interface at compile time.
var _ ServicePrincipalUsageRecorder = (*mockUsageRecorder)(nil)

type mockServiceLookup struct {
	keys  map[string]*rsa.PublicKey
	slugs map[string]string
}

func (m *mockServiceLookup) LookupPublicKey(_ context.Context, keyID string) (*rsa.PublicKey, string, error) {
	key, ok := m.keys[keyID]
	if !ok {
		return nil, "", fmt.Errorf("key not found: %s", keyID)
	}
	slug := m.slugs[keyID]
	return key, slug, nil
}

func generateTestServiceKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	hash := sha256.Sum256(pubDER)
	kid := base64.RawURLEncoding.EncodeToString(hash[:12])

	return key, kid
}

func createServiceJWT(t *testing.T, key *rsa.PrivateKey, kid, issuer string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": issuer,
		"aud": "falcon-id",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"jti": uuid.New().String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

func TestServiceAuth_ValidJWT(t *testing.T) {
	gin.SetMode(gin.TestMode)

	key, kid := generateTestServiceKey(t)
	lookup := &mockServiceLookup{
		keys:  map[string]*rsa.PublicKey{kid: &key.PublicKey},
		slugs: map[string]string{kid: "crm-service"},
	}

	mw := NewServiceAuthMiddleware(lookup, "")

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.GET("/test", mw.ServiceAuth(), func(c *gin.Context) {
		slug, _ := c.Get("service_slug")
		c.JSON(200, gin.H{"ok": true, "slug": slug})
	})

	tokenString := createServiceJWT(t, key, kid, "crm-service")

	c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer "+tokenString)
	r.ServeHTTP(w, c.Request)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestServiceAuth_ExpiredJWT(t *testing.T) {
	gin.SetMode(gin.TestMode)

	key, kid := generateTestServiceKey(t)
	lookup := &mockServiceLookup{
		keys:  map[string]*rsa.PublicKey{kid: &key.PublicKey},
		slugs: map[string]string{kid: "crm-service"},
	}

	mw := NewServiceAuthMiddleware(lookup, "")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	r.GET("/test", mw.ServiceAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// Create expired token
	claims := jwt.MapClaims{
		"iss": "crm-service",
		"aud": "falcon-id",
		"exp": time.Now().Add(-5 * time.Minute).Unix(), // Expired
		"iat": time.Now().Add(-10 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, _ := token.SignedString(key)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestServiceAuth_InvalidKid(t *testing.T) {
	gin.SetMode(gin.TestMode)

	key, _ := generateTestServiceKey(t)
	lookup := &mockServiceLookup{
		keys:  map[string]*rsa.PublicKey{},
		slugs: map[string]string{},
	}

	mw := NewServiceAuthMiddleware(lookup, "")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	r.GET("/test", mw.ServiceAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	tokenString := createServiceJWT(t, key, "unknown-kid", "crm-service")

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestServiceAuth_LegacyInternalKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mw := NewServiceAuthMiddleware(&mockServiceLookup{
		keys:  map[string]*rsa.PublicKey{},
		slugs: map[string]string{},
	}, "super-secret-legacy-key-32chars!")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	r.GET("/test", mw.ServiceAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("X-Internal-Key", "super-secret-legacy-key-32chars!")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestServiceAuth_NoCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mw := NewServiceAuthMiddleware(&mockServiceLookup{
		keys:  map[string]*rsa.PublicKey{},
		slugs: map[string]string{},
	}, "")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	r.GET("/test", mw.ServiceAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// createServiceJWTWithScopes builds a service JWT that includes a "scope" claim.
func createServiceJWTWithScopes(t *testing.T, key *rsa.PrivateKey, kid, issuer, scopes string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   issuer,
		"aud":   "falcon-id",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
		"jti":   uuid.New().String(),
		"scope": scopes,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

func TestServiceAuth_ScopesExtractedIntoContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	key, kid := generateTestServiceKey(t)
	lookup := &mockServiceLookup{
		keys:  map[string]*rsa.PublicKey{kid: &key.PublicKey},
		slugs: map[string]string{kid: "integration-bus"},
	}

	mw := NewServiceAuthMiddleware(lookup, "")

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	var capturedScopes string
	r.GET("/test", mw.ServiceAuth(), func(c *gin.Context) {
		raw, _ := c.Get(CtxKeyServiceScopes)
		capturedScopes, _ = raw.(string)
		c.JSON(200, gin.H{"ok": true})
	})

	tokenString := createServiceJWTWithScopes(t, key, kid, "integration-bus", "events:publish events:consume")

	c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer "+tokenString)
	r.ServeHTTP(w, c.Request)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "events:publish events:consume", capturedScopes)
}

func TestServiceAuth_AuditRecorderCalledOnSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	key, kid := generateTestServiceKey(t)
	lookup := &mockServiceLookup{
		keys:  map[string]*rsa.PublicKey{kid: &key.PublicKey},
		slugs: map[string]string{kid: "billing-service"},
	}

	type usageCall struct {
		slug string
	}
	calls := make(chan usageCall, 1)

	recorder := &mockUsageRecorder{
		fn: func(slug, _ string) {
			calls <- usageCall{slug: slug}
		},
	}

	mw := NewServiceAuthMiddleware(lookup, "")
	mw.SetUsageRecorder(recorder)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.GET("/test", mw.ServiceAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	tokenString := createServiceJWT(t, key, kid, "billing-service")
	c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer "+tokenString)
	r.ServeHTTP(w, c.Request)

	assert.Equal(t, http.StatusOK, w.Code)

	select {
	case call := <-calls:
		assert.Equal(t, "billing-service", call.slug)
	case <-time.After(500 * time.Millisecond):
		t.Error("usage recorder was not called within 500ms")
	}
}

// mockUsageRecorder is a test double for ServicePrincipalUsageRecorder.
type mockUsageRecorder struct {
	fn func(slug, ip string)
}

func (m *mockUsageRecorder) RecordServicePrincipalUsage(_ context.Context, slug string, ip string, _ time.Time) error {
	if m.fn != nil {
		m.fn(slug, ip)
	}
	return nil
}

// TestValidateServiceJWTAudience_MultiAud — regression test for the
// post-83a128e multi-aud token shape. validateServiceJWTAudience must
// accept []interface{} aud for BOTH self-issued and external paths;
// pre-fix the self-issued path string-cast `aud` and returned
// "missing audience in self-issued token" for any array shape, which
// silently broke the serviceclient-provisioner cluster-wide.
func TestValidateServiceJWTAudience_MultiAud(t *testing.T) {
	cases := []struct {
		name         string
		aud          interface{}
		isSelfIssued bool
		wantErr      bool
	}{
		// self-issued (kid==oauthKeyID, slug="oauth-client")
		{
			name: "self-issued string aud (legacy)",
			aud:  "svc-talon",
			isSelfIssued: true,
			wantErr:      false,
		},
		{
			name: "self-issued array aud (post-multi-aud)",
			aud: []interface{}{
				"svc-talon",
				"https://api.hexxlock.com",
				"hexxlock-services",
			},
			isSelfIssued: true,
			wantErr:      false,
		},
		{
			name:         "self-issued empty array",
			aud:          []interface{}{},
			isSelfIssued: true,
			wantErr:      true,
		},
		{
			name:         "self-issued missing aud",
			aud:          nil,
			isSelfIssued: true,
			wantErr:      true,
		},
		// external service JWT (kid in registry, slug=<service>)
		{
			name:         "external string aud falcon-id",
			aud:          "falcon-id",
			isSelfIssued: false,
			wantErr:      false,
		},
		{
			name:         "external array aud containing falcon-id",
			aud:          []interface{}{"falcon-id", "https://api.hexxlock.com"},
			isSelfIssued: false,
			wantErr:      false,
		},
		{
			name:         "external array aud NOT containing falcon-id",
			aud:          []interface{}{"some-other-service"},
			isSelfIssued: false,
			wantErr:      true,
		},
		{
			name:         "external string aud wrong",
			aud:          "wrong-aud",
			isSelfIssued: false,
			wantErr:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{}
			if tc.aud != nil {
				claims["aud"] = tc.aud
			}
			err := validateServiceJWTAudience(claims, tc.isSelfIssued)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestExtractAudiences_AllShapes — verifies the normalisation helper
// returns []string regardless of the input encoding.
func TestExtractAudiences_AllShapes(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want []string
	}{
		{"string non-empty", "falcon-id", []string{"falcon-id"}},
		{"string empty", "", nil},
		{"interface array of strings", []interface{}{"a", "b"}, []string{"a", "b"}},
		{"interface array filters non-string", []interface{}{"a", 42, "b"}, []string{"a", "b"}},
		{"interface array filters empty string", []interface{}{"a", "", "b"}, []string{"a", "b"}},
		{"native []string", []string{"a", "b"}, []string{"a", "b"}},
		{"nil", nil, nil},
		{"unexpected type", 42, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractAudiences(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}
