// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ==================== In-memory PAR store for tests ====================

// memPARStore is a simple in-memory implementation of PARStore for unit tests.
type memPARStore struct {
	entries map[string]*PAREntry
}

func newMemPARStore() *memPARStore {
	return &memPARStore{entries: make(map[string]*PAREntry)}
}

func (s *memPARStore) SetPAR(_ context.Context, entry *PAREntry) error {
	s.entries[entry.Reference] = entry
	return nil
}

func (s *memPARStore) GetPAR(_ context.Context, reference string) (*PAREntry, error) {
	e, ok := s.entries[reference]
	if !ok {
		return nil, nil
	}
	return e, nil
}

func (s *memPARStore) DeletePAR(_ context.Context, reference string) error {
	delete(s.entries, reference)
	return nil
}

// ==================== Helpers ====================

// newTestOAuthService returns an OAuthProviderService with a minimal config.
// RSA keys are auto-generated so the test does not require key files.
func newTestOAuthService(t *testing.T) *OAuthProviderService {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:   "test-secret-for-par-tests",
		ServicePort: "8080",
	}
	svc, err := NewOAuthProviderService(
		&noopOAuthClientRepo{},
		&noopUserRepo{},
		cfg,
	)
	require.NoError(t, err)
	return svc
}

// activeConfidentialClient returns a minimal, active, confidential OAuth client
// with the given response types and redirect URIs.
func activeConfidentialClient(responseTypes, redirectURIs []string) *models.OAuthClient {
	return &models.OAuthClient{
		ClientID:       "test-client",
		IsActive:       true,
		IsConfidential: true,
		ResponseTypes:  responseTypes,
		RedirectURIs:   redirectURIs,
		Scopes:         []string{"openid", "profile"},
	}
}

// validParams returns a well-formed OAuthAuthorizeRequest that satisfies the
// confidential client returned by activeConfidentialClient.
func validParams() *models.OAuthAuthorizeRequest {
	return &models.OAuthAuthorizeRequest{
		ResponseType: "code",
		ClientID:     "test-client",
		RedirectURI:  "https://app.example.com/callback",
		Scope:        "openid profile",
		State:        "random-state",
	}
}

// ==================== Tests: PushAuthorizationRequest ====================

func TestPushAuthorizationRequest_Success(t *testing.T) {
	svc := newTestOAuthService(t)
	store := newMemPARStore()
	svc.SetPARStore(store)

	client := activeConfidentialClient(
		[]string{"code"},
		[]string{"https://app.example.com/callback"},
	)
	params := validParams()

	resp, err := svc.PushAuthorizationRequest(context.Background(), client, params)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, strings.HasPrefix(resp.RequestURI, "urn:ietf:params:oauth:request_uri:"),
		"request_uri must use the URN prefix defined by RFC 9126")
	assert.Equal(t, PARTTLSeconds, resp.ExpiresIn)

	// The reference must be stored in the PAR store.
	reference := strings.TrimPrefix(resp.RequestURI, "urn:ietf:params:oauth:request_uri:")
	assert.NotEmpty(t, reference)
	stored, err := store.GetPAR(context.Background(), reference)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, client.ClientID, stored.ClientID)
	assert.Equal(t, params.ResponseType, stored.ResponseType)
	assert.Equal(t, params.RedirectURI, stored.RedirectURI)
	assert.Equal(t, params.Scope, stored.Scope)
	assert.Equal(t, params.State, stored.State)
}

func TestPushAuthorizationRequest_NoPARStore(t *testing.T) {
	svc := newTestOAuthService(t)
	// parStore is nil by default — PAR not configured.

	client := activeConfidentialClient([]string{"code"}, []string{"https://app.example.com/callback"})
	params := validParams()

	_, err := svc.PushAuthorizationRequest(context.Background(), client, params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server_error")
}

func TestPushAuthorizationRequest_InvalidResponseType(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetPARStore(newMemPARStore())

	client := activeConfidentialClient([]string{"code"}, []string{"https://app.example.com/callback"})
	params := validParams()
	params.ResponseType = "token" // not registered for this client

	_, err := svc.PushAuthorizationRequest(context.Background(), client, params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported_response_type")
}

func TestPushAuthorizationRequest_InvalidRedirectURI(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetPARStore(newMemPARStore())

	client := activeConfidentialClient([]string{"code"}, []string{"https://app.example.com/callback"})
	params := validParams()
	params.RedirectURI = "https://attacker.com/steal" // not registered

	_, err := svc.PushAuthorizationRequest(context.Background(), client, params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_request")
}

func TestPushAuthorizationRequest_PKCERequired_MissingChallenge(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetPARStore(newMemPARStore())

	client := activeConfidentialClient([]string{"code"}, []string{"https://app.example.com/callback"})
	client.RequirePKCE = true
	params := validParams()
	// No code_challenge provided.

	_, err := svc.PushAuthorizationRequest(context.Background(), client, params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "code_challenge is required")
}

func TestPushAuthorizationRequest_PKCERequired_Success(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetPARStore(newMemPARStore())

	client := activeConfidentialClient([]string{"code"}, []string{"https://app.example.com/callback"})
	client.RequirePKCE = true
	params := validParams()
	params.CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	params.CodeChallengeMethod = "S256"

	resp, err := svc.PushAuthorizationRequest(context.Background(), client, params)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.RequestURI)
}

func TestPushAuthorizationRequest_InactiveClient(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetPARStore(newMemPARStore())

	client := activeConfidentialClient([]string{"code"}, []string{"https://app.example.com/callback"})
	client.IsActive = false
	params := validParams()

	_, err := svc.PushAuthorizationRequest(context.Background(), client, params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_client")
}

func TestPushAuthorizationRequest_MissingResponseType(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetPARStore(newMemPARStore())

	client := activeConfidentialClient([]string{"code"}, []string{"https://app.example.com/callback"})
	params := validParams()
	params.ResponseType = ""

	_, err := svc.PushAuthorizationRequest(context.Background(), client, params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_request")
}

// ==================== Tests: ResolvePARRequest ====================

func TestResolvePARRequest_Success(t *testing.T) {
	svc := newTestOAuthService(t)
	store := newMemPARStore()
	svc.SetPARStore(store)

	client := activeConfidentialClient([]string{"code"}, []string{"https://app.example.com/callback"})
	params := validParams()

	// Push first.
	pushResp, err := svc.PushAuthorizationRequest(context.Background(), client, params)
	require.NoError(t, err)

	// Resolve.
	req, err := svc.ResolvePARRequest(context.Background(), client.ClientID, pushResp.RequestURI)
	require.NoError(t, err)
	require.NotNil(t, req)

	assert.Equal(t, params.ResponseType, req.ResponseType)
	assert.Equal(t, params.RedirectURI, req.RedirectURI)
	assert.Equal(t, params.Scope, req.Scope)
	assert.Equal(t, params.State, req.State)
}

func TestResolvePARRequest_SingleUse(t *testing.T) {
	svc := newTestOAuthService(t)
	store := newMemPARStore()
	svc.SetPARStore(store)

	client := activeConfidentialClient([]string{"code"}, []string{"https://app.example.com/callback"})
	params := validParams()

	pushResp, err := svc.PushAuthorizationRequest(context.Background(), client, params)
	require.NoError(t, err)

	// First resolution succeeds.
	_, err = svc.ResolvePARRequest(context.Background(), client.ClientID, pushResp.RequestURI)
	require.NoError(t, err)

	// Second resolution must fail (entry was deleted).
	_, err = svc.ResolvePARRequest(context.Background(), client.ClientID, pushResp.RequestURI)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_request")
}

func TestResolvePARRequest_ClientIDMismatch(t *testing.T) {
	svc := newTestOAuthService(t)
	store := newMemPARStore()
	svc.SetPARStore(store)

	client := activeConfidentialClient([]string{"code"}, []string{"https://app.example.com/callback"})
	params := validParams()

	pushResp, err := svc.PushAuthorizationRequest(context.Background(), client, params)
	require.NoError(t, err)

	// Try to resolve with a different client_id — must fail.
	_, err = svc.ResolvePARRequest(context.Background(), "different-client", pushResp.RequestURI)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id mismatch")
}

func TestResolvePARRequest_UnknownRequestURI(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetPARStore(newMemPARStore())

	_, err := svc.ResolvePARRequest(context.Background(), "any-client",
		"urn:ietf:params:oauth:request_uri:doesnotexist123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_request")
}

func TestResolvePARRequest_ExpiredEntry(t *testing.T) {
	svc := newTestOAuthService(t)
	store := newMemPARStore()
	svc.SetPARStore(store)

	// Manually insert an already-expired entry.
	ref := "expiredreference"
	store.entries[ref] = &PAREntry{
		Reference:    ref,
		ClientID:     "test-client",
		ResponseType: "code",
		RedirectURI:  "https://app.example.com/callback",
		ExpiresAt:    time.Now().Add(-5 * time.Second).Unix(), // already expired
	}

	_, err := svc.ResolvePARRequest(context.Background(), "test-client",
		"urn:ietf:params:oauth:request_uri:"+ref)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestResolvePARRequest_NoPARStore(t *testing.T) {
	svc := newTestOAuthService(t)
	// parStore is nil.

	_, err := svc.ResolvePARRequest(context.Background(), "any-client",
		"urn:ietf:params:oauth:request_uri:anything")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_request")
}

func TestResolvePARRequest_MalformedRequestURI(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetPARStore(newMemPARStore())

	tests := []struct {
		name       string
		requestURI string
	}{
		{"empty string", ""},
		{"missing prefix", "not-a-urn"},
		{"only prefix", "urn:ietf:params:oauth:request_uri:"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.ResolvePARRequest(context.Background(), "client", tc.requestURI)
			require.Error(t, err)
		})
	}
}

// ==================== Tests: Discovery document ====================

func TestGetDiscoveryDocument_IncludesPAREndpoint_WhenStoreSet(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetPARStore(newMemPARStore())

	doc := svc.GetDiscoveryDocument()
	assert.NotEmpty(t, doc.PushedAuthorizationRequestEndpoint,
		"discovery document must advertise the PAR endpoint when PAR store is configured")
	assert.Contains(t, doc.PushedAuthorizationRequestEndpoint, "/oauth/par")
}

func TestGetDiscoveryDocument_OmitsPAREndpoint_WhenStoreNil(t *testing.T) {
	svc := newTestOAuthService(t)
	// parStore is nil — Redis not available.

	doc := svc.GetDiscoveryDocument()
	assert.Empty(t, doc.PushedAuthorizationRequestEndpoint,
		"discovery document must NOT advertise PAR endpoint when PAR store is not configured")
}

// ==================== Noop repository stubs ====================
// These are the minimum implementations needed to construct OAuthProviderService in tests.

type noopOAuthClientRepo struct{}

func (r *noopOAuthClientRepo) Create(_ context.Context, _ *models.OAuthClient) error { return nil }
func (r *noopOAuthClientRepo) GetByID(_ context.Context, _ uuid.UUID) (*models.OAuthClient, error) {
	return nil, nil
}

func (r *noopOAuthClientRepo) GetByClientID(_ context.Context, _ string) (*models.OAuthClient, error) {
	return nil, nil
}

func (r *noopOAuthClientRepo) GetByTenantID(_ context.Context, _ uuid.UUID, _, _ int) ([]*models.OAuthClient, int64, error) {
	return nil, 0, nil
}
func (r *noopOAuthClientRepo) Update(_ context.Context, _ *models.OAuthClient) error { return nil }
func (r *noopOAuthClientRepo) Delete(_ context.Context, _ uuid.UUID) error           { return nil }
func (r *noopOAuthClientRepo) UpdateSecret(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}

func (r *noopOAuthClientRepo) CreateAuthorizationCode(_ context.Context, _ *models.OAuthAuthorizationCode) error {
	return nil
}

func (r *noopOAuthClientRepo) GetAuthorizationCode(_ context.Context, _ string) (*models.OAuthAuthorizationCode, error) {
	return nil, nil
}

func (r *noopOAuthClientRepo) MarkAuthorizationCodeUsed(_ context.Context, _ uuid.UUID) error {
	return nil
}

// BeginTx returns a noop transaction handle. The PAR/discovery tests that use
// this stub never exercise the authorization_code exchange, so the handle is
// only here to satisfy the oauthProviderServiceClientRepo interface.
func (r *noopOAuthClientRepo) BeginTx(_ context.Context) (repositories.OAuthClientTx, error) {
	return &noopOAuthClientTx{}, nil
}

// noopOAuthClientTx is a do-nothing OAuthClientTx: the CAS always wins and the
// token persists, so a stub-backed exchange would succeed without touching a DB.
type noopOAuthClientTx struct{}

func (t *noopOAuthClientTx) MarkAuthorizationCodeUsedCAS(_ context.Context, _ uuid.UUID) (bool, error) {
	return true, nil
}
func (t *noopOAuthClientTx) CreateOAuthToken(_ context.Context, _ *models.OAuthToken) error {
	return nil
}
func (t *noopOAuthClientTx) Commit(_ context.Context) error   { return nil }
func (t *noopOAuthClientTx) Rollback(_ context.Context) error { return nil }

func (r *noopOAuthClientRepo) CreateOAuthToken(_ context.Context, _ *models.OAuthToken) error {
	return nil
}

func (r *noopOAuthClientRepo) GetOAuthTokenByHash(_ context.Context, _ string) (*models.OAuthToken, error) {
	return nil, nil
}
func (r *noopOAuthClientRepo) RevokeOAuthToken(_ context.Context, _ string) error { return nil }

// ConsumeRefreshToken defaults to "won the CAS" so the default rotate path in
// RefreshTokens proceeds for stubs that don't model reuse/race semantics.
func (r *noopOAuthClientRepo) ConsumeRefreshToken(_ context.Context, _ uuid.UUID) (bool, error) {
	return true, nil
}

func (r *noopOAuthClientRepo) RevokeRefreshTokenFamily(_ context.Context, _ uuid.UUID) (int64, error) {
	return 0, nil
}
func (r *noopOAuthClientRepo) RevokeAllClientTokens(_ context.Context, _ uuid.UUID) error { return nil }
func (r *noopOAuthClientRepo) RevokeUserClientTokens(_ context.Context, _, _ uuid.UUID) error {
	return nil
}

func (r *noopOAuthClientRepo) GetConsent(_ context.Context, _, _ uuid.UUID) (*models.OAuthConsent, error) {
	return nil, nil
}

func (r *noopOAuthClientRepo) CreateOrUpdateConsent(_ context.Context, _ *models.OAuthConsent) error {
	return nil
}
func (r *noopOAuthClientRepo) RevokeConsent(_ context.Context, _, _ uuid.UUID) error { return nil }
func (r *noopOAuthClientRepo) GetUserConsents(_ context.Context, _ uuid.UUID) ([]*models.OAuthConsent, error) {
	return nil, nil
}
func (r *noopOAuthClientRepo) GetUserConsentsEnriched(_ context.Context, _ uuid.UUID) ([]*models.OAuthConsentEnriched, error) {
	return nil, nil
}

type noopUserRepo struct{}

func (r *noopUserRepo) GetByID(_ context.Context, _ uuid.UUID) (*models.User, error) {
	return nil, nil
}

func (r *noopUserRepo) HasAnyMFAFactor(_ context.Context, _ uuid.UUID) (bool, error) {
	return false, nil
}
