// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// Mock: oauthProviderServiceClientRepo
// ---------------------------------------------------------------------------

type MockOAuthClientRepo struct {
	mock.Mock
}

func (m *MockOAuthClientRepo) Create(ctx context.Context, client *models.OAuthClient) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthClient, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.OAuthClient), args.Error(1)
}

func (m *MockOAuthClientRepo) GetByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error) {
	args := m.Called(ctx, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.OAuthClient), args.Error(1)
}

func (m *MockOAuthClientRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.OAuthClient, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.OAuthClient), args.Get(1).(int64), args.Error(2)
}

func (m *MockOAuthClientRepo) Update(ctx context.Context, client *models.OAuthClient) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) UpdateSecret(ctx context.Context, id uuid.UUID, secretHash string) error {
	args := m.Called(ctx, id, secretHash)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) CreateAuthorizationCode(ctx context.Context, code *models.OAuthAuthorizationCode) error {
	args := m.Called(ctx, code)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) GetAuthorizationCode(ctx context.Context, code string) (*models.OAuthAuthorizationCode, error) {
	args := m.Called(ctx, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.OAuthAuthorizationCode), args.Error(1)
}

func (m *MockOAuthClientRepo) MarkAuthorizationCodeUsed(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) BeginTx(ctx context.Context) (repositories.OAuthClientTx, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(repositories.OAuthClientTx), args.Error(1)
}

func (m *MockOAuthClientRepo) CreateOAuthToken(ctx context.Context, token *models.OAuthToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) GetOAuthTokenByHash(ctx context.Context, tokenHash string) (*models.OAuthToken, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.OAuthToken), args.Error(1)
}

func (m *MockOAuthClientRepo) RevokeOAuthToken(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) SetTokenReplacedBy(ctx context.Context, tokenID, successorID uuid.UUID) error {
	args := m.Called(ctx, tokenID, successorID)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) RefreshSuccessorUnused(ctx context.Context, successorID uuid.UUID) (bool, error) {
	args := m.Called(ctx, successorID)
	return args.Bool(0), args.Error(1)
}

func (m *MockOAuthClientRepo) ConsumeRefreshToken(ctx context.Context, tokenID uuid.UUID) (bool, error) {
	args := m.Called(ctx, tokenID)
	return args.Bool(0), args.Error(1)
}

func (m *MockOAuthClientRepo) RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) (int64, error) {
	args := m.Called(ctx, familyID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockOAuthClientRepo) RevokeTokensBySession(ctx context.Context, sessionID, userID uuid.UUID) (int64, error) {
	args := m.Called(ctx, sessionID, userID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockOAuthClientRepo) ListSessionIDsByIdpSession(ctx context.Context, idpSessionID, userID uuid.UUID) ([]uuid.UUID, error) {
	args := m.Called(ctx, idpSessionID, userID)
	ids, _ := args.Get(0).([]uuid.UUID)
	return ids, args.Error(1)
}

func (m *MockOAuthClientRepo) RevokeAllClientTokens(ctx context.Context, clientID uuid.UUID) error {
	args := m.Called(ctx, clientID)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) RevokeUserClientTokens(ctx context.Context, userID, clientID uuid.UUID) error {
	args := m.Called(ctx, userID, clientID)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) GetConsent(ctx context.Context, userID, clientID uuid.UUID) (*models.OAuthConsent, error) {
	args := m.Called(ctx, userID, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.OAuthConsent), args.Error(1)
}

func (m *MockOAuthClientRepo) CreateOrUpdateConsent(ctx context.Context, consent *models.OAuthConsent) error {
	args := m.Called(ctx, consent)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) RevokeConsent(ctx context.Context, userID, clientID uuid.UUID) error {
	args := m.Called(ctx, userID, clientID)
	return args.Error(0)
}

func (m *MockOAuthClientRepo) GetUserConsentsEnriched(ctx context.Context, userID uuid.UUID) ([]*models.OAuthConsentEnriched, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.OAuthConsentEnriched), args.Error(1)
}

func (m *MockOAuthClientRepo) GetUserConsents(ctx context.Context, userID uuid.UUID) ([]*models.OAuthConsent, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.OAuthConsent), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: oauthProviderServiceUserRepo
// ---------------------------------------------------------------------------

type MockOAuthUserRepo struct {
	mock.Mock
}

func (m *MockOAuthUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockOAuthUserRepo) HasAnyMFAFactor(ctx context.Context, id uuid.UUID) (bool, error) {
	args := m.Called(ctx, id)
	return args.Bool(0), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestOAuthProviderService(t *testing.T, clientRepo oauthProviderServiceClientRepo, userRepo oauthProviderServiceUserRepo) *OAuthProviderService {
	t.Helper()
	cfg := &config.Config{ServicePort: "8080"}
	svc, err := NewOAuthProviderService(clientRepo, userRepo, cfg)
	require.NoError(t, err)
	return svc
}

func buildActiveOAuthClient(tenantID uuid.UUID) *models.OAuthClient {
	return &models.OAuthClient{
		ID:                       uuid.New(),
		TenantID:                 tenantID,
		ClientID:                 "test-client-id",
		Name:                     "Test Client",
		GrantTypes:               []string{"authorization_code", "client_credentials", "refresh_token"},
		ResponseTypes:            []string{"code"},
		RedirectURIs:             []string{"https://example.com/callback"},
		Scopes:                   []string{"openid", "profile", "email"},
		AccessTokenLifetime:      3600,
		RefreshTokenLifetime:     2592000,
		IDTokenLifetime:          3600,
		IsPublic:                 false,
		IsConfidential:           true,
		IsActive:                 true,
		TokenEndpointAuthMethod:  "client_secret_basic",
		IDTokenSignedResponseAlg: "RS256",
		CreatedAt:                time.Now(),
		UpdatedAt:                time.Now(),
	}
}

// ---------------------------------------------------------------------------
// Tests: CreateClient
// ---------------------------------------------------------------------------

func TestOAuthProviderService_CreateClient_ConfidentialClient(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	creatorID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	req := &models.CreateOAuthClientRequest{
		Name:           "My App",
		GrantTypes:     []string{"authorization_code"},
		ResponseTypes:  []string{"code"},
		RedirectURIs:   []string{"https://myapp.com/callback"},
		Scopes:         []string{"openid", "profile"},
		IsPublic:       false,
		IsConfidential: true,
	}

	mockClientRepo.On("Create", ctx, mock.AnythingOfType("*models.OAuthClient")).Return(nil)

	client, secret, err := svc.CreateClient(ctx, tenantID, req, &creatorID)

	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.NotEmpty(t, client.ClientID)
	assert.NotEmpty(t, secret, "confidential client must receive a plain-text secret")
	assert.Equal(t, tenantID, client.TenantID)
	assert.Equal(t, req.Name, client.Name)
	assert.True(t, client.IsActive)
	assert.Equal(t, &creatorID, client.CreatedBy)
	mockClientRepo.AssertExpectations(t)
}

func TestOAuthProviderService_CreateClient_PublicClient(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	req := &models.CreateOAuthClientRequest{
		Name:          "SPA App",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		RedirectURIs:  []string{"https://spa.example.com/callback"},
		Scopes:        []string{"openid"},
		IsPublic:      true,
		RequirePKCE:   true,
	}

	mockClientRepo.On("Create", ctx, mock.AnythingOfType("*models.OAuthClient")).Return(nil)

	client, secret, err := svc.CreateClient(ctx, tenantID, req, nil)

	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Empty(t, secret, "public clients do not get a secret")
	assert.True(t, client.IsPublic)
	mockClientRepo.AssertExpectations(t)
}

func TestOAuthProviderService_CreateClient_RepositoryError(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	req := &models.CreateOAuthClientRequest{
		Name:     "Failing Client",
		IsPublic: false,
	}

	mockClientRepo.On("Create", ctx, mock.AnythingOfType("*models.OAuthClient")).
		Return(errors.New("db write error"))

	client, secret, err := svc.CreateClient(ctx, tenantID, req, nil)

	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Empty(t, secret)
	assert.Contains(t, err.Error(), "db write error")
	mockClientRepo.AssertExpectations(t)
}

func TestOAuthProviderService_CreateClient_CustomTokenLifetimes(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	accessTTL := 1800
	refreshTTL := 604800
	idTokenTTL := 900
	req := &models.CreateOAuthClientRequest{
		Name:                 "Custom TTL Client",
		IsPublic:             false,
		AccessTokenLifetime:  &accessTTL,
		RefreshTokenLifetime: &refreshTTL,
		IDTokenLifetime:      &idTokenTTL,
	}

	mockClientRepo.On("Create", ctx, mock.AnythingOfType("*models.OAuthClient")).Return(nil)

	client, _, err := svc.CreateClient(ctx, tenantID, req, nil)

	require.NoError(t, err)
	assert.Equal(t, accessTTL, client.AccessTokenLifetime)
	assert.Equal(t, refreshTTL, client.RefreshTokenLifetime)
	assert.Equal(t, idTokenTTL, client.IDTokenLifetime)
}

// TestOAuthProviderService_CreateClient_ClientCredentials_NilSlicesCoerced
// — locks down the Bug-6 fix: client_credentials clients omit
// redirect_uris / response_types in the request payload (per RFC 6749
// §3.1.2) but the iam_oauth_clients schema declares those columns
// NOT NULL with a DEFAULT of '{}'. The DEFAULT only fires when the
// column is OMITTED from the INSERT, so the service layer MUST coerce
// nil → []string{} before persisting, otherwise we get
//
//	null value in column "redirect_uris" of relation
//	"iam_oauth_clients" violates not-null constraint (SQLSTATE 23502)
func TestOAuthProviderService_CreateClient_ClientCredentials_NilSlicesCoerced(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	req := &models.CreateOAuthClientRequest{
		Name:           "svc-billing service",
		GrantTypes:     []string{"client_credentials"},
		Scopes:         []string{"billing:read"},
		IsConfidential: true,
		// RedirectURIs + ResponseTypes intentionally nil (omitted)
	}

	var captured *models.OAuthClient
	mockClientRepo.On("Create", ctx, mock.AnythingOfType("*models.OAuthClient")).
		Run(func(args mock.Arguments) {
			captured = args.Get(1).(*models.OAuthClient)
		}).
		Return(nil)

	_, _, err := svc.CreateClient(ctx, tenantID, req, nil)

	require.NoError(t, err)
	require.NotNil(t, captured)
	assert.NotNil(t, captured.RedirectURIs, "RedirectURIs must be non-nil to satisfy NOT NULL constraint")
	assert.Empty(t, captured.RedirectURIs, "RedirectURIs should round-trip as empty slice")
	assert.NotNil(t, captured.ResponseTypes, "ResponseTypes must be non-nil")
	assert.Empty(t, captured.ResponseTypes, "ResponseTypes should round-trip as empty slice")
}

// TestOAuthProviderService_CreateClient_AuthorizationCode_DerivesResponseTypes
// — locks down the Bug-7 fix: when a caller registers an
// authorization_code client without explicit response_types (a common
// shape: the provisioner only knows grant_types + redirect_uris), the
// service must derive ["code"] per RFC 7591 §2 / OIDC Core §3 instead
// of demanding response_types from the caller.
func TestOAuthProviderService_CreateClient_AuthorizationCode_DerivesResponseTypes(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	req := &models.CreateOAuthClientRequest{
		Name:           "svc-accounts service",
		GrantTypes:     []string{"authorization_code", "refresh_token"},
		RedirectURIs:   []string{"https://accounts.hexxlock.com/api/auth/oidc-callback"},
		Scopes:         []string{"openid", "email", "profile"},
		IsConfidential: true,
		// ResponseTypes intentionally omitted
	}

	var captured *models.OAuthClient
	mockClientRepo.On("Create", ctx, mock.AnythingOfType("*models.OAuthClient")).
		Run(func(args mock.Arguments) {
			captured = args.Get(1).(*models.OAuthClient)
		}).
		Return(nil)

	_, _, err := svc.CreateClient(ctx, tenantID, req, nil)

	require.NoError(t, err)
	require.NotNil(t, captured)
	assert.Equal(t, []string{"code"}, captured.ResponseTypes,
		"authorization_code grant must derive response_types=[code]")
}

// (No implicit-grant test: OAuth 2.1 / BCP-225 §10.2 removes the
// implicit grant entirely — falcon-id rejects it at the
// validateOAuth21GrantsAndResponses gate before the derivation logic
// runs. The "implicit" → ["token", "id_token"] mapping in CreateClient
// remains for completeness/spec-fidelity but is not exercised here.)

// TestOAuthProviderService_CreateClient_HonorsRequestedClientID — Bug 8
// regression: when the caller supplies a client_id, the persisted client
// MUST use that exact value (subject to format + uniqueness validation).
// The platform's ServiceClient provisioner relies on this to keep its
// Vault entry (`svc-<service>`) and the DB row in lockstep.
func TestOAuthProviderService_CreateClient_HonorsRequestedClientID(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	requestedID := "svc-accounts"
	req := &models.CreateOAuthClientRequest{
		ClientID:       &requestedID,
		Name:           "accounts service",
		GrantTypes:     []string{"client_credentials"},
		Scopes:         []string{"accounts:read"},
		IsConfidential: true,
	}

	// resolveClientID consults GetByClientID to detect collisions.
	// Mock the "available" path — a not-found error.
	mockClientRepo.On("GetByClientID", ctx, requestedID).
		Return((*models.OAuthClient)(nil), errors.New("not found"))

	var captured *models.OAuthClient
	mockClientRepo.On("Create", ctx, mock.AnythingOfType("*models.OAuthClient")).
		Run(func(args mock.Arguments) {
			captured = args.Get(1).(*models.OAuthClient)
		}).
		Return(nil)

	_, _, err := svc.CreateClient(ctx, tenantID, req, nil)

	require.NoError(t, err)
	require.NotNil(t, captured)
	assert.Equal(t, requestedID, captured.ClientID,
		"caller-supplied client_id must be used verbatim")
}

// TestOAuthProviderService_CreateClient_RejectsConflictingClientID —
// Bug 8 conflict path: when the requested id is already registered,
// return ErrClientIDConflict (the handler maps to 409).
func TestOAuthProviderService_CreateClient_RejectsConflictingClientID(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	requestedID := "svc-accounts"
	req := &models.CreateOAuthClientRequest{
		ClientID:       &requestedID,
		Name:           "duplicate",
		GrantTypes:     []string{"client_credentials"},
		Scopes:         []string{"accounts:read"},
		IsConfidential: true,
	}

	mockClientRepo.On("GetByClientID", ctx, requestedID).
		Return(&models.OAuthClient{ClientID: requestedID, ID: uuid.New()}, nil)

	_, _, err := svc.CreateClient(ctx, tenantID, req, nil)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrClientIDConflict),
		"expected ErrClientIDConflict, got %v", err)
}

// TestOAuthProviderService_CreateClient_RejectsInvalidClientIDFormat —
// Bug 8 format-validation path: out-of-shape client_ids must be rejected
// with an invalid_client_metadata-prefixed error so the handler maps to 400.
func TestOAuthProviderService_CreateClient_RejectsInvalidClientIDFormat(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	cases := []struct {
		name string
		id   string
	}{
		{"starts with hyphen", "-svc-accounts"},
		{"contains space", "svc accounts"},
		{"contains slash", "svc/accounts"},
		{"empty after deref", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mockClientRepo := new(MockOAuthClientRepo)
			mockUserRepo := new(MockOAuthUserRepo)
			svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

			id := tc.id
			var idPtr *string
			if id != "" {
				idPtr = &id
			}
			req := &models.CreateOAuthClientRequest{
				ClientID:       idPtr,
				Name:           "demo",
				GrantTypes:     []string{"client_credentials"},
				Scopes:         []string{"x:y"},
				IsConfidential: true,
			}

			// The "empty after deref" case has nil pointer => generates an id.
			// Mock generation path so the test reaches the assertion either way.
			if idPtr == nil {
				mockClientRepo.On("Create", ctx, mock.AnythingOfType("*models.OAuthClient")).
					Return(nil).Maybe()
				_, _, err := svc.CreateClient(ctx, tenantID, req, nil)
				assert.NoError(t, err, "nil ClientID should generate one, not error")
				return
			}

			_, _, err := svc.CreateClient(ctx, tenantID, req, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid_client_metadata",
				"format-validation failures must be tagged for the handler 400 mapping")
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: GetClient / ListClients
// ---------------------------------------------------------------------------

func TestOAuthProviderService_GetClient_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	clientID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	expected := buildActiveOAuthClient(tenantID)
	expected.ID = clientID

	mockClientRepo.On("GetByID", ctx, clientID).Return(expected, nil)

	got, err := svc.GetClient(ctx, clientID)

	require.NoError(t, err)
	assert.Equal(t, expected.ID, got.ID)
	mockClientRepo.AssertExpectations(t)
}

func TestOAuthProviderService_ListClients_ByTenant(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	clients := []*models.OAuthClient{
		buildActiveOAuthClient(tenantID),
		buildActiveOAuthClient(tenantID),
	}

	mockClientRepo.On("GetByTenantID", ctx, tenantID, 1, 20).
		Return(clients, int64(2), nil)

	result, total, err := svc.ListClients(ctx, tenantID, 1, 20)

	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, int64(2), total)
	mockClientRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ValidateAuthorizeRequest
// ---------------------------------------------------------------------------

func TestOAuthProviderService_ValidateAuthorizeRequest_ValidRequest(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	oauthClient := buildActiveOAuthClient(tenantID)

	req := &models.OAuthAuthorizeRequest{
		ClientID:            oauthClient.ClientID,
		ResponseType:        "code",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		State:               "random-state-value",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}

	mockClientRepo.On("GetByClientID", ctx, req.ClientID).Return(oauthClient, nil)

	validatedClient, err := svc.ValidateAuthorizeRequest(ctx, req)

	require.NoError(t, err)
	assert.NotNil(t, validatedClient)
	assert.Equal(t, oauthClient.ID, validatedClient.ID)
	mockClientRepo.AssertExpectations(t)
}

func TestOAuthProviderService_ValidateAuthorizeRequest_UnknownClient(t *testing.T) {
	ctx := context.Background()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	req := &models.OAuthAuthorizeRequest{
		ClientID:     "nonexistent-client",
		ResponseType: "code",
		RedirectURI:  "https://example.com/callback",
	}

	mockClientRepo.On("GetByClientID", ctx, req.ClientID).
		Return(nil, errors.New("not found"))

	validatedClient, err := svc.ValidateAuthorizeRequest(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, validatedClient)
	assert.Contains(t, err.Error(), "invalid_client")
}

func TestOAuthProviderService_ValidateAuthorizeRequest_InvalidRedirectURI(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	oauthClient := buildActiveOAuthClient(tenantID)
	req := &models.OAuthAuthorizeRequest{
		ClientID:     oauthClient.ClientID,
		ResponseType: "code",
		RedirectURI:  "https://evil.example.com/callback",
		Scope:        "openid",
	}

	mockClientRepo.On("GetByClientID", ctx, req.ClientID).Return(oauthClient, nil)

	validatedClient, err := svc.ValidateAuthorizeRequest(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, validatedClient)
	assert.Contains(t, err.Error(), "redirect_uri")
}

func TestOAuthProviderService_ValidateAuthorizeRequest_InactiveClient(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	oauthClient := buildActiveOAuthClient(tenantID)
	oauthClient.IsActive = false

	req := &models.OAuthAuthorizeRequest{
		ClientID:     oauthClient.ClientID,
		ResponseType: "code",
		RedirectURI:  "https://example.com/callback",
	}

	mockClientRepo.On("GetByClientID", ctx, req.ClientID).Return(oauthClient, nil)

	validatedClient, err := svc.ValidateAuthorizeRequest(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, validatedClient)
	assert.Contains(t, err.Error(), "not active")
}

// ---------------------------------------------------------------------------
// Tests: CreateAuthorizationCode
// ---------------------------------------------------------------------------

func TestOAuthProviderService_CreateAuthorizationCode_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	oauthClient := buildActiveOAuthClient(tenantID)

	req := &models.OAuthAuthorizeRequest{
		ClientID:    oauthClient.ClientID,
		RedirectURI: "https://example.com/callback",
		Scope:       "openid profile",
		State:       "state123",
		Nonce:       "nonce456",
	}

	mockClientRepo.On("CreateAuthorizationCode", ctx, mock.AnythingOfType("*models.OAuthAuthorizationCode")).
		Return(nil)

	code, err := svc.CreateAuthorizationCode(ctx, oauthClient, userID, req)

	require.NoError(t, err)
	assert.NotEmpty(t, code, "returned code must not be empty")
	mockClientRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: RegenerateClientSecret
// ---------------------------------------------------------------------------

func TestOAuthProviderService_RegenerateClientSecret_ConfidentialClient(t *testing.T) {
	ctx := context.Background()
	clientID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	oauthClient := buildActiveOAuthClient(uuid.New())
	oauthClient.ID = clientID
	oauthClient.IsPublic = false

	mockClientRepo.On("GetByID", ctx, clientID).Return(oauthClient, nil)
	mockClientRepo.On("UpdateSecret", ctx, clientID, mock.AnythingOfType("string")).Return(nil)

	newSecret, err := svc.RegenerateClientSecret(ctx, clientID)

	require.NoError(t, err)
	assert.NotEmpty(t, newSecret)
	mockClientRepo.AssertExpectations(t)
}

func TestOAuthProviderService_RegenerateClientSecret_PublicClientError(t *testing.T) {
	ctx := context.Background()
	clientID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	oauthClient := buildActiveOAuthClient(uuid.New())
	oauthClient.ID = clientID
	oauthClient.IsPublic = true

	mockClientRepo.On("GetByID", ctx, clientID).Return(oauthClient, nil)

	newSecret, err := svc.RegenerateClientSecret(ctx, clientID)

	assert.Error(t, err)
	assert.Empty(t, newSecret)
	assert.Contains(t, err.Error(), "public clients do not have secrets")
	mockClientRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ClientCredentialsGrant
// ---------------------------------------------------------------------------

func TestOAuthProviderService_ClientCredentialsGrant_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	oauthClient := buildActiveOAuthClient(tenantID)

	mockClientRepo.On("CreateOAuthToken", ctx, mock.AnythingOfType("*models.OAuthToken")).Return(nil)

	resp, err := svc.ClientCredentialsGrant(ctx, oauthClient, []string{"openid"}, "")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
	mockClientRepo.AssertExpectations(t)
}

func TestOAuthProviderService_ClientCredentialsGrant_DisallowedGrant(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	oauthClient := buildActiveOAuthClient(tenantID)
	oauthClient.GrantTypes = []string{"authorization_code"} // no client_credentials

	resp, err := svc.ClientCredentialsGrant(ctx, oauthClient, []string{"openid"}, "")

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "unauthorized_client")
}

// ---------------------------------------------------------------------------
// Tests: UpdateClient
// ---------------------------------------------------------------------------

func TestOAuthProviderService_UpdateClient_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	clientID := uuid.New()
	updaterID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	existing := buildActiveOAuthClient(tenantID)
	existing.ID = clientID

	newName := "Updated App Name"
	req := &models.UpdateOAuthClientRequest{
		Name: &newName,
	}

	mockClientRepo.On("GetByID", ctx, clientID).Return(existing, nil)
	mockClientRepo.On("Update", ctx, mock.AnythingOfType("*models.OAuthClient")).Return(nil)

	updated, err := svc.UpdateClient(ctx, clientID, req, &updaterID)

	require.NoError(t, err)
	assert.Equal(t, newName, updated.Name)
	assert.Equal(t, &updaterID, updated.UpdatedBy)
	mockClientRepo.AssertExpectations(t)
}

// The native-app relaxation (private-use scheme URIs) is decided on the
// merged client traits: a request that makes the client native may use it,
// one that strips a trait may not.
func TestOAuthProviderService_UpdateClient_NativeAppUsesMergedTraits(t *testing.T) {
	ctx := context.Background()
	updaterID := uuid.New()
	uri := "com.example.app:/logout"
	yes, no := true, false

	run := func(t *testing.T, existing *models.OAuthClient, req *models.UpdateOAuthClientRequest) error {
		t.Helper()
		mockClientRepo := new(MockOAuthClientRepo)
		svc := newTestOAuthProviderService(t, mockClientRepo, new(MockOAuthUserRepo))
		svc.cfg.NativeAppSchemeDomains = []string{"example.com"}
		// Native apps are public, which cannot hold client_credentials.
		existing.GrantTypes = []string{"authorization_code", "refresh_token"}
		mockClientRepo.On("GetByID", ctx, existing.ID).Return(existing, nil)
		mockClientRepo.On("Update", ctx, mock.AnythingOfType("*models.OAuthClient")).Return(nil).Maybe()
		_, err := svc.UpdateClient(ctx, existing.ID, req, &updaterID)
		return err
	}

	t.Run("request makes client native", func(t *testing.T) {
		existing := buildActiveOAuthClient(uuid.New())
		err := run(t, existing, &models.UpdateOAuthClientRequest{
			IsPublic: &yes, RequirePKCE: &yes, IsFirstParty: &yes,
			PostLogoutRedirectURIs: []string{uri},
		})
		require.NoError(t, err)
	})
	t.Run("request strips a native trait", func(t *testing.T) {
		existing := buildActiveOAuthClient(uuid.New())
		existing.IsPublic, existing.RequirePKCE, existing.IsFirstParty = true, true, true
		err := run(t, existing, &models.UpdateOAuthClientRequest{
			IsPublic: &no, PostLogoutRedirectURIs: []string{uri},
		})
		require.Error(t, err)
	})
	t.Run("stored non-native stays non-native", func(t *testing.T) {
		existing := buildActiveOAuthClient(uuid.New())
		err := run(t, existing, &models.UpdateOAuthClientRequest{PostLogoutRedirectURIs: []string{uri}})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// Tests: DeleteClient
// ---------------------------------------------------------------------------

func TestOAuthProviderService_DeleteClient_Success(t *testing.T) {
	ctx := context.Background()
	clientID := uuid.New()

	mockClientRepo := new(MockOAuthClientRepo)
	mockUserRepo := new(MockOAuthUserRepo)
	svc := newTestOAuthProviderService(t, mockClientRepo, mockUserRepo)

	mockClientRepo.On("Delete", ctx, clientID).Return(nil)

	err := svc.DeleteClient(ctx, clientID)

	require.NoError(t, err)
	mockClientRepo.AssertExpectations(t)
}
