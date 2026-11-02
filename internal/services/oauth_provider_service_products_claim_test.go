// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// productsClaimFixture wires a ProductSubscriptionResolver over in-memory
// repos with one product in each claim state for the given tenant:
//   - "acmeapp"  active       → state omitted
//   - "acmeweb"   provisioning → state "provisioning" (plan set)
//   - "talon"    failed       → state "failed"
//
// Returns the resolver and the expected slug → state map.
func productsClaimFixture(tenantID uuid.UUID) (*ProductSubscriptionResolver, map[string]string) {
	active, prov, failed := uuid.New(), uuid.New(), uuid.New()
	plan := "pro"
	instances := &mockSubscriptionInstanceRepo{instances: []models.ProductInstance{
		{ID: uuid.New(), TenantID: tenantID, ProductID: active, ProvisioningState: models.ProvisioningStateActive},
		{ID: uuid.New(), TenantID: tenantID, ProductID: prov, ProvisioningState: models.ProvisioningStateCreating, PlanID: &plan},
		{ID: uuid.New(), TenantID: tenantID, ProductID: failed, ProvisioningState: models.ProvisioningStateFailed},
	}}
	products := &mockSubscriptionProductRepo{products: map[uuid.UUID]*models.Product{
		active: {ID: active, Slug: "acmeapp"},
		prov:   {ID: prov, Slug: "acmeweb"},
		failed: {ID: failed, Slug: "talon"},
	}}
	return NewProductSubscriptionResolver(instances, products), map[string]string{
		"acmeapp": "",
		"acmeweb":  "provisioning",
		"talon":   "failed",
	}
}

// assertProductsClaimState decodes the access token and asserts the
// `products` claim carries `state` exactly as token_service's mint paths do:
// present for provisioning/failed, omitted (not "") for active.
func assertProductsClaimState(t *testing.T, accessToken string, want map[string]string) {
	t.Helper()
	claims := decodeJWTUnverified(t, accessToken)
	raw, ok := claims["products"]
	require.True(t, ok, "products claim MUST be present on user-bound /oauth/token output")
	list, ok := raw.([]any)
	require.True(t, ok, "products claim must be a JSON array, got %T", raw)
	require.Len(t, list, len(want))

	for _, item := range list {
		entry, ok := item.(map[string]any)
		require.True(t, ok, "products entry must be an object, got %T", item)
		slug, _ := entry["slug"].(string)
		wantState, known := want[slug]
		require.True(t, known, "unexpected product slug %q", slug)
		assert.NotEmpty(t, entry["pid"], "pid must be present for %s", slug)

		state, present := entry["state"]
		if wantState == "" {
			assert.False(t, present, "active product %s must OMIT state (json omitempty), got %v", slug, state)
		} else {
			require.True(t, present, "BUG GUARD: %s is %s but OAuth token dropped `state` — provisioning interstitial would never fire", slug, wantState)
			assert.Equal(t, wantState, state, "state for %s", slug)
		}
		if slug == "acmeweb" {
			assert.Equal(t, "pro", entry["plan"], "plan must still be carried")
		}
	}
}

func TestOAuthProductsClaim_AuthorizationCode_CarriesState(t *testing.T) {
	svc, repo, client, redirectURI, code := newTxExchangeFixture(t)
	user, err := svc.userRepo.GetByID(context.Background(), repo.code.UserID)
	require.NoError(t, err)
	resolver, want := productsClaimFixture(user.TenantID)
	svc.SetProductSubscriptionResolver(resolver)

	resp, err := svc.ExchangeAuthorizationCode(context.Background(), client, code, redirectURI, "", "")
	require.NoError(t, err)
	assertProductsClaimState(t, resp.AccessToken, want)
}

func TestOAuthProductsClaim_RefreshToken_CarriesState(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	user := subjectUser()
	svc := newTestOAuthProviderService(t, repo, &fixedUserRepo{user: user})
	resolver, want := productsClaimFixture(user.TenantID)
	svc.SetProductSubscriptionResolver(resolver)

	client := activeConfidentialBFFClient("rotate")
	inbound := "inbound-refresh-token-products-claim"
	inboundHash := svc.hashSecret(inbound)
	inboundID := uuid.New()
	repo.addToken(inboundHash, &models.OAuthToken{
		ID:            inboundID,
		TenantID:      client.TenantID,
		ClientID:      client.ID,
		UserID:        &user.ID,
		TokenType:     "access_token",
		Token:         "irrelevant-access-token-hash",
		Scopes:        []string{"openid", "profile"},
		RefreshToken:  &inboundHash,
		TokenFamilyID: &inboundID,
		ExpiresAt:     time.Now().Add(time.Hour),
		CreatedAt:     time.Now().Add(-time.Minute),
		UpdatedAt:     time.Now().Add(-time.Minute),
	})

	resp, err := svc.RefreshTokens(context.Background(), client, inbound, "")
	require.NoError(t, err)
	assertProductsClaimState(t, resp.AccessToken, want)
}

func TestOAuthProductsClaim_TokenExchange_CarriesState(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	user := subjectUser()
	svc := newTestOAuthProviderService(t, repo, &fixedUserRepo{user: user})
	resolver, want := productsClaimFixture(user.TenantID)
	svc.SetProductSubscriptionResolver(resolver)

	client := activeConfidentialBFFClient("rotate")

	// Mint a genuine subject token from this service so ValidateAccessToken
	// accepts it, then register its row where TokenExchangeGrant looks.
	subject, err := svc.generateTokens(context.Background(), client, user, []string{"openid", "profile"}, nil, nil, nil, nil)
	require.NoError(t, err)
	subjectHash := svc.hashSecret(subject.AccessToken)
	repo.addToken(subjectHash, &models.OAuthToken{
		ID:        uuid.New(),
		TenantID:  client.TenantID,
		ClientID:  client.ID,
		UserID:    &user.ID,
		TokenType: "access_token",
		Token:     subjectHash,
		Scopes:    []string{"openid", "profile"},
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	resp, err := svc.TokenExchangeGrant(
		context.Background(),
		client,
		subject.AccessToken,
		"urn:ietf:params:oauth:token-type:access_token",
		"",
		nil,
	)
	require.NoError(t, err)
	assertProductsClaimState(t, resp.AccessToken, want)
}

// TestToProductSubscriptionClaims_EmptyIsNil locks the omit-when-empty
// contract every mint path relies on to drop the claim entirely.
func TestToProductSubscriptionClaims_EmptyIsNil(t *testing.T) {
	assert.Nil(t, toProductSubscriptionClaims(nil))
	assert.Nil(t, toProductSubscriptionClaims([]ProductClaim{}))
}

// TestOAuthProductsClaim_ResolverError_OmitsProductsClaim locks the
// fail-closed contract at the OAuth /oauth/token mint path
// (OAuthProviderService.generateTokensWithSink): when the resolver errors,
// token issuance must still succeed (a transient DB hiccup shouldn't 500
// the code exchange) but the `products` claim must be entirely absent —
// never an empty array and never "all products".
func TestOAuthProductsClaim_ResolverError_OmitsProductsClaim(t *testing.T) {
	svc, repo, client, redirectURI, code := newTxExchangeFixture(t)
	failingResolver := NewProductSubscriptionResolver(
		&mockSubscriptionInstanceRepo{err: fmt.Errorf("db unavailable")},
		&mockSubscriptionProductRepo{products: map[uuid.UUID]*models.Product{}},
	)
	svc.SetProductSubscriptionResolver(failingResolver)
	_ = repo

	resp, err := svc.ExchangeAuthorizationCode(context.Background(), client, code, redirectURI, "", "")
	require.NoError(t, err, "resolver failure must not fail token issuance")

	claims := decodeJWTUnverified(t, resp.AccessToken)
	_, present := claims["products"]
	assert.False(t, present, "resolver error must fail closed: products claim must be entirely absent, not empty or all-products")
}
