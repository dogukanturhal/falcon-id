// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestRARService() *RARService {
	return NewRARService()
}

func buildRARClient(types ...string) models.OAuthClient {
	return models.OAuthClient{
		AuthorizationDetailTypes: types,
	}
}

// ---------------------------------------------------------------------------
// Tests: ParseAuthorizationDetails
// ---------------------------------------------------------------------------

func TestRARService_ParseAuthorizationDetails_EmptyInputReturnsNil(t *testing.T) {
	svc := newTestRARService()
	details, err := svc.ParseAuthorizationDetails("")
	require.NoError(t, err)
	assert.Nil(t, details)
}

func TestRARService_ParseAuthorizationDetails_ValidSingleDetail(t *testing.T) {
	svc := newTestRARService()
	raw := `[{"type":"payment_initiation","actions":["initiate"]}]`
	details, err := svc.ParseAuthorizationDetails(raw)
	require.NoError(t, err)
	require.Len(t, details, 1)
	assert.Equal(t, "payment_initiation", details[0].Type)
	assert.Equal(t, []string{"initiate"}, details[0].Actions)
}

func TestRARService_ParseAuthorizationDetails_ValidMultipleDetails(t *testing.T) {
	svc := newTestRARService()
	raw := `[
		{"type":"payment_initiation","actions":["initiate"]},
		{"type":"account_information","locations":["https://bank.example"]}
	]`
	details, err := svc.ParseAuthorizationDetails(raw)
	require.NoError(t, err)
	require.Len(t, details, 2)
	assert.Equal(t, "payment_initiation", details[0].Type)
	assert.Equal(t, "account_information", details[1].Type)
}

func TestRARService_ParseAuthorizationDetails_WithExtraFields(t *testing.T) {
	svc := newTestRARService()
	raw := `[{"type":"payment_initiation","instructedAmount":{"amount":100,"currency":"USD"}}]`
	details, err := svc.ParseAuthorizationDetails(raw)
	require.NoError(t, err)
	require.Len(t, details, 1)
	assert.Equal(t, "payment_initiation", details[0].Type)
	assert.Contains(t, details[0].Extra, "instructedAmount")
}

func TestRARService_ParseAuthorizationDetails_InvalidJSON(t *testing.T) {
	svc := newTestRARService()
	_, err := svc.ParseAuthorizationDetails(`not valid json`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_authorization_details")
}

func TestRARService_ParseAuthorizationDetails_NotAnArray(t *testing.T) {
	svc := newTestRARService()
	_, err := svc.ParseAuthorizationDetails(`{"type":"payment_initiation"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_authorization_details")
}

// ---------------------------------------------------------------------------
// Tests: ValidateAgainstClient
// ---------------------------------------------------------------------------

func TestRARService_ValidateAgainstClient_ClientWithNoRestrictions(t *testing.T) {
	svc := newTestRARService()
	details := []models.AuthorizationDetail{
		{Type: "payment_initiation"},
		{Type: "account_information"},
	}
	client := buildRARClient() // no restrictions
	assert.NoError(t, svc.ValidateAgainstClient(details, client))
}

func TestRARService_ValidateAgainstClient_AllTypesAllowed(t *testing.T) {
	svc := newTestRARService()
	details := []models.AuthorizationDetail{{Type: "payment_initiation"}}
	client := buildRARClient("payment_initiation", "account_information")
	assert.NoError(t, svc.ValidateAgainstClient(details, client))
}

func TestRARService_ValidateAgainstClient_TypeNotAllowed(t *testing.T) {
	svc := newTestRARService()
	details := []models.AuthorizationDetail{{Type: "unknown_type"}}
	client := buildRARClient("payment_initiation")
	err := svc.ValidateAgainstClient(details, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_authorization_details")
	assert.Contains(t, err.Error(), "unknown_type")
}

func TestRARService_ValidateAgainstClient_EmptyTypeInDetail(t *testing.T) {
	svc := newTestRARService()
	details := []models.AuthorizationDetail{{Type: ""}} // missing required field
	client := buildRARClient("payment_initiation")
	err := svc.ValidateAgainstClient(details, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_authorization_details")
}

func TestRARService_ValidateAgainstClient_EmptyDetailsSlice(t *testing.T) {
	svc := newTestRARService()
	client := buildRARClient("payment_initiation")
	assert.NoError(t, svc.ValidateAgainstClient(nil, client))
	assert.NoError(t, svc.ValidateAgainstClient([]models.AuthorizationDetail{}, client))
}

// ---------------------------------------------------------------------------
// Tests: EmbedInToken
// ---------------------------------------------------------------------------

func TestRARService_EmbedInToken_NoDetailsIsNoop(t *testing.T) {
	svc := newTestRARService()
	claims := map[string]interface{}{"sub": "user-1"}
	svc.EmbedInToken(claims, nil)
	assert.NotContains(t, claims, "authorization_details")

	svc.EmbedInToken(claims, []models.AuthorizationDetail{})
	assert.NotContains(t, claims, "authorization_details")
}

func TestRARService_EmbedInToken_AddsClaimWhenDetailsPresent(t *testing.T) {
	svc := newTestRARService()
	claims := map[string]interface{}{"sub": "user-1"}
	details := []models.AuthorizationDetail{
		{Type: "payment_initiation", Actions: []string{"initiate"}},
	}
	svc.EmbedInToken(claims, details)

	got, ok := claims["authorization_details"]
	require.True(t, ok, "authorization_details claim must be present")
	embedded, ok := got.([]models.AuthorizationDetail)
	require.True(t, ok)
	require.Len(t, embedded, 1)
	assert.Equal(t, "payment_initiation", embedded[0].Type)
}

func TestRARService_EmbedInToken_PreservesExistingClaims(t *testing.T) {
	svc := newTestRARService()
	claims := map[string]interface{}{
		"sub":   "user-1",
		"scope": "openid",
	}
	details := []models.AuthorizationDetail{{Type: "account_information"}}
	svc.EmbedInToken(claims, details)

	assert.Equal(t, "user-1", claims["sub"])
	assert.Equal(t, "openid", claims["scope"])
	assert.Contains(t, claims, "authorization_details")
}

// ---------------------------------------------------------------------------
// Tests: integration — parse → validate → embed pipeline
// ---------------------------------------------------------------------------

func TestRARService_FullPipeline_ValidRequest(t *testing.T) {
	svc := newTestRARService()
	raw := `[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"amount":50.00,"currency":"EUR"}}]`

	details, err := svc.ParseAuthorizationDetails(raw)
	require.NoError(t, err)

	client := buildRARClient("payment_initiation")
	require.NoError(t, svc.ValidateAgainstClient(details, client))

	claims := map[string]interface{}{"sub": "user-42"}
	svc.EmbedInToken(claims, details)

	embedded := claims["authorization_details"].([]models.AuthorizationDetail)
	assert.Equal(t, "payment_initiation", embedded[0].Type)
	assert.Contains(t, embedded[0].Extra, "instructedAmount")
}

func TestRARService_FullPipeline_DisallowedType(t *testing.T) {
	svc := newTestRARService()
	raw := `[{"type":"payment_initiation"}]`

	details, err := svc.ParseAuthorizationDetails(raw)
	require.NoError(t, err)

	client := buildRARClient("account_information") // does not include payment_initiation
	err = svc.ValidateAgainstClient(details, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "payment_initiation")
}
