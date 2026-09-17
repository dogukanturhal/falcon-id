// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Tests: AuthorizationDetail.UnmarshalJSON
// ---------------------------------------------------------------------------

func TestAuthorizationDetail_UnmarshalJSON_StandardFields(t *testing.T) {
	raw := `{
		"type":       "payment_initiation",
		"actions":    ["initiate", "status"],
		"locations":  ["https://bank.example/payments"],
		"datatypes":  ["balances"],
		"identifier": "acct-001",
		"privileges": ["single-use"]
	}`

	var d AuthorizationDetail
	require.NoError(t, json.Unmarshal([]byte(raw), &d))

	assert.Equal(t, "payment_initiation", d.Type)
	assert.Equal(t, []string{"initiate", "status"}, d.Actions)
	assert.Equal(t, []string{"https://bank.example/payments"}, d.Locations)
	assert.Equal(t, []string{"balances"}, d.Datatypes)
	assert.Equal(t, "acct-001", d.Identifier)
	assert.Equal(t, []string{"single-use"}, d.Privileges)
	assert.Empty(t, d.Extra)
}

func TestAuthorizationDetail_UnmarshalJSON_ExtraFields(t *testing.T) {
	raw := `{
		"type":              "payment_initiation",
		"instructedAmount":  {"amount": 123.50, "currency": "EUR"},
		"creditorName":      "Merchant Ltd"
	}`

	var d AuthorizationDetail
	require.NoError(t, json.Unmarshal([]byte(raw), &d))

	assert.Equal(t, "payment_initiation", d.Type)
	require.NotNil(t, d.Extra)
	assert.Contains(t, d.Extra, "instructedAmount")
	assert.Contains(t, d.Extra, "creditorName")
	assert.Equal(t, "Merchant Ltd", d.Extra["creditorName"])
}

func TestAuthorizationDetail_UnmarshalJSON_MinimalTypeOnly(t *testing.T) {
	raw := `{"type":"account_information"}`

	var d AuthorizationDetail
	require.NoError(t, json.Unmarshal([]byte(raw), &d))

	assert.Equal(t, "account_information", d.Type)
	assert.Empty(t, d.Actions)
	assert.Empty(t, d.Locations)
	assert.Empty(t, d.Extra)
}

func TestAuthorizationDetail_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var d AuthorizationDetail
	err := json.Unmarshal([]byte(`not-json`), &d)
	assert.Error(t, err)
}

func TestAuthorizationDetail_UnmarshalJSON_InvalidActionsType(t *testing.T) {
	raw := `{"type":"foo","actions":"not-an-array"}`
	var d AuthorizationDetail
	err := json.Unmarshal([]byte(raw), &d)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "actions")
}

// ---------------------------------------------------------------------------
// Tests: AuthorizationDetail.MarshalJSON
// ---------------------------------------------------------------------------

func TestAuthorizationDetail_MarshalJSON_RoundTrip(t *testing.T) {
	original := `{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"amount":123.5,"currency":"EUR"}}`

	var d AuthorizationDetail
	require.NoError(t, json.Unmarshal([]byte(original), &d))

	encoded, err := json.Marshal(d)
	require.NoError(t, err)

	// Verify round-trip by decoding again.
	var d2 AuthorizationDetail
	require.NoError(t, json.Unmarshal(encoded, &d2))
	assert.Equal(t, d.Type, d2.Type)
	assert.Equal(t, d.Actions, d2.Actions)
	assert.Equal(t, d.Extra["instructedAmount"], d2.Extra["instructedAmount"])
}

func TestAuthorizationDetail_MarshalJSON_OmitsEmptyOptionalFields(t *testing.T) {
	d := AuthorizationDetail{Type: "account_information"}

	encoded, err := json.Marshal(d)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &m))
	assert.Equal(t, "account_information", m["type"])
	assert.NotContains(t, m, "actions")
	assert.NotContains(t, m, "locations")
	assert.NotContains(t, m, "identifier")
}

func TestAuthorizationDetail_MarshalJSON_StandardFieldsTakePrecedenceOverExtra(t *testing.T) {
	// Construct a detail where Extra has a "type" key that should be overridden by the struct field.
	d := AuthorizationDetail{
		Type:  "payment_initiation",
		Extra: map[string]interface{}{"type": "overridden"},
	}

	encoded, err := json.Marshal(d)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &m))
	assert.Equal(t, "payment_initiation", m["type"], "struct field must win over Extra key")
}

// ---------------------------------------------------------------------------
// Tests: AuthorizationDetail.Validate
// ---------------------------------------------------------------------------

func TestAuthorizationDetail_Validate_TypeRequired(t *testing.T) {
	d := AuthorizationDetail{}
	err := d.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'type' field is required")
}

func TestAuthorizationDetail_Validate_AllTypesPermittedWhenListEmpty(t *testing.T) {
	d := AuthorizationDetail{Type: "payment_initiation"}
	assert.NoError(t, d.Validate(nil))
	assert.NoError(t, d.Validate([]string{}))
}

func TestAuthorizationDetail_Validate_TypeInAllowedList(t *testing.T) {
	d := AuthorizationDetail{Type: "payment_initiation"}
	allowed := []string{"payment_initiation", "account_information"}
	assert.NoError(t, d.Validate(allowed))
}

func TestAuthorizationDetail_Validate_TypeNotInAllowedList(t *testing.T) {
	d := AuthorizationDetail{Type: "unknown_type"}
	allowed := []string{"payment_initiation"}
	err := d.Validate(allowed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown_type")
	assert.Contains(t, err.Error(), "not permitted")
}

// ---------------------------------------------------------------------------
// Tests: AuthorizationDetailsRequest (slice unmarshaling)
// ---------------------------------------------------------------------------

func TestAuthorizationDetailsRequest_UnmarshalJSON_MultipleDetails(t *testing.T) {
	raw := `[
		{"type":"payment_initiation","actions":["initiate"]},
		{"type":"account_information","locations":["https://bank.example/accounts"]}
	]`

	var details AuthorizationDetailsRequest
	require.NoError(t, json.Unmarshal([]byte(raw), &details))
	require.Len(t, details, 2)
	assert.Equal(t, "payment_initiation", details[0].Type)
	assert.Equal(t, "account_information", details[1].Type)
}
