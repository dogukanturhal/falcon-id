// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── mock replay store ─────────────────────────────────────────────────────────

type mockReplayStore struct {
	consumed map[string]bool
}

func newMockReplayStore() *mockReplayStore {
	return &mockReplayStore{consumed: make(map[string]bool)}
}

func (m *mockReplayStore) MarkAssertionConsumed(_ context.Context, id string, _ time.Duration) (bool, error) {
	if m.consumed[id] {
		return false, nil
	}
	m.consumed[id] = true
	return true, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

const (
	spEntityID   = "https://sp.example.com/saml/metadata"
	acsURL       = "https://sp.example.com/saml/acs"
	bearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // test fixture value, not a real credential
)

func defaultConfig() *AssertionValidationConfig {
	return &AssertionValidationConfig{
		ExpectedAudience:    spEntityID,
		ExpectedDestination: acsURL,
		ExpectedRecipient:   acsURL,
		ClockSkew:           2 * time.Minute,
		MaxAssertionAge:     8 * time.Hour,
	}
}

func validAssertion() *ParsedAssertion {
	now := time.Now().UTC()
	return &ParsedAssertion{
		ID:                        "_assert001",
		IssueInstant:              now,
		Issuer:                    "https://idp.example.com",
		Audience:                  spEntityID,
		ResponseDestination:       acsURL,
		Recipient:                 acsURL,
		SubjectConfirmationMethod: bearerMethod,
		NotBefore:                 now.Add(-1 * time.Minute),
		NotOnOrAfter:              now.Add(5 * time.Minute),
		NameID:                    "user@example.com",
	}
}

// ── test cases ────────────────────────────────────────────────────────────────

func TestValidateAssertionSemantics_HappyPath(t *testing.T) {
	err := ValidateAssertionSemantics(
		context.Background(),
		validAssertion(),
		defaultConfig(),
		newMockReplayStore(),
	)
	assert.NoError(t, err)
}

func TestValidateAssertionSemantics_AudienceMismatch(t *testing.T) {
	a := validAssertion()
	a.Audience = "https://other-sp.example.com"
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), newMockReplayStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience mismatch")
}

func TestValidateAssertionSemantics_AudienceEmptyWhenExpected(t *testing.T) {
	a := validAssertion()
	a.Audience = ""
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), newMockReplayStore())
	require.Error(t, err)
	// The error should state that the audience is missing.
	assert.Contains(t, err.Error(), "Audience")
}

func TestValidateAssertionSemantics_DestinationMismatch(t *testing.T) {
	a := validAssertion()
	a.ResponseDestination = "https://wrong.example.com/acs"
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), newMockReplayStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "destination mismatch")
}

func TestValidateAssertionSemantics_RecipientMismatch(t *testing.T) {
	a := validAssertion()
	a.Recipient = "https://wrong.example.com/acs"
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), newMockReplayStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "recipient mismatch")
}

func TestValidateAssertionSemantics_InvalidSubjectConfirmationMethod(t *testing.T) {
	a := validAssertion()
	a.SubjectConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), newMockReplayStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SubjectConfirmation Method")
}

func TestValidateAssertionSemantics_BearerMethodAccepted(t *testing.T) {
	a := validAssertion()
	a.SubjectConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), newMockReplayStore())
	assert.NoError(t, err)
}

func TestValidateAssertionSemantics_NotYetValid_OutsideSkew(t *testing.T) {
	a := validAssertion()
	// NotBefore is 10 minutes in the future, skew is only 2 minutes.
	a.NotBefore = time.Now().UTC().Add(10 * time.Minute)
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), newMockReplayStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet valid")
}

func TestValidateAssertionSemantics_NotYetValid_WithinSkew(t *testing.T) {
	a := validAssertion()
	// NotBefore is 1 minute in the future, skew is 2 minutes — should pass.
	a.NotBefore = time.Now().UTC().Add(1 * time.Minute)
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), newMockReplayStore())
	assert.NoError(t, err)
}

func TestValidateAssertionSemantics_Expired_OutsideSkew(t *testing.T) {
	a := validAssertion()
	// NotOnOrAfter was 10 minutes ago, skew is only 2 minutes.
	a.NotOnOrAfter = time.Now().UTC().Add(-10 * time.Minute)
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), newMockReplayStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestValidateAssertionSemantics_Expired_WithinSkew(t *testing.T) {
	a := validAssertion()
	// NotOnOrAfter was 1 minute ago, skew is 2 minutes — should pass.
	a.NotOnOrAfter = time.Now().UTC().Add(-1 * time.Minute)
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), newMockReplayStore())
	assert.NoError(t, err)
}

func TestValidateAssertionSemantics_MaxAssertionAge_Exceeded(t *testing.T) {
	a := validAssertion()
	// IssueInstant is 9 hours ago, MaxAssertionAge is 8 hours.
	a.IssueInstant = time.Now().UTC().Add(-9 * time.Hour)
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), newMockReplayStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too old")
}

func TestValidateAssertionSemantics_ReplayPrevention_FirstUse(t *testing.T) {
	store := newMockReplayStore()
	err := ValidateAssertionSemantics(context.Background(), validAssertion(), defaultConfig(), store)
	assert.NoError(t, err)
	// The ID must now be recorded.
	assert.True(t, store.consumed["_assert001"])
}

func TestValidateAssertionSemantics_ReplayPrevention_SecondUse(t *testing.T) {
	store := newMockReplayStore()
	a := validAssertion()

	// First use must succeed.
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), store)
	require.NoError(t, err)

	// Second use must fail.  Reuse the same ID.
	a2 := validAssertion()
	a2.ID = a.ID
	err2 := ValidateAssertionSemantics(context.Background(), a2, defaultConfig(), store)
	require.Error(t, err2)
	assert.Contains(t, err2.Error(), "replay")
}

func TestValidateAssertionSemantics_NilReplayStore_Skips(t *testing.T) {
	// When replayStore is nil the function should not attempt replay prevention
	// (no panic, no error from the replay step).
	err := ValidateAssertionSemantics(context.Background(), validAssertion(), defaultConfig(), nil)
	assert.NoError(t, err)
}

func TestValidateAssertionSemantics_EmptySubjectConfirmationMethod_Accepted(t *testing.T) {
	// An empty SubjectConfirmationMethod is not validated — only non-empty,
	// non-bearer values are rejected.
	a := validAssertion()
	a.SubjectConfirmationMethod = ""
	err := ValidateAssertionSemantics(context.Background(), a, defaultConfig(), newMockReplayStore())
	assert.NoError(t, err)
}

func TestValidateAssertionSemantics_NoAudienceCheck_WhenExpectedEmpty(t *testing.T) {
	cfg := defaultConfig()
	cfg.ExpectedAudience = ""

	a := validAssertion()
	a.Audience = "" // audience can be empty if SP does not require check

	err := ValidateAssertionSemantics(context.Background(), a, cfg, newMockReplayStore())
	assert.NoError(t, err)
}

func TestValidateAssertionSemantics_MaxAssertionAge_Zero_Skips(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxAssertionAge = 0 // disabled

	a := validAssertion()
	a.IssueInstant = time.Now().UTC().Add(-24 * time.Hour) // very old

	err := ValidateAssertionSemantics(context.Background(), a, cfg, newMockReplayStore())
	assert.NoError(t, err)
}
