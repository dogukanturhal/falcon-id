// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"context"
	"fmt"
	"time"
)

// AssertionReplayStore defines the interface for tracking consumed assertion IDs.
type AssertionReplayStore interface {
	// MarkAssertionConsumed attempts to mark an assertion ID as consumed.
	// Returns true if this is the first time the ID was seen, false if it was
	// already consumed (replay).
	MarkAssertionConsumed(ctx context.Context, assertionID string, ttl time.Duration) (bool, error)
}

// AssertionValidationConfig holds all parameters needed to fully validate
// a SAML assertion's semantic content (post-signature).
type AssertionValidationConfig struct {
	// ExpectedAudience is our SP entity ID.
	ExpectedAudience string
	// ExpectedDestination is our ACS URL.
	ExpectedDestination string
	// ExpectedRecipient is our ACS URL (same as destination for POST binding).
	ExpectedRecipient string
	// ClockSkew is the tolerance for NotBefore/NotOnOrAfter checks.
	ClockSkew time.Duration
	// MaxAssertionAge is the maximum age of an assertion.
	MaxAssertionAge time.Duration
}

// ParsedAssertion is a normalized representation of the assertion fields
// needed for semantic validation.
type ParsedAssertion struct {
	ID                        string
	IssueInstant              time.Time
	Issuer                    string
	Audience                  string
	ResponseDestination       string
	Recipient                 string
	SubjectConfirmationMethod string
	NotBefore                 time.Time
	NotOnOrAfter              time.Time
	NameID                    string
	NameIDFormat              string
	SessionIndex              string
	InResponseTo              string
	Attributes                map[string][]string
}

// checkAudienceRestriction validates the Audience field against the SP entity ID.
func checkAudienceRestriction(assertion *ParsedAssertion, expected string) error {
	if expected == "" {
		return nil
	}
	if assertion.Audience == "" {
		return fmt.Errorf("assertion missing Audience but SP requires audience restriction for %q", expected)
	}
	if assertion.Audience != expected {
		return fmt.Errorf("audience mismatch: got %q, expected %q", assertion.Audience, expected)
	}
	return nil
}

// checkDestination validates the Destination field against the ACS URL.
func checkDestination(assertion *ParsedAssertion, expected string) error {
	if expected == "" {
		return nil
	}
	if assertion.ResponseDestination == "" {
		return fmt.Errorf("assertion missing Destination but SP requires destination check for %q", expected)
	}
	if assertion.ResponseDestination != expected {
		return fmt.Errorf("destination mismatch: got %q, expected %q", assertion.ResponseDestination, expected)
	}
	return nil
}

// checkRecipient validates the Recipient field against the ACS URL.
func checkRecipient(assertion *ParsedAssertion, expected string) error {
	if expected == "" {
		return nil
	}
	if assertion.Recipient == "" {
		return fmt.Errorf("assertion missing Recipient but SP requires recipient check for %q", expected)
	}
	if assertion.Recipient != expected {
		return fmt.Errorf("recipient mismatch: got %q, expected %q", assertion.Recipient, expected)
	}
	return nil
}

// checkTimeConditions validates NotBefore/NotOnOrAfter with clock skew and
// the optional maximum assertion age.
func checkTimeConditions(assertion *ParsedAssertion, now time.Time, skew, maxAge time.Duration) error {
	if !assertion.NotBefore.IsZero() && now.Add(skew).Before(assertion.NotBefore) {
		return fmt.Errorf("assertion not yet valid (NotBefore=%s, now=%s, skew=%s)",
			assertion.NotBefore.Format(time.RFC3339), now.Format(time.RFC3339), skew)
	}
	if !assertion.NotOnOrAfter.IsZero() && now.After(assertion.NotOnOrAfter.Add(skew)) {
		return fmt.Errorf("assertion expired (NotOnOrAfter=%s, now=%s, skew=%s)",
			assertion.NotOnOrAfter.Format(time.RFC3339), now.Format(time.RFC3339), skew)
	}
	if maxAge > 0 && !assertion.IssueInstant.IsZero() {
		if age := now.Sub(assertion.IssueInstant); age > maxAge {
			return fmt.Errorf("assertion too old (age=%s, max=%s)", age, maxAge)
		}
	}
	return nil
}

// checkReplayPrevention marks the assertion ID as consumed and returns an error
// on replay.
func checkReplayPrevention(ctx context.Context, assertion *ParsedAssertion, replayStore AssertionReplayStore, ttl time.Duration) error {
	if assertion.ID == "" || replayStore == nil {
		return nil
	}
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	isNew, err := replayStore.MarkAssertionConsumed(ctx, assertion.ID, ttl)
	if err != nil {
		return fmt.Errorf("replay store error: %w", err)
	}
	if !isNew {
		return fmt.Errorf("assertion ID %q has already been consumed (replay)", assertion.ID)
	}
	return nil
}

// ValidateAssertionSemantics performs all post-signature semantic checks:
//   - Audience restriction matches our SP entity ID
//   - Destination matches our ACS URL
//   - Recipient in SubjectConfirmationData matches our ACS URL
//   - SubjectConfirmation Method is bearer
//   - NotBefore / NotOnOrAfter with clock skew
//   - Assertion age does not exceed MaxAssertionAge
//   - Assertion ID has not been seen before (replay prevention)
func ValidateAssertionSemantics(
	ctx context.Context,
	assertion *ParsedAssertion,
	config *AssertionValidationConfig,
	replayStore AssertionReplayStore,
) error {
	if err := checkAudienceRestriction(assertion, config.ExpectedAudience); err != nil {
		return err
	}
	if err := checkDestination(assertion, config.ExpectedDestination); err != nil {
		return err
	}
	if err := checkRecipient(assertion, config.ExpectedRecipient); err != nil {
		return err
	}

	const bearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // not a credential, this is an XML attribute name constant
	if assertion.SubjectConfirmationMethod != "" && assertion.SubjectConfirmationMethod != bearerMethod {
		return fmt.Errorf("unsupported SubjectConfirmation Method: %q", assertion.SubjectConfirmationMethod)
	}

	now := time.Now().UTC()
	if err := checkTimeConditions(assertion, now, config.ClockSkew, config.MaxAssertionAge); err != nil {
		return err
	}

	return checkReplayPrevention(ctx, assertion, replayStore, config.MaxAssertionAge)
}
