// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// saml_sp_identity_controls_test.go pins the three t-109 decisions.
//
// Each has a POSITIVE control: an opt-in that never grants, or a refusal that
// fires on everything, passes every negative case while breaking real SAML.

import (
	"context"
	"testing"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func TestUnsolicitedAssertion_RefusedUnlessOptedIn(t *testing.T) {
	svc := &SAMLSPService{}

	// No config at all: an assertion we never asked for must be refused.
	if err := svc.validateAndConsumeAuthnRequest(context.Background(),
		&models.IdentityProvider{}, ""); err == nil {
		t.Fatal("an unsolicited assertion must be refused when IdP-initiated SSO is not enabled")
	}

	// Explicitly disabled.
	off := &models.IdentityProvider{SAMLSPConfig: &models.SAMLSPConfig{SPAllowIdPInitiated: false}}
	if err := svc.validateAndConsumeAuthnRequest(context.Background(), off, ""); err == nil {
		t.Fatal("sp_allow_idp_initiated=false must refuse an unsolicited assertion")
	}
	t.Log("PASS: unsolicited assertions refused by default")

	// POSITIVE CONTROL: a tenant that has deliberately enabled IdP-initiated SSO
	// must still be able to use it, otherwise this is a wall rather than a gate.
	on := &models.IdentityProvider{SAMLSPConfig: &models.SAMLSPConfig{SPAllowIdPInitiated: true}}
	if err := svc.validateAndConsumeAuthnRequest(context.Background(), on, ""); err != nil {
		t.Fatalf("sp_allow_idp_initiated=true must permit IdP-initiated SSO, got: %v", err)
	}
	t.Log("PASS positive: opting in genuinely enables IdP-initiated SSO")
}

func TestSAMLEmailVerified_RequiresExplicitTrustAndAnAddress(t *testing.T) {
	// The decision recorded for finding (b): SAML carries no email_verified
	// claim, so the only real justification is an explicit admin decision.
	cases := []struct {
		name  string
		trust bool
		email string
		want  bool
	}{
		{"no trust configured, address present", false, "a@corp.example", false},
		{"trust configured but no address asserted", true, "", false},
		{"trust configured and address asserted", true, "a@corp.example", true},
		{"neither", false, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &models.IdentityProvider{SAMLSPConfig: &models.SAMLSPConfig{
				SPTrustIDPEmailVerification: tc.trust,
			}}
			got := p.SAMLSPConfig.TrustsAssertedEmail(tc.email)
			if got != tc.want {
				t.Fatalf("want IsEmailVerified=%v, got %v", tc.want, got)
			}
		})
	}
	// POSITIVE CONTROL is the third case above: a tenant that has explicitly
	// declared its IdP verifies addresses still gets verified users. Hardcoding
	// false would pass the other three and silently downgrade every SAML tenant.
	t.Log("PASS: verification is asserted only on an explicit decision plus a real address")
}
