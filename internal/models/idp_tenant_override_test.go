// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// baseProvider returns a minimal IdentityProvider for test use.
func baseProvider(providerType string) *IdentityProvider {
	return &IdentityProvider{
		ID:                 uuid.New(),
		Type:               providerType,
		Name:               "test-provider",
		DisplayName:        "Test Provider",
		IsEnabled:          true,
		AutoProvisionUsers: false,
	}
}

// TestIDPWithOverride_EffectiveShowAsButton verifies the NULL-means-inherit rule
// for ShowAsButton across social and enterprise provider types.
func TestIDPWithOverride_EffectiveShowAsButton(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		providerType string
		overrideVal  *bool // nil = no override record at all
		noOverride   bool  // true means Override is nil
		want         bool
	}{
		// --- No override record at all ---
		{name: "google_no_override", providerType: "google", noOverride: true, want: true},
		{name: "microsoft_no_override", providerType: "microsoft", noOverride: true, want: true},
		{name: "github_no_override", providerType: "github", noOverride: true, want: true},
		{name: "apple_no_override", providerType: "apple", noOverride: true, want: true},
		{name: "linkedin_no_override", providerType: "linkedin", noOverride: true, want: true},
		{name: "oauth_no_override", providerType: "oauth", noOverride: true, want: true},
		{name: "oidc_no_override", providerType: "oidc", noOverride: true, want: true},
		{name: "ldap_no_override", providerType: "ldap", noOverride: true, want: false},
		{name: "saml_no_override", providerType: "saml", noOverride: true, want: false},

		// --- Override record present but ShowAsButton is NULL ---
		{name: "google_override_null", providerType: "google", overrideVal: nil, want: true},
		{name: "ldap_override_null", providerType: "ldap", overrideVal: nil, want: false},

		// --- Override explicitly sets the value ---
		{name: "google_override_false", providerType: "google", overrideVal: boolPtr(false), want: false},
		{name: "ldap_override_true", providerType: "ldap", overrideVal: boolPtr(true), want: true},
		{name: "saml_override_true", providerType: "saml", overrideVal: boolPtr(true), want: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			combo := &IDPWithOverride{
				Provider: baseProvider(tc.providerType),
			}

			if !tc.noOverride {
				combo.Override = &IDPTenantOverride{
					ShowAsButton: tc.overrideVal,
				}
			}

			assert.Equal(t, tc.want, combo.EffectiveShowAsButton())
		})
	}
}

// TestIDPWithOverride_EffectiveSignupEnabled verifies signup-enabled resolution.
func TestIDPWithOverride_EffectiveSignupEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		autoProvision    bool // provider.AutoProvisionUsers
		overrideIsSignup *bool
		noOverride       bool
		want             bool
	}{
		{name: "no_override_auto_false", autoProvision: false, noOverride: true, want: false},
		{name: "no_override_auto_true", autoProvision: true, noOverride: true, want: true},
		{name: "override_null_auto_false", autoProvision: false, overrideIsSignup: nil, want: false},
		{name: "override_null_auto_true", autoProvision: true, overrideIsSignup: nil, want: true},
		{name: "override_true", autoProvision: false, overrideIsSignup: boolPtr(true), want: true},
		{name: "override_false", autoProvision: true, overrideIsSignup: boolPtr(false), want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := baseProvider("google")
			p.AutoProvisionUsers = tc.autoProvision

			combo := &IDPWithOverride{Provider: p}
			if !tc.noOverride {
				combo.Override = &IDPTenantOverride{IsSignupEnabled: tc.overrideIsSignup}
			}

			assert.Equal(t, tc.want, combo.EffectiveSignupEnabled())
		})
	}
}

// TestIDPWithOverride_EffectiveAssignMembership verifies assign-membership resolution.
func TestIDPWithOverride_EffectiveAssignMembership(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		autoProvision bool
		overrideVal   *bool
		noOverride    bool
		want          bool
	}{
		{name: "no_override_auto_false", autoProvision: false, noOverride: true, want: false},
		{name: "no_override_auto_true", autoProvision: true, noOverride: true, want: true},
		{name: "override_null", autoProvision: true, overrideVal: nil, want: true},
		{name: "override_true", autoProvision: false, overrideVal: boolPtr(true), want: true},
		{name: "override_false", autoProvision: true, overrideVal: boolPtr(false), want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := baseProvider("google")
			p.AutoProvisionUsers = tc.autoProvision

			combo := &IDPWithOverride{Provider: p}
			if !tc.noOverride {
				combo.Override = &IDPTenantOverride{AssignMembershipOnLogin: tc.overrideVal}
			}

			assert.Equal(t, tc.want, combo.EffectiveAssignMembership())
		})
	}
}

// TestIDPWithOverride_EffectiveDisplayName verifies display-name override resolution.
func TestIDPWithOverride_EffectiveDisplayName(t *testing.T) {
	t.Parallel()

	p := baseProvider("google")
	p.DisplayName = "Global Google"

	t.Run("no override", func(t *testing.T) {
		combo := &IDPWithOverride{Provider: p}
		assert.Equal(t, "Global Google", combo.EffectiveDisplayName())
	})

	t.Run("override with blank display name", func(t *testing.T) {
		combo := &IDPWithOverride{
			Provider: p,
			Override: &IDPTenantOverride{DisplayName: strPtr("")},
		}
		assert.Equal(t, "Global Google", combo.EffectiveDisplayName())
	})

	t.Run("override with custom display name", func(t *testing.T) {
		combo := &IDPWithOverride{
			Provider: p,
			Override: &IDPTenantOverride{DisplayName: strPtr("Acme Google Login")},
		}
		assert.Equal(t, "Acme Google Login", combo.EffectiveDisplayName())
	})
}

// TestIDPWithOverride_EffectiveIsEnabled verifies enabled-flag resolution.
func TestIDPWithOverride_EffectiveIsEnabled(t *testing.T) {
	t.Parallel()

	t.Run("no override uses provider flag", func(t *testing.T) {
		p := baseProvider("google")
		p.IsEnabled = true
		combo := &IDPWithOverride{Provider: p}
		assert.True(t, combo.EffectiveIsEnabled())
	})

	t.Run("override disabled takes precedence over enabled provider", func(t *testing.T) {
		p := baseProvider("google")
		p.IsEnabled = true
		combo := &IDPWithOverride{
			Provider: p,
			Override: &IDPTenantOverride{IsEnabled: false},
		}
		assert.False(t, combo.EffectiveIsEnabled())
	})

	t.Run("override enabled takes precedence over disabled provider", func(t *testing.T) {
		p := baseProvider("ldap")
		p.IsEnabled = false
		combo := &IDPWithOverride{
			Provider: p,
			Override: &IDPTenantOverride{IsEnabled: true},
		}
		assert.True(t, combo.EffectiveIsEnabled())
	})
}

// TestIDPWithOverride_ToResponse verifies the DTO serialisation.
func TestIDPWithOverride_ToResponse(t *testing.T) {
	t.Parallel()

	p := baseProvider("google")
	p.AutoProvisionUsers = true
	overrideID := uuid.New()
	tenantID := uuid.New()

	showFalse := false
	signupTrue := true

	combo := &IDPWithOverride{
		Provider: p,
		Override: &IDPTenantOverride{
			ID:              overrideID,
			TenantID:        tenantID,
			ProviderID:      p.ID,
			IsEnabled:       true,
			ShowAsButton:    &showFalse,
			IsSignupEnabled: &signupTrue,
		},
	}

	resp := combo.ToResponse()

	assert.Equal(t, overrideID, resp.ID)
	assert.Equal(t, tenantID, resp.TenantID)
	assert.Equal(t, p.ID, resp.ProviderID)
	// Effective values
	assert.False(t, resp.EffectiveShowAsButton)
	assert.True(t, resp.EffectiveSignupEnabled)
	assert.True(t, resp.EffectiveAssignMember) // from AutoProvisionUsers fallback
}
