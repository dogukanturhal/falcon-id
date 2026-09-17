// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// stubIDPRoutingRepo is a minimal fake satisfying idpRoutingRepo. Only the
// FindByEmailDomain branch is exercised below; the CRUD methods return
// zero values so an accidental call from the service surfaces as a
// test-side panic on a nil pointer or an unexpected nil return.
type stubIDPRoutingRepo struct {
	rule *models.IDPRoutingRule
	err  error
	// lastDomain captures the argument passed to FindByEmailDomain so the
	// test can assert the service applied the email→domain normalisation
	// (lower-case, trim).
	lastDomain   string
	lastTenantID uuid.UUID
}

func (s *stubIDPRoutingRepo) FindByEmailDomain(_ context.Context, tenantID uuid.UUID, domain string) (*models.IDPRoutingRule, error) {
	s.lastTenantID = tenantID
	s.lastDomain = domain
	return s.rule, s.err
}

// Unused-in-this-test repo methods, present to satisfy the interface.
func (s *stubIDPRoutingRepo) Create(_ context.Context, _ *models.IDPRoutingRule) error {
	return nil
}
func (s *stubIDPRoutingRepo) GetByID(_ context.Context, _, _ uuid.UUID) (*models.IDPRoutingRule, error) {
	return nil, nil
}
func (s *stubIDPRoutingRepo) Update(_ context.Context, _ *models.IDPRoutingRule) error { return nil }
func (s *stubIDPRoutingRepo) Delete(_ context.Context, _, _ uuid.UUID) error           { return nil }
func (s *stubIDPRoutingRepo) ListByTenant(_ context.Context, _ uuid.UUID) ([]models.IDPRoutingRule, error) {
	return nil, nil
}

// newTestRoutingService builds an IDPRoutingService against the stub.
// Bypasses NewIDPRoutingService because that constructor expects the
// concrete *repositories.IDPRoutingRepository type — the stub satisfies
// the idpRoutingRepo interface but isn't that concrete type.
func newTestRoutingService(stub *stubIDPRoutingRepo) *IDPRoutingService {
	return &IDPRoutingService{repo: stub}
}

func tenantID() uuid.UUID { return uuid.MustParse("00000000-0000-0000-0000-000000000099") }

func activeRule(name string) *models.IDPRoutingRule {
	return &models.IDPRoutingRule{
		ID:                 uuid.New(),
		TenantID:           tenantID(),
		IdentityProviderID: uuid.New(),
		RuleType:           "email_domain",
		RuleValue:          "acme.com",
		Priority:           10,
		IsEnabled:          true,
		ProviderName:       name,
		ProviderType:       "oidc",
		ProviderIsActive:   true,
	}
}

func disabledRule(name string) *models.IDPRoutingRule {
	r := activeRule(name)
	r.IsEnabled = false
	return r
}

func inactiveProviderRule(name string) *models.IDPRoutingRule {
	r := activeRule(name)
	r.ProviderIsActive = false
	return r
}

func TestIDPRoutingResolution_IsUsable(t *testing.T) {
	tests := []struct {
		name string
		res  *IDPRoutingResolution
		want bool
	}{
		{"nil resolution", nil, false},
		{"nil rule", &IDPRoutingResolution{}, false},
		{"active rule and provider", &IDPRoutingResolution{Rule: activeRule("ok")}, true},
		{"rule disabled", &IDPRoutingResolution{Rule: activeRule("d"), RuleDisabled: true}, false},
		{"provider inactive", &IDPRoutingResolution{Rule: activeRule("p"), ProviderInactive: true}, false},
		{"both disabled", &IDPRoutingResolution{Rule: activeRule("b"), RuleDisabled: true, ProviderInactive: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.res.IsUsable())
		})
	}
}

func TestResolveIDPForEmail_NoMatch(t *testing.T) {
	stub := &stubIDPRoutingRepo{rule: nil}
	svc := newTestRoutingService(stub)
	rule, err := svc.ResolveIDPForEmail(context.Background(), tenantID(), "alice@unclaimed.example")
	require.NoError(t, err)
	assert.Nil(t, rule)
	assert.Equal(t, "unclaimed.example", stub.lastDomain, "service must normalise the email to its lowercase domain before hitting the repo")
}

func TestResolveIDPForEmail_ActiveRule(t *testing.T) {
	want := activeRule("acme-oidc")
	stub := &stubIDPRoutingRepo{rule: want}
	svc := newTestRoutingService(stub)
	got, err := svc.ResolveIDPForEmail(context.Background(), tenantID(), "ALICE@Acme.COM")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, want.ID, got.ID)
	assert.Equal(t, "acme.com", stub.lastDomain)
}

func TestResolveIDPForEmail_DisabledRuleCollapsesToNil(t *testing.T) {
	// Legacy method preserves "nil = unusable" contract so existing
	// callers' if-nil branches still work. The audit signal lives in
	// the warn log (not observable from the legacy return).
	stub := &stubIDPRoutingRepo{rule: disabledRule("disabled-oidc")}
	svc := newTestRoutingService(stub)
	got, err := svc.ResolveIDPForEmail(context.Background(), tenantID(), "alice@acme.com")
	require.NoError(t, err)
	assert.Nil(t, got, "legacy ResolveIDPForEmail must collapse disabled rules to nil to preserve the existing caller contract")
}

func TestResolveIDPForEmail_InactiveProviderCollapsesToNil(t *testing.T) {
	stub := &stubIDPRoutingRepo{rule: inactiveProviderRule("inactive-oidc")}
	svc := newTestRoutingService(stub)
	got, err := svc.ResolveIDPForEmail(context.Background(), tenantID(), "alice@acme.com")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestResolveIDPForEmail_InvalidEmail(t *testing.T) {
	stub := &stubIDPRoutingRepo{}
	svc := newTestRoutingService(stub)
	_, err := svc.ResolveIDPForEmail(context.Background(), tenantID(), "not-an-email")
	require.Error(t, err)
	assert.Empty(t, stub.lastDomain, "invalid email must short-circuit before the repo call")
}

func TestResolveIDPForEmailWithState_NoMatch(t *testing.T) {
	stub := &stubIDPRoutingRepo{rule: nil}
	svc := newTestRoutingService(stub)
	res, err := svc.ResolveIDPForEmailWithState(context.Background(), tenantID(), "alice@unclaimed.example")
	require.NoError(t, err)
	assert.Nil(t, res, "no rule for the domain returns a nil resolution (distinct from a rule-exists-but-disabled resolution)")
}

func TestResolveIDPForEmailWithState_ActiveRule(t *testing.T) {
	want := activeRule("acme-oidc")
	stub := &stubIDPRoutingRepo{rule: want}
	svc := newTestRoutingService(stub)
	res, err := svc.ResolveIDPForEmailWithState(context.Background(), tenantID(), "alice@acme.com")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.IsUsable())
	assert.False(t, res.RuleDisabled)
	assert.False(t, res.ProviderInactive)
	assert.Equal(t, want.ID, res.Rule.ID)
}

func TestResolveIDPForEmailWithState_DisabledRule(t *testing.T) {
	// G5 audit: pre-fix this state was indistinguishable from
	// "no rule exists" at the caller boundary. Post-fix, the caller
	// gets the rule pointer + RuleDisabled=true and can surface
	// "your routing rule was disabled by the admin" instead of the
	// misleading "your domain is unknown" message.
	want := disabledRule("disabled-oidc")
	stub := &stubIDPRoutingRepo{rule: want}
	svc := newTestRoutingService(stub)
	res, err := svc.ResolveIDPForEmailWithState(context.Background(), tenantID(), "alice@acme.com")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.Rule, "disabled-rule case must return a non-nil rule pointer so the caller can identify which rule was hit")
	assert.True(t, res.RuleDisabled)
	assert.False(t, res.ProviderInactive)
	assert.False(t, res.IsUsable())
}

func TestResolveIDPForEmailWithState_InactiveProvider(t *testing.T) {
	want := inactiveProviderRule("p-inactive")
	stub := &stubIDPRoutingRepo{rule: want}
	svc := newTestRoutingService(stub)
	res, err := svc.ResolveIDPForEmailWithState(context.Background(), tenantID(), "alice@acme.com")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.Rule)
	assert.False(t, res.RuleDisabled)
	assert.True(t, res.ProviderInactive)
	assert.False(t, res.IsUsable())
}

func TestResolveIDPForEmailWithState_DomainLowercasedAndTrimmed(t *testing.T) {
	stub := &stubIDPRoutingRepo{}
	svc := newTestRoutingService(stub)
	_, err := svc.ResolveIDPForEmailWithState(context.Background(), tenantID(), "alice@ACME.com")
	require.NoError(t, err)
	assert.Equal(t, "acme.com", stub.lastDomain)
}
