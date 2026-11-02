// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// setSlugChecker is a TenantSlugAvailabilityChecker over a set of taken slugs.
type setSlugChecker struct{ taken map[string]bool }

func (c *setSlugChecker) IsSlugAvailable(_ context.Context, slug string) (bool, error) {
	return !c.taken[slug], nil
}

type recordingPrefs struct {
	mu      sync.Mutex
	slug    string
	patch   json.RawMessage
	userID  uuid.UUID
	failing bool
}

func (p *recordingPrefs) PatchProduct(_ context.Context, userID uuid.UUID, slug string, patch json.RawMessage) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.userID, p.slug, p.patch = userID, slug, patch
	if p.failing {
		return nil, errors.New("prefs down")
	}
	return patch, nil
}

type companyFixture struct {
	repo     *mockSignupRequestRepo
	registry *mockTenantManagementRegistrar
	tenants  *mockSignupTenantCreator
	users    *mockSignupUserCreator
	svc      *SignupService
	req      *models.SignupRequest
	tenantID uuid.UUID
}

// newCompanyFixture wires a verified, unprovisioned business request whose
// tenant-management registration succeeds with any slug.
func newCompanyFixture(t *testing.T, taken ...string) *companyFixture {
	t.Helper()
	f := &companyFixture{
		repo:     &mockSignupRequestRepo{},
		registry: &mockTenantManagementRegistrar{},
		tenants:  &mockSignupTenantCreator{},
		users:    &mockSignupUserCreator{},
		tenantID: uuid.New(),
	}
	f.svc = buildSignupServiceWithRegistrar(f.repo, &mockSignupEmailSender{}, f.tenants, f.registry, f.users, &mockSignupUserLookup{})
	checker := &setSlugChecker{taken: map[string]bool{}}
	for _, s := range taken {
		checker.taken[s] = true
	}
	f.svc.SetSlugChecker(checker)
	f.req = verifiedRequest("john@acme.com", "business")

	tenant := &models.Tenant{ID: f.tenantID, Type: "customer"}
	user := fakeUser(f.tenantID, f.req.Email)
	f.repo.On("GetByID", mock.Anything, f.req.ID).Return(f.req, nil)
	f.registry.On("Register", mock.Anything, mock.Anything).Return(&TenantManagementRegisterResult{ID: f.tenantID}, nil)
	f.repo.On("SetProvisionedTenant", mock.Anything, f.req.ID, f.tenantID, mock.Anything).Return(nil)
	f.tenants.On("CreateTenant", mock.Anything, mock.Anything).Return(tenant, nil)
	f.users.On("CreateForSignup", mock.Anything, mock.Anything, mock.Anything).Return(user, nil)
	f.repo.On("MarkCompleted", mock.Anything, f.req.ID, f.tenantID, user.ID).Return(nil)
	return f
}

func (f *companyFixture) complete(in models.CompleteSignupInput) (*CompleteSignupResult, error) {
	in.SignupRequestID = f.req.ID
	in.CompletionSecret = testCompletionSecret
	in.Password = "AcmeSecure1!"
	return f.svc.CompleteSignup(context.Background(), &in, "", "")
}

func (f *companyFixture) registeredSlug() string {
	for _, c := range f.registry.Calls {
		if c.Method == "Register" {
			return c.Arguments.Get(1).(*TenantManagementRegisterRequest).TenantSlug
		}
	}
	return ""
}

func TestCompleteSignup_CompanyName_DerivesAndPersistsSlug(t *testing.T) {
	t.Parallel()
	f := newCompanyFixture(t)
	f.repo.On("SetCompanyDetails", mock.Anything, f.req.ID, "Kaya İnşaat San. ve Tic. Ltd. Şti.", "kaya-insaat").Return(nil)

	res, err := f.complete(models.CompleteSignupInput{CompanyName: "  Kaya İnşaat San. ve Tic. Ltd. Şti.  "})
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, "kaya-insaat", f.registeredSlug())
	f.repo.AssertExpectations(t)
}

func TestCompleteSignup_CompanyName_CollisionPicksNumberedSlug(t *testing.T) {
	t.Parallel()
	f := newCompanyFixture(t, "kaya-insaat", "kaya-insaat-2")
	f.repo.On("SetCompanyDetails", mock.Anything, f.req.ID, "Kaya İnşaat", "kaya-insaat").Return(nil)

	_, err := f.complete(models.CompleteSignupInput{CompanyName: "Kaya İnşaat"})
	require.NoError(t, err)
	assert.Equal(t, "kaya-insaat-3", f.registeredSlug())
}

func TestCompleteSignup_ExplicitSlug_UsedAndValidated(t *testing.T) {
	t.Parallel()
	f := newCompanyFixture(t)
	f.repo.On("SetCompanyDetails", mock.Anything, f.req.ID, "Acme", "acme-hq").Return(nil)

	_, err := f.complete(models.CompleteSignupInput{CompanyName: "Acme", Slug: " Acme-HQ "})
	require.NoError(t, err)
	assert.Equal(t, "acme-hq", f.registeredSlug())

	// Taken or reserved slugs fail the same generic way, before any write.
	for _, slug := range []string{"taken-co", "admin"} {
		g := newCompanyFixture(t, "taken-co")
		_, err := g.complete(models.CompleteSignupInput{CompanyName: "Acme", Slug: slug})
		var se *SignupStateError
		require.ErrorAs(t, err, &se, slug)
		assert.Equal(t, "slug_unavailable", se.Code)
		g.repo.AssertNotCalled(t, "SetCompanyDetails", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		g.registry.AssertNotCalled(t, "Register", mock.Anything, mock.Anything)
	}
}

func TestCompleteSignup_InvalidCompanyName_Rejected(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"A", "bad\x00name", strings.Repeat("x", 121)} {
		f := newCompanyFixture(t)
		_, err := f.complete(models.CompleteSignupInput{CompanyName: name})
		var se *SignupStateError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, "invalid_company_name", se.Code)
	}
}

func TestCompleteSignup_NoCompanyName_KeepsWordPairFallback(t *testing.T) {
	t.Parallel()
	f := newCompanyFixture(t)

	_, err := f.complete(models.CompleteSignupInput{})
	require.NoError(t, err)
	f.repo.AssertNotCalled(t, "SetCompanyDetails", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assert.NotEmpty(t, f.registeredSlug())
	assert.NotEqual(t, "company", f.registeredSlug())
}

func TestCompleteSignup_UnusableName_FallsBackToWordPair(t *testing.T) {
	t.Parallel()
	f := newCompanyFixture(t)
	f.repo.On("SetCompanyDetails", mock.Anything, f.req.ID, "AB", "").Return(nil)

	_, err := f.complete(models.CompleteSignupInput{CompanyName: "AB"})
	require.NoError(t, err)
	assert.NotEqual(t, "ab", f.registeredSlug())
	assert.Contains(t, f.registeredSlug(), "-")
}

func TestCompleteSignup_ResumeIgnoresIncomingCompany(t *testing.T) {
	t.Parallel()
	f := newCompanyFixture(t)
	registered := f.tenantID
	slug := "kaya-insaat"
	f.req.TenantID = &registered
	f.req.CompanySlug = &slug
	f.tenants.On("GetByID", mock.Anything, registered).Return(nil, nil)

	_, err := f.complete(models.CompleteSignupInput{CompanyName: "Other Name", Slug: "other-slug"})
	require.NoError(t, err)
	f.repo.AssertNotCalled(t, "SetCompanyDetails", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	f.registry.AssertNotCalled(t, "Register", mock.Anything, mock.Anything)
	assert.Equal(t, "kaya-insaat", *f.req.CompanySlug)
}

func TestCompleteSignup_MarketingConsent_BestEffort(t *testing.T) {
	t.Parallel()
	yes := true
	f := newCompanyFixture(t)
	prefs := &recordingPrefs{}
	f.svc.SetPreferencesWriter(prefs)

	_, err := f.complete(models.CompleteSignupInput{MarketingConsent: &yes})
	require.NoError(t, err)
	assert.Equal(t, "acmeweb", prefs.slug)
	assert.JSONEq(t, `{"onboarding_profile":{"marketingConsent":true}}`, string(prefs.patch))

	// A failing writer never fails the signup.
	g := newCompanyFixture(t)
	g.svc.SetPreferencesWriter(&recordingPrefs{failing: true})
	_, err = g.complete(models.CompleteSignupInput{MarketingConsent: &yes})
	require.NoError(t, err)

	// No consent given: nothing written.
	h := newCompanyFixture(t)
	none := &recordingPrefs{}
	h.svc.SetPreferencesWriter(none)
	_, err = h.complete(models.CompleteSignupInput{})
	require.NoError(t, err)
	assert.Empty(t, none.slug)
}

func TestSuggestSlug(t *testing.T) {
	t.Parallel()
	svc := &SignupService{slugChecker: &setSlugChecker{taken: map[string]bool{"kaya-insaat": true}}}

	slug, ok := svc.SuggestSlug(context.Background(), "Kaya İnşaat Ltd. Şti.")
	assert.True(t, ok)
	assert.Equal(t, "kaya-insaat-2", slug)

	slug, ok = svc.SuggestSlug(context.Background(), "Admin")
	assert.True(t, ok)
	assert.Equal(t, "admin-2", slug)

	// Unusable name: a valid word-pair suggestion.
	slug, ok = svc.SuggestSlug(context.Background(), "AB")
	assert.True(t, ok)
	assert.True(t, models.IsValidSlug(slug))

	// Every readable candidate taken, or no checker: a hint, not available.
	full := &SignupService{slugChecker: &setSlugChecker{taken: map[string]bool{
		"acme": true, "acme-2": true, "acme-3": true, "acme-4": true, "acme-5": true,
	}}}
	slug, ok = full.SuggestSlug(context.Background(), "Acme")
	assert.False(t, ok)
	assert.True(t, models.IsValidSlug(slug))
	_, ok = (&SignupService{}).SuggestSlug(context.Background(), "Acme")
	assert.False(t, ok)
}

func TestSlugCandidates(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"acme", "acme-2", "acme-3", "acme-4", "acme-5"}, slugCandidates("acme"))
	assert.Nil(t, slugCandidates(""))
}
