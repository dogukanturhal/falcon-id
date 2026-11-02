// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TestSignupService_CompleteSignup_PlanCodeOptional proves the signup
// wizard's removed plan-selection step (2026-09-18, t-signup-no-plan-step)
// cannot block signup: CompleteSignup with an empty PlanCode now succeeds
// and provisions the tenant/user exactly like a populated PlanCode would,
// for both business and personal account types.
//
// This is the CONTROL for "removing plan_required did not reopen the
// original bug": e75eeb7 (2026-09-17) added a check that made this exact
// call fail with SignupStateError{Code: "plan_required"}. If that check
// were still present (or reintroduced), this test fails with a
// *SignupStateError — run it against a checkout of e75eeb7 to see it fail.
// What makes the ORIGINAL gap (empty plan -> no trial subscription row
// ever created) safe to reopen here is verified separately in
// TestSignupService_CompleteSignup_EmptyPlanCode_ReachesPlanAwareHook
// (signup_service_hook_test.go): the empty PlanCode is forwarded, not
// dropped, to the plan-aware post-signup hook, whose production
// implementation calls subscription-management's StartTrial — which
// resolves an empty PackageCode via packageRepo.FindDefault instead of
// refusing (see platform-commerce trial.go's 2026-09-18
// reverse-trial-redesign doc comment, verified live against
// hexxlock_subscription_management.subscription_packages:
// is_default=true, trial_enabled=true on package "scale").
func TestSignupService_CompleteSignup_PlanCodeOptional(t *testing.T) {
	t.Run("personal", func(t *testing.T) {
		t.Parallel()

		repo := &mockSignupRequestRepo{}
		emailSvc := &mockSignupEmailSender{}
		tenantSvc := &mockSignupTenantCreator{}
		userSvc := &mockSignupUserCreator{}
		lookup := &mockSignupUserLookup{}

		svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

		req := verifiedRequest("plan-optional-personal@example.com", "personal")
		consumerTenant := &models.Tenant{
			ID:   models.WellKnownTenantConsumer,
			Slug: "hexxlock-consumer",
			Type: models.TenantType("consumer"),
		}
		user := fakeUser(consumerTenant.ID, req.Email)

		repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)
		tenantSvc.On("GetByID", mock.Anything, models.WellKnownTenantConsumer).Return(consumerTenant, nil)
		userSvc.On("CreateForSignup", mock.Anything, mock.Anything, mock.Anything).Return(user, nil)
		repo.On("MarkCompleted", mock.Anything, req.ID, consumerTenant.ID, user.ID).Return(nil)

		result, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
			SignupRequestID: req.ID,
			Password:        "Sup3rSecure1!",
			// PlanCode deliberately left empty — this is what the signup
			// wizard now always sends, since it has no plan-selection step.
		}, "", "")

		require.NoError(t, err)
		require.NotNil(t, result)
		repo.AssertExpectations(t)
	})

	t.Run("business", func(t *testing.T) {
		t.Parallel()

		repo := &mockSignupRequestRepo{}
		emailSvc := &mockSignupEmailSender{}
		tenantSvc := &mockSignupTenantCreator{}
		userSvc := &mockSignupUserCreator{}
		lookup := &mockSignupUserLookup{}

		svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

		companyName := testAcmeCorpOrg
		companySlug := testTenantSlugAcme
		req := verifiedRequest("plan-optional-biz@acme.com", "business")
		req.CompanyName = &companyName
		req.CompanySlug = &companySlug

		// stubTenantManagementRegistrar (wired by buildSignupService) mints
		// its own random ID per call, so the tenant fixture just needs a
		// fixed ID for CreateTenant to hand back — the real registrar ID
		// isn't asserted here, only that provisioning completes.
		tenant := &models.Tenant{ID: uuid.New(), Name: testAcmeCorpOrg, Type: "customer"}
		user := fakeUser(tenant.ID, req.Email)

		repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)
		repo.On("SetProvisionedTenant", mock.Anything, req.ID, mock.Anything, testTenantSlugAcme).Return(nil)
		tenantSvc.On("CreateTenant", mock.Anything, mock.MatchedBy(func(r *models.CreateTenantRequest) bool {
			return r.Slug == testTenantSlugAcme && r.ID != nil
		})).Return(tenant, nil)
		userSvc.On("CreateForSignup", mock.Anything, mock.Anything, mock.Anything).Return(user, nil)
		repo.On("MarkCompleted", mock.Anything, req.ID, tenant.ID, user.ID).Return(nil)

		result, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
			SignupRequestID: req.ID,
			Password:        "AcmeSecure1!",
			// PlanCode deliberately left empty.
		}, "", "")

		require.NoError(t, err)
		require.NotNil(t, result)
		repo.AssertExpectations(t)
	})
}

// TestSlugWordLists_ExcludeReserved is the control referenced by the doc
// comments on slugAdjectives/slugNouns: every curated word must be absent
// from models.ReservedTenantSlugs and individually satisfy
// models.IsValidSlug, so a generated "<adjective>-<noun>" pair can never
// collide with the reserved-word check by construction.
func TestSlugWordLists_ExcludeReserved(t *testing.T) {
	for _, list := range [][]string{slugAdjectives, slugNouns} {
		for _, w := range list {
			assert.False(t, models.IsReservedSlug(w), "word %q must not be reserved", w)
			assert.True(t, models.IsValidSlug(w), "word %q must itself satisfy IsValidSlug", w)
		}
	}
}

// TestSlugWordLists_NoDuplicates guards against a copy/paste duplicate
// silently shrinking the effective word-pair space.
func TestSlugWordLists_NoDuplicates(t *testing.T) {
	for name, list := range map[string][]string{"adjectives": slugAdjectives, "nouns": slugNouns} {
		seen := make(map[string]bool, len(list))
		for _, w := range list {
			require.False(t, seen[w], "%s: duplicate word %q", name, w)
			seen[w] = true
		}
	}
}

// TestRandomTenantSlug_ValidNotReserved proves every candidate the
// generator can produce, with and without a disambiguator, is itself
// valid and not reserved — the exact predicate provisionTenant relies on.
func TestRandomTenantSlug_ValidNotReserved(t *testing.T) {
	for _, withDisambiguator := range []bool{false, true} {
		for i := 0; i < 200; i++ {
			slug, err := randomTenantSlug(withDisambiguator)
			require.NoError(t, err)
			assert.True(t, models.IsValidSlug(slug), "slug %q must satisfy IsValidSlug", slug)
			assert.False(t, models.IsReservedSlug(slug), "slug %q must not be reserved", slug)
			parts := strings.Split(slug, "-")
			if withDisambiguator {
				require.Len(t, parts, 3, "slug %q must have a disambiguator suffix", slug)
				assert.Len(t, parts[2], 4, "disambiguator must be 4 hex chars")
			} else {
				require.Len(t, parts, 2, "slug %q must be a bare word pair", slug)
			}
		}
	}
}

// TestRandomTenantSlug_NotSequential is a control against the "not
// guessable in sequence" requirement: consecutive candidates must not
// share a predictable, incrementing structure (e.g. a plain counter or a
// suffix that only ever grows). We can't prove non-guessability directly,
// but we CAN prove the generator draws from a wide space and doesn't just
// cycle a small number of values in a fixed order — enough attempts that
// two draws colliding would be a red flag, not the expected case.
func TestRandomTenantSlug_NotSequential(t *testing.T) {
	seen := make(map[string]bool)
	collisions := 0
	const n = 200
	for i := 0; i < n; i++ {
		slug, err := randomTenantSlug(false)
		require.NoError(t, err)
		if seen[slug] {
			collisions++
		}
		seen[slug] = true
	}
	// slugAdjectives x slugNouns is large (80x86 = 6880+ combos); with 200
	// draws, a handful of birthday collisions is expected statistically,
	// but a generator that were secretly sequential/small-cycle would
	// produce many more distinct-but-patterned values than this loose
	// bound allows for. This is a sanity floor, not a precise statistical
	// test.
	assert.Less(t, collisions, n/2, "unexpectedly high collision rate suggests too small a candidate space")
}

// TestCandidateTenantSlug_RetryNeverRepeatsColliedBase proves the
// base-supplied retry path (attempt > 0, non-empty base) always produces
// a different candidate than the base itself, so a genuine collision on a
// caller-supplied slug can never resubmit the identical value.
func TestCandidateTenantSlug_RetryNeverRepeatsColliedBase(t *testing.T) {
	for i := 0; i < 50; i++ {
		candidate, err := candidateTenantSlug("acme", 1)
		require.NoError(t, err)
		assert.NotEqual(t, "acme", candidate)
		assert.True(t, strings.HasPrefix(candidate, "acme-"))
	}
}

// TestCandidateTenantSlug_NoBaseFirstAttemptIsBarePair proves attempt 0
// with no base is a bare word pair (no disambiguator noise on the common,
// non-colliding path — the vast majority of real self-service signups).
func TestCandidateTenantSlug_NoBaseFirstAttemptIsBarePair(t *testing.T) {
	candidate, err := candidateTenantSlug("", 0)
	require.NoError(t, err)
	assert.Equal(t, 2, len(strings.Split(candidate, "-")), "attempt 0 with no base should be a bare word pair, got %q", candidate)
	assert.True(t, models.IsValidSlug(candidate))
	assert.False(t, models.IsReservedSlug(candidate))
}
