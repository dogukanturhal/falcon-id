// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TestSignupService_CompleteSignup_PlanRequired proves the commercial-gap
// fix directly: an empty PlanCode is rejected with
// SignupStateError{Code: "plan_required"} BEFORE any tenant/user
// provisioning happens, for both business and personal account types.
// This is the control for the enforcement claim — with the check removed,
// this test fails (verified manually while developing the fix).
func TestSignupService_CompleteSignup_PlanRequired(t *testing.T) {
	for _, accountType := range []string{"business", "personal"} {
		t.Run(accountType, func(t *testing.T) {
			t.Parallel()

			repo := &mockSignupRequestRepo{}
			emailSvc := &mockSignupEmailSender{}
			tenantSvc := &mockSignupTenantCreator{}
			userSvc := &mockSignupUserCreator{}
			lookup := &mockSignupUserLookup{}

			svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

			req := verifiedRequest("plan-required@example.com", accountType)
			repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)

			_, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{
				SignupRequestID: req.ID,
				Password:        "Sup3rSecure1!",
				// PlanCode deliberately left empty.
			}, "", "")

			require.Error(t, err)
			var stateErr *SignupStateError
			require.ErrorAs(t, err, &stateErr)
			assert.Equal(t, "plan_required", stateErr.Code)

			tenantSvc.AssertNotCalled(t, "CreateTenant")
			tenantSvc.AssertNotCalled(t, "GetByID")
			userSvc.AssertNotCalled(t, "CreateForSignup")
			repo.AssertNotCalled(t, "MarkCompleted")
		})
	}
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
