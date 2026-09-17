// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// conditional_access_service_test.go covers the security-critical policy
// evaluation logic of ConditionalAccessService.
//
// ConditionalAccessService embeds *pgxpool.Pool directly (not an interface),
// which precludes mocking the DB layer in unit tests.  This file focuses on
// the pure, deterministic helper methods that hold all evaluation logic:
//
//   - subjectMatches     — who the policy targets and who it excludes
//   - conditionsMatch    — IP ranges, risk score, MFA status, time window, client app
//   - actionPrecedence   — correct severity ordering (deny > reauth > mfa > session > allow)
//   - isInTimeRange      — time window boundary conditions
//   - uuidSliceToStringSlice / parseUUIDs — data-layer helper round-trips
//
// Integration tests (Create/List/EvaluateLogin/Simulate with a real PG pool)
// live in the integration test suite.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newPolicy returns a ConditionalAccessPolicy with sensible defaults.
func newPolicy(action models.CAPAction) models.ConditionalAccessPolicy {
	return models.ConditionalAccessPolicy{
		ID:             uuid.New(),
		Name:           "test-policy",
		IsEnabled:      true,
		TargetAllUsers: true,
		Action:         action,
	}
}

// condJSON marshals a CAPConditions struct into the JSONB []byte stored on
// ConditionalAccessPolicy.Conditions.
func condJSON(t *testing.T, c models.CAPConditions) []byte {
	t.Helper()
	b, err := json.Marshal(c)
	require.NoError(t, err)
	return b
}

var testSvc = &ConditionalAccessService{}

// ---------------------------------------------------------------------------
// actionPrecedence — severity ordering
// ---------------------------------------------------------------------------

func TestActionPrecedence_OrderIsCorrect(t *testing.T) {
	assert.Less(t,
		actionPrecedence(models.CAPActionAllow),
		actionPrecedence(models.CAPActionRestrictSession),
		"restrict_session must be more restrictive than allow",
	)
	assert.Less(t,
		actionPrecedence(models.CAPActionRestrictSession),
		actionPrecedence(models.CAPActionRequireMFA),
		"require_mfa must be more restrictive than restrict_session",
	)
	assert.Less(t,
		actionPrecedence(models.CAPActionRequireMFA),
		actionPrecedence(models.CAPActionRequireReauth),
		"require_reauthentication must be more restrictive than require_mfa",
	)
	assert.Less(t,
		actionPrecedence(models.CAPActionRequireReauth),
		actionPrecedence(models.CAPActionDeny),
		"deny must be the most restrictive action",
	)
}

func TestActionPrecedence_UnknownAction_ReturnsZero(t *testing.T) {
	assert.Equal(t, 0, actionPrecedence("unknown_action"))
}

// ---------------------------------------------------------------------------
// subjectMatches — targeting and exclusion
// ---------------------------------------------------------------------------

func TestSubjectMatches_TargetAllUsers_Matches(t *testing.T) {
	p := newPolicy(models.CAPActionDeny)
	p.TargetAllUsers = true

	ctx := models.CAPEvaluationContext{UserID: uuid.New()}
	assert.True(t, testSvc.subjectMatches(&p, ctx))
}

func TestSubjectMatches_TargetSpecificUser_Matches(t *testing.T) {
	userID := uuid.New()
	p := newPolicy(models.CAPActionRequireMFA)
	p.TargetAllUsers = false
	p.TargetUsers = []uuid.UUID{userID}

	ctx := models.CAPEvaluationContext{UserID: userID}
	assert.True(t, testSvc.subjectMatches(&p, ctx))
}

func TestSubjectMatches_TargetSpecificUser_OtherUser_NoMatch(t *testing.T) {
	p := newPolicy(models.CAPActionRequireMFA)
	p.TargetAllUsers = false
	p.TargetUsers = []uuid.UUID{uuid.New()}

	ctx := models.CAPEvaluationContext{UserID: uuid.New()}
	assert.False(t, testSvc.subjectMatches(&p, ctx))
}

func TestSubjectMatches_TargetGroup_UserInGroup_Matches(t *testing.T) {
	groupID := uuid.New()
	p := newPolicy(models.CAPActionRequireMFA)
	p.TargetAllUsers = false
	p.TargetGroups = []uuid.UUID{groupID}

	ctx := models.CAPEvaluationContext{
		UserID:     uuid.New(),
		UserGroups: []uuid.UUID{groupID},
	}
	assert.True(t, testSvc.subjectMatches(&p, ctx))
}

func TestSubjectMatches_TargetGroup_UserNotInGroup_NoMatch(t *testing.T) {
	p := newPolicy(models.CAPActionRequireMFA)
	p.TargetAllUsers = false
	p.TargetGroups = []uuid.UUID{uuid.New()}

	ctx := models.CAPEvaluationContext{
		UserID:     uuid.New(),
		UserGroups: []uuid.UUID{uuid.New()},
	}
	assert.False(t, testSvc.subjectMatches(&p, ctx))
}

func TestSubjectMatches_TargetRole_UserHasRole_Matches(t *testing.T) {
	p := newPolicy(models.CAPActionRequireMFA)
	p.TargetAllUsers = false
	p.TargetRoles = []string{"admin", "manager"}

	ctx := models.CAPEvaluationContext{
		UserID:    uuid.New(),
		UserRoles: []string{"manager"},
	}
	assert.True(t, testSvc.subjectMatches(&p, ctx))
}

func TestSubjectMatches_TargetRole_UserLacksRole_NoMatch(t *testing.T) {
	p := newPolicy(models.CAPActionRequireMFA)
	p.TargetAllUsers = false
	p.TargetRoles = []string{"admin"}

	ctx := models.CAPEvaluationContext{
		UserID:    uuid.New(),
		UserRoles: []string{"viewer"},
	}
	assert.False(t, testSvc.subjectMatches(&p, ctx))
}

// SECURITY: exclusion must override targeting — even "target_all_users" is
// blocked when the user is in ExcludeUsers.
func TestSubjectMatches_ExcludeUser_OverridesTargetAll(t *testing.T) {
	userID := uuid.New()
	p := newPolicy(models.CAPActionDeny)
	p.TargetAllUsers = true
	p.ExcludeUsers = []uuid.UUID{userID}

	ctx := models.CAPEvaluationContext{UserID: userID}
	assert.False(t, testSvc.subjectMatches(&p, ctx),
		"excluded user must not match even when TargetAllUsers is true")
}

func TestSubjectMatches_ExcludeGroup_OverridesTargetAll(t *testing.T) {
	groupID := uuid.New()
	p := newPolicy(models.CAPActionDeny)
	p.TargetAllUsers = true
	p.ExcludeGroups = []uuid.UUID{groupID}

	ctx := models.CAPEvaluationContext{
		UserID:     uuid.New(),
		UserGroups: []uuid.UUID{groupID},
	}
	assert.False(t, testSvc.subjectMatches(&p, ctx),
		"excluded group member must not match even when TargetAllUsers is true")
}

func TestSubjectMatches_NoTargets_NoMatch(t *testing.T) {
	p := newPolicy(models.CAPActionDeny)
	p.TargetAllUsers = false
	// No TargetUsers, TargetGroups, or TargetRoles

	ctx := models.CAPEvaluationContext{UserID: uuid.New()}
	assert.False(t, testSvc.subjectMatches(&p, ctx))
}

// ---------------------------------------------------------------------------
// conditionsMatch — IP ranges
// ---------------------------------------------------------------------------

func TestConditionsMatch_EmptyConditions_AlwaysMatches(t *testing.T) {
	p := newPolicy(models.CAPActionAllow)
	p.Conditions = nil

	ctx := models.CAPEvaluationContext{IPAddress: "1.2.3.4"}
	assert.True(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_IPRange_InRange_Matches(t *testing.T) {
	p := newPolicy(models.CAPActionDeny)
	p.Conditions = condJSON(t, models.CAPConditions{
		IPRanges: []string{"10.0.0.0/8"},
	})

	ctx := models.CAPEvaluationContext{IPAddress: "10.1.2.3"}
	assert.True(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_IPRange_OutOfRange_NoMatch(t *testing.T) {
	p := newPolicy(models.CAPActionDeny)
	p.Conditions = condJSON(t, models.CAPConditions{
		IPRanges: []string{"10.0.0.0/8"},
	})

	ctx := models.CAPEvaluationContext{IPAddress: "192.168.1.1"}
	assert.False(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_IPRange_NoIPInContext_SkipsCheck(t *testing.T) {
	// Empty IPAddress in context means the IP check is skipped.
	p := newPolicy(models.CAPActionDeny)
	p.Conditions = condJSON(t, models.CAPConditions{
		IPRanges: []string{"10.0.0.0/8"},
	})

	ctx := models.CAPEvaluationContext{IPAddress: ""}
	// IP range condition present but context has no IP → condition does NOT apply
	assert.True(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_IPRange_InvalidCIDR_Skipped(t *testing.T) {
	p := newPolicy(models.CAPActionDeny)
	p.Conditions = condJSON(t, models.CAPConditions{
		IPRanges: []string{"not-a-cidr"},
	})

	ctx := models.CAPEvaluationContext{IPAddress: "1.2.3.4"}
	// Invalid CIDR is skipped → no ranges match → condition fails
	assert.False(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_IPRange_MultipleRanges_MatchesFirst(t *testing.T) {
	p := newPolicy(models.CAPActionDeny)
	p.Conditions = condJSON(t, models.CAPConditions{
		IPRanges: []string{"192.168.0.0/16", "10.0.0.0/8"},
	})

	ctx := models.CAPEvaluationContext{IPAddress: "10.5.5.5"}
	assert.True(t, testSvc.conditionsMatch(&p, ctx))
}

// ---------------------------------------------------------------------------
// conditionsMatch — risk score
// ---------------------------------------------------------------------------

func TestConditionsMatch_RiskLevelMin_AboveThreshold_Matches(t *testing.T) {
	riskMin := 50
	p := newPolicy(models.CAPActionRequireMFA)
	p.Conditions = condJSON(t, models.CAPConditions{
		RiskLevelMin: &riskMin,
	})

	ctx := models.CAPEvaluationContext{RiskScore: 75}
	assert.True(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_RiskLevelMin_BelowThreshold_NoMatch(t *testing.T) {
	riskMin := 50
	p := newPolicy(models.CAPActionRequireMFA)
	p.Conditions = condJSON(t, models.CAPConditions{
		RiskLevelMin: &riskMin,
	})

	ctx := models.CAPEvaluationContext{RiskScore: 30}
	assert.False(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_RiskLevelMin_AtThreshold_Matches(t *testing.T) {
	riskMin := 50
	p := newPolicy(models.CAPActionRequireMFA)
	p.Conditions = condJSON(t, models.CAPConditions{
		RiskLevelMin: &riskMin,
	})

	ctx := models.CAPEvaluationContext{RiskScore: 50}
	assert.True(t, testSvc.conditionsMatch(&p, ctx))
}

// ---------------------------------------------------------------------------
// conditionsMatch — MFA status
// ---------------------------------------------------------------------------

func TestConditionsMatch_MFAStatus_Enrolled_UserEnrolled_Matches(t *testing.T) {
	p := newPolicy(models.CAPActionAllow)
	p.Conditions = condJSON(t, models.CAPConditions{
		MFAStatus: "enrolled",
	})

	ctx := models.CAPEvaluationContext{MFAEnabled: true}
	assert.True(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_MFAStatus_Enrolled_UserNotEnrolled_NoMatch(t *testing.T) {
	p := newPolicy(models.CAPActionRequireMFA)
	p.Conditions = condJSON(t, models.CAPConditions{
		MFAStatus: "enrolled",
	})

	ctx := models.CAPEvaluationContext{MFAEnabled: false}
	assert.False(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_MFAStatus_NotEnrolled_UserNotEnrolled_Matches(t *testing.T) {
	p := newPolicy(models.CAPActionRequireMFA)
	p.Conditions = condJSON(t, models.CAPConditions{
		MFAStatus: "not_enrolled",
	})

	ctx := models.CAPEvaluationContext{MFAEnabled: false}
	assert.True(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_MFAStatus_NotEnrolled_UserEnrolled_NoMatch(t *testing.T) {
	p := newPolicy(models.CAPActionRequireMFA)
	p.Conditions = condJSON(t, models.CAPConditions{
		MFAStatus: "not_enrolled",
	})

	ctx := models.CAPEvaluationContext{MFAEnabled: true}
	assert.False(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_MFAStatus_Empty_MatchesAny(t *testing.T) {
	p := newPolicy(models.CAPActionAllow)
	p.Conditions = condJSON(t, models.CAPConditions{
		MFAStatus: "",
	})

	// Empty MFA status constraint matches both enrolled and not-enrolled users.
	assert.True(t, testSvc.conditionsMatch(&p, models.CAPEvaluationContext{MFAEnabled: true}))
	assert.True(t, testSvc.conditionsMatch(&p, models.CAPEvaluationContext{MFAEnabled: false}))
}

// ---------------------------------------------------------------------------
// conditionsMatch — client apps
// ---------------------------------------------------------------------------

func TestConditionsMatch_ClientApps_MatchingApp_Matches(t *testing.T) {
	p := newPolicy(models.CAPActionDeny)
	p.Conditions = condJSON(t, models.CAPConditions{
		ClientApps: []string{"app-a", "app-b"},
	})

	ctx := models.CAPEvaluationContext{ClientApp: "app-b"}
	assert.True(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_ClientApps_NonMatchingApp_NoMatch(t *testing.T) {
	p := newPolicy(models.CAPActionDeny)
	p.Conditions = condJSON(t, models.CAPConditions{
		ClientApps: []string{"app-a"},
	})

	ctx := models.CAPEvaluationContext{ClientApp: "app-z"}
	assert.False(t, testSvc.conditionsMatch(&p, ctx))
}

func TestConditionsMatch_ClientApps_NoClientInContext_SkipsCheck(t *testing.T) {
	// Empty ClientApp in context → client-app condition does not apply.
	p := newPolicy(models.CAPActionDeny)
	p.Conditions = condJSON(t, models.CAPConditions{
		ClientApps: []string{"app-a"},
	})

	ctx := models.CAPEvaluationContext{ClientApp: ""}
	assert.True(t, testSvc.conditionsMatch(&p, ctx))
}

// ---------------------------------------------------------------------------
// isInTimeRange — time window boundary conditions
// ---------------------------------------------------------------------------

func TestIsInTimeRange_NoDays_NoStartEnd_AlwaysMatches(t *testing.T) {
	// Empty time range matches everything.
	tr := models.CAPTimeRange{}
	// Use a fixed time to avoid test flakiness.
	now := time.Date(2026, 3, 7, 14, 30, 0, 0, time.UTC)
	assert.True(t, isInTimeRange(now, tr))
}

func TestIsInTimeRange_DayMatch_WithinWindow_Matches(t *testing.T) {
	// Friday = weekday 5
	friday := time.Date(2026, 3, 6, 10, 0, 0, 0, time.UTC)
	require.Equal(t, time.Friday, friday.Weekday())

	tr := models.CAPTimeRange{
		Days:  []int{5}, // Friday
		Start: "09:00",
		End:   "17:00",
	}
	assert.True(t, isInTimeRange(friday, tr))
}

func TestIsInTimeRange_DayMismatch_NoMatch(t *testing.T) {
	// Saturday = weekday 6
	saturday := time.Date(2026, 3, 7, 10, 0, 0, 0, time.UTC)
	require.Equal(t, time.Saturday, saturday.Weekday())

	tr := models.CAPTimeRange{
		Days:  []int{1, 2, 3, 4, 5}, // Mon-Fri only
		Start: "09:00",
		End:   "17:00",
	}
	assert.False(t, isInTimeRange(saturday, tr))
}

func TestIsInTimeRange_TimeBeforeWindow_NoMatch(t *testing.T) {
	earlyMorning := time.Date(2026, 3, 9, 7, 0, 0, 0, time.UTC) // Monday 07:00
	require.Equal(t, time.Monday, earlyMorning.Weekday())

	tr := models.CAPTimeRange{
		Days:  []int{1}, // Monday
		Start: "09:00",
		End:   "17:00",
	}
	assert.False(t, isInTimeRange(earlyMorning, tr))
}

func TestIsInTimeRange_TimeAfterWindow_NoMatch(t *testing.T) {
	lateEvening := time.Date(2026, 3, 9, 20, 0, 0, 0, time.UTC) // Monday 20:00
	tr := models.CAPTimeRange{
		Days:  []int{1}, // Monday
		Start: "09:00",
		End:   "17:00",
	}
	assert.False(t, isInTimeRange(lateEvening, tr))
}

func TestIsInTimeRange_AtStartBoundary_Matches(t *testing.T) {
	atStart := time.Date(2026, 3, 9, 9, 0, 0, 0, time.UTC) // Monday 09:00
	tr := models.CAPTimeRange{
		Days:  []int{1},
		Start: "09:00",
		End:   "17:00",
	}
	assert.True(t, isInTimeRange(atStart, tr))
}

func TestIsInTimeRange_AtEndBoundary_Matches(t *testing.T) {
	atEnd := time.Date(2026, 3, 9, 17, 0, 0, 0, time.UTC) // Monday 17:00
	tr := models.CAPTimeRange{
		Days:  []int{1},
		Start: "09:00",
		End:   "17:00",
	}
	assert.True(t, isInTimeRange(atEnd, tr))
}

func TestIsInTimeRange_EmptyDays_AnyDayMatches(t *testing.T) {
	// When Days is empty, any day is accepted.
	saturday := time.Date(2026, 3, 7, 14, 0, 0, 0, time.UTC)
	tr := models.CAPTimeRange{
		Days:  nil, // any day
		Start: "09:00",
		End:   "17:00",
	}
	assert.True(t, isInTimeRange(saturday, tr))
}

// ---------------------------------------------------------------------------
// uuidSliceToStringSlice + parseUUIDs — round-trip
// ---------------------------------------------------------------------------

func TestUUIDSliceToStringSlice_EmptyInput(t *testing.T) {
	result := uuidSliceToStringSlice(nil)
	assert.Equal(t, []string{}, result)
}

func TestUUIDSliceToStringSlice_NonEmpty(t *testing.T) {
	ids := []uuid.UUID{uuid.New(), uuid.New()}
	result := uuidSliceToStringSlice(ids)
	require.Len(t, result, 2)
	assert.Equal(t, ids[0].String(), result[0])
	assert.Equal(t, ids[1].String(), result[1])
}

func TestParseUUIDs_ValidStrings_Parsed(t *testing.T) {
	ids := []uuid.UUID{uuid.New(), uuid.New()}
	strs := []string{ids[0].String(), ids[1].String()}

	result := parseUUIDs(strs)
	require.Len(t, result, 2)
	assert.Equal(t, ids[0], result[0])
	assert.Equal(t, ids[1], result[1])
}

func TestParseUUIDs_InvalidString_Skipped(t *testing.T) {
	id := uuid.New()
	strs := []string{id.String(), "not-a-uuid", "also-invalid"}

	result := parseUUIDs(strs)
	// Only the valid UUID should be in the output.
	require.Len(t, result, 1)
	assert.Equal(t, id, result[0])
}

func TestParseUUIDs_EmptyInput_ReturnsEmpty(t *testing.T) {
	result := parseUUIDs(nil)
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// UUIDSlice round-trip (uuidSliceToStringSlice → parseUUIDs)
// ---------------------------------------------------------------------------

func TestUUIDSlice_RoundTrip(t *testing.T) {
	original := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	strs := uuidSliceToStringSlice(original)
	restored := parseUUIDs(strs)

	require.Len(t, restored, len(original))
	for i, id := range original {
		assert.Equal(t, id, restored[i])
	}
}

// ---------------------------------------------------------------------------
// CAPEvaluationResult helpers
// ---------------------------------------------------------------------------

func TestCAPEvaluationResult_IsDenied(t *testing.T) {
	assert.True(t, (&models.CAPEvaluationResult{Action: models.CAPActionDeny}).IsDenied())
	assert.False(t, (&models.CAPEvaluationResult{Action: models.CAPActionAllow}).IsDenied())
	assert.False(t, (&models.CAPEvaluationResult{Action: models.CAPActionRequireMFA}).IsDenied())
}

func TestCAPEvaluationResult_RequiresMFA(t *testing.T) {
	assert.True(t, (&models.CAPEvaluationResult{Action: models.CAPActionRequireMFA}).RequiresMFA())
	assert.False(t, (&models.CAPEvaluationResult{Action: models.CAPActionDeny}).RequiresMFA())
	assert.False(t, (&models.CAPEvaluationResult{Action: models.CAPActionAllow}).RequiresMFA())
}

// ---------------------------------------------------------------------------
// Simulated EvaluateLogin logic (in-process, no DB)
// ---------------------------------------------------------------------------

// TestEvaluateLogin_Logic_DenyTakesPrecedence simulates the EvaluateLogin loop
// logic with two in-process policies to verify that deny always wins.
func TestEvaluateLogin_Logic_DenyTakesPrecedence(t *testing.T) {
	userID := uuid.New()

	policies := []models.ConditionalAccessPolicy{
		{
			ID:             uuid.New(),
			Name:           "allow-mfa",
			IsEnabled:      true,
			TargetAllUsers: true,
			Action:         models.CAPActionRequireMFA,
		},
		{
			ID:             uuid.New(),
			Name:           "deny-risky",
			IsEnabled:      true,
			TargetAllUsers: true,
			Action:         models.CAPActionDeny,
		},
	}

	ctx := models.CAPEvaluationContext{
		UserID:    userID,
		IPAddress: "10.0.0.1",
	}

	// Simulate the evaluation loop from EvaluateLogin.
	result := &models.CAPEvaluationResult{Action: models.CAPActionAllow}
	for i := range policies {
		p := &policies[i]
		if !p.IsEnabled {
			continue
		}
		if !testSvc.subjectMatches(p, ctx) {
			continue
		}
		if !testSvc.conditionsMatch(p, ctx) {
			continue
		}
		result.MatchedPolicies = append(result.MatchedPolicies, *p)
		if actionPrecedence(p.Action) > actionPrecedence(result.Action) {
			result.Action = p.Action
		}
		if result.Action == models.CAPActionDeny {
			break
		}
	}

	assert.Equal(t, models.CAPActionDeny, result.Action,
		"deny must take precedence over require_mfa")
	assert.True(t, result.IsDenied())
}

func TestEvaluateLogin_Logic_DisabledPoliciesSkipped(t *testing.T) {
	policies := []models.ConditionalAccessPolicy{
		{
			ID:             uuid.New(),
			Name:           "disabled-deny",
			IsEnabled:      false, // disabled
			TargetAllUsers: true,
			Action:         models.CAPActionDeny,
		},
	}

	_ = models.CAPEvaluationContext{UserID: uuid.New()}
	result := &models.CAPEvaluationResult{Action: models.CAPActionAllow}

	for i := range policies {
		p := &policies[i]
		if !p.IsEnabled {
			continue
		}
		if actionPrecedence(p.Action) > actionPrecedence(result.Action) {
			result.Action = p.Action
		}
	}

	assert.Equal(t, models.CAPActionAllow, result.Action,
		"disabled policy must not affect evaluation result")
}

func TestEvaluateLogin_Logic_ExcludedUserGetsAllow(t *testing.T) {
	exemptUser := uuid.New()

	policies := []models.ConditionalAccessPolicy{
		{
			ID:             uuid.New(),
			Name:           "deny-everyone-except-exempt",
			IsEnabled:      true,
			TargetAllUsers: true,
			ExcludeUsers:   []uuid.UUID{exemptUser},
			Action:         models.CAPActionDeny,
		},
	}

	ctx := models.CAPEvaluationContext{UserID: exemptUser}
	result := &models.CAPEvaluationResult{Action: models.CAPActionAllow}

	for i := range policies {
		p := &policies[i]
		if !p.IsEnabled {
			continue
		}
		if !testSvc.subjectMatches(p, ctx) {
			continue
		}
		if actionPrecedence(p.Action) > actionPrecedence(result.Action) {
			result.Action = p.Action
		}
	}

	assert.Equal(t, models.CAPActionAllow, result.Action,
		"excluded user must not be affected by deny policy")
}
