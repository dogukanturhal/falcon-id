// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// auth_service_enrollment_interrupt_test.go locks down the fix for the risk-
// MFA registration-interrupt lockout cliff (Q2-tier1-iam-iap-audit MFA-01,
// 2026-04-28). The invariant under test: when risk-based MFA fires for a
// user without an enrolled authenticator, createMFAChallenge MUST take the
// enrollment-interrupt branch and MUST NOT call SendEmailMFACode — emailing
// an unverifiable code to an unbound mailbox is the phishing surface that
// caused the original cliff.

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func TestCreateMFAEnrollmentInterrupt_ReturnsTokenAndDoesNotEmailCode(t *testing.T) {
	cache := newFakeEnrollCache()
	mfa := &fakeEnrollMFA{}
	enrollSvc := NewMFAEnrollmentService(cache, mfa, newFakeEnrollUserRepo(), nil)

	svc := &AuthService{
		config:           newAuthCfg(),
		mfaEnrollmentSvc: enrollSvc,
		// mfaService deliberately nil — proves the new branch never calls it
		// via the registration-interrupt path (the SendEmailMFACode in the
		// alternate branch would NPE if reached).
	}

	user := &models.User{
		ID:         uuid.New(),
		TenantID:   uuid.New(),
		Username:   "alice",
		MFAEnabled: false,
	}
	tenantCtx := &tenantContext{
		TenantID:   user.TenantID,
		TenantSlug: "acme",
	}
	risk := &models.RiskAssessment{
		TotalScore:  50,
		Level:       models.RiskLevelMedium,
		RequiresMFA: true,
	}
	req := &models.LoginRequest{
		Username: "alice",
		ClientID: "svc-talon",
	}

	// hasFactor=false exercises the enrollment-interrupt fork (user has
	// no enrolled MFA factor; risk policy is the sole trigger).
	resp, err := svc.createMFAChallenge(context.Background(), tenantCtx, user, req, "1.2.3.4", "test-ua/1.0", false, risk, false)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.RequiresMFAEnrollment, "must return the registration-interrupt outcome")
	assert.False(t, resp.RequiresMFA, "must NOT return the legacy MFA-challenge outcome (would imply a code was sent)")
	assert.NotEmpty(t, resp.EnrollmentToken)
	assert.Equal(t, []string{"webauthn", "totp", "email"}, resp.EnrollmentMethods)
	assert.Equal(t, int64(600), resp.EnrollmentExpiresIn, "10-minute TTL is the tier-1 contract")

	assert.Equal(t, 0, mfa.sendEmailCodeCalls, "ROOT-CAUSE INVARIANT: no email code may be sent to an unenrolled user (the original lockout-cliff phishing surface)")
	assert.Equal(t, 0, mfa.totpSetupCalls, "TOTP setup is initialised on-demand from the enrollment UI, not at interrupt-issue time")

	// Token must be a valid lookup target with the same ip+ua.
	sess, err := enrollSvc.LookupSession(context.Background(), resp.EnrollmentToken, "1.2.3.4", "test-ua/1.0")
	require.NoError(t, err)
	assert.Equal(t, user.ID.String(), sess.UserID)
	assert.Equal(t, user.TenantID.String(), sess.TenantID)
	assert.Equal(t, "acme", sess.TenantSlug)
	assert.Equal(t, "svc-talon", sess.ClientID)
	assert.Equal(t, 50, sess.RiskScore)
	assert.Equal(t, "medium", sess.RiskLevel)
}

func TestCreateMFAEnrollmentInterrupt_FailsClosedWhenServiceMissing(t *testing.T) {
	// If risk-based MFA is active but the enrollment service was never wired,
	// we MUST NOT silently fall back to the lockout-cliff branch. Operators
	// fix the wiring; users don't get phishing-baited.
	svc := &AuthService{
		config: newAuthCfg(),
		// mfaEnrollmentSvc is nil — the misconfiguration this test guards.
	}
	user := &models.User{ID: uuid.New(), TenantID: uuid.New(), Username: "bob", MFAEnabled: false}
	tenantCtx := &tenantContext{TenantID: user.TenantID, TenantSlug: "acme"}
	risk := &models.RiskAssessment{TotalScore: 50, Level: models.RiskLevelMedium, RequiresMFA: true}
	req := &models.LoginRequest{Username: "bob"}

	_, err := svc.createMFAChallenge(context.Background(), tenantCtx, user, req, "1.2.3.4", "ua", false, risk, false)
	require.Error(t, err, "missing enrollment service must fail closed at /api/v1/auth/login")
}
