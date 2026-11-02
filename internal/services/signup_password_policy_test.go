// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

func signupPolicyUserService() *UserService {
	return &UserService{config: &config.Config{
		PasswordMinLength: 12, PasswordRequireUpper: true, PasswordRequireLower: true,
		PasswordRequireDigit: true, PasswordRequireSpecial: true,
	}}
}

type preflightUserCreator struct {
	mockSignupUserCreator
	validator *UserService
}

func (u *preflightUserCreator) SignupPasswordPolicy() SignupPasswordPolicy {
	return u.validator.SignupPasswordPolicy()
}
func (u *preflightUserCreator) PrepareSignupCredential(ctx context.Context, password string) (*PreparedSignupCredential, error) {
	return u.validator.PrepareSignupCredential(ctx, password)
}

type signupBreachStub struct {
	breached bool
	err      error
	calls    int
}

func (b *signupBreachStub) IsCompromised(context.Context, string) (bool, int, error) {
	b.calls++
	return b.breached, 1, b.err
}

type signupSessionSpy struct{ calls int }

func (s *signupSessionSpy) IssueSessionForNewUser(context.Context, uuid.UUID, *models.User, string, string) (*models.LoginResponse, error) {
	s.calls++
	return &models.LoginResponse{}, nil
}

func TestSignupPasswordPolicy_ContractAndUnicode(t *testing.T) {
	svc := signupPolicyUserService()
	p := svc.SignupPasswordPolicy()
	require.Equal(t, "unicode_code_points", p.LengthUnit)
	require.Equal(t, 12, p.MinLength)
	require.Zero(t, p.MaxLength)
	require.Equal(t, "disabled", p.BreachCheck)
	for _, tc := range []struct {
		name, password string
		violations     []string
	}{
		{"old UI accepted", "Abcdefgh1!", []string{"min_length"}},
		{"bytes are not characters", "Éé١😀abcd", []string{"min_length"}},
		{"all required classes", "aaaaaaaaaaaa", []string{"require_upper", "require_digit", "require_special"}},
		{"Unicode classes", "Éé١😀abcdefgh", nil},
		{"whitespace preserved", "Abcdefghi1! ", nil},
		{"long passphrase", "Aa1!" + strings.Repeat("phrase ", 100), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.ValidateSignupPassword(context.Background(), tc.password)
			if tc.violations == nil {
				require.NoError(t, err)
				return
			}
			var violation *SignupPasswordError
			require.ErrorAs(t, err, &violation)
			assert.Equal(t, tc.violations, violation.Violations)
			assert.Equal(t, p, violation.Policy)
			assert.NotContains(t, err.Error(), tc.password)
		})
	}
	// Deployment config, not a frontend copy, changes both validation and GET.
	svc.config.PasswordMinLength = 20
	require.Equal(t, 20, svc.SignupPasswordPolicy().MinLength)
	require.Error(t, svc.ValidateSignupPassword(context.Background(), "Abcdefghijkl1!"))
	p = svc.SignupPasswordPolicy()
	p.MaxLength = 24
	require.Error(t, p.Validate("Ab1!"+strings.Repeat("x", 21)))
}

func TestSignupPasswordPolicy_RejectsBeforeAllSideEffects(t *testing.T) {
	for _, accountType := range []string{"business", "personal"} {
		for _, tc := range []struct {
			name, password string
			breached       bool
		}{
			{"missing", "", false}, {"short", "Abcd123!", false},
			{"composition", "aaaaaaaaaaaa", false}, {"breached", "UniqueTestPass1!", true},
		} {
			t.Run(accountType+"/"+tc.name, func(t *testing.T) {
				repo := &mockSignupRequestRepo{}
				req := verifiedRequest("unit@example.invalid", accountType)
				repo.On("GetByID", mock.Anything, req.ID).Return(req, nil).Maybe()
				email, tenant, registrar := &mockSignupEmailSender{}, &mockSignupTenantCreator{}, &mockTenantManagementRegistrar{}
				user := &preflightUserCreator{validator: signupPolicyUserService()}
				checker := &signupBreachStub{breached: tc.breached}
				user.validator.breachChecker = checker
				hook, session := &mockPostSignupHook{}, &signupSessionSpy{}
				svc := NewSignupService(repo, email, tenant, registrar, user, &mockSignupUserLookup{}, "downstream.com", "starter", testOTPKey)
				svc.SetPostSignupHook(hook)
				svc.SetSessionIssuer(session)
				result, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret, SignupRequestID: req.ID, Password: tc.password}, "", "")
				require.Nil(t, result)
				var violation *SignupPasswordError
				require.ErrorAs(t, err, &violation)
				assert.Empty(t, tenant.Calls)
				assert.Empty(t, registrar.Calls)
				assert.Empty(t, user.Calls)
				assert.Empty(t, email.Calls)
				repo.AssertNotCalled(t, "MarkCompleted", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
				repo.AssertNotCalled(t, "MarkVerified", mock.Anything, mock.Anything)
				assert.True(t, req.Verified)
				assert.False(t, req.Completed)
				assert.False(t, hook.called)
				assert.Zero(t, session.calls)
				if tc.breached {
					assert.Equal(t, []string{"breached"}, violation.Violations)
				} else {
					assert.Zero(t, checker.calls)
				}
			})
		}
	}
}

func TestSignupPasswordPolicy_VerifiedRequestCanCorrectPassword(t *testing.T) {
	for _, accountType := range []string{"business", "personal"} {
		t.Run(accountType, func(t *testing.T) {
			repo := &mockSignupRequestRepo{}
			req := verifiedRequest("unit@example.invalid", accountType)
			repo.On("GetByID", mock.Anything, req.ID).Return(req, nil).Twice()
			tenant, registrar, email := &mockSignupTenantCreator{}, &mockTenantManagementRegistrar{}, &mockSignupEmailSender{}
			user := &preflightUserCreator{validator: signupPolicyUserService()}
			session := &signupSessionSpy{}
			svc := NewSignupService(repo, email, tenant, registrar, user, &mockSignupUserLookup{}, "downstream.com", "starter", testOTPKey)
			svc.SetSessionIssuer(session)
			input := &models.CompleteSignupInput{CompletionSecret: testCompletionSecret, SignupRequestID: req.ID, Password: "Abcd123!", PlanCode: "starter"}
			_, err := svc.CompleteSignup(context.Background(), input, "", "")
			require.Error(t, err)
			tenantID := models.WellKnownTenantConsumer
			if accountType == "business" {
				tenantID = uuid.New()
				registrar.On("Register", mock.Anything, mock.Anything).Return(&TenantManagementRegisterResult{ID: tenantID}, nil).Once()
				repo.On("SetProvisionedTenant", mock.Anything, req.ID, tenantID, mock.AnythingOfType("string")).Return(nil).Once()
				tenant.On("CreateTenant", mock.Anything, mock.Anything).Return(&models.Tenant{ID: tenantID}, nil).Once()
			} else {
				tenant.On("GetByID", mock.Anything, tenantID).Return(&models.Tenant{ID: tenantID}, nil).Once()
			}
			createdUser := fakeUser(tenantID, req.Email)
			user.On("CreateForSignup", mock.Anything, mock.MatchedBy(func(r *models.CreateUserRequest) bool { return r.Password == "CorrectedSecret1!" }), mock.Anything).Return(createdUser, nil).Once()
			repo.On("MarkCompleted", mock.Anything, req.ID, tenantID, createdUser.ID).Return(nil).Once()
			input.Password = "CorrectedSecret1!"
			result, err := svc.CompleteSignup(context.Background(), input, "", "")
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, 1, session.calls)
			assert.Empty(t, email.Calls)
			if accountType == "personal" {
				assert.Empty(t, registrar.Calls)
				tenant.AssertNotCalled(t, "CreateTenant", mock.Anything, mock.Anything)
			}
			repo.AssertExpectations(t)
			user.AssertExpectations(t)
			tenant.AssertExpectations(t)
			registrar.AssertExpectations(t)
		})
	}
}

func TestSignupPasswordPolicy_BreachOutagePreservesExistingPolicy(t *testing.T) {
	// Existing auth behavior is best-effort, not a claim of fail-closed NIST compliance.
	svc := signupPolicyUserService()
	svc.breachChecker = &signupBreachStub{err: errors.New("unit-test outage")}
	require.Equal(t, "best_effort", svc.SignupPasswordPolicy().BreachCheck)
	require.NoError(t, svc.ValidateSignupPassword(context.Background(), "UniqueTestPass1!"))
}
