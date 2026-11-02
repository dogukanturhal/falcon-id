// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// --- Mocks ---

type mockPostSignupHook struct {
	called      bool
	tenantID    uuid.UUID
	userID      uuid.UUID
	accountType string
	err         error
}

func (m *mockPostSignupHook) OnSignupComplete(_ context.Context, tenantID, userID uuid.UUID, accountType string) error {
	m.called = true
	m.tenantID = tenantID
	m.userID = userID
	m.accountType = accountType
	return m.err
}

type stubSignupRepo struct {
	req *models.SignupRequest
}

func (s *stubSignupRepo) Create(_ context.Context, _ *models.SignupRequest) error { return nil }
func (s *stubSignupRepo) GetByToken(_ context.Context, _ string) (*models.SignupRequest, error) {
	return nil, fmt.Errorf("not found")
}

func (s *stubSignupRepo) GetByID(_ context.Context, _ uuid.UUID) (*models.SignupRequest, error) {
	if s.req != nil {
		return s.req, nil
	}
	return nil, fmt.Errorf("not found")
}

func (s *stubSignupRepo) GetPendingByEmail(_ context.Context, _ string) (*models.SignupRequest, error) {
	return nil, nil
}
func (s *stubSignupRepo) MarkVerified(_ context.Context, _ uuid.UUID) error { return nil }
func (s *stubSignupRepo) MarkCompleted(_ context.Context, _ uuid.UUID, _, _ uuid.UUID) error {
	return nil
}

func (s *stubSignupRepo) SetProvisionedTenant(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ string) error {
	return nil
}

func (s *stubSignupRepo) SetCompanyDetails(_ context.Context, _ uuid.UUID, _, _ string) error {
	return nil
}

func (s *stubSignupRepo) SetCompletionSecretHash(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}

func (s *stubSignupRepo) SetContinuation(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}

func (s *stubSignupRepo) ReserveVerificationResend(context.Context, uuid.UUID, time.Duration, time.Duration, int, int, bool) (bool, error) {
	return true, nil
}
func (s *stubSignupRepo) SetVerificationCode(context.Context, uuid.UUID, string, time.Time) error {
	return nil
}
func (s *stubSignupRepo) ClaimVerificationAttempt(context.Context, uuid.UUID, int, int) (string, time.Time, int, bool, error) {
	return "", time.Time{}, 0, false, nil
}
func (s *stubSignupRepo) ConsumeVerificationCode(context.Context, uuid.UUID, string) (bool, error) {
	return false, nil
}

func (s *stubSignupRepo) CountCompletedBusinessSignupsByEmailDomain(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// mockPlanAwareHook additionally implements PlanAwarePostSignupHook, so
// SignupService.CompleteSignup's type-assertion picks
// OnSignupCompleteWithPlan over the plain OnSignupComplete — this is what
// PostSignupProvisioner (the production hook) implements, and what
// forwards PlanCode through to TrialStarter.StartTrial.
type mockPlanAwareHook struct {
	calledWithPlan bool
	planCode       string
}

func (m *mockPlanAwareHook) OnSignupComplete(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}

func (m *mockPlanAwareHook) OnSignupCompleteWithPlan(_ context.Context, _, _ uuid.UUID, _ string, planCode string) error {
	m.calledWithPlan = true
	m.planCode = planCode
	return nil
}

// TestSignupService_CompleteSignup_EmptyPlanCode_ReachesPlanAwareHook is
// the other half of the plan-optional control
// (TestSignupService_CompleteSignup_PlanCodeOptional in
// signup_service_slug_test.go proves signup itself doesn't fail; this
// proves the empty value is FORWARDED, not silently dropped, to the
// plan-aware hook — the path that reaches TrialStarter.StartTrial and,
// in production, subscription-management's packageRepo.FindDefault
// fallback). If CompleteSignup ever went back to defaulting PlanCode to
// some hardcoded string before calling the hook, this test would catch it
// (planCode would come back non-empty here).
func TestSignupService_CompleteSignup_EmptyPlanCode_ReachesPlanAwareHook(t *testing.T) {
	hook := &mockPlanAwareHook{}
	reqID := uuid.New()
	repo := &stubSignupRepo{
		req: &models.SignupRequest{CompletionSecretHash: testCompletionSecretHash(),
			ID:          reqID,
			Email:       "plan-forward@example.com",
			Verified:    true,
			AccountType: "business",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}

	svc := NewSignupService(repo, &stubSignupEmail{}, &stubSignupTenantCreator{}, stubTenantManagementRegistrar{}, &stubSignupUserCreator{}, &stubSignupUserLookup{}, "downstream.com", "starter", testOTPKey)
	svc.SetPostSignupHook(hook)

	user, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: reqID,
		Password:        "TestPass123!",
		// PlanCode deliberately left empty.
	}, "", "")

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.True(t, hook.calledWithPlan, "OnSignupCompleteWithPlan should be called even with an empty PlanCode")
	assert.Empty(t, hook.planCode, "empty PlanCode must be forwarded as-is, not defaulted to a hardcoded value")
}

// stubSignupEmail records the plaintext code of every send (the only place the
// plaintext exists in these tests, as in production).
type stubSignupEmail struct {
	mu    sync.Mutex
	codes []string
	names []string
}

func (s *stubSignupEmail) SendSignupVerificationEmail(_ context.Context, _, code, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes = append(s.codes, code)
	s.names = append(s.names, name)
	return nil
}

func (s *stubSignupEmail) lastName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.names) == 0 {
		return ""
	}
	return s.names[len(s.names)-1]
}

func (s *stubSignupEmail) lastCode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.codes) == 0 {
		return ""
	}
	return s.codes[len(s.codes)-1]
}

type stubSignupTenantCreator struct {
	tenant *models.Tenant
}

func (s *stubSignupTenantCreator) CreateTenant(_ context.Context, req *models.CreateTenantRequest) (*models.Tenant, error) {
	t := &models.Tenant{ID: uuid.New(), Name: req.Name, Slug: req.Slug}
	s.tenant = t
	return t, nil
}

// GetByID returns the well-known consumer tenant for personal-account
// signup tests, mirroring what bootstrapConsumerTenant produces in prod.
// Returns nil for any other ID so an accidental lookup for a non-consumer
// tenant in a test surfaces as the explicit "consumer tenant missing"
// error rather than a silent pass.
func (s *stubSignupTenantCreator) GetByID(_ context.Context, id uuid.UUID) (*models.Tenant, error) {
	if id == models.WellKnownTenantConsumer {
		return &models.Tenant{
			ID:   models.WellKnownTenantConsumer,
			Slug: "hexxlock-consumer",
			Type: models.TenantType("consumer"),
		}, nil
	}
	return nil, nil
}

type stubSignupUserCreator struct {
	user *models.User
}

func (s *stubSignupUserCreator) SignupPasswordPolicy() SignupPasswordPolicy {
	return SignupPasswordPolicy{Version: 1, LengthUnit: "unicode_code_points", MinLength: 8, BreachCheck: "disabled"}
}
func (s *stubSignupUserCreator) PrepareSignupCredential(_ context.Context, password string) (*PreparedSignupCredential, error) {
	if err := s.SignupPasswordPolicy().Validate(password); err != nil {
		return nil, err
	}
	return &PreparedSignupCredential{passwordHash: "test-hash", passwordDigest: sha256.Sum256([]byte(password))}, nil
}

func (s *stubSignupUserCreator) CreateForSignup(_ context.Context, req *models.CreateUserRequest, _ *PreparedSignupCredential) (*models.User, error) {
	u := &models.User{ID: uuid.New(), TenantID: req.TenantID, Username: req.Username, Email: req.Email}
	s.user = u
	return u, nil
}

type stubSignupUserLookup struct{}

func (s *stubSignupUserLookup) GetByEmail(_ context.Context, _ string) (*models.User, error) {
	return nil, nil // not found
}

// --- Tests ---

func TestSignupService_CompleteSignup_CallsPostSignupHook(t *testing.T) {
	hook := &mockPostSignupHook{}
	reqID := uuid.New()
	repo := &stubSignupRepo{
		req: &models.SignupRequest{CompletionSecretHash: testCompletionSecretHash(),
			ID:          reqID,
			Email:       "test@example.com",
			Verified:    true,
			AccountType: "business",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}

	svc := NewSignupService(repo, &stubSignupEmail{}, &stubSignupTenantCreator{}, stubTenantManagementRegistrar{}, &stubSignupUserCreator{}, &stubSignupUserLookup{}, "downstream.com", "starter", testOTPKey)
	svc.SetPostSignupHook(hook)

	user, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: reqID,
		Password:        "TestPass123!",
		PlanCode:        "starter",
	}, "", "")

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.True(t, hook.called, "post-signup hook should be called")
	assert.NotEqual(t, uuid.Nil, hook.tenantID)
	assert.NotEqual(t, uuid.Nil, hook.userID)
	assert.Equal(t, "business", hook.accountType)
}

func TestSignupService_CompleteSignup_HookError_NonFatal(t *testing.T) {
	hook := &mockPostSignupHook{err: fmt.Errorf("hook failed")}
	reqID := uuid.New()
	repo := &stubSignupRepo{
		req: &models.SignupRequest{CompletionSecretHash: testCompletionSecretHash(),
			ID:          reqID,
			Email:       "test@example.com",
			Verified:    true,
			AccountType: "personal",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}

	svc := NewSignupService(repo, &stubSignupEmail{}, &stubSignupTenantCreator{}, stubTenantManagementRegistrar{}, &stubSignupUserCreator{}, &stubSignupUserLookup{}, "downstream.com", "starter", testOTPKey)
	svc.SetPostSignupHook(hook)

	user, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: reqID,
		Password:        "TestPass123!",
		PlanCode:        "starter",
	}, "", "")

	assert.NoError(t, err, "hook failure should not fail signup")
	assert.NotNil(t, user)
	assert.True(t, hook.called)
}

func TestSignupService_CompleteSignup_NilHook_NoError(t *testing.T) {
	reqID := uuid.New()
	repo := &stubSignupRepo{
		req: &models.SignupRequest{CompletionSecretHash: testCompletionSecretHash(),
			ID:          reqID,
			Email:       "test@example.com",
			Verified:    true,
			AccountType: "personal",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}

	svc := NewSignupService(repo, &stubSignupEmail{}, &stubSignupTenantCreator{}, stubTenantManagementRegistrar{}, &stubSignupUserCreator{}, &stubSignupUserLookup{}, "downstream.com", "starter", testOTPKey)
	// No hook set

	user, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: reqID,
		Password:        "TestPass123!",
		PlanCode:        "starter",
	}, "", "")

	assert.NoError(t, err)
	assert.NotNil(t, user)
}
