// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"fmt"
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

type stubSignupEmail struct{}

func (s *stubSignupEmail) SendSignupVerificationEmail(_ context.Context, _, _, _ string) error {
	return nil
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
		req: &models.SignupRequest{
			ID:          reqID,
			Email:       "test@example.com",
			Verified:    true,
			AccountType: "business",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}

	svc := NewSignupService(repo, &stubSignupEmail{}, &stubSignupTenantCreator{}, stubTenantManagementRegistrar{}, &stubSignupUserCreator{}, &stubSignupUserLookup{}, "downstream.com", "starter")
	svc.SetPostSignupHook(hook)

	user, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{
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
		req: &models.SignupRequest{
			ID:          reqID,
			Email:       "test@example.com",
			Verified:    true,
			AccountType: "personal",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}

	svc := NewSignupService(repo, &stubSignupEmail{}, &stubSignupTenantCreator{}, stubTenantManagementRegistrar{}, &stubSignupUserCreator{}, &stubSignupUserLookup{}, "downstream.com", "starter")
	svc.SetPostSignupHook(hook)

	user, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{
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
		req: &models.SignupRequest{
			ID:          reqID,
			Email:       "test@example.com",
			Verified:    true,
			AccountType: "personal",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}

	svc := NewSignupService(repo, &stubSignupEmail{}, &stubSignupTenantCreator{}, stubTenantManagementRegistrar{}, &stubSignupUserCreator{}, &stubSignupUserLookup{}, "downstream.com", "starter")
	// No hook set

	user, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{
		SignupRequestID: reqID,
		Password:        "TestPass123!",
		PlanCode:        "starter",
	}, "", "")

	assert.NoError(t, err)
	assert.NotNil(t, user)
}
