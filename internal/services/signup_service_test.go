// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	testAcmeCorpOrg = "Acme Corp"
)

// isGeneratedFallbackSlug reports whether s looks like the word-pair
// fallback slug randomTenantSlug mints ("adjective-noun", or
// "adjective-noun-<hex4>" once a disambiguator was appended after a
// collision) — as opposed to the old flat "tenant-<hex>" scheme it
// replaced. It does not check word-list membership; IsValidSlug and
// IsReservedSlug (checked alongside every use of this helper) already
// cover format and the reserved-word blocklist.
func isGeneratedFallbackSlug(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 2 && len(parts) != 3 {
		return false
	}
	for i, p := range parts {
		if p == "" {
			return false
		}
		if i < 2 {
			for _, r := range p {
				if r < 'a' || r > 'z' {
					return false
				}
			}
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockSignupRequestRepo struct{ mock.Mock }

func (m *mockSignupRequestRepo) Create(ctx context.Context, req *models.SignupRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *mockSignupRequestRepo) GetByToken(ctx context.Context, token string) (*models.SignupRequest, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SignupRequest), args.Error(1)
}

func (m *mockSignupRequestRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.SignupRequest, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SignupRequest), args.Error(1)
}

func (m *mockSignupRequestRepo) GetPendingByEmail(ctx context.Context, email string) (*models.SignupRequest, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SignupRequest), args.Error(1)
}

func (m *mockSignupRequestRepo) MarkVerified(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockSignupRequestRepo) MarkCompleted(ctx context.Context, id uuid.UUID, tenantID, userID uuid.UUID) error {
	return m.Called(ctx, id, tenantID, userID).Error(0)
}

func (m *mockSignupRequestRepo) SetProvisionedTenant(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, slug string) error {
	return m.Called(ctx, id, tenantID, slug).Error(0)
}

func (m *mockSignupRequestRepo) SetCompanyDetails(ctx context.Context, id uuid.UUID, name, slug string) error {
	return m.Called(ctx, id, name, slug).Error(0)
}

func (m *mockSignupRequestRepo) SetCompletionSecretHash(ctx context.Context, id uuid.UUID, hash string) error {
	return m.Called(ctx, id, hash).Error(0)
}

func (m *mockSignupRequestRepo) SetContinuation(ctx context.Context, id uuid.UUID, continuation string) error {
	return m.Called(ctx, id, continuation).Error(0)
}

func (m *mockSignupRequestRepo) ReserveVerificationResend(ctx context.Context, id uuid.UUID, cooldown, window time.Duration, maxPerWindow, maxFailedTotal int, requireUnverified bool) (bool, error) {
	args := m.Called(ctx, id, cooldown, window, maxPerWindow, maxFailedTotal, requireUnverified)
	return args.Bool(0), args.Error(1)
}

func (m *mockSignupRequestRepo) SetVerificationCode(ctx context.Context, id uuid.UUID, hash string, expiresAt time.Time) error {
	return m.Called(ctx, id, hash, expiresAt).Error(0)
}

func (m *mockSignupRequestRepo) ClaimVerificationAttempt(ctx context.Context, id uuid.UUID, maxAttempts, maxFailedTotal int) (string, time.Time, int, bool, error) {
	args := m.Called(ctx, id, maxAttempts, maxFailedTotal)
	return args.String(0), args.Get(1).(time.Time), args.Int(2), args.Bool(3), args.Error(4)
}

func (m *mockSignupRequestRepo) ConsumeVerificationCode(ctx context.Context, id uuid.UUID, hash string) (bool, error) {
	args := m.Called(ctx, id, hash)
	return args.Bool(0), args.Error(1)
}

func (m *mockSignupRequestRepo) CountCompletedBusinessSignupsByEmailDomain(ctx context.Context, domain string) (int, error) {
	args := m.Called(ctx, domain)
	return args.Int(0), args.Error(1)
}

// ---

type mockSignupEmailSender struct{ mock.Mock }

func (m *mockSignupEmailSender) SendSignupVerificationEmail(ctx context.Context, email, token, name string) error {
	return m.Called(ctx, email, token, name).Error(0)
}

// ---

type mockSignupTenantCreator struct{ mock.Mock }

func (m *mockSignupTenantCreator) CreateTenant(ctx context.Context, req *models.CreateTenantRequest) (*models.Tenant, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Tenant), args.Error(1)
}

// GetByID is the read-side counterpart to CreateTenant. Used by the
// personal-account signup path to look up the well-known consumer
// tenant; passed through to testify/mock so individual tests can
// drive the (consumer-tenant-missing) error branch via
// `mock.On("GetByID", ...).Return((*models.Tenant)(nil), err)`.
func (m *mockSignupTenantCreator) GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Tenant), args.Error(1)
}

// ---

type mockSignupUserCreator struct{ mock.Mock }

func (m *mockSignupUserCreator) SignupPasswordPolicy() SignupPasswordPolicy {
	return SignupPasswordPolicy{Version: 1, LengthUnit: "unicode_code_points", MinLength: 8, BreachCheck: "disabled"}
}
func (m *mockSignupUserCreator) PrepareSignupCredential(_ context.Context, password string) (*PreparedSignupCredential, error) {
	if err := m.SignupPasswordPolicy().Validate(password); err != nil {
		return nil, err
	}
	return &PreparedSignupCredential{passwordHash: "test-hash", passwordDigest: sha256.Sum256([]byte(password))}, nil
}

func (m *mockSignupUserCreator) CreateForSignup(ctx context.Context, req *models.CreateUserRequest, credential *PreparedSignupCredential) (*models.User, error) {
	args := m.Called(ctx, req, credential)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// ---

type mockSignupUserLookup struct{ mock.Mock }

func (m *mockSignupUserLookup) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// mockTenantManagementRegistrar lets a test drive the registrar-failure
// hard-fail path explicitly via `mock.On("Register", ...)`.
type mockTenantManagementRegistrar struct{ mock.Mock }

func (m *mockTenantManagementRegistrar) Register(ctx context.Context, req *TenantManagementRegisterRequest) (*TenantManagementRegisterResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TenantManagementRegisterResult), args.Error(1)
}

// stubTenantManagementRegistrar always succeeds with a fresh ID. Used as
// the default in buildSignupService for every test that doesn't care about
// registrar behavior (i.e. every personal-account test, which never
// reaches this dependency, plus the business-success test) — a plain
// stub rather than an unconfigured testify mock so those 20+ call sites
// don't each need a `.On("Register", ...)` expectation.
type stubTenantManagementRegistrar struct{}

func (stubTenantManagementRegistrar) Register(context.Context, *TenantManagementRegisterRequest) (*TenantManagementRegisterResult, error) {
	return &TenantManagementRegisterResult{ID: uuid.New()}, nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func buildSignupService(
	repo *mockSignupRequestRepo,
	email *mockSignupEmailSender,
	tenant *mockSignupTenantCreator,
	user *mockSignupUserCreator,
	lookup *mockSignupUserLookup,
) *SignupService {
	return NewSignupService(repo, email, tenant, stubTenantManagementRegistrar{}, user, lookup, "downstream.com", "starter", testOTPKey)
}

// buildSignupServiceWithRegistrar is buildSignupService with an explicit,
// caller-controlled registrar — for tests that exercise registrar
// success/failure semantics directly (t-597 hard-fail path).
func buildSignupServiceWithRegistrar(
	repo *mockSignupRequestRepo,
	email *mockSignupEmailSender,
	tenant *mockSignupTenantCreator,
	registrar TenantManagementRegistrar,
	user *mockSignupUserCreator,
	lookup *mockSignupUserLookup,
) *SignupService {
	return NewSignupService(repo, email, tenant, registrar, user, lookup, "downstream.com", "starter", testOTPKey)
}

func freshInput(accountType string) *models.CreateSignupRequestInput { //nolint:unparam // accountType is always "personal" currently but kept for flexibility
	// Personal accounts pick a username; the service derives
	// <username>@downstream.com. (Business signups use businessInput().)
	return &models.CreateSignupRequestInput{
		Username:    "jane",
		FirstName:   "Jane",
		AccountType: accountType,
	}
}

func businessInput() *models.CreateSignupRequestInput {
	return &models.CreateSignupRequestInput{
		Email:       "john@acme.com",
		FirstName:   "John",
		AccountType: "business",
		CompanyName: testAcmeCorpOrg,
	}
}

func pendingRequest(email string) *models.SignupRequest {
	now := time.Now()
	first := "Jane"
	return &models.SignupRequest{
		ID:                uuid.New(),
		Email:             email,
		FirstName:         &first,
		AccountType:       "personal",
		VerificationToken: "existing-token",
		Verified:          false,
		Completed:         false,
		ExpiresAt:         now.Add(24 * time.Hour),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func verifiedRequest(email, accountType string) *models.SignupRequest {
	req := pendingRequest(email)
	req.AccountType = accountType
	req.Verified = true
	req.CompletionSecretHash = testCompletionSecretHash()
	now := time.Now()
	req.VerifiedAt = &now
	return req
}

func fakeUser(tenantID uuid.UUID, email string) *models.User {
	return &models.User{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Email:     email,
		Username:  "jane",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// ---------------------------------------------------------------------------
// InitiateSignup
// ---------------------------------------------------------------------------

func TestSignupService_InitiateSignup_PersonalSuccess(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	input := freshInput("personal")

	// No existing user.
	lookup.On("GetByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
	// No pending request.
	repo.On("GetPendingByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
	// Persist signup request.
	repo.On("Create", mock.Anything, mock.AnythingOfType("*models.SignupRequest")).Return(nil)
	// Send email (best-effort).
	emailSvc.On("SendSignupVerificationEmail", mock.Anything, "jane@downstream.com", mock.AnythingOfType("string"), "Jane").Return(nil)

	result, err := svc.InitiateSignup(context.Background(), input, "10.0.0.1", "TestAgent/1.0")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "jane@downstream.com", result.Email)
	assert.Equal(t, "personal", result.AccountType)
	assert.False(t, result.Verified)
	assert.NotEmpty(t, result.VerificationToken)

	repo.AssertExpectations(t)
	emailSvc.AssertExpectations(t)
	lookup.AssertExpectations(t)
}

func TestSignupService_InitiateSignup_BusinessSuccess(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	input := businessInput()

	lookup.On("GetByEmail", mock.Anything, "john@acme.com").Return(nil, errors.New("not found"))
	// Abuse control (see InitiateSignup's one-trial-per-work-domain doc
	// comment): acme.com has no prior COMPLETED business signup, so this
	// returns 0 and InitiateSignup proceeds. The "blocks a second signup"
	// half of this control is its own test,
	// TestSignupService_InitiateSignup_BusinessDomainAlreadyTrialed below.
	repo.On("CountCompletedBusinessSignupsByEmailDomain", mock.Anything, "acme.com").Return(0, nil)
	repo.On("GetPendingByEmail", mock.Anything, "john@acme.com").Return(nil, errors.New("not found"))
	repo.On("Create", mock.Anything, mock.MatchedBy(func(r *models.SignupRequest) bool {
		return r.AccountType == "business" &&
			r.CompanyName != nil && *r.CompanyName == testAcmeCorpOrg &&
			r.CompanySlug != nil && *r.CompanySlug == testTenantSlugAcme
	})).Return(nil)
	emailSvc.On("SendSignupVerificationEmail", mock.Anything, "john@acme.com", mock.AnythingOfType("string"), "John").Return(nil)

	result, err := svc.InitiateSignup(context.Background(), input, "10.0.0.2", "Chrome/120")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "business", result.AccountType)
	require.NotNil(t, result.CompanySlug)
	assert.Equal(t, testTenantSlugAcme, *result.CompanySlug)

	repo.AssertExpectations(t)
	emailSvc.AssertExpectations(t)
}

// TestSignupService_InitiateSignup_BusinessDomainAlreadyTrialed is the
// CONTROL for the one-trial-per-work-domain abuse control added
// 2026-09-18 (t-signup-no-plan-step) alongside removing the signup
// wizard's plan step (see InitiateSignup's doc comment on the check
// itself for the full rationale: every self-serve signup now gets a
// full top-tier trial with no card, so nothing else stopped
// bob@acme.com from re-running signup right after alice@acme.com).
//
// This proves a SECOND business signup at a domain that already has one
// COMPLETED business signup is refused with SignupStateError{"domain_trial_exists"}
// — never reaching GetPendingByEmail/Create/SendSignupVerificationEmail
// (mock.Mock panics on an unexpected call, so those being absent from
// this test's expectations is itself part of the assertion: if the
// early-return were ever deleted, this test would fail loudly on an
// unexpected mock call, not silently pass).
func TestSignupService_InitiateSignup_BusinessDomainAlreadyTrialed(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	input := &models.CreateSignupRequestInput{
		Email:       "second-employee@acme.com",
		FirstName:   "Bob",
		AccountType: "business",
		CompanyName: testAcmeCorpOrg,
	}

	lookup.On("GetByEmail", mock.Anything, "second-employee@acme.com").Return(nil, errors.New("not found"))
	repo.On("CountCompletedBusinessSignupsByEmailDomain", mock.Anything, "acme.com").Return(1, nil)

	result, err := svc.InitiateSignup(context.Background(), input, "10.0.0.3", "Chrome/120")

	require.Error(t, err)
	require.Nil(t, result)
	var stateErr *SignupStateError
	require.ErrorAs(t, err, &stateErr)
	assert.Equal(t, "domain_trial_exists", stateErr.Code)

	repo.AssertExpectations(t)
	emailSvc.AssertExpectations(t)
	repo.AssertNotCalled(t, "GetPendingByEmail", mock.Anything, mock.Anything)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
	emailSvc.AssertNotCalled(t, "SendSignupVerificationEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestSignupService_InitiateSignup_FreeEmailDomain_NotDomainLimited is the
// paired negative/positive control for the check above: a SECOND signup
// at a well-known free-webmail domain (gmail.com) is NOT blocked even
// though CountCompletedBusinessSignupsByEmailDomain is never even called
// — proving the exemption in freeEmailProviderDomains actually short-
// circuits before the repo query, not merely that the repo happens to
// return 0. If the exemption check were ever removed, this test's
// AssertNotCalled would fail as soon as the (unmocked) repo call panicked.
func TestSignupService_InitiateSignup_FreeEmailDomain_NotDomainLimited(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	input := &models.CreateSignupRequestInput{
		Email:       "founder@gmail.com",
		FirstName:   "Casey",
		AccountType: "business",
		CompanyName: "Solo Founder LLC",
	}

	lookup.On("GetByEmail", mock.Anything, "founder@gmail.com").Return(nil, errors.New("not found"))
	repo.On("GetPendingByEmail", mock.Anything, "founder@gmail.com").Return(nil, errors.New("not found"))
	repo.On("Create", mock.Anything, mock.MatchedBy(func(r *models.SignupRequest) bool {
		return r.AccountType == "business" && r.Email == "founder@gmail.com"
	})).Return(nil)
	emailSvc.On("SendSignupVerificationEmail", mock.Anything, "founder@gmail.com", mock.AnythingOfType("string"), "Casey").Return(nil)

	result, err := svc.InitiateSignup(context.Background(), input, "10.0.0.4", "Chrome/120")

	require.NoError(t, err)
	require.NotNil(t, result)

	repo.AssertExpectations(t)
	emailSvc.AssertExpectations(t)
	repo.AssertNotCalled(t, "CountCompletedBusinessSignupsByEmailDomain", mock.Anything, mock.Anything)
}

// TestSignupService_InitiateSignup_PersonalAccount_NeverDomainChecked
// proves the domain check does not even run for personal accounts —
// every personal signup shares ONE consumer domain
// (consumerEmailDomain(), downstream.com in this test's fixture), so
// running this check there would lock out every personal signup after
// the very first one. See InitiateSignup's doc comment for why personal
// accounts never start a billing trial at all.
func TestSignupService_InitiateSignup_PersonalAccount_NeverDomainChecked(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	input := freshInput("personal")

	lookup.On("GetByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
	repo.On("GetPendingByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
	repo.On("Create", mock.Anything, mock.Anything).Return(nil)
	emailSvc.On("SendSignupVerificationEmail", mock.Anything, "jane@downstream.com", mock.AnythingOfType("string"), "Jane").Return(nil)

	result, err := svc.InitiateSignup(context.Background(), input, "10.0.0.5", "agent")

	require.NoError(t, err)
	require.NotNil(t, result)

	repo.AssertExpectations(t)
	emailSvc.AssertExpectations(t)
	repo.AssertNotCalled(t, "CountCompletedBusinessSignupsByEmailDomain", mock.Anything, mock.Anything)
}

func TestSignupService_InitiateSignup_ExistingUser_ReturnsError(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	input := freshInput("personal")
	existingUser := fakeUser(uuid.New(), "jane@downstream.com")

	lookup.On("GetByEmail", mock.Anything, "jane@downstream.com").Return(existingUser, nil)

	result, err := svc.InitiateSignup(context.Background(), input, "10.0.0.1", "agent")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "an account with this email already exists")
	repo.AssertNotCalled(t, "Create")
	emailSvc.AssertNotCalled(t, "SendSignupVerificationEmail")
}

func TestSignupService_InitiateSignup_PendingExists_ResendEmail(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	input := freshInput("personal")
	existing := pendingRequest("jane@downstream.com")

	lookup.On("GetByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
	repo.On("GetPendingByEmail", mock.Anything, "jane@downstream.com").Return(existing, nil)
	repo.On("ReserveVerificationResend", mock.Anything, existing.ID, mock.Anything, mock.Anything, mock.Anything, mock.Anything, true).Return(true, nil)
	repo.On("SetVerificationCode", mock.Anything, existing.ID, mock.AnythingOfType("string"), mock.Anything).Return(nil)
	emailSvc.On("SendSignupVerificationEmail", mock.Anything, "jane@downstream.com", mock.MatchedBy(func(c string) bool { return signupCodeRE.MatchString(c) }), "Jane").Return(nil)

	result, err := svc.InitiateSignup(context.Background(), input, "10.0.0.1", "agent")

	require.NoError(t, err)
	require.NotNil(t, result)
	// Must return the existing request (same ID), not a new one.
	assert.Equal(t, existing.ID, result.ID)
	// Must NOT create a new record.
	repo.AssertNotCalled(t, "Create")
	emailSvc.AssertExpectations(t)
}

// TestSignupService_InitiateSignup_VerifiedButNotCompleted_Resumes proves the
// fix for the "atlasbadi" / "atlasbadi-a1ad" production duplicate-tenant
// bug: retrying InitiateSignup for an email that already verified but never
// finished CompleteSignup must return the SAME signup request (so the
// client resumes into CompleteSignup against it), not silently fall through
// to minting a brand-new request row — the second half of that bug lived in
// provisionTenant re-registering a tenant for the new row (see the
// TestSignupService_CompleteSignup_ResumesAfterPartialTenantRegistration
// test for that half).
func TestSignupService_InitiateSignup_VerifiedButNotCompleted_Resumes(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	input := freshInput("personal")
	existing := verifiedRequest("jane@downstream.com", "personal")

	lookup.On("GetByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
	// GetPendingByEmail's own WHERE clause is "NOT completed AND expires_at
	// > NOW()" — it does not filter on `verified`, so a verified-but-
	// incomplete row is exactly what it returns here.
	repo.On("GetPendingByEmail", mock.Anything, "jane@downstream.com").Return(existing, nil)
	// Recovery: the same throttled resend path runs (requireUnverified=false),
	// so the resumer must re-prove the mailbox with a fresh code.
	repo.On("ReserveVerificationResend", mock.Anything, existing.ID, mock.Anything, mock.Anything, mock.Anything, mock.Anything, false).Return(true, nil)
	repo.On("SetVerificationCode", mock.Anything, existing.ID, mock.AnythingOfType("string"), mock.Anything).Return(nil)
	emailSvc.On("SendSignupVerificationEmail", mock.Anything, "jane@downstream.com", mock.MatchedBy(func(c string) bool { return signupCodeRE.MatchString(c) }), "Jane").Return(nil)

	result, err := svc.InitiateSignup(context.Background(), input, "10.0.0.1", "agent")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, existing.ID, result.ID)
	// Must NOT create a new record (that would orphan a tenant).
	repo.AssertNotCalled(t, "Create")
	emailSvc.AssertExpectations(t)
}

func TestSignupService_InitiateSignup_EmailSendFailure_StillSucceeds(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	input := freshInput("personal")

	lookup.On("GetByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
	repo.On("GetPendingByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
	repo.On("Create", mock.Anything, mock.AnythingOfType("*models.SignupRequest")).Return(nil)
	// Email send fails — should not propagate.
	emailSvc.On("SendSignupVerificationEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(errors.New("SMTP timeout"))

	result, err := svc.InitiateSignup(context.Background(), input, "10.0.0.1", "agent")

	require.NoError(t, err, "email send failure must not abort signup initiation")
	require.NotNil(t, result)
	assert.Equal(t, "jane@downstream.com", result.Email)
}

func TestSignupService_InitiateSignup_UsernameNormalization(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	// Personal: username is trimmed + lowercased before the email is derived.
	input := &models.CreateSignupRequestInput{
		Username:    "  JANE  ",
		FirstName:   "Jane",
		AccountType: "personal",
	}

	lookup.On("GetByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
	repo.On("GetPendingByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
	repo.On("Create", mock.Anything, mock.MatchedBy(func(r *models.SignupRequest) bool {
		return r.Email == "jane@downstream.com"
	})).Return(nil)
	emailSvc.On("SendSignupVerificationEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	result, err := svc.InitiateSignup(context.Background(), input, "10.0.0.1", "agent")

	require.NoError(t, err)
	assert.Equal(t, "jane@downstream.com", result.Email)
}

func TestSignupService_CheckUsernameAvailable(t *testing.T) {
	t.Parallel()

	t.Run("available", func(t *testing.T) {
		repo := &mockSignupRequestRepo{}
		lookup := &mockSignupUserLookup{}
		svc := buildSignupService(repo, &mockSignupEmailSender{}, &mockSignupTenantCreator{}, &mockSignupUserCreator{}, lookup)
		lookup.On("GetByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
		repo.On("GetPendingByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))

		ok, email, err := svc.CheckUsernameAvailable(context.Background(), "Jane")
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "jane@downstream.com", email)
	})

	t.Run("taken", func(t *testing.T) {
		repo := &mockSignupRequestRepo{}
		lookup := &mockSignupUserLookup{}
		svc := buildSignupService(repo, &mockSignupEmailSender{}, &mockSignupTenantCreator{}, &mockSignupUserCreator{}, lookup)
		lookup.On("GetByEmail", mock.Anything, "jane@downstream.com").Return(fakeUser(uuid.New(), "jane@downstream.com"), nil)

		ok, _, err := svc.CheckUsernameAvailable(context.Background(), "jane")
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("invalid format", func(t *testing.T) {
		svc := buildSignupService(&mockSignupRequestRepo{}, &mockSignupEmailSender{}, &mockSignupTenantCreator{}, &mockSignupUserCreator{}, &mockSignupUserLookup{})
		ok, _, err := svc.CheckUsernameAvailable(context.Background(), "ab") // too short
		require.Error(t, err)
		assert.False(t, ok)
	})
}

func TestSignupService_InitiateSignup_RepoPersistError(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	input := freshInput("personal")

	lookup.On("GetByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
	repo.On("GetPendingByEmail", mock.Anything, "jane@downstream.com").Return(nil, errors.New("not found"))
	repo.On("Create", mock.Anything, mock.AnythingOfType("*models.SignupRequest")).
		Return(errors.New("unique constraint violation"))

	result, err := svc.InitiateSignup(context.Background(), input, "10.0.0.1", "agent")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "create signup request")
	emailSvc.AssertNotCalled(t, "SendSignupVerificationEmail")
}

// ---------------------------------------------------------------------------
// VerifyEmail
// ---------------------------------------------------------------------------

func TestSignupService_VerifyEmail_Success(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	pending := pendingRequest("jane@example.com")

	repo.On("GetByToken", mock.Anything, "valid-token").Return(pending, nil)
	repo.On("MarkVerified", mock.Anything, pending.ID).Return(nil)
	repo.On("SetCompletionSecretHash", mock.Anything, pending.ID, mock.AnythingOfType("string")).Return(nil)

	result, err := svc.VerifyEmail(context.Background(), &models.VerifySignupEmailInput{Token: "valid-token"})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Verified)
	assert.NotNil(t, result.VerifiedAt)

	repo.AssertExpectations(t)
}

func TestSignupService_VerifyEmail_InvalidToken(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	repo.On("GetByToken", mock.Anything, "bad-token").Return(nil, errors.New("not found"))

	result, err := svc.VerifyEmail(context.Background(), &models.VerifySignupEmailInput{Token: "bad-token"})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid or expired verification token")
}

func TestSignupService_VerifyEmail_ExpiredToken(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	expired := pendingRequest("jane@example.com")
	expired.ExpiresAt = time.Now().Add(-1 * time.Hour) // already expired

	repo.On("GetByToken", mock.Anything, "expired-token").Return(expired, nil)

	result, err := svc.VerifyEmail(context.Background(), &models.VerifySignupEmailInput{Token: "expired-token"})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "verification token has expired")
	repo.AssertNotCalled(t, "MarkVerified")
}

func TestSignupService_VerifyEmail_AlreadyVerified_Idempotent(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	alreadyVerified := pendingRequest("jane@example.com")
	alreadyVerified.Verified = true
	now := time.Now()
	alreadyVerified.VerifiedAt = &now

	repo.On("GetByToken", mock.Anything, "already-verified-token").Return(alreadyVerified, nil)
	repo.On("SetCompletionSecretHash", mock.Anything, alreadyVerified.ID, mock.AnythingOfType("string")).Return(nil)

	result, err := svc.VerifyEmail(context.Background(), &models.VerifySignupEmailInput{Token: "already-verified-token"})

	require.NoError(t, err, "re-verifying must succeed (idempotent)")
	require.NotNil(t, result)
	assert.True(t, result.Verified)
	// Must NOT call MarkVerified a second time.
	repo.AssertNotCalled(t, "MarkVerified")
}

func TestSignupService_VerifyEmail_MarkVerifiedError(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	pending := pendingRequest("jane@example.com")

	repo.On("GetByToken", mock.Anything, "ok-token").Return(pending, nil)
	repo.On("MarkVerified", mock.Anything, pending.ID).Return(errors.New("db error"))

	result, err := svc.VerifyEmail(context.Background(), &models.VerifySignupEmailInput{Token: "ok-token"})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "mark verified")
}

// ---------------------------------------------------------------------------
// CompleteSignup
// ---------------------------------------------------------------------------

func TestSignupService_CompleteSignup_PersonalSuccess(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	req := verifiedRequest("jane@example.com", "personal")
	// Since 2026-05-22 personal signups enroll into the shared
	// consumer tenant (models.WellKnownTenantConsumer) rather than
	// minting per-user "personal-XXXX" tenants. The provisionTenant
	// path now calls GetByID instead of CreateTenant for this case.
	consumerTenant := &models.Tenant{
		ID:   models.WellKnownTenantConsumer,
		Slug: "hexxlock-consumer",
		Type: models.TenantType("consumer"),
	}
	user := fakeUser(consumerTenant.ID, req.Email)

	repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)
	tenantSvc.On("GetByID", mock.Anything, models.WellKnownTenantConsumer).Return(consumerTenant, nil)
	userSvc.On("CreateForSignup", mock.Anything, mock.MatchedBy(func(r *models.CreateUserRequest) bool {
		return r.Email == req.Email && r.TenantID == consumerTenant.ID
	}), mock.Anything).Return(user, nil)
	repo.On("MarkCompleted", mock.Anything, req.ID, consumerTenant.ID, user.ID).Return(nil)

	result, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: req.ID,
		Password:        "SecurePassword1!",
		PlanCode:        "starter",
	}, "", "")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, user.ID, result.User.ID)
	assert.Equal(t, consumerTenant.ID, result.User.TenantID)

	repo.AssertExpectations(t)
	tenantSvc.AssertExpectations(t)
	userSvc.AssertExpectations(t)
}

func TestSignupService_CompleteSignup_BusinessSuccess(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	registrar := &mockTenantManagementRegistrar{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupServiceWithRegistrar(repo, emailSvc, tenantSvc, registrar, userSvc, lookup)

	companyName := testAcmeCorpOrg
	companySlug := testTenantSlugAcme
	req := verifiedRequest("john@acme.com", "business")
	req.CompanyName = &companyName
	req.CompanySlug = &companySlug

	// The ID tenant-management would have minted for this same tenant.
	// t-597 / ADR-0029: falcon-id's local iam_tenants row must reuse it so
	// both systems agree on one tenant identity.
	registeredTenantID := uuid.New()
	tenant := &models.Tenant{ID: registeredTenantID, Name: testAcmeCorpOrg, Type: "customer"}
	user := fakeUser(tenant.ID, req.Email)

	repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)
	registrar.On("Register", mock.Anything, mock.MatchedBy(func(r *TenantManagementRegisterRequest) bool {
		return r.TenantName == testAcmeCorpOrg && r.TenantSlug == testTenantSlugAcme && r.Email == req.Email
	})).Return(&TenantManagementRegisterResult{ID: registeredTenantID}, nil)
	repo.On("SetProvisionedTenant", mock.Anything, req.ID, registeredTenantID, testTenantSlugAcme).Return(nil)
	tenantSvc.On("CreateTenant", mock.Anything, mock.MatchedBy(func(r *models.CreateTenantRequest) bool {
		return r.Type == "customer" && r.Name == testAcmeCorpOrg && r.Slug == testTenantSlugAcme &&
			r.ID != nil && *r.ID == registeredTenantID
	})).Return(tenant, nil)
	userSvc.On("CreateForSignup", mock.Anything, mock.AnythingOfType("*models.CreateUserRequest"), mock.Anything).Return(user, nil)
	repo.On("MarkCompleted", mock.Anything, req.ID, tenant.ID, user.ID).Return(nil)

	result, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: req.ID,
		Password:        "AcmeSecure1!",
		PlanCode:        "starter",
	}, "", "")

	require.NoError(t, err)
	assert.Equal(t, user.ID, result.User.ID)

	repo.AssertExpectations(t)
	registrar.AssertExpectations(t)
	tenantSvc.AssertExpectations(t)
	userSvc.AssertExpectations(t)
}

// TestSignupService_CompleteSignup_TenantRegistrationFails_HardFails proves
// the t-597 fix's central invariant: if tenant-management registration
// fails, CompleteSignup must fail too, and the local iam_tenants row must
// NEVER be created — a signup must not "succeed" into a tenant with no
// possible quota.
func TestSignupService_CompleteSignup_TenantRegistrationFails_HardFails(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	registrar := &mockTenantManagementRegistrar{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupServiceWithRegistrar(repo, emailSvc, tenantSvc, registrar, userSvc, lookup)

	companyName := testAcmeCorpOrg
	companySlug := testTenantSlugAcme
	req := verifiedRequest("john@acme.com", "business")
	req.CompanyName = &companyName
	req.CompanySlug = &companySlug

	repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)
	registrar.On("Register", mock.Anything, mock.Anything).
		Return((*TenantManagementRegisterResult)(nil), errors.New("tenant-management unreachable"))

	result, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: req.ID,
		Password:        "AcmeSecure1!",
		PlanCode:        "starter",
	}, "", "")

	require.Error(t, err)
	assert.Nil(t, result)
	tenantSvc.AssertNotCalled(t, "CreateTenant")
	userSvc.AssertNotCalled(t, "CreateForSignup")
	repo.AssertNotCalled(t, "MarkCompleted", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestSignupService_CompleteSignup_ResumesAfterPartialTenantRegistration
// proves the fix for the production duplicate-tenant bug (tenant
// "atlasbadi" 938ba35f left as a permanent zero-user orphan after
// "atlasbadi-a1ad" cf097694 was minted 24 seconds later for a retry of the
// SAME signup). req.TenantID already set (as SetProvisionedTenant would
// have left it after a prior attempt's successful Register, followed by a
// failed/incomplete local CreateTenant) must make provisionTenant resume
// straight into CreateTenant using the already-registered tenant ID and
// the already-accepted slug — Register must NOT be called again.
func TestSignupService_CompleteSignup_ResumesAfterPartialTenantRegistration(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	registrar := &mockTenantManagementRegistrar{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupServiceWithRegistrar(repo, emailSvc, tenantSvc, registrar, userSvc, lookup)

	companyName := testAcmeCorpOrg
	req := verifiedRequest("john@acme.com", "business")
	req.CompanyName = &companyName

	// Simulates the checkpoint SetProvisionedTenant would have written
	// after a prior attempt's Register succeeded but local CreateTenant
	// did not run (or failed) — tenant_id set, company_slug overwritten
	// with the tenant-management-accepted slug (not the original
	// candidate, which may have collided).
	alreadyRegisteredTenantID := uuid.New()
	acceptedSlug := testTenantSlugAcme
	req.TenantID = &alreadyRegisteredTenantID
	req.CompanySlug = &acceptedSlug

	tenant := &models.Tenant{ID: alreadyRegisteredTenantID, Name: testAcmeCorpOrg, Slug: acceptedSlug, Type: "customer"}
	user := fakeUser(tenant.ID, req.Email)

	repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)
	// The local iam_tenants row does not exist yet for this ID.
	tenantSvc.On("GetByID", mock.Anything, alreadyRegisteredTenantID).Return(nil, nil)
	tenantSvc.On("CreateTenant", mock.Anything, mock.MatchedBy(func(r *models.CreateTenantRequest) bool {
		return r.ID != nil && *r.ID == alreadyRegisteredTenantID && r.Slug == acceptedSlug
	})).Return(tenant, nil)
	userSvc.On("CreateForSignup", mock.Anything, mock.AnythingOfType("*models.CreateUserRequest"), mock.Anything).Return(user, nil)
	repo.On("MarkCompleted", mock.Anything, req.ID, tenant.ID, user.ID).Return(nil)

	result, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: req.ID,
		Password:        "AcmeSecure1!",
		PlanCode:        "starter",
	}, "", "")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, tenant.ID, result.User.TenantID)
	// The whole point: a SECOND tenant-management registration must never
	// happen for a signup request that already has one.
	registrar.AssertNotCalled(t, "Register", mock.Anything, mock.Anything)
	repo.AssertNotCalled(t, "SetProvisionedTenant", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestSignupService_CompleteSignup_FullyResumedRetry_IsIdempotent proves
// that if BOTH phases already completed on a prior attempt (tenant-
// management row AND local iam_tenants row both exist for req.TenantID —
// e.g. CompleteSignup is called twice because a client retried after a
// slow/lost HTTP response), provisionTenant returns the existing tenant
// without calling either Register or CreateTenant again.
func TestSignupService_CompleteSignup_FullyResumedRetry_IsIdempotent(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	registrar := &mockTenantManagementRegistrar{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupServiceWithRegistrar(repo, emailSvc, tenantSvc, registrar, userSvc, lookup)

	companyName := testAcmeCorpOrg
	req := verifiedRequest("john@acme.com", "business")
	req.CompanyName = &companyName

	tenantID := uuid.New()
	slug := testTenantSlugAcme
	req.TenantID = &tenantID
	req.CompanySlug = &slug

	existingTenant := &models.Tenant{ID: tenantID, Name: testAcmeCorpOrg, Slug: slug, Type: "customer"}
	user := fakeUser(tenantID, req.Email)

	repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)
	// Both phases already provisioned: the local tenant already exists.
	tenantSvc.On("GetByID", mock.Anything, tenantID).Return(existingTenant, nil)
	userSvc.On("CreateForSignup", mock.Anything, mock.AnythingOfType("*models.CreateUserRequest"), mock.Anything).Return(user, nil)
	repo.On("MarkCompleted", mock.Anything, req.ID, tenantID, user.ID).Return(nil)

	result, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: req.ID,
		Password:        "AcmeSecure1!",
		PlanCode:        "starter",
	}, "", "")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, tenantID, result.User.TenantID)
	registrar.AssertNotCalled(t, "Register", mock.Anything, mock.Anything)
	tenantSvc.AssertNotCalled(t, "CreateTenant", mock.Anything, mock.Anything)
}

// TestSignupService_CompleteSignup_BusinessNoCompanySlug_GeneratesRandomSlug
// proves the fix for the production bug: the Brevo-style signup page never
// sets CompanySlug (email+password only), so provisionTenant must NOT fall
// back to a fixed literal like "company" — that hardcoded fallback is what
// let only the FIRST self-service signup ever complete, since every
// subsequent one collided on the same slug. With CompanySlug nil, it must
// mint a fresh, valid, non-reserved random slug instead.
func TestSignupService_CompleteSignup_BusinessNoCompanySlug_GeneratesRandomSlug(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	registrar := &mockTenantManagementRegistrar{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupServiceWithRegistrar(repo, emailSvc, tenantSvc, registrar, userSvc, lookup)

	// CompanyName and CompanySlug both left nil, exactly like the real
	// signup page's request payload.
	req := verifiedRequest("jane@newco.example.com", "business")

	registeredTenantID := uuid.New()
	tenant := &models.Tenant{ID: registeredTenantID, Name: models.PlaceholderTenantName, Type: "customer"}
	user := fakeUser(tenant.ID, req.Email)

	repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)
	registrar.On("Register", mock.Anything, mock.MatchedBy(func(r *TenantManagementRegisterRequest) bool {
		return r.TenantName == models.PlaceholderTenantName &&
			isGeneratedFallbackSlug(r.TenantSlug) &&
			models.IsValidSlug(r.TenantSlug) &&
			!models.IsReservedSlug(r.TenantSlug)
	})).Return(&TenantManagementRegisterResult{ID: registeredTenantID}, nil)
	repo.On("SetProvisionedTenant", mock.Anything, req.ID, registeredTenantID, mock.MatchedBy(func(slug string) bool {
		return isGeneratedFallbackSlug(slug) && slug != "company"
	})).Return(nil)
	tenantSvc.On("CreateTenant", mock.Anything, mock.MatchedBy(func(r *models.CreateTenantRequest) bool {
		return isGeneratedFallbackSlug(r.Slug) && r.Slug != "company"
	})).Return(tenant, nil)
	userSvc.On("CreateForSignup", mock.Anything, mock.AnythingOfType("*models.CreateUserRequest"), mock.Anything).Return(user, nil)
	repo.On("MarkCompleted", mock.Anything, req.ID, tenant.ID, user.ID).Return(nil)

	result, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: req.ID,
		Password:        "Sup3rSecure1!",
		PlanCode:        "starter",
	}, "", "")

	require.NoError(t, err)
	assert.Equal(t, user.ID, result.User.ID)

	repo.AssertExpectations(t)
	registrar.AssertExpectations(t)
	tenantSvc.AssertExpectations(t)
}

// TestSignupService_CompleteSignup_TenantSlugCollision_RetriesWithDifferentSlug
// proves the collision-retry loop. tenant-management's public register
// endpoint collapses a genuine slug conflict into the same generic error
// as any other failure (TenantHandler.Register masks every Create() error,
// including "slug already exists", as a flat 500 "An internal error
// occurred"), so provisionTenant cannot tell "collision" apart from
// "outage" from the error text alone. On failure it must retry with a
// FRESH candidate slug — never give up after one attempt, and never
// resubmit the same (just-rejected) slug.
func TestSignupService_CompleteSignup_TenantSlugCollision_RetriesWithDifferentSlug(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	registrar := &mockTenantManagementRegistrar{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupServiceWithRegistrar(repo, emailSvc, tenantSvc, registrar, userSvc, lookup)

	req := verifiedRequest("jane@newco.example.com", "business")

	registeredTenantID := uuid.New()
	tenant := &models.Tenant{ID: registeredTenantID, Name: models.PlaceholderTenantName, Type: "customer"}
	user := fakeUser(tenant.ID, req.Email)

	// Captured via .Run(), which testify invokes exactly once per actual
	// resolved call — NOT via a side-effecting mock.MatchedBy predicate,
	// which testify's internal call-resolution can invoke more than once
	// per real call while diffing against every registered expectation.
	var seenSlugs []string
	captureSlug := func(args mock.Arguments) {
		seenSlugs = append(seenSlugs, args.Get(1).(*TenantManagementRegisterRequest).TenantSlug)
	}

	repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)
	// First attempt: simulates the wire-indistinguishable "slug already
	// exists" 500 from tenant-management's public register endpoint.
	registrar.On("Register", mock.Anything, mock.Anything).
		Run(captureSlug).
		Return((*TenantManagementRegisterResult)(nil), errors.New("tenant-management register failed (500): An internal error occurred")).
		Once()
	// Second attempt: succeeds with whatever new candidate the retry mints.
	registrar.On("Register", mock.Anything, mock.Anything).
		Run(captureSlug).
		Return(&TenantManagementRegisterResult{ID: registeredTenantID}, nil).
		Once()
	repo.On("SetProvisionedTenant", mock.Anything, req.ID, registeredTenantID, mock.AnythingOfType("string")).Return(nil)
	tenantSvc.On("CreateTenant", mock.Anything, mock.AnythingOfType("*models.CreateTenantRequest")).Return(tenant, nil)
	userSvc.On("CreateForSignup", mock.Anything, mock.AnythingOfType("*models.CreateUserRequest"), mock.Anything).Return(user, nil)
	repo.On("MarkCompleted", mock.Anything, req.ID, tenant.ID, user.ID).Return(nil)

	result, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: req.ID,
		Password:        "Sup3rSecure1!",
		PlanCode:        "starter",
	}, "", "")

	require.NoError(t, err)
	assert.Equal(t, user.ID, result.User.ID)
	require.Len(t, seenSlugs, 2, "expected exactly one retry after the simulated collision")
	assert.NotEqual(t, seenSlugs[0], seenSlugs[1], "retry must use a NEW slug, never resubmit the one that just collided")

	registrar.AssertExpectations(t)
	tenantSvc.AssertExpectations(t)
}

func TestSignupService_CompleteSignup_NotVerified_ReturnsError(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	unverified := pendingRequest("jane@example.com") // Verified = false
	unverified.CompletionSecretHash = testCompletionSecretHash()

	repo.On("GetByID", mock.Anything, unverified.ID).Return(unverified, nil)

	_, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: unverified.ID,
		Password:        "Pass1234!",
		PlanCode:        "starter",
	}, "", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "email not yet verified")
	tenantSvc.AssertNotCalled(t, "CreateTenant")
}

func TestSignupService_CompleteSignup_AlreadyCompleted_ReturnsError(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	done := verifiedRequest("jane@example.com", "personal")
	done.Completed = true

	repo.On("GetByID", mock.Anything, done.ID).Return(done, nil)

	_, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: done.ID,
		Password:        "Pass1234!",
		PlanCode:        "starter",
	}, "", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "signup already completed")
	tenantSvc.AssertNotCalled(t, "CreateTenant")
}

func TestSignupService_CompleteSignup_Expired_ReturnsError(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	expired := verifiedRequest("jane@example.com", "personal")
	expired.ExpiresAt = time.Now().Add(-1 * time.Hour)

	repo.On("GetByID", mock.Anything, expired.ID).Return(expired, nil)

	_, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: expired.ID,
		Password:        "Pass1234!",
		PlanCode:        "starter",
	}, "", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "signup request has expired")
	tenantSvc.AssertNotCalled(t, "CreateTenant")
}

func TestSignupService_CompleteSignup_SignupNotFound_ReturnsError(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	missingID := uuid.New()
	repo.On("GetByID", mock.Anything, missingID).Return(nil, pgx.ErrNoRows)

	_, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: missingID,
		Password:        "Pass1234!",
		PlanCode:        "starter",
	}, "", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "signup request not found")
}

func TestSignupService_CompleteSignup_ConsumerTenantMissing(t *testing.T) {
	// Renamed + repurposed (2026-05-22): the legacy
	// TestSignupService_CompleteSignup_TenantCreateError tested the
	// per-user "personal-XXXX" CreateTenant failure path. That path
	// is gone — personal signups now look up the shared consumer
	// tenant (models.WellKnownTenantConsumer) via GetByID instead.
	// This test exercises the equivalent "consumer tenant missing"
	// failure surface that arises when bootstrapConsumerTenant fails
	// or has not been run yet, exercising the explicit error branch
	// in provisionTenant.
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	req := verifiedRequest("jane@example.com", "personal")

	repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)
	// GetByID returns nil tenant — bootstrap-not-run case.
	tenantSvc.On("GetByID", mock.Anything, models.WellKnownTenantConsumer).
		Return((*models.Tenant)(nil), nil)

	_, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: req.ID,
		Password:        "Pass1234!",
		PlanCode:        "starter",
	}, "", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "consumer tenant")
	userSvc.AssertNotCalled(t, "CreateForSignup")
}

func TestSignupService_CompleteSignup_UserCreateError(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	req := verifiedRequest("jane@example.com", "personal")
	consumerTenant := &models.Tenant{
		ID:   models.WellKnownTenantConsumer,
		Slug: "hexxlock-consumer",
		Type: models.TenantType("consumer"),
	}

	repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)
	tenantSvc.On("GetByID", mock.Anything, models.WellKnownTenantConsumer).
		Return(consumerTenant, nil)
	userSvc.On("CreateForSignup", mock.Anything, mock.AnythingOfType("*models.CreateUserRequest"), mock.Anything).
		Return(nil, errors.New("email already registered"))

	_, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: req.ID,
		Password:        "Pass1234!",
		PlanCode:        "starter",
	}, "", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "create user")
	repo.AssertNotCalled(t, "MarkCompleted")
}

func TestSignupService_CompleteSignup_MarkCompletedError_NonFatal(t *testing.T) {
	t.Parallel()

	repo := &mockSignupRequestRepo{}
	emailSvc := &mockSignupEmailSender{}
	tenantSvc := &mockSignupTenantCreator{}
	userSvc := &mockSignupUserCreator{}
	lookup := &mockSignupUserLookup{}

	svc := buildSignupService(repo, emailSvc, tenantSvc, userSvc, lookup)

	req := verifiedRequest("jane@example.com", "personal")
	consumerTenant := &models.Tenant{
		ID:   models.WellKnownTenantConsumer,
		Slug: "hexxlock-consumer",
		Type: models.TenantType("consumer"),
	}
	user := fakeUser(consumerTenant.ID, req.Email)

	repo.On("GetByID", mock.Anything, req.ID).Return(req, nil)
	tenantSvc.On("GetByID", mock.Anything, models.WellKnownTenantConsumer).Return(consumerTenant, nil)
	userSvc.On("CreateForSignup", mock.Anything, mock.AnythingOfType("*models.CreateUserRequest"), mock.Anything).Return(user, nil)
	// MarkCompleted fails — must be non-fatal.
	repo.On("MarkCompleted", mock.Anything, req.ID, consumerTenant.ID, user.ID).Return(errors.New("db error"))

	result, err := svc.CompleteSignup(context.Background(), &models.CompleteSignupInput{CompletionSecret: testCompletionSecret,
		SignupRequestID: req.ID,
		Password:        "Pass1234!",
		PlanCode:        "starter",
	}, "", "")

	require.NoError(t, err, "MarkCompleted failure must not abort CompleteSignup")
	assert.Equal(t, user.ID, result.User.ID)
}

// ---------------------------------------------------------------------------
// generateSlug
// ---------------------------------------------------------------------------

func TestGenerateSlug(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple words", testAcmeCorpOrg, testTenantSlugAcme},
		{"special chars stripped", "My  Company!", "my-company"},
		{"numbers kept", "Company 42", "company-42"},
		{"dashes preserved", "already-slugged", "already-slugged"},
		{"leading trailing dashes trimmed", "-bad-slug-", "bad-slug"},
		{"only special chars", "!@#$%", ""},
		{"empty string", "", ""},
		{"accents folded", "Héllo Wörld", "hello-world"},
		{"turkish a.s.", "Çağrı Yazılım A.Ş.", "cagri-yazilim"},
		{"turkish ltd sti", "Kaya İnşaat San. ve Tic. Ltd. Şti.", "kaya-insaat"},
		{"dotted capital I", "İstanbul", "istanbul"},
		{"dotless capital I", "IŞIK Mobilya", "isik-mobilya"},
		{"too short falls back", "AB", ""},
		{"reserved gets suffix", "Admin", "admin-2"},
		{"suffix only is kept", "Ltd", "ltd"},
		{"80 chars cut at hyphen", strings.Repeat("abcdefghi ", 8), "abcdefghi-abcdefghi-abcdefghi-abcdefghi"},
		{"long single word hard cut", strings.Repeat("x", 80), strings.Repeat("x", 40)},
		{"multiple consecutive spaces", "A   B   C", "a-b-c"},
	}

	for _, tt := range tests {
		tt := tt // capture range var
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := generateSlug(tt.input)
			assert.Equal(t, tt.expected, got, "generateSlug(%q)", tt.input)
		})
	}
}
