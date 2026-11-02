// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

const (
	contClientID    = "acmeapp-web"
	contRedirectURI = "https://example.com/api/auth/oidc-callback"
	contValid       = "/oauth/authorize?response_type=code&client_id=acmeapp-web&redirect_uri=https%3A%2F%2Fexample.com%2Fapi%2Fauth%2Foidc-callback&state=abc"
	contDefaultApp  = "https://example.com/api/auth/oidc-start?continue=/onboarding"
)

func newContinuationOAuth(t *testing.T, mutate func(*models.OAuthClient)) *OAuthProviderService {
	t.Helper()
	client := buildActiveOAuthClient(uuid.New())
	client.ClientID = contClientID
	client.RedirectURIs = []string{contRedirectURI}
	client.IsFirstParty = true
	if mutate != nil {
		mutate(client)
	}
	repo := &MockOAuthClientRepo{}
	repo.On("GetByClientID", mock.Anything, contClientID).Return(client, nil)
	repo.On("GetByClientID", mock.Anything, mock.Anything).Return(nil, repositories.ErrOAuthClientNotFound)
	return newTestOAuthProviderService(t, repo, &fixedUserRepo{})
}

func TestParseAuthorizeContinuation_Shape(t *testing.T) {
	valid := []string{
		"/oauth/authorize",
		"/oauth/authorize?client_id=a",
		contValid,
	}
	for _, raw := range valid {
		_, err := ParseAuthorizeContinuation(raw)
		assert.NoError(t, err, raw)
	}

	invalid := map[string]string{
		"empty":                "",
		"other path":           "/oauth/token?client_id=a",
		"prefix extension":     "/oauth/authorize-evil?client_id=a",
		"sub path":             "/oauth/authorize/../../admin",
		"dot segment":          "/oauth/./authorize",
		"encoded slash":        "/oauth/authorize%2f..%2fadmin",
		"absolute":             "https://evil.example/oauth/authorize?client_id=a",
		"protocol relative":    "//evil.example/oauth/authorize",
		"scheme only":          "javascript:alert(1)",
		"backslash":            "/oauth/authorize\\@evil.example",
		"fragment":             "/oauth/authorize?client_id=a#frag",
		"newline":              "/oauth/authorize?client_id=a\nSet-Cookie: x=y",
		"userinfo":             "//user@evil.example/oauth/authorize",
		"bad query escape":     "/oauth/authorize?client_id=%zz",
		"leading space":        " /oauth/authorize",
		"over length":          "/oauth/authorize?x=" + strings.Repeat("a", MaxAuthorizeContinuationLen),
		"query smuggled path":  "/oauth/authorizeX",
		"case variant":         "/OAUTH/authorize?client_id=a",
		"nul byte":             "/oauth/authorize?client_id=a\x00",
		"relative no leading/": "oauth/authorize",
	}
	for name, raw := range invalid {
		_, err := ParseAuthorizeContinuation(raw)
		assert.ErrorIs(t, err, ErrInvalidAuthorizeContinuation, name)
	}
}

func TestValidateAuthorizeContinuation_ChecksClientAndRedirectURI(t *testing.T) {
	ctx := context.Background()

	t.Run("registered active client and redirect_uri", func(t *testing.T) {
		assert.NoError(t, newContinuationOAuth(t, nil).ValidateAuthorizeContinuation(ctx, contValid))
	})
	t.Run("inactive client", func(t *testing.T) {
		svc := newContinuationOAuth(t, func(c *models.OAuthClient) { c.IsActive = false })
		assert.ErrorIs(t, svc.ValidateAuthorizeContinuation(ctx, contValid), ErrInvalidAuthorizeContinuation)
	})
	t.Run("third-party client is not a signup landing", func(t *testing.T) {
		svc := newContinuationOAuth(t, func(c *models.OAuthClient) { c.IsFirstParty = false })
		assert.ErrorIs(t, svc.ValidateAuthorizeContinuation(ctx, contValid), ErrInvalidAuthorizeContinuation)
	})
	t.Run("redirect_uri not registered for the client", func(t *testing.T) {
		raw := "/oauth/authorize?client_id=acmeapp-web&redirect_uri=https%3A%2F%2Fevil.example%2Fcb"
		assert.ErrorIs(t, newContinuationOAuth(t, nil).ValidateAuthorizeContinuation(ctx, raw), ErrInvalidAuthorizeContinuation)
	})
	t.Run("unknown client", func(t *testing.T) {
		raw := "/oauth/authorize?client_id=nobody&redirect_uri=" + contRedirectURI
		assert.ErrorIs(t, newContinuationOAuth(t, nil).ValidateAuthorizeContinuation(ctx, raw), ErrInvalidAuthorizeContinuation)
	})
	t.Run("missing client_id or redirect_uri", func(t *testing.T) {
		svc := newContinuationOAuth(t, nil)
		assert.ErrorIs(t, svc.ValidateAuthorizeContinuation(ctx, "/oauth/authorize"), ErrInvalidAuthorizeContinuation)
		assert.ErrorIs(t, svc.ValidateAuthorizeContinuation(ctx, "/oauth/authorize?client_id=acmeapp-web"), ErrInvalidAuthorizeContinuation)
	})
}

// memSignupRepo keeps signup requests in memory so a test can drive
// initiate -> verify -> complete with nothing but the persisted row, i.e. with
// no browser-side state at all.
type memSignupRepo struct {
	rows map[uuid.UUID]*models.SignupRequest
	mail *stubSignupEmail // set by newContinuationSignup: holds the emailed codes
	// resend state per request (cooldown is not simulated; only the cap).
	resends    map[uuid.UUID]int
	maxResends int
	mu         sync.Mutex
}

func newMemSignupRepo() *memSignupRepo {
	return &memSignupRepo{rows: map[uuid.UUID]*models.SignupRequest{}, resends: map[uuid.UUID]int{}, maxResends: signupResendMaxPerHour}
}

func (m *memSignupRepo) Create(_ context.Context, r *models.SignupRequest) error {
	cp := *r
	m.rows[r.ID] = &cp
	return nil
}

func (m *memSignupRepo) GetByToken(_ context.Context, token string) (*models.SignupRequest, error) {
	for _, r := range m.rows {
		if r.VerificationToken == token && !r.Completed && r.VerificationCodeHash == nil {
			cp := *r
			return &cp, nil
		}
	}
	return nil, errors.New("not found")
}

func (m *memSignupRepo) GetByID(_ context.Context, id uuid.UUID) (*models.SignupRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rows[id]; ok {
		cp := *r
		return &cp, nil
	}
	return nil, pgx.ErrNoRows
}

func (m *memSignupRepo) GetPendingByEmail(_ context.Context, email string) (*models.SignupRequest, error) {
	for _, r := range m.rows {
		if r.Email == email && !r.Completed {
			cp := *r
			return &cp, nil
		}
	}
	return nil, errors.New("none")
}

func (m *memSignupRepo) ReserveVerificationResend(_ context.Context, id uuid.UUID, _, _ time.Duration, max, maxFailedTotal int, requireUnverified bool) (bool, error) {
	r := m.rows[id]
	if r == nil || r.Completed || r.VerificationFailedTotal >= maxFailedTotal || (requireUnverified && r.Verified) || m.resends[id] >= max {
		return false, nil
	}
	m.resends[id]++
	return true, nil
}

func (m *memSignupRepo) SetVerificationCode(_ context.Context, id uuid.UUID, hash string, exp time.Time) error {
	r := m.rows[id]
	r.VerificationCodeHash, r.VerificationCodeExpiresAt, r.VerificationAttempts = &hash, &exp, 0
	return nil
}

func (m *memSignupRepo) ClaimVerificationAttempt(_ context.Context, id uuid.UUID, max, maxFailedTotal int) (string, time.Time, int, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.rows[id]
	if r == nil || r.Completed || r.VerificationCodeHash == nil || r.VerificationAttempts >= max ||
		r.VerificationFailedTotal >= maxFailedTotal || !r.VerificationCodeExpiresAt.After(time.Now()) {
		return "", time.Time{}, 0, false, nil
	}
	r.VerificationAttempts++
	r.VerificationFailedTotal++
	return *r.VerificationCodeHash, *r.VerificationCodeExpiresAt, r.VerificationAttempts, true, nil
}

func (m *memSignupRepo) ConsumeVerificationCode(_ context.Context, id uuid.UUID, hash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.rows[id]
	if r == nil || r.Completed || r.VerificationCodeHash == nil || *r.VerificationCodeHash != hash || !r.VerificationCodeExpiresAt.After(time.Now()) {
		return false, nil
	}
	r.Verified = true
	now := time.Now()
	r.VerifiedAt = &now
	r.VerificationCodeExpiresAt = &now
	if r.VerificationFailedTotal > 0 {
		r.VerificationFailedTotal--
	}
	return true, nil
}

func (m *memSignupRepo) MarkVerified(_ context.Context, id uuid.UUID) error {
	m.rows[id].Verified = true
	return nil
}

func (m *memSignupRepo) MarkCompleted(_ context.Context, id, _, _ uuid.UUID) error {
	m.rows[id].CompletionSecretHash = nil
	m.rows[id].Completed = true
	return nil
}

func (m *memSignupRepo) SetProvisionedTenant(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}

func (m *memSignupRepo) SetCompanyDetails(_ context.Context, id uuid.UUID, name, slug string) error {
	m.rows[id].CompanyName = &name
	m.rows[id].CompanySlug = nil
	if slug != "" {
		m.rows[id].CompanySlug = &slug
	}
	return nil
}

func (m *memSignupRepo) SetContinuation(_ context.Context, id uuid.UUID, c string) error {
	if m.rows[id].Continuation == nil {
		m.rows[id].Continuation = &c
	}
	return nil
}

func (m *memSignupRepo) SetCompletionSecretHash(_ context.Context, id uuid.UUID, h string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[id].CompletionSecretHash = &h
	return nil
}

func (m *memSignupRepo) CountCompletedBusinessSignupsByEmailDomain(context.Context, string) (int, error) {
	return 0, nil
}

// capturingUserCreator records the CreateUserRequest signup hands to user creation.
type capturingUserCreator struct {
	stubSignupUserCreator
	last *models.CreateUserRequest
}

func (c *capturingUserCreator) CreateForSignup(ctx context.Context, req *models.CreateUserRequest, cred *PreparedSignupCredential) (*models.User, error) {
	c.last = req
	return c.stubSignupUserCreator.CreateForSignup(ctx, req, cred)
}

func newContinuationSignup(t *testing.T, oauth *OAuthProviderService) (*SignupService, *memSignupRepo, *capturingUserCreator) {
	t.Helper()
	repo := newMemSignupRepo()
	repo.mail = &stubSignupEmail{}
	users := &capturingUserCreator{}
	svc := NewSignupService(repo, repo.mail, &stubSignupTenantCreator{}, stubTenantManagementRegistrar{}, users, &stubSignupUserLookup{}, "downstream.com", "starter", testOTPKey)
	svc.SetContinuationValidator(oauth)
	svc.SetDefaultAppURL(contDefaultApp)
	return svc, repo, users
}

// verifyWithEmailedCode verifies a request the way a person does: by the code
// that was emailed, addressed by signup id.
func verifyWithEmailedCode(ctx context.Context, svc *SignupService, repo *memSignupRepo, req *models.SignupRequest) (*models.SignupRequest, error) {
	return svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{SignupID: req.ID.String(), Code: repo.mail.lastCode()})
}

func personalSignup(continuation string) *models.CreateSignupRequestInput {
	return &models.CreateSignupRequestInput{Username: "jane", FirstName: "Jane", AccountType: "personal", Continuation: continuation}
}

func completeInput(id uuid.UUID, secret string) *models.CompleteSignupInput {
	return &models.CompleteSignupInput{SignupRequestID: id, Password: "TestPass123!", CompletionSecret: secret}
}

func TestSignupContinuation_HostileValuesAreRejectedNotStored(t *testing.T) {
	hostile := []string{
		"https://evil.example/oauth/authorize?client_id=acmeapp-web&redirect_uri=" + contRedirectURI,
		"//evil.example/oauth/authorize",
		"/oauth/authorize-evil?client_id=acmeapp-web&redirect_uri=" + contRedirectURI,
		"/oauth/authorize?client_id=acmeapp-web&redirect_uri=https%3A%2F%2Fevil.example%2Fcb",
		"/oauth/authorize?client_id=nobody&redirect_uri=" + contRedirectURI,
		"javascript:alert(1)",
	}
	for _, raw := range hostile {
		svc, repo, _ := newContinuationSignup(t, newContinuationOAuth(t, nil))
		_, err := svc.InitiateSignup(context.Background(), personalSignup(raw), "10.0.0.1", "UA")
		var stateErr *SignupStateError
		require.ErrorAs(t, err, &stateErr, raw)
		assert.Equal(t, "invalid_continuation", stateErr.Code, raw)
		assert.Empty(t, repo.rows, "nothing may be persisted for %q", raw)
	}
}

func TestSignupContinuation_RefusedWhenNoValidatorIsWired(t *testing.T) {
	repo := newMemSignupRepo()
	svc := NewSignupService(repo, &stubSignupEmail{}, &stubSignupTenantCreator{}, stubTenantManagementRegistrar{}, &stubSignupUserCreator{}, &stubSignupUserLookup{}, "downstream.com", "starter", testOTPKey)
	_, err := svc.InitiateSignup(context.Background(), personalSignup(contValid), "", "")
	var stateErr *SignupStateError
	require.ErrorAs(t, err, &stateErr)
	assert.Equal(t, "invalid_continuation", stateErr.Code)
}

func TestSignupContinuation_RoundTripsThroughVerifyAndCompleteWithoutBrowserState(t *testing.T) {
	svc, repo, users := newContinuationSignup(t, newContinuationOAuth(t, nil))
	ctx := context.Background()

	req, err := svc.InitiateSignup(ctx, personalSignup(contValid), "10.0.0.1", "UA")
	require.NoError(t, err)
	require.NotNil(t, repo.rows[req.ID].Continuation)
	assert.Equal(t, contValid, *repo.rows[req.ID].Continuation)

	// Verified from another browser: only the emailed code and the signup id.
	verified, err := verifyWithEmailedCode(ctx, svc, repo, req)
	require.NoError(t, err)

	result, err := svc.CompleteSignup(ctx, completeInput(verified.ID, verified.CompletionSecret), "10.0.0.2", "OtherBrowser")
	require.NoError(t, err)
	assert.Equal(t, contValid, result.RedirectURL)
	require.NotNil(t, users.last)
	assert.True(t, users.last.EmailVerified, "completion follows the verification link, so the mailbox is proven")
}

func TestSignupContinuation_DefaultAppURLUsedWhenNoneOrNoLongerValid(t *testing.T) {
	ctx := context.Background()

	t.Run("no continuation submitted", func(t *testing.T) {
		svc, mem, _ := newContinuationSignup(t, newContinuationOAuth(t, nil))
		req, err := svc.InitiateSignup(ctx, personalSignup(""), "", "")
		require.NoError(t, err)
		verified, err := verifyWithEmailedCode(ctx, svc, mem, req)
		require.NoError(t, err)
		result, err := svc.CompleteSignup(ctx, completeInput(verified.ID, verified.CompletionSecret), "", "")
		require.NoError(t, err)
		assert.Equal(t, contDefaultApp, result.RedirectURL)
	})

	t.Run("client deactivated between signup and completion", func(t *testing.T) {
		client := buildActiveOAuthClient(uuid.New())
		client.ClientID = contClientID
		client.RedirectURIs = []string{contRedirectURI}
		client.IsFirstParty = true
		repo := &MockOAuthClientRepo{}
		repo.On("GetByClientID", mock.Anything, contClientID).Return(client, nil)
		oauth := newTestOAuthProviderService(t, repo, &fixedUserRepo{})
		svc, mem, _ := newContinuationSignup(t, oauth)

		req, err := svc.InitiateSignup(ctx, personalSignup(contValid), "", "")
		require.NoError(t, err)
		verified, err := verifyWithEmailedCode(ctx, svc, mem, req)
		require.NoError(t, err)

		client.IsActive = false
		result, err := svc.CompleteSignup(ctx, completeInput(verified.ID, verified.CompletionSecret), "", "")
		require.NoError(t, err)
		assert.Equal(t, contDefaultApp, result.RedirectURL)
	})

	t.Run("misconfigured default is ignored", func(t *testing.T) {
		svc, _, _ := newContinuationSignup(t, newContinuationOAuth(t, nil))
		svc.SetDefaultAppURL("javascript:alert(1)")
		svc.defaultAppURL = ""
		svc.SetDefaultAppURL("not a url")
		assert.Empty(t, svc.defaultAppURL)
	})
}

func TestSignupContinuation_RepeatedSignupNeverOverwritesAStoredContinuation(t *testing.T) {
	svc, repo, _ := newContinuationSignup(t, newContinuationOAuth(t, nil))
	ctx := context.Background()

	first, err := svc.InitiateSignup(ctx, personalSignup(""), "", "")
	require.NoError(t, err)

	// A request with no continuation may gain one...
	second, err := svc.InitiateSignup(ctx, personalSignup(contValid), "", "")
	require.NoError(t, err)
	require.Equal(t, first.ID, second.ID, "the pending request is reused")
	require.NotNil(t, repo.rows[first.ID].Continuation)
	assert.Equal(t, contValid, *repo.rows[first.ID].Continuation)

	// ...but an unauthenticated repeat caller can never replace it.
	other := "/oauth/authorize?response_type=code&client_id=acmeapp-web&redirect_uri=https%3A%2F%2Fexample.com%2Fapi%2Fauth%2Foidc-callback&state=attacker"
	_, err = svc.InitiateSignup(ctx, personalSignup(other), "", "")
	require.NoError(t, err)
	assert.Equal(t, contValid, *repo.rows[first.ID].Continuation)
}

// The signup id is returned to whoever starts a signup for an address. Holding
// only the id must never let anyone complete it and own the mailbox's account.
func TestSignupCompletion_RequiresTheVerifyEmailSecret(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*SignupService, *memSignupRepo, *models.SignupRequest, string) {
		svc, repo, _ := newContinuationSignup(t, newContinuationOAuth(t, nil))
		req, err := svc.InitiateSignup(ctx, personalSignup(""), "", "")
		require.NoError(t, err)
		verified, err := verifyWithEmailedCode(ctx, svc, repo, req) // the victim enters the emailed code
		require.NoError(t, err)
		require.NotEmpty(t, verified.CompletionSecret)
		return svc, repo, verified, verified.CompletionSecret
	}
	unavailable := func(t *testing.T, err error) {
		t.Helper()
		var stateErr *SignupStateError
		require.ErrorAs(t, err, &stateErr)
		assert.Equal(t, "signup_request_unavailable", stateErr.Code)
	}

	t.Run("attacker holding only the id", func(t *testing.T) {
		svc, repo, req, _ := setup(t)
		// The attacker re-runs signup for the victim address and learns the id.
		again, err := svc.InitiateSignup(ctx, personalSignup(""), "", "")
		require.NoError(t, err)
		require.Equal(t, req.ID, again.ID)
		assert.Empty(t, again.CompletionSecret, "initiate must never return the secret")

		for _, secret := range []string{"", "guess"} {
			_, err = svc.CompleteSignup(ctx, completeInput(again.ID, secret), "", "")
			unavailable(t, err)
		}
		assert.False(t, repo.rows[req.ID].Completed)
	})

	t.Run("mismatch answers like an unknown id", func(t *testing.T) {
		svc, _, req, secret := setup(t)
		_, wrong := svc.CompleteSignup(ctx, completeInput(req.ID, secret+"x"), "", "")
		_, unknown := svc.CompleteSignup(ctx, completeInput(uuid.New(), secret), "", "")
		unavailable(t, wrong)
		unavailable(t, unknown)
		assert.Equal(t, unknown.Error(), wrong.Error())
	})

	t.Run("the right secret completes once and is not reusable", func(t *testing.T) {
		svc, repo, req, secret := setup(t)
		_, err := svc.CompleteSignup(ctx, completeInput(req.ID, secret), "", "")
		require.NoError(t, err)
		assert.Nil(t, repo.rows[req.ID].CompletionSecretHash, "cleared on completion")

		_, err = svc.CompleteSignup(ctx, completeInput(req.ID, secret), "", "")
		unavailable(t, err)
	})

	t.Run("a used code cannot be replayed to mint another secret", func(t *testing.T) {
		svc, repo, req, first := setup(t)
		_, err := verifyWithEmailedCode(ctx, svc, repo, req)
		var stateErr *SignupStateError
		require.ErrorAs(t, err, &stateErr)
		assert.Equal(t, "verification_code_invalid", stateErr.Code)

		_, err = svc.CompleteSignup(ctx, completeInput(req.ID, first), "", "")
		require.NoError(t, err, "the original secret still works")
	})

	t.Run("a request that was never verified has no secret to match", func(t *testing.T) {
		svc, _, _ := newContinuationSignup(t, newContinuationOAuth(t, nil))
		req, err := svc.InitiateSignup(ctx, personalSignup(""), "", "")
		require.NoError(t, err)
		_, err = svc.CompleteSignup(ctx, completeInput(req.ID, ""), "", "")
		unavailable(t, err)
	})
}
