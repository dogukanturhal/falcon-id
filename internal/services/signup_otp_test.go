// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func otpSetup(t *testing.T) (*SignupService, *memSignupRepo, *models.SignupRequest) {
	t.Helper()
	svc, repo, _ := newContinuationSignup(t, newContinuationOAuth(t, nil))
	req, err := svc.InitiateSignup(context.Background(), personalSignup(""), "10.0.0.1", "UA")
	require.NoError(t, err)
	return svc, repo, req
}

func codeErr(t *testing.T, err error) string {
	t.Helper()
	var se *SignupStateError
	require.ErrorAs(t, err, &se)
	return se.Code
}

func wrongCode(real string) string {
	if real == "000000" {
		return "000001"
	}
	return "000000"
}

func TestSignupOTP_CodeFormatAndUniformity(t *testing.T) {
	const n = 20000
	counts := make([]int, 10) // leading-digit histogram
	seen := map[string]bool{}
	for i := 0; i < n; i++ {
		c, err := generateSignupCode()
		require.NoError(t, err)
		require.Regexp(t, `^[0-9]{6}$`, c)
		counts[c[0]-'0']++
		seen[c] = true
	}
	// Each leading digit should hold ~10% (2000); +-25% is ~11 sigma, so a
	// modulo-biased or truncated generator is caught, a fair one never flakes.
	for d, c := range counts {
		assert.InDelta(t, n/10, c, float64(n/10)/4, "leading digit %d", d)
	}
	assert.Greater(t, len(seen), n*9/10, "codes must not repeat like a tiny space")
}

func TestSignupOTP_OnlyHashIsStored(t *testing.T) {
	svc, repo, req := otpSetup(t)
	code := repo.mail.lastCode()
	require.Regexp(t, `^[0-9]{6}$`, code)

	row := repo.rows[req.ID]
	require.NotNil(t, row.VerificationCodeHash)
	assert.Equal(t, svc.hashVerificationCode(req.ID, code), *row.VerificationCodeHash)
	assert.NotContains(t, *row.VerificationCodeHash, code)
	assert.NotEqual(t, code, row.VerificationToken)
	assert.NotContains(t, fmt.Sprintf("%+v", *row), code+" ", "plaintext must not be on the row")
	// Bound to the request: the same code hashes differently for another row.
	assert.NotEqual(t, *row.VerificationCodeHash, svc.hashVerificationCode(uuid.New(), code))
	assert.WithinDuration(t, time.Now().Add(15*time.Minute), *row.VerificationCodeExpiresAt, time.Minute)
}

func TestSignupOTP_VerifyByIDAndByEmail_AcceptsSpacesAndDashes(t *testing.T) {
	ctx := context.Background()
	svc, repo, req := otpSetup(t)
	code := repo.mail.lastCode()
	spaced := code[:3] + " " + code[3:]
	v, err := svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{Email: " " + strings.ToUpper(req.Email) + " ", Code: spaced})
	require.NoError(t, err)
	assert.True(t, v.Verified)
	assert.NotEmpty(t, v.CompletionSecret)

	svc2, repo2, req2 := otpSetup(t)
	c2 := repo2.mail.lastCode()
	v2, err := svc2.VerifyEmail(ctx, &models.VerifySignupEmailInput{SignupID: req2.ID.String(), Code: c2[:3] + "-" + c2[3:]})
	require.NoError(t, err)
	assert.True(t, v2.Verified)
}

func TestSignupOTP_LookupRequiresEmailOrID(t *testing.T) {
	ctx := context.Background()
	svc, repo, req := otpSetup(t)
	code := repo.mail.lastCode()

	_, err := svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{Code: code})
	assert.Equal(t, "verification_code_invalid", codeErr(t, err), "code alone must never resolve a request")
	assert.False(t, repo.rows[req.ID].Verified)

	// Same code, other person's id/email: no match, and the other row is untouched.
	_, err = svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{SignupID: uuid.NewString(), Code: code})
	assert.Equal(t, "verification_code_invalid", codeErr(t, err))
	_, err = svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{Email: "nobody@downstream.com", Code: code})
	assert.Equal(t, "verification_code_invalid", codeErr(t, err))
	_, err = svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{SignupID: req.ID.String(), Code: "12ab56"})
	assert.Equal(t, "verification_code_invalid", codeErr(t, err))
}

func TestSignupOTP_ExpiredCode(t *testing.T) {
	ctx := context.Background()
	svc, repo, req := otpSetup(t)
	past := time.Now().Add(-time.Second)
	repo.rows[req.ID].VerificationCodeExpiresAt = &past
	_, err := verifyWithEmailedCode(ctx, svc, repo, req)
	assert.Equal(t, "verification_code_invalid", codeErr(t, err), "an expired code answers invalid, never expired")
	assert.False(t, repo.rows[req.ID].Verified)
}

func TestSignupOTP_FiveWrongAttemptsBurnTheCode(t *testing.T) {
	ctx := context.Background()
	svc, repo, req := otpSetup(t)
	code := repo.mail.lastCode()
	bad := wrongCode(code)

	for i := 1; i < signupCodeMaxAttempts; i++ {
		_, err := svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{SignupID: req.ID.String(), Code: bad})
		assert.Equal(t, "verification_code_invalid", codeErr(t, err), "attempt %d", i)
	}
	_, err := svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{SignupID: req.ID.String(), Code: bad})
	assert.Equal(t, "verification_attempts_exceeded", codeErr(t, err), "5th wrong attempt burns the code")

	// Even the correct code no longer works.
	_, err = verifyWithEmailedCode(ctx, svc, repo, req)
	assert.Equal(t, "verification_attempts_exceeded", codeErr(t, err))
	assert.False(t, repo.rows[req.ID].Verified)
}

func TestSignupOTP_ResendInvalidatesOldCodeAndResetsAttempts(t *testing.T) {
	ctx := context.Background()
	svc, repo, req := otpSetup(t)
	old := repo.mail.lastCode()
	for i := 0; i < signupCodeMaxAttempts; i++ {
		_, _ = svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{SignupID: req.ID.String(), Code: wrongCode(old)})
	}
	require.Equal(t, signupCodeMaxAttempts, repo.rows[req.ID].VerificationAttempts)

	again, err := svc.InitiateSignup(ctx, personalSignup(""), "10.0.0.1", "UA")
	require.NoError(t, err)
	require.Equal(t, req.ID, again.ID)
	fresh := repo.mail.lastCode()
	require.Len(t, repo.mail.codes, 2)
	assert.Equal(t, 0, repo.rows[req.ID].VerificationAttempts)

	if fresh != old {
		_, err = svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{SignupID: req.ID.String(), Code: old})
		assert.Equal(t, "verification_code_invalid", codeErr(t, err), "the old code is dead")
	}
	v, err := svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{SignupID: req.ID.String(), Code: fresh})
	require.NoError(t, err)
	assert.True(t, v.Verified)
}

func TestSignupOTP_ResendIsCapped(t *testing.T) {
	ctx := context.Background()
	svc, repo, _ := otpSetup(t)
	for i := 0; i < signupResendMaxPerHour; i++ {
		_, err := svc.InitiateSignup(ctx, personalSignup(""), "", "")
		require.NoError(t, err, "resend %d", i+1)
	}
	_, err := svc.InitiateSignup(ctx, personalSignup(""), "", "")
	assert.Equal(t, "resend_throttled", codeErr(t, err))
	assert.Len(t, repo.mail.codes, 1+signupResendMaxPerHour, "a throttled resend sends nothing")
}

func TestSignupOTP_CodeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	svc, repo, req := otpSetup(t)
	_, err := verifyWithEmailedCode(ctx, svc, repo, req)
	require.NoError(t, err)
	_, err = verifyWithEmailedCode(ctx, svc, repo, req)
	assert.Equal(t, "verification_code_invalid", codeErr(t, err), "a used code is spent")
}

func TestSignupOTP_LegacyTokenOnlyForRowsWithoutCodeHash(t *testing.T) {
	ctx := context.Background()
	svc, repo, req := otpSetup(t)

	// New rows never expose a usable token: the placeholder is rejected.
	_, err := svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{Token: repo.rows[req.ID].VerificationToken})
	require.Error(t, err)
	assert.False(t, repo.rows[req.ID].Verified)

	// A pre-deploy row (no hash) still verifies with its long token.
	legacy := &models.SignupRequest{
		ID: uuid.New(), Email: "old@downstream.com", AccountType: "personal",
		VerificationToken: strings.Repeat("ab", 32), ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, repo.Create(ctx, legacy))
	v, err := svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{Token: legacy.VerificationToken})
	require.NoError(t, err)
	assert.True(t, v.Verified)
	assert.NotEmpty(t, v.CompletionSecret)
}

func TestSignupOTP_LegacyPendingRowGetsCodeOnResend(t *testing.T) {
	ctx := context.Background()
	svc, repo, _ := newContinuationSignup(t, newContinuationOAuth(t, nil))
	legacy := &models.SignupRequest{
		ID: uuid.New(), Email: "jane@downstream.com", AccountType: "personal",
		VerificationToken: strings.Repeat("cd", 32), ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, repo.Create(ctx, legacy))
	_, err := svc.InitiateSignup(ctx, personalSignup(""), "", "")
	require.NoError(t, err)
	assert.Len(t, repo.mail.codes, 1)
	require.NotNil(t, repo.rows[legacy.ID].VerificationCodeHash)
	// The old token is dead once the row has a code.
	_, err = svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{Token: legacy.VerificationToken})
	require.Error(t, err)
}

var testOTPKey = []byte("services-test-signup-otp-key-32b")

func TestSignupOTP_HashIsKeyedHMAC(t *testing.T) {
	id := uuid.New()
	a := &SignupService{otpKey: testOTPKey}
	b := &SignupService{otpKey: []byte("another-key-another-key-another!")}
	assert.Equal(t, a.hashVerificationCode(id, "123456"), a.hashVerificationCode(id, "123456"))
	assert.NotEqual(t, a.hashVerificationCode(id, "123456"), b.hashVerificationCode(id, "123456"), "a different key must not verify")
	assert.NotEqual(t, a.hashVerificationCode(id, "123456"), a.hashVerificationCode(uuid.New(), "123456"), "bound to the request id")

	k1, err := DeriveSignupOTPKey("salt-one")
	require.NoError(t, err)
	k2, err := DeriveSignupOTPKey("salt-two")
	require.NoError(t, err)
	assert.Len(t, k1, 32)
	assert.NotEqual(t, k1, k2)
}

func TestSignupOTP_RowCapHoldsAcrossResends(t *testing.T) {
	ctx := context.Background()
	svc, repo, req := otpSetup(t)
	attempts := 0
	// Burn 5 wrong guesses per code, resending between codes, until the row cap.
	for round := 0; round < 3; round++ {
		bad := wrongCode(repo.mail.lastCode())
		for i := 0; i < signupCodeMaxAttempts; i++ {
			_, err := svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{SignupID: req.ID.String(), Code: bad})
			attempts++
			require.Error(t, err)
			if attempts == signupCodeRowMaxFailures {
				assert.Equal(t, "verification_attempts_exceeded", codeErr(t, err))
			} else {
				_ = codeErr(t, err)
			}
		}
		if round < 2 {
			_, err := svc.InitiateSignup(ctx, personalSignup(""), "", "")
			require.NoError(t, err, "resend %d", round+1)
		}
	}
	assert.Equal(t, signupCodeRowMaxFailures, repo.rows[req.ID].VerificationFailedTotal)

	// A further resend is refused and the correct code of the last send no longer helps.
	_, err := svc.InitiateSignup(ctx, personalSignup(""), "", "")
	assert.Equal(t, "resend_throttled", codeErr(t, err))
	_, err = verifyWithEmailedCode(ctx, svc, repo, req)
	assert.Equal(t, "verification_attempts_exceeded", codeErr(t, err))
	assert.False(t, repo.rows[req.ID].Verified)
}

func TestSignupOTP_ConcurrentCorrectSubmitsExactlyOneSucceeds(t *testing.T) {
	ctx := context.Background()
	svc, repo, req := otpSetup(t)
	code := repo.mail.lastCode()
	const n = 8
	var ok int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := svc.VerifyEmail(ctx, &models.VerifySignupEmailInput{SignupID: req.ID.String(), Code: code}); err == nil {
				atomic.AddInt32(&ok, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	assert.EqualValues(t, 1, ok, "single-use code: exactly one concurrent submit wins")
}

func TestSignupOTP_VerifiedNotCompleted_ResendThenVerifyRotatesSecret(t *testing.T) {
	ctx := context.Background()
	svc, repo, req := otpSetup(t)
	first, err := verifyWithEmailedCode(ctx, svc, repo, req)
	require.NoError(t, err)
	oldSecret := first.CompletionSecret
	require.NotEmpty(t, oldSecret)
	sentBefore := len(repo.mail.codes)

	// Same email signs up again: recovery sends a fresh code to the mailbox.
	again, err := svc.InitiateSignup(ctx, personalSignup(""), "", "")
	require.NoError(t, err)
	assert.Equal(t, req.ID, again.ID)
	assert.Len(t, repo.mail.codes, sentBefore+1)

	second, err := verifyWithEmailedCode(ctx, svc, repo, req)
	require.NoError(t, err)
	require.NotEmpty(t, second.CompletionSecret)
	assert.NotEqual(t, oldSecret, second.CompletionSecret)

	_, err = svc.CompleteSignup(ctx, completeInput(req.ID, oldSecret), "", "")
	require.Error(t, err, "the old completion secret must stop working")
	assert.False(t, repo.rows[req.ID].Completed)
	_, err = svc.CompleteSignup(ctx, completeInput(req.ID, second.CompletionSecret), "", "")
	require.NoError(t, err)
}

func TestSignupOTP_ResendUsesStoredFirstName(t *testing.T) {
	ctx := context.Background()
	svc, repo, _ := otpSetup(t)
	in := personalSignup("")
	in.FirstName = "Mallory"
	_, err := svc.InitiateSignup(ctx, in, "", "")
	require.NoError(t, err)
	assert.Equal(t, "Jane", repo.mail.lastName())
}
