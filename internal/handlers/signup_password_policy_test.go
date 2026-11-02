// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// Use the real orchestrator and validator through HTTP. Nil provisioning
// dependencies make any attempt to bypass preflight fail this test immediately.
type httpPolicyCreator struct{ policy services.SignupPasswordPolicy }

func (u httpPolicyCreator) SignupPasswordPolicy() services.SignupPasswordPolicy { return u.policy }
func (u httpPolicyCreator) PrepareSignupCredential(_ context.Context, p string) (*services.PreparedSignupCredential, error) {
	if err := u.policy.Validate(p); err != nil {
		return nil, err
	}
	return &services.PreparedSignupCredential{}, nil
}
func (u httpPolicyCreator) CreateForSignup(context.Context, *models.CreateUserRequest, *services.PreparedSignupCredential) (*models.User, error) {
	panic("unexpected user creation")
}

type httpPolicyRepo struct {
	services.SignupRequestRepo
	req *models.SignupRequest
}

func (r httpPolicyRepo) GetByID(context.Context, uuid.UUID) (*models.SignupRequest, error) {
	return r.req, nil
}

func TestSignupPolicy_DirectHTTPBypassAndPublicContract(t *testing.T) {
	p := services.SignupPasswordPolicy{Version: 1, LengthUnit: "unicode_code_points", MinLength: 12, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSpecial: true, BreachCheck: "disabled"}
	sum := sha256.Sum256([]byte("completion-secret"))
	hash := hex.EncodeToString(sum[:])
	req := &models.SignupRequest{ID: uuid.New(), Verified: true, CompletionSecretHash: &hash, AccountType: "business", ExpiresAt: time.Now().Add(time.Hour)}
	svc := services.NewSignupService(httpPolicyRepo{req: req}, nil, nil, nil, httpPolicyCreator{p}, nil, "", "", testOTPKey)
	router := newTestRouter(svc)
	router.GET("/api/v1/auth/signup/password-policy", NewSignupHandler(svc, zap.NewNop()).PasswordPolicy)
	for _, password := range []string{"", "Abcd123!", "aaaaaaaaaaaa", "Éé١😀abcd"} {
		w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/complete", signupJSONBody(t, map[string]interface{}{"signup_request_id": req.ID, "completion_secret": "completion-secret", "password": password}))
		require.Equal(t, http.StatusUnprocessableEntity, w.Code)
		body := signupDecodeJSON(t, w)
		assert.Equal(t, "password_policy_violation", body["code"])
		assert.NotEmpty(t, body["violations"])
		assert.Equal(t, float64(12), body["policy"].(map[string]interface{})["min_length"])
		assert.True(t, req.Verified)
		assert.False(t, req.Completed)
	}
	w := signupDoRequest(t, router, http.MethodGet, "/api/v1/auth/signup/password-policy", signupJSONBody(t, nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "unicode_code_points", signupDecodeJSON(t, w)["length_unit"])
}
var testOTPKey = []byte("handlers-test-signup-otp-key-32b")
