// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

type witnessTOTPStub struct {
	beginErr, finishErr error
	gotSession          string
	gotState            string
	gotCode             string
}

func (s *witnessTOTPStub) BeginTOTP(_ context.Context, _ *models.CurrentUser, sess, _, _, state string) (string, time.Duration, error) {
	s.gotSession, s.gotState = sess, state
	return "cid", 120 * time.Second, s.beginErr
}

func (s *witnessTOTPStub) FinishTOTP(_ context.Context, _ *models.CurrentUser, _ string, _ string, code, _, _ string) (*services.FinishTOTPResult, error) {
	s.gotCode = code
	if s.finishErr != nil {
		return nil, s.finishErr
	}
	now := time.Now()
	return &services.FinishTOTPResult{State: "st", JWS: &services.WitnessJWS{SignedJWS: "a.b.c", AdminSub: "sub", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}}, nil
}

func (s *witnessTOTPStub) Status(context.Context, *models.CurrentUser) services.WitnessTOTPStatus {
	return services.WitnessTOTPStatus{}
}

func witnessTOTPEngine(stub *witnessTOTPStub, withUser bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewWitnessTOTPHandler(stub, zap.NewNop())
	r.Use(func(c *gin.Context) {
		if withUser {
			c.Set(middleware.CurrentUserKey, &models.CurrentUser{ID: uuid.New()})
			c.Set("session_id", uuid.MustParse(witnessTestSessionID))
		}
		c.Next()
	})
	r.POST("/begin", h.Begin)
	r.POST("/finish", h.Finish)
	return r
}

func doJSON(r *gin.Engine, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return w
}

func TestWitnessTOTPHandler_BeginFinishHappyPath(t *testing.T) {
	stub := &witnessTOTPStub{}
	r := witnessTOTPEngine(stub, true)

	w := doJSON(r, "/begin", `{"device_uuid":"`+witnessTestDeviceUUID+`","ek_pubkey_hash":"`+witnessTestEKHash+`","state":"st"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"challenge_id":"cid","expires_in":120}`, w.Body.String())
	assert.Equal(t, witnessTestSessionID, stub.gotSession)
	assert.Equal(t, "st", stub.gotState)

	w = doJSON(r, "/finish", `{"challenge_id":"cid","code":"123456"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp witnessFinishResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "a.b.c", resp.SignedJWS)
	assert.Equal(t, "st", resp.State)
	assert.Equal(t, "123456", stub.gotCode)
}

func TestWitnessTOTPHandler_MapsRefusals(t *testing.T) {
	r := witnessTOTPEngine(&witnessTOTPStub{beginErr: &services.WitnessError{Status: 403, Code: services.WitnessErrHasPasskey, Message: "passkey"}}, true)
	w := doJSON(r, "/begin", `{"device_uuid":"x","ek_pubkey_hash":"y"}`)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), services.WitnessErrHasPasskey)

	r = witnessTOTPEngine(&witnessTOTPStub{finishErr: &services.WitnessError{Status: 401, Code: services.WitnessErrCodeInvalid, Message: "invalid code", RemainingAttempts: 2}}, true)
	w = doJSON(r, "/finish", `{"challenge_id":"cid","code":"000000"}`)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), `"remaining_attempts":2`)
}

func TestWitnessTOTPHandler_Validation(t *testing.T) {
	r := witnessTOTPEngine(&witnessTOTPStub{}, true)
	assert.Equal(t, http.StatusBadRequest, doJSON(r, "/begin", `{}`).Code)
	assert.Equal(t, http.StatusBadRequest, doJSON(r, "/finish", `{"challenge_id":"cid"}`).Code)
	r = witnessTOTPEngine(&witnessTOTPStub{}, false)
	assert.Equal(t, http.StatusUnauthorized, doJSON(r, "/begin", `{"device_uuid":"x","ek_pubkey_hash":"y"}`).Code)
	assert.Equal(t, http.StatusUnauthorized, doJSON(r, "/finish", `{"challenge_id":"c","code":"1"}`).Code)
}
