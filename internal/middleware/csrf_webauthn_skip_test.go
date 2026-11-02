// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestCSRF_ExemptPath_WebAuthnConditionalBegin_SkipsValidation locks the
// pre-auth WebAuthn skip list. These endpoints run before any IdP
// session exists, so the session-bound double-submit token cannot exist
// (CSRFRedisKeyPrefix:<sessionID> has no entry — there is no sessionID).
// Anti-CSRF is provided at the protocol layer by the WebAuthn assertion
// itself (hardware-key-signed + origin-bound + non-replayable per W3C
// WebAuthn L3 §5.1.4) — strictly stronger than the session-bound token.
//
// Without this skip the primary-login button at id.example.com/login
// returns "csrf_validation_failed" on every passkey ceremony attempt
// (live repro 2026-05-24 immediately after frontend!92 deploy).
//
// Mirrors TestCSRF_ExemptPath_Login_SkipsValidation — same root cause
// (pre-auth state → no session-bound token possible).
func TestCSRF_ExemptPath_WebAuthnConditionalBegin_SkipsValidation(t *testing.T) {
	for _, path := range []string{
		"/api/auth/webauthn/conditional/begin",
		"/api/v1/auth/webauthn/conditional/begin",
		"/api/auth/webauthn/conditional/complete",
		"/api/v1/auth/webauthn/conditional/complete",
		"/api/auth/webauthn/login/begin",
		"/api/v1/auth/webauthn/login/begin",
		"/api/auth/webauthn/login/finish",
		"/api/v1/auth/webauthn/login/finish",
	} {
		t.Run(path, func(t *testing.T) {
			m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

			w := httptest.NewRecorder()
			_, router := gin.CreateTestContext(w)
			router.POST(path, m.CSRF(), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code,
				"pre-auth WebAuthn primary-login endpoint %q MUST skip CSRF — no session exists yet to bind a token to", path)
		})
	}
}

// TestCSRF_ExemptPath_InvitationRegister_SkipsValidation locks the pre-auth
// invitation onboarding endpoint. The invitee has no session, so no
// session-bound CSRF token can exist; the single-use invitation token is the
// credential. Regression: invited-member signup returned 403 on preview
// (2026-10-14) because the route was not on the skip list.
func TestCSRF_ExemptPath_InvitationRegister_SkipsValidation(t *testing.T) {
	for _, path := range []string{
		"/api/auth/invitations/register",
		"/api/v1/auth/invitations/register",
	} {
		t.Run(path, func(t *testing.T) {
			m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

			w := httptest.NewRecorder()
			_, router := gin.CreateTestContext(w)
			router.POST(path, m.CSRF(), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "invitation register %q MUST skip CSRF", path)
		})
	}
}
