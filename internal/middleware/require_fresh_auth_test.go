// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

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

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TestRequireFreshAuth_RFC9470_Behaviour exercises the three branches of
// the step-up gate. Wire format MUST match RFC 9470 §4 so off-the-shelf
// OAuth client libraries (Auth0 SDK, oauth2-proxy, modern OIDC SPA libs)
// can detect the step-up requirement without bespoke parsing.
func TestRequireFreshAuth_RFC9470_Behaviour(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := &AuthMiddleware{config: authTestConfig()}
	const maxAge = 5 * time.Minute

	type tc struct {
		name           string
		user           *models.CurrentUser // nil = unauthenticated
		wantStatus     int
		wantError      string
		wantHasMaxAge  bool
		wantHasWWWAuth bool
	}

	now := time.Now()
	cases := []tc{
		{
			name: "fresh access token within max_age — pass",
			user: &models.CurrentUser{
				ID:         uuid.New(),
				AuthMethod: models.AuthMethodAccessToken,
				AuthTime:   now.Add(-1 * time.Minute).Unix(),
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "fresh idp_session cookie within max_age — pass (cookie-auth allowed when AuthTime is recent)",
			user: &models.CurrentUser{
				ID:         uuid.New(),
				AuthMethod: models.AuthMethodIdpSession,
				AuthTime:   now.Add(-30 * time.Second).Unix(),
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "stale auth (10 minutes old, max_age=5m) — 401 with RFC 9470 challenge",
			user: &models.CurrentUser{
				ID:         uuid.New(),
				AuthMethod: models.AuthMethodAccessToken,
				AuthTime:   now.Add(-10 * time.Minute).Unix(),
			},
			wantStatus:     http.StatusUnauthorized,
			wantError:      "insufficient_user_authentication",
			wantHasMaxAge:  true,
			wantHasWWWAuth: true,
		},
		{
			name: "AuthTime zero (pre-RFC-9470 token / legacy session) — fail closed",
			user: &models.CurrentUser{
				ID:         uuid.New(),
				AuthMethod: models.AuthMethodAccessToken,
				AuthTime:   0,
			},
			wantStatus:     http.StatusUnauthorized,
			wantError:      "insufficient_user_authentication",
			wantHasMaxAge:  true,
			wantHasWWWAuth: true,
		},
		{
			name:       "no CurrentUser in context — 401 plain unauthorized (auth missing)",
			user:       nil,
			wantStatus: http.StatusUnauthorized,
			wantError:  "unauthorized",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := gin.New()
			r.Use(func(ctx *gin.Context) {
				if c.user != nil {
					ctx.Set(CurrentUserKey, c.user)
				}
			})
			r.POST("/sensitive", m.RequireFreshAuth(maxAge), func(ctx *gin.Context) {
				ctx.JSON(http.StatusOK, gin.H{"ok": true})
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/sensitive", nil)
			r.ServeHTTP(w, req)

			require.Equal(t, c.wantStatus, w.Code)

			if c.wantError != "" {
				var body map[string]any
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
				assert.Equal(t, c.wantError, body["error"], "JSON body 'error' must signal the step-up error class")
			}

			if c.wantHasMaxAge {
				var body map[string]any
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
				// JSON numbers decode as float64
				assert.InEpsilon(t, maxAge.Seconds(), body["max_age"], 0.001, "JSON body must carry max_age in seconds")
			}

			if c.wantHasWWWAuth {
				ww := w.Header().Get("WWW-Authenticate")
				assert.True(t, strings.HasPrefix(ww, "Bearer "), "WWW-Authenticate must use Bearer scheme per RFC 9470 §4")
				assert.Contains(t, ww, `error="insufficient_user_authentication"`, "challenge error class")
				assert.Contains(t, ww, "max_age=", "challenge must carry max_age parameter")
			}
		})
	}
}
