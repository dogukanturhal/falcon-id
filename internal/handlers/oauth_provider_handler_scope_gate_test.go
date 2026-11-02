// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
)

// The tenant-admin surface must refuse privileged scopes; the trusted
// provisioner route must get past the scope gate (the nil service then
// panics, which gin.Recovery turns into a 500).
func TestOAuthClientAdmin_PrivilegedScopeGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewOAuthProviderHandler(nil, nil, zap.NewNop())
	body := `{"name":"svc client","grant_types":["client_credentials"],"scopes":["service:register"]}`

	for _, tc := range []struct {
		name    string
		trusted bool
		denied  bool
	}{{"tenant admin", false, true}, {"trusted provisioner", true, false}} {
		{
			// UpdateClient loads the client through the service before the
			// gate, so only Create is exercised at handler level; Update
			// shares ValidateTenantClientScopes (service test).
			route := struct{ method, path string }{http.MethodPost, "/clients"}
			t.Run(tc.name, func(t *testing.T) {
				r := gin.New()
				r.Use(gin.Recovery(), func(c *gin.Context) {
					c.Set(middleware.CtxKeyTrustedRegistration, tc.trusted)
					c.Next()
				})
				r.POST("/clients", h.CreateClient)
				w := httptest.NewRecorder()
				req := httptest.NewRequest(route.method, route.path, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				r.ServeHTTP(w, req)
				if tc.denied {
					assert.Equal(t, http.StatusForbidden, w.Code)
					assert.Contains(t, w.Body.String(), "invalid_scope")
				} else {
					assert.NotEqual(t, http.StatusForbidden, w.Code)
				}
			})
		}
	}
}
