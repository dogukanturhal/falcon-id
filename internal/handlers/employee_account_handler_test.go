// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
)

func employeeAccountRouter(h *handlers.TeamInvitationHandler, scoped bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/internal/v1/tenants")
	if scoped {
		g.Use(middleware.RequireScope("iam:employee-accounts:write"))
	}
	g.POST("/:id/employee-accounts", h.ProvisionEmployeeAccount)
	g.PUT("/:id/employee-accounts/:userId/access-expiry", h.SetEmployeeAccessExpiry)
	return r
}

func doJSON(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// Without the iam:employee-accounts:write scope neither route reaches the handler.
func TestEmployeeAccounts_WithoutScope_Forbidden(t *testing.T) {
	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	r := employeeAccountRouter(h, true)
	tenant := uuid.NewString()
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/internal/v1/tenants/" + tenant + "/employee-accounts", `{"email":"a@b.co"}`},
		{http.MethodPut, "/internal/v1/tenants/" + tenant + "/employee-accounts/" + uuid.NewString() + "/access-expiry", `{"expiresAt":null}`},
	} {
		w := doJSON(r, c.method, c.path, c.body)
		assert.Contains(t, []int{http.StatusForbidden, http.StatusUnauthorized}, w.Code, c.path)
	}
}

// An unwired handler fails closed (503) instead of panicking or creating a user with a seat.
func TestEmployeeAccounts_Unwired_503(t *testing.T) {
	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	r := employeeAccountRouter(h, false)
	tenant := uuid.NewString()
	w := doJSON(r, http.MethodPost, "/internal/v1/tenants/"+tenant+"/employee-accounts", `{"email":"a@b.co"}`)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	w = doJSON(r, http.MethodPut, "/internal/v1/tenants/"+tenant+"/employee-accounts/"+uuid.NewString()+"/access-expiry", `{"expiresAt":null}`)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}
