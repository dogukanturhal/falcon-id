// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

func TestPolicyHandler_RejectsCustomRego(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewPolicyHandler(nil, nil) // nil repo: rejection must happen before any DB access

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(middleware.CurrentUserKey, &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New()})
	})
	r.POST("/policies", h.Create)
	r.PUT("/policies/:id", h.Update)

	cases := []struct{ method, path, body string }{
		{http.MethodPost, "/policies", `{"name":"p","effect":"deny","rego_code":"package x"}`},
		{http.MethodPut, "/policies/" + uuid.NewString(), `{"rego_code":"package x"}`},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body)))
		assert.Equal(t, http.StatusBadRequest, w.Code, tc.method)
		assert.Contains(t, w.Body.String(), "custom_rego_unsupported", tc.method)
	}
}
