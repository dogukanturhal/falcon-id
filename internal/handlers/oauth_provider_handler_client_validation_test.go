// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

type prodTenantLookup struct{}

func (prodTenantLookup) GetByID(_ context.Context, id uuid.UUID) (*models.Tenant, error) {
	return &models.Tenant{ID: id, Type: models.TenantType("customer")}, nil
}

// A client-input redirect_uri violation must surface as 400
// invalid_redirect_uri (RFC 7591 §3.2.2), not 500.
func TestOAuthClientAdmin_CreateClient_InvalidRedirectURIIs400(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, err := services.NewOAuthProviderService(nil, nil, &config.Config{ServicePort: "8080"})
	require.NoError(t, err)
	svc.SetTenantTypeLookup(prodTenantLookup{})
	h := NewOAuthProviderHandler(svc, nil, zap.NewNop())

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(middleware.TenantIDKey, uuid.New())
		c.Next()
	})
	r.POST("/clients", h.CreateClient)

	body := `{"name":"web","grant_types":["authorization_code"],"response_types":["code"],"redirect_uris":["http://app.example.com/cb"],"scopes":["openid"],"logo_url":"https://app.example.com/l.png"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_redirect_uri", resp["error"])
	assert.Contains(t, resp["error_description"], "https scheme")
}
