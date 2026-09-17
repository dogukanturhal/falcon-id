// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// SchemaVersionHandler relies entirely on route-level RequireAuth +
// RequirePlatformAdmin middleware for the auth gate — the handler
// itself reads no user context. These tests cover the handler's
// own input-validation surface (UUID parsing, required + range-bounded
// query params). Service-side behaviour is covered by the existing
// schema_version_tracker tests.
//
// Constructor takes a service interface (schemaVersionService) but
// these tests use nil — every assertion below verifies the handler
// short-circuits BEFORE the service call, so the nil deref would
// surface as a test failure rather than a silent skip.

func TestSchemaVersionHandler_GetDriftReport_MissingLatestVersion(t *testing.T) {
	h := NewSchemaVersionHandler(nil, zap.NewNop())

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, err := http.NewRequest(http.MethodGet, "/schema-versions/drift", nil)
	require.NoError(t, err)
	c.Request = req

	h.GetDriftReport(c)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "latest_version")
}

func TestSchemaVersionHandler_GetDriftReport_InvalidLatestVersion(t *testing.T) {
	h := NewSchemaVersionHandler(nil, zap.NewNop())
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, err := http.NewRequest(http.MethodGet, "/schema-versions/drift?latest_version=not-a-number", nil)
	require.NoError(t, err)
	c.Request = req
	h.GetDriftReport(c)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSchemaVersionHandler_GetDriftReport_NegativeLatestVersion(t *testing.T) {
	h := NewSchemaVersionHandler(nil, zap.NewNop())
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, err := http.NewRequest(http.MethodGet, "/schema-versions/drift?latest_version=-1", nil)
	require.NoError(t, err)
	c.Request = req
	h.GetDriftReport(c)
	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"negative version is meaningless — handler must reject before reaching the service")
}

func TestSchemaVersionHandler_GetTenantVersions_InvalidUUID(t *testing.T) {
	h := NewSchemaVersionHandler(nil, zap.NewNop())
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, err := http.NewRequest(http.MethodGet, "/schema-versions/tenant/not-a-uuid", nil)
	require.NoError(t, err)
	c.Request = req
	c.Params = gin.Params{{Key: "tenant_id", Value: "not-a-uuid"}}
	h.GetTenantVersions(c)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
