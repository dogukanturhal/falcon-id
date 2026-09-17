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
)

// TenantMeteringHandler also relies on route-level
// RequireAuth + RequirePlatformAdmin for the auth gate. These tests
// cover the handler's own validation surface — query-param parsing
// and the nil-monitor graceful-degradation path.

func TestTenantMeteringHandler_GetTenantResources_NilMonitor_ReturnsEmpty(t *testing.T) {
	// Locks the graceful-degradation contract: when the monitor is
	// nil (Redis unavailable), the snapshot list must surface as 200
	// + empty, NOT 500. The platform-admin UI's "resource usage"
	// page renders correctly even in degraded mode this way.
	h := NewTenantMeteringHandler(nil, nil)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, err := http.NewRequest(http.MethodGet, "/tenant-resources", nil)
	require.NoError(t, err)
	c.Request = req

	h.GetTenantResources(c)
	assert.Equal(t, http.StatusOK, rec.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	snapshots, ok := body["snapshots"].([]interface{})
	require.True(t, ok)
	assert.Len(t, snapshots, 0)
}

func TestTenantMeteringHandler_GetTenantMetering_RequiresTenantID(t *testing.T) {
	h := NewTenantMeteringHandler(nil, nil)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, err := http.NewRequest(http.MethodGet, "/metering/tenant/", nil)
	require.NoError(t, err)
	c.Request = req
	// Empty tenant_id param simulates a misconfigured route call —
	// the handler must reject before reaching the DB.
	c.Params = gin.Params{{Key: "tenant_id", Value: ""}}

	h.GetTenantMetering(c)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestParseMeteringTimeRange_InvalidFrom(t *testing.T) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, _ := http.NewRequest(http.MethodGet, "/metering/summary?from=not-a-timestamp", nil)
	c.Request = req
	_, _, ok := parseMeteringTimeRange(c)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "invalid_from", body["error"])
}

func TestParseMeteringTimeRange_InvalidTo(t *testing.T) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, _ := http.NewRequest(http.MethodGet, "/metering/summary?to=garbage", nil)
	c.Request = req
	_, _, ok := parseMeteringTimeRange(c)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "invalid_to", body["error"])
}

func TestParseMeteringTimeRange_InvertedRange(t *testing.T) {
	// `to` before `from` is nonsensical; the handler must reject
	// before invoking the DB query (which would produce an empty
	// result + waste a roundtrip + a misleading 200 response).
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, _ := http.NewRequest(http.MethodGet,
		"/metering/summary?from=2026-05-21T12:00:00Z&to=2026-05-21T11:00:00Z", nil)
	c.Request = req
	_, _, ok := parseMeteringTimeRange(c)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "invalid_range", body["error"])
}

func TestParseMeteringTimeRange_DefaultsTo24Hours(t *testing.T) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, _ := http.NewRequest(http.MethodGet, "/metering/summary", nil)
	c.Request = req
	from, to, ok := parseMeteringTimeRange(c)
	require.True(t, ok)
	delta := to.Sub(from)
	// Allow a few ms of slop — defaults are "now" and "now-24h"
	// computed via separate time.Now() calls in the impl.
	assert.InDelta(t, 24*60*60, delta.Seconds(), 1.0)
}
