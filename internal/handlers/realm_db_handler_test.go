// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRealmSlugBody = `{"realm_slug":"acme"}`

// ─────────────────────────────────────────────────────────────
// Mock provisioner
// ─────────────────────────────────────────────────────────────

type mockProvisioner struct {
	provisionFn    func(ctx context.Context, realmID uuid.UUID, realmSlug string, preferredRegion string) (*RealmDatabase, error)
	decommissionFn func(ctx context.Context, realmID uuid.UUID) error
	healthFn       func(ctx context.Context, realmID uuid.UUID) (*RealmDatabaseHealth, error)
}

func (m *mockProvisioner) ProvisionDatabase(ctx context.Context, realmID uuid.UUID, realmSlug string, preferredRegion string) (*RealmDatabase, error) {
	if m.provisionFn != nil {
		return m.provisionFn(ctx, realmID, realmSlug, preferredRegion)
	}
	return &RealmDatabase{
		ID:           uuid.New(),
		RealmID:      realmID,
		DatabaseName: "db_" + realmSlug,
		Host:         "localhost",
		Port:         5432,
		Status:       "active",
		CreatedAt:    time.Now(),
	}, nil
}

func (m *mockProvisioner) DecommissionDatabase(ctx context.Context, realmID uuid.UUID) error {
	if m.decommissionFn != nil {
		return m.decommissionFn(ctx, realmID)
	}
	return nil
}

func (m *mockProvisioner) GetDatabaseHealth(ctx context.Context, realmID uuid.UUID) (*RealmDatabaseHealth, error) {
	if m.healthFn != nil {
		return m.healthFn(ctx, realmID)
	}
	return &RealmDatabaseHealth{
		RealmID: realmID,
		Status:  "ok",
	}, nil
}

// mockRealmLookup implements RealmLookup for tests.
type mockRealmLookup struct {
	getSlugFn func(ctx context.Context, realmID uuid.UUID) (string, error)
}

func (m *mockRealmLookup) GetSlugByID(ctx context.Context, realmID uuid.UUID) (string, error) {
	if m.getSlugFn != nil {
		return m.getSlugFn(ctx, realmID)
	}
	return "default-slug", nil
}

// ─────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────

func newTestRealmDBHandler(p RealmDatabaseProvisioner, rl RealmLookup) *RealmDBHandler {
	return NewRealmDBHandler(p, rl)
}

// ─────────────────────────────────────────────────────────────
// ProvisionDatabase
// ─────────────────────────────────────────────────────────────

func TestProvisionDatabase_InvalidRealmID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newTestRealmDBHandler(&mockProvisioner{}, &mockRealmLookup{})
	router := gin.New()
	router.POST("/platform/realms/:id/provision-database", h.ProvisionDatabase)

	body := testRealmSlugBody
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/platform/realms/not-a-uuid/provision-database", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid realm ID", resp["error"])
}

func TestProvisionDatabase_MissingSlug(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()
	// Pass nil realmLookup so that an empty slug in the body is not resolved
	// and the handler returns 400 as expected.
	h := newTestRealmDBHandler(&mockProvisioner{}, nil)
	router := gin.New()
	router.POST("/platform/realms/:id/provision-database", h.ProvisionDatabase)

	// realm_slug is required; omit it to trigger binding error
	body := `{}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/platform/realms/"+realmID.String()+"/provision-database", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["error"])
}

func TestProvisionDatabase_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()
	dbID := uuid.New()

	p := &mockProvisioner{
		provisionFn: func(_ context.Context, rid uuid.UUID, _ string, _ string) (*RealmDatabase, error) {
			return &RealmDatabase{
				ID:           dbID,
				RealmID:      rid,
				DatabaseName: "db_acme",
				Host:         "pg-host",
				Port:         5432,
				Status:       "active",
				CreatedAt:    time.Now(),
			}, nil
		},
	}

	h := newTestRealmDBHandler(p, &mockRealmLookup{})
	router := gin.New()
	router.POST("/platform/realms/:id/provision-database", h.ProvisionDatabase)

	body := testRealmSlugBody
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/platform/realms/"+realmID.String()+"/provision-database", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, dbID.String(), resp["id"])
	assert.Equal(t, realmID.String(), resp["realm_id"])
	assert.Equal(t, "db_acme", resp["database_name"])
	assert.Equal(t, "pg-host", resp["host"])
	assert.Equal(t, "active", resp["status"])
}

func TestProvisionDatabase_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()
	p := &mockProvisioner{
		provisionFn: func(_ context.Context, _ uuid.UUID, _ string, _ string) (*RealmDatabase, error) {
			return nil, errors.New("database already exists")
		},
	}

	h := newTestRealmDBHandler(p, &mockRealmLookup{})
	router := gin.New()
	router.POST("/platform/realms/:id/provision-database", h.ProvisionDatabase)

	body := testRealmSlugBody
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/platform/realms/"+realmID.String()+"/provision-database", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ─────────────────────────────────────────────────────────────
// DecommissionDatabase
// ─────────────────────────────────────────────────────────────

func TestDecommissionDatabase_InvalidRealmID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newTestRealmDBHandler(&mockProvisioner{}, &mockRealmLookup{})
	router := gin.New()
	router.DELETE("/platform/realms/:id/database", h.DecommissionDatabase)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/platform/realms/not-a-uuid/database", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid realm ID", resp["error"])
}

func TestDecommissionDatabase_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()
	var capturedID uuid.UUID

	p := &mockProvisioner{
		decommissionFn: func(_ context.Context, rid uuid.UUID) error {
			capturedID = rid
			return nil
		},
	}

	h := newTestRealmDBHandler(p, &mockRealmLookup{})
	router := gin.New()
	router.DELETE("/platform/realms/:id/database", h.DecommissionDatabase)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/platform/realms/"+realmID.String()+"/database", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, realmID, capturedID)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "database decommissioned", resp["message"])
}

func TestDecommissionDatabase_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()
	p := &mockProvisioner{
		decommissionFn: func(_ context.Context, _ uuid.UUID) error {
			return errors.New("database not found")
		},
	}

	h := newTestRealmDBHandler(p, &mockRealmLookup{})
	router := gin.New()
	router.DELETE("/platform/realms/:id/database", h.DecommissionDatabase)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/platform/realms/"+realmID.String()+"/database", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ─────────────────────────────────────────────────────────────
// GetDatabaseHealth
// ─────────────────────────────────────────────────────────────

func TestGetDatabaseHealth_InvalidRealmID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newTestRealmDBHandler(&mockProvisioner{}, &mockRealmLookup{})
	router := gin.New()
	router.GET("/platform/realms/:id/database-health", h.GetDatabaseHealth)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/platform/realms/not-a-uuid/database-health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid realm ID", resp["error"])
}

func TestGetDatabaseHealth_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	realmID := uuid.New()
	h := newTestRealmDBHandler(&mockProvisioner{}, &mockRealmLookup{})
	router := gin.New()
	router.GET("/platform/realms/:id/database-health", h.GetDatabaseHealth)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/platform/realms/"+realmID.String()+"/database-health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, realmID.String(), resp["realm_id"])
	assert.Equal(t, "ok", resp["status"])
}
