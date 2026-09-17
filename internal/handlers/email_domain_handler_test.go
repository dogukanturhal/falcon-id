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

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// emailDomainServiceFake – in-process test double
// ---------------------------------------------------------------------------

type emailDomainServiceFake struct {
	listResp     []*models.EmailDomainRegistry
	listErr      error
	getResp      *models.EmailDomainRegistry
	getErr       error
	registerResp *models.EmailDomainRegistry
	registerErr  error
	verifyErr    error
	deleteErr    error
	updateResp   *models.EmailDomainRegistry
	updateErr    error
}

func (f *emailDomainServiceFake) ListDomains(_ context.Context, _ uuid.UUID) ([]*models.EmailDomainRegistry, error) {
	return f.listResp, f.listErr
}

func (f *emailDomainServiceFake) GetDomain(_ context.Context, _ uuid.UUID) (*models.EmailDomainRegistry, error) {
	return f.getResp, f.getErr
}

func (f *emailDomainServiceFake) RegisterDomain(_ context.Context, _ uuid.UUID, _ *models.CreateEmailDomainRequest) (*models.EmailDomainRegistry, error) {
	return f.registerResp, f.registerErr
}

func (f *emailDomainServiceFake) VerifyDomain(_ context.Context, _ uuid.UUID) error {
	return f.verifyErr
}

func (f *emailDomainServiceFake) DeleteDomain(_ context.Context, _ uuid.UUID) error {
	return f.deleteErr
}

func (f *emailDomainServiceFake) UpdateDomain(_ context.Context, _ uuid.UUID, _ bool) (*models.EmailDomainRegistry, error) {
	return f.updateResp, f.updateErr
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newEmailDomainTestRouter(svc *emailDomainServiceFake) *gin.Engine {
	r := gin.New()
	h := NewEmailDomainHandler(svc)

	tenant := r.Group("/api/v1/admin/tenants/:tenant_id")
	tenant.GET("/domains", h.ListDomains)
	tenant.POST("/domains", h.RegisterDomain)
	tenant.GET("/domains/:domain_id", h.GetDomain)
	tenant.POST("/domains/:domain_id/verify", h.VerifyDomain)
	tenant.DELETE("/domains/:domain_id", h.DeleteDomain)

	return r
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

func performEmailDomainRequest(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, path, nil)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decodeEmailDomainBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

func buildDomainEntry(tenantID uuid.UUID, domain string) *models.EmailDomainRegistry {
	token := "abc123verifytoken"
	now := time.Now()
	return &models.EmailDomainRegistry{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Domain:             domain,
		IsVerified:         false,
		VerificationToken:  &token,
		VerificationMethod: string(models.VerificationMethodDNSTXT),
		AutoEnroll:         false,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

// ---------------------------------------------------------------------------
// Tests: ListDomains (GET /api/v1/admin/tenants/:tenant_id/domains)
// ---------------------------------------------------------------------------

func TestEmailDomainHandler_ListDomains_Success(t *testing.T) {
	tenantID := uuid.New()
	svc := &emailDomainServiceFake{
		listResp: []*models.EmailDomainRegistry{
			buildDomainEntry(tenantID, "example.com"),
			buildDomainEntry(tenantID, "acme.io"),
		},
	}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains"
	w := performEmailDomainRequest(r, http.MethodGet, path, "")

	assert.Equal(t, http.StatusOK, w.Code)
	body := decodeEmailDomainBody(t, w)
	assert.Equal(t, true, body["success"])
	data, ok := body["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, data, 2)
}

func TestEmailDomainHandler_ListDomains_Empty(t *testing.T) {
	tenantID := uuid.New()
	svc := &emailDomainServiceFake{listResp: []*models.EmailDomainRegistry{}}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains"
	w := performEmailDomainRequest(r, http.MethodGet, path, "")

	assert.Equal(t, http.StatusOK, w.Code)
	body := decodeEmailDomainBody(t, w)
	assert.Equal(t, true, body["success"])
}

func TestEmailDomainHandler_ListDomains_InvalidTenantID(t *testing.T) {
	r := newEmailDomainTestRouter(&emailDomainServiceFake{})
	w := performEmailDomainRequest(r, http.MethodGet, "/api/v1/admin/tenants/not-a-uuid/domains", "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEmailDomainHandler_ListDomains_ServiceError(t *testing.T) {
	tenantID := uuid.New()
	svc := &emailDomainServiceFake{listErr: errors.New("db error")}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains"
	w := performEmailDomainRequest(r, http.MethodGet, path, "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	body := decodeEmailDomainBody(t, w)
	assert.Equal(t, false, body["success"])
}

// ---------------------------------------------------------------------------
// Tests: GetDomain (GET /api/v1/admin/tenants/:tenant_id/domains/:domain_id)
// ---------------------------------------------------------------------------

func TestEmailDomainHandler_GetDomain_Success(t *testing.T) {
	tenantID := uuid.New()
	domainID := uuid.New()
	entry := buildDomainEntry(tenantID, "example.com")
	entry.ID = domainID

	svc := &emailDomainServiceFake{getResp: entry}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains/" + domainID.String()
	w := performEmailDomainRequest(r, http.MethodGet, path, "")

	assert.Equal(t, http.StatusOK, w.Code)
	body := decodeEmailDomainBody(t, w)
	assert.Equal(t, true, body["success"])
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, domainID.String(), data["id"])
}

func TestEmailDomainHandler_GetDomain_NotFound(t *testing.T) {
	tenantID := uuid.New()
	domainID := uuid.New()
	svc := &emailDomainServiceFake{getResp: nil, getErr: nil}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains/" + domainID.String()
	w := performEmailDomainRequest(r, http.MethodGet, path, "")

	assert.Equal(t, http.StatusNotFound, w.Code)
	body := decodeEmailDomainBody(t, w)
	assert.Equal(t, false, body["success"])
}

func TestEmailDomainHandler_GetDomain_ServiceError(t *testing.T) {
	tenantID := uuid.New()
	domainID := uuid.New()
	svc := &emailDomainServiceFake{getErr: errors.New("db error")}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains/" + domainID.String()
	w := performEmailDomainRequest(r, http.MethodGet, path, "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestEmailDomainHandler_GetDomain_InvalidDomainID(t *testing.T) {
	tenantID := uuid.New()
	r := newEmailDomainTestRouter(&emailDomainServiceFake{})
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains/bad-uuid"
	w := performEmailDomainRequest(r, http.MethodGet, path, "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: RegisterDomain (POST /api/v1/admin/tenants/:tenant_id/domains)
// ---------------------------------------------------------------------------

func TestEmailDomainHandler_RegisterDomain_Success(t *testing.T) {
	tenantID := uuid.New()
	entry := buildDomainEntry(tenantID, "new.com")

	svc := &emailDomainServiceFake{registerResp: entry}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains"
	body := `{"domain":"new.com","auto_enroll":true}`
	w := performEmailDomainRequest(r, http.MethodPost, path, body)

	assert.Equal(t, http.StatusCreated, w.Code)
	resp := decodeEmailDomainBody(t, w)
	assert.Equal(t, true, resp["success"])
	assert.NotNil(t, resp["data"])
}

func TestEmailDomainHandler_RegisterDomain_MalformedJSON(t *testing.T) {
	tenantID := uuid.New()
	r := newEmailDomainTestRouter(&emailDomainServiceFake{})
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains"
	w := performEmailDomainRequest(r, http.MethodPost, path, `not-json`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEmailDomainHandler_RegisterDomain_MissingRequiredField(t *testing.T) {
	tenantID := uuid.New()
	r := newEmailDomainTestRouter(&emailDomainServiceFake{})
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains"
	// domain field is required via binding tag
	w := performEmailDomainRequest(r, http.MethodPost, path, `{"auto_enroll":false}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEmailDomainHandler_RegisterDomain_InvalidTenantID(t *testing.T) {
	r := newEmailDomainTestRouter(&emailDomainServiceFake{})
	w := performEmailDomainRequest(r, http.MethodPost, "/api/v1/admin/tenants/bad/domains", `{"domain":"x.com"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEmailDomainHandler_RegisterDomain_ServiceError_Conflict(t *testing.T) {
	tenantID := uuid.New()
	svc := &emailDomainServiceFake{registerErr: errors.New("domain already exists for another tenant")}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains"
	body := `{"domain":"taken.com"}`
	w := performEmailDomainRequest(r, http.MethodPost, path, body)

	// "already" maps to Conflict (409) via HandleError.
	assert.Equal(t, http.StatusConflict, w.Code)
	resp := decodeEmailDomainBody(t, w)
	assert.Equal(t, false, resp["success"])
}

func TestEmailDomainHandler_RegisterDomain_ServiceError_InvalidDomain(t *testing.T) {
	tenantID := uuid.New()
	svc := &emailDomainServiceFake{registerErr: errors.New("invalid domain format")}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains"
	body := `{"domain":"nodot"}`
	w := performEmailDomainRequest(r, http.MethodPost, path, body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: VerifyDomain (POST /api/v1/admin/tenants/:tenant_id/domains/:domain_id/verify)
// ---------------------------------------------------------------------------

func TestEmailDomainHandler_VerifyDomain_Success(t *testing.T) {
	tenantID := uuid.New()
	domainID := uuid.New()

	svc := &emailDomainServiceFake{}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains/" + domainID.String() + "/verify"
	w := performEmailDomainRequest(r, http.MethodPost, path, "")

	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeEmailDomainBody(t, w)
	assert.Equal(t, true, resp["success"])
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "domain verified", data["message"])
}

func TestEmailDomainHandler_VerifyDomain_InvalidDomainID(t *testing.T) {
	tenantID := uuid.New()
	r := newEmailDomainTestRouter(&emailDomainServiceFake{})
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains/bad-uuid/verify"
	w := performEmailDomainRequest(r, http.MethodPost, path, "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEmailDomainHandler_VerifyDomain_InvalidTenantID(t *testing.T) {
	domainID := uuid.New()
	r := newEmailDomainTestRouter(&emailDomainServiceFake{})
	path := "/api/v1/admin/tenants/bad/domains/" + domainID.String() + "/verify"
	w := performEmailDomainRequest(r, http.MethodPost, path, "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEmailDomainHandler_VerifyDomain_NotFound(t *testing.T) {
	tenantID := uuid.New()
	domainID := uuid.New()
	svc := &emailDomainServiceFake{verifyErr: errors.New("domain not found: record not found")}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains/" + domainID.String() + "/verify"
	w := performEmailDomainRequest(r, http.MethodPost, path, "")

	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeEmailDomainBody(t, w)
	assert.Equal(t, false, resp["success"])
}

func TestEmailDomainHandler_VerifyDomain_ServiceError(t *testing.T) {
	tenantID := uuid.New()
	domainID := uuid.New()
	svc := &emailDomainServiceFake{verifyErr: errors.New("internal db error")}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains/" + domainID.String() + "/verify"
	w := performEmailDomainRequest(r, http.MethodPost, path, "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: DeleteDomain (DELETE /api/v1/admin/tenants/:tenant_id/domains/:domain_id)
// ---------------------------------------------------------------------------

func TestEmailDomainHandler_DeleteDomain_Success(t *testing.T) {
	tenantID := uuid.New()
	domainID := uuid.New()

	svc := &emailDomainServiceFake{}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains/" + domainID.String()
	w := performEmailDomainRequest(r, http.MethodDelete, path, "")

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestEmailDomainHandler_DeleteDomain_InvalidDomainID(t *testing.T) {
	tenantID := uuid.New()
	r := newEmailDomainTestRouter(&emailDomainServiceFake{})
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains/bad-uuid"
	w := performEmailDomainRequest(r, http.MethodDelete, path, "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEmailDomainHandler_DeleteDomain_InvalidTenantID(t *testing.T) {
	domainID := uuid.New()
	r := newEmailDomainTestRouter(&emailDomainServiceFake{})
	path := "/api/v1/admin/tenants/bad/domains/" + domainID.String()
	w := performEmailDomainRequest(r, http.MethodDelete, path, "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEmailDomainHandler_DeleteDomain_ServiceError(t *testing.T) {
	tenantID := uuid.New()
	domainID := uuid.New()
	svc := &emailDomainServiceFake{deleteErr: errors.New("db error")}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains/" + domainID.String()
	w := performEmailDomainRequest(r, http.MethodDelete, path, "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := decodeEmailDomainBody(t, w)
	assert.Equal(t, false, resp["success"])
}

func TestEmailDomainHandler_DeleteDomain_NotFound(t *testing.T) {
	tenantID := uuid.New()
	domainID := uuid.New()
	svc := &emailDomainServiceFake{deleteErr: errors.New("not found")}
	r := newEmailDomainTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/domains/" + domainID.String()
	w := performEmailDomainRequest(r, http.MethodDelete, path, "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}
