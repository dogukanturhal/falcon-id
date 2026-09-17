// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// IAMDevicePreRegRepository is the narrow interface the pre-registration
// handler depends on. Satisfied by *repositories.IAMDevicePreRegRepository in
// production and a test double in unit tests.
type IAMDevicePreRegRepository interface {
	BulkInsert(ctx context.Context, tenantID uuid.UUID, createdBy string, inputs []repositories.PreRegInput) (int, []repositories.PreRegRowError, error)
	GetByEKPubkeyHash(ctx context.Context, hash string) (repositories.IAMDevicePreRegRow, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]repositories.IAMDevicePreRegRow, error)
	DeleteByID(ctx context.Context, tenantID, id uuid.UUID) error
}

// IAMDevicePreRegHandler serves the corporate device pre-registration endpoints
// (the zero-touch CORP allowlist). All endpoints live under
// /internal/v1/iam-devices/ and are protected by ServiceAuth (the jess
// controller is the sole caller — directly for the attest-time corp-asset
// check, and on behalf of a human admin in jess-web for the management CRUD).
//
// See migration 0007_iam_device_preregistrations.sql for the trust model.
type IAMDevicePreRegHandler struct {
	repo IAMDevicePreRegRepository
}

// NewIAMDevicePreRegHandler constructs a handler wired to the given repository.
func NewIAMDevicePreRegHandler(repo IAMDevicePreRegRepository) *IAMDevicePreRegHandler {
	return &IAMDevicePreRegHandler{repo: repo}
}

// ─── Request / Response shapes ───────────────────────────────────────────────

// corpAssetResponse is returned by GET
// /internal/v1/iam-devices/corp-asset/by-ek-hash/:hash. It is the attest-time
// allowlist check jess calls. A device that is not pre-registered yields
// is_corporate_asset=false (200, not 404) — "not a corporate asset" is a valid
// answer, not an error.
type corpAssetResponse struct {
	IsCorporateAsset bool   `json:"is_corporate_asset"`
	TenantID         string `json:"tenant_id,omitempty"`
	AssetTag         string `json:"asset_tag,omitempty"`
	SerialNumber     string `json:"serial_number,omitempty"`
}

// preRegDeviceInput is one device in a bulk pre-registration request.
type preRegDeviceInput struct {
	EKPubkeyHash string `json:"ek_pubkey_hash,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	AssetTag     string `json:"asset_tag,omitempty"`
	Model        string `json:"model,omitempty"`
	Note         string `json:"note,omitempty"`
}

// bulkPreRegRequest is the JSON body for POST
// /internal/v1/iam-devices/pre-registrations/bulk.
type bulkPreRegRequest struct {
	TenantID  string              `json:"tenant_id"`
	CreatedBy string              `json:"created_by,omitempty"`
	Devices   []preRegDeviceInput `json:"devices"`
}

// bulkPreRegResponse reports partial success: how many NEW rows were inserted
// (re-imports of known devices are silently skipped) plus per-row errors.
type bulkPreRegResponse struct {
	Imported int                           `json:"imported"`
	Errors   []repositories.PreRegRowError `json:"errors"`
}

// preRegView is the JSON projection of a pre-registration row for the list API.
type preRegView struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	EKPubkeyHash string `json:"ek_pubkey_hash,omitempty"` // hex-encoded
	SerialNumber string `json:"serial_number,omitempty"`
	AssetTag     string `json:"asset_tag,omitempty"`
	Model        string `json:"model,omitempty"`
	Note         string `json:"note,omitempty"`
	CreatedBy    string `json:"created_by,omitempty"`
	CreatedAt    string `json:"created_at"` // RFC3339
}

// ─── Handlers ────────────────────────────────────────────────────────────────

// CorpAssetByEKHash handles GET
// /internal/v1/iam-devices/corp-asset/by-ek-hash/:hash — the jess attest-time
// allowlist check. Returns {is_corporate_asset:false} (200) for an unknown EK.
func (h *IAMDevicePreRegHandler) CorpAssetByEKHash(c *gin.Context) {
	hash := c.Param("hash")
	if len(hash) != 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_hash", "details": "hash must be 64 hex characters"})
		return
	}
	if _, err := hex.DecodeString(hash); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_hash", "details": "hash is not valid hex"})
		return
	}

	row, err := h.repo.GetByEKPubkeyHash(c.Request.Context(), hash)
	if err != nil {
		if isNotFoundError(err) {
			c.JSON(http.StatusOK, corpAssetResponse{IsCorporateAsset: false})
			return
		}
		logger.Error("IAMDevicePreRegHandler.CorpAssetByEKHash: repository error",
			zap.Error(err), zap.String("ek_hash", hash), zap.String("remote_addr", GetClientIP(c)))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup_failed"})
		return
	}

	resp := corpAssetResponse{IsCorporateAsset: true, TenantID: row.TenantID.String()}
	if row.AssetTag != nil {
		resp.AssetTag = *row.AssetTag
	}
	if row.SerialNumber != nil {
		resp.SerialNumber = *row.SerialNumber
	}
	c.JSON(http.StatusOK, resp)
}

// BulkPreRegister handles POST /internal/v1/iam-devices/pre-registrations/bulk.
// Idempotent: re-importing a known device is a no-op (not counted, not an
// error). Per-row validation failures are reported, never abort the batch.
func (h *IAMDevicePreRegHandler) BulkPreRegister(c *gin.Context) {
	var req bulkPreRegRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_body", "details": err.Error()})
		return
	}
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_tenant_id", "details": err.Error()})
		return
	}
	if len(req.Devices) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no_devices", "details": "devices must not be empty"})
		return
	}

	inputs := make([]repositories.PreRegInput, len(req.Devices))
	for i, d := range req.Devices {
		inputs[i] = repositories.PreRegInput{
			EKPubkeyHash: d.EKPubkeyHash,
			SerialNumber: d.SerialNumber,
			AssetTag:     d.AssetTag,
			Model:        d.Model,
			Note:         d.Note,
		}
	}

	inserted, rowErrs, err := h.repo.BulkInsert(c.Request.Context(), tenantID, req.CreatedBy, inputs)
	if err != nil {
		logger.Error("IAMDevicePreRegHandler.BulkPreRegister: repository error",
			zap.Error(err), zap.String("tenant_id", req.TenantID), zap.String("remote_addr", GetClientIP(c)))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "import_failed"})
		return
	}
	if rowErrs == nil {
		rowErrs = []repositories.PreRegRowError{}
	}
	c.JSON(http.StatusOK, bulkPreRegResponse{Imported: inserted, Errors: rowErrs})
}

// List handles GET /internal/v1/iam-devices/pre-registrations?tenant_id=<uuid>.
func (h *IAMDevicePreRegHandler) List(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Query("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_tenant_id", "details": "tenant_id query param must be a UUID"})
		return
	}

	rows, err := h.repo.ListByTenant(c.Request.Context(), tenantID)
	if err != nil {
		logger.Error("IAMDevicePreRegHandler.List: repository error",
			zap.Error(err), zap.String("tenant_id", tenantID.String()), zap.String("remote_addr", GetClientIP(c)))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list_failed"})
		return
	}

	views := make([]preRegView, len(rows))
	for i, row := range rows {
		v := preRegView{
			ID:        row.ID.String(),
			TenantID:  row.TenantID.String(),
			CreatedAt: row.CreatedAt.UTC().Format(time.RFC3339),
		}
		if len(row.EKPubkeyHash) > 0 {
			v.EKPubkeyHash = hex.EncodeToString(row.EKPubkeyHash)
		}
		if row.SerialNumber != nil {
			v.SerialNumber = *row.SerialNumber
		}
		if row.AssetTag != nil {
			v.AssetTag = *row.AssetTag
		}
		if row.Model != nil {
			v.Model = *row.Model
		}
		if row.Note != nil {
			v.Note = *row.Note
		}
		if row.CreatedBy != nil {
			v.CreatedBy = *row.CreatedBy
		}
		views[i] = v
	}
	c.JSON(http.StatusOK, views)
}

// Delete handles DELETE
// /internal/v1/iam-devices/pre-registrations/:id?tenant_id=<uuid>. Tenant-scoped.
func (h *IAMDevicePreRegHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_id", "details": "id path param must be a UUID"})
		return
	}
	tenantID, err := uuid.Parse(c.Query("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_tenant_id", "details": "tenant_id query param must be a UUID"})
		return
	}

	if err := h.repo.DeleteByID(c.Request.Context(), tenantID, id); err != nil {
		if isNotFoundError(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "pre_registration_not_found"})
			return
		}
		logger.Error("IAMDevicePreRegHandler.Delete: repository error",
			zap.Error(err), zap.String("id", id.String()), zap.String("remote_addr", GetClientIP(c)))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete_failed"})
		return
	}
	c.Status(http.StatusNoContent)
}
