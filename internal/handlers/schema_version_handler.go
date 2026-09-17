// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// schemaVersionService is the interface satisfied by *services.SchemaVersionTracker.
// Using an interface here enables mocking in tests without importing the service package.
type schemaVersionService interface {
	GetVersions(ctx context.Context) ([]services.TenantSchemaVersion, error)
	GetVersionForTenant(ctx context.Context, tenantID uuid.UUID, dbName string) (*services.TenantSchemaVersion, error)
	GetDriftReport(ctx context.Context, latestVersion int) ([]services.TenantSchemaVersion, error)
}

// SchemaVersionHandler exposes tenant schema version and drift detection endpoints.
type SchemaVersionHandler struct {
	svc    schemaVersionService
	logger *zap.Logger
}

// NewSchemaVersionHandler creates a SchemaVersionHandler backed by the given service.
func NewSchemaVersionHandler(svc schemaVersionService, log *zap.Logger) *SchemaVersionHandler {
	if log == nil {
		log = zap.NewNop()
	}
	return &SchemaVersionHandler{svc: svc, logger: log}
}

// ListVersions handles GET /api/v1/platform/schema-versions.
//
// @Summary List all tenant schema versions
// @Description Returns schema version records for every registered tenant database
// @Tags Schema Versioning
// @Produce json
// @Success 200 {object} map[string]interface{} "List of tenant schema versions"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/schema-versions [get]
func (h *SchemaVersionHandler) ListVersions(c *gin.Context) {
	versions, err := h.svc.GetVersions(c.Request.Context())
	if err != nil {
		h.logger.Error("SchemaVersionHandler.ListVersions failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list schema versions"})
		return
	}
	if versions == nil {
		versions = []services.TenantSchemaVersion{}
	}
	c.JSON(http.StatusOK, gin.H{
		"schema_versions": versions,
		"total":           len(versions),
	})
}

// GetDriftReport handles GET /api/v1/platform/schema-versions/drift.
//
// Query parameters:
//   - latest_version (required): the current global migration version to compare against.
//
// @Summary Tenant schema drift report
// @Description Returns all tenant databases whose schema version is behind the specified latest version
// @Tags Schema Versioning
// @Produce json
// @Param latest_version query int true "Global latest migration version"
// @Success 200 {object} map[string]interface{} "List of drifted tenant databases"
// @Failure 400 {object} map[string]string "Missing or invalid latest_version"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/schema-versions/drift [get]
func (h *SchemaVersionHandler) GetDriftReport(c *gin.Context) {
	latestStr := c.Query("latest_version")
	if latestStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "latest_version query parameter is required"})
		return
	}
	latestVersion, err := strconv.Atoi(latestStr)
	if err != nil || latestVersion < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "latest_version must be a non-negative integer"})
		return
	}

	drifted, err := h.svc.GetDriftReport(c.Request.Context(), latestVersion)
	if err != nil {
		h.logger.Error("SchemaVersionHandler.GetDriftReport failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate drift report"})
		return
	}
	if drifted == nil {
		drifted = []services.TenantSchemaVersion{}
	}
	c.JSON(http.StatusOK, gin.H{
		"drifted_databases": drifted,
		"total":             len(drifted),
		"latest_version":    latestVersion,
	})
}

// GetTenantVersions handles GET /api/v1/platform/schema-versions/tenant/:tenant_id.
//
// Query parameters:
//   - database_name (optional): filter to a specific database name.
//
// @Summary Get schema version for a tenant
// @Description Returns schema version record(s) for the specified tenant
// @Tags Schema Versioning
// @Produce json
// @Param tenant_id path string true "Tenant UUID"
// @Param database_name query string false "Filter by database name"
// @Success 200 {object} map[string]interface{} "Tenant schema version(s)"
// @Failure 400 {object} map[string]string "Invalid tenant ID"
// @Failure 404 {object} map[string]string "No schema version record found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/schema-versions/tenant/{tenant_id} [get]
func (h *SchemaVersionHandler) GetTenantVersions(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}

	dbName := c.Query("database_name")
	if dbName != "" {
		// Return a single record for the specific (tenant, db) pair.
		v, err := h.svc.GetVersionForTenant(c.Request.Context(), tenantID, dbName)
		if err != nil {
			h.logger.Error("SchemaVersionHandler.GetTenantVersions failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve schema version"})
			return
		}
		if v == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "no schema version record found for this tenant and database"})
			return
		}
		c.JSON(http.StatusOK, v)
		return
	}

	// No database_name filter — return all versions for this tenant by scanning
	// the full set and filtering in application code.  This is safe because
	// each tenant realistically has a small number of registered databases.
	all, err := h.svc.GetVersions(c.Request.Context())
	if err != nil {
		h.logger.Error("SchemaVersionHandler.GetTenantVersions (all) failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve schema versions"})
		return
	}

	var filtered []services.TenantSchemaVersion
	for _, v := range all {
		if v.TenantID == tenantID {
			filtered = append(filtered, v)
		}
	}
	if filtered == nil {
		filtered = []services.TenantSchemaVersion{}
	}

	c.JSON(http.StatusOK, gin.H{
		"tenant_id":       tenantID,
		"schema_versions": filtered,
		"total":           len(filtered),
	})
}
