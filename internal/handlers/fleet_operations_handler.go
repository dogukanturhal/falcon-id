// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// fleetRunner is the interface satisfied by *services.FleetOperationsRunner.
type fleetRunner interface {
	RunMigrations(ctx context.Context, migrationDir string, maxConcurrent int) (*services.FleetOperationResult, error)
	RunSQL(ctx context.Context, sql string, maxConcurrent int) (*services.FleetOperationResult, error)
	RunHealthCheck(ctx context.Context, maxConcurrent int) (*services.FleetOperationResult, error)
	GetCapacityReport(ctx context.Context) ([]services.HostCapacityReport, error)
}

// FleetOperationsHandler exposes fleet-wide database operation endpoints.
// All operations require platform administrator privileges (enforced by the
// router middleware — see registerPlatformAdminRoutes).
type FleetOperationsHandler struct {
	runner fleetRunner
	log    *zap.Logger
}

// NewFleetOperationsHandler creates a handler backed by the given runner.
func NewFleetOperationsHandler(runner fleetRunner, log *zap.Logger) *FleetOperationsHandler {
	if log == nil {
		log = zap.NewNop()
	}
	return &FleetOperationsHandler{runner: runner, log: log}
}

// runMigrationsRequest is the request body for POST /fleet/migrations.
type runMigrationsRequest struct {
	MigrationDir  string `json:"migration_dir"`
	MaxConcurrent int    `json:"max_concurrent"`
}

// runSQLRequest is the request body for POST /fleet/sql.
type runSQLRequest struct {
	SQL           string `json:"sql" binding:"required"`
	MaxConcurrent int    `json:"max_concurrent"`
}

// runHealthCheckRequest is the optional request body for POST /fleet/health-check.
type runHealthCheckRequest struct {
	MaxConcurrent int `json:"max_concurrent"`
}

// RunMigrations handles POST /api/v1/platform/fleet/migrations.
//
// Runs pending migrations across all active tenant databases with bounded
// parallelism. Returns a per-database outcome report.
//
// @Summary Run fleet-wide migrations
// @Description Runs connectivity and schema-version checks across all active tenant databases
// @Tags Fleet Operations
// @Accept json
// @Produce json
// @Param body body runMigrationsRequest false "Migration parameters"
// @Success 200 {object} services.FleetOperationResult "Fleet operation result"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/fleet/migrations [post]
func (h *FleetOperationsHandler) RunMigrations(c *gin.Context) {
	var req runMigrationsRequest
	// Request body is optional; ignore bind error and use defaults.
	_ = c.ShouldBindJSON(&req)

	if req.MaxConcurrent <= 0 {
		req.MaxConcurrent = 10
	}

	h.log.Info("Fleet migrations requested",
		zap.String("migration_dir", req.MigrationDir),
		zap.Int("max_concurrent", req.MaxConcurrent),
	)

	result, err := h.runner.RunMigrations(c.Request.Context(), req.MigrationDir, req.MaxConcurrent)
	if err != nil {
		h.log.Error("FleetOperationsHandler.RunMigrations failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "fleet migrations failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

// RunSQL handles POST /api/v1/platform/fleet/sql.
//
// Executes an arbitrary SQL statement across all active tenant databases.
// Intended for ad-hoc data fixes, index creation, or schema patches that
// must be applied fleet-wide outside the normal migration pipeline.
//
// CAUTION: This endpoint executes raw SQL with platform-admin privileges.
// Audit all SQL before issuing. Destructive statements (DROP, TRUNCATE, DELETE
// without WHERE) should be tested on a single target first.
//
// @Summary Run SQL across all tenant databases
// @Description Executes a SQL statement on every active tenant database in parallel
// @Tags Fleet Operations
// @Accept json
// @Produce json
// @Param body body runSQLRequest true "SQL and concurrency parameters"
// @Success 200 {object} services.FleetOperationResult "Fleet operation result"
// @Failure 400 {object} map[string]string "Missing SQL"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/fleet/sql [post]
func (h *FleetOperationsHandler) RunSQL(c *gin.Context) {
	var req runSQLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sql field is required"})
		return
	}

	if req.MaxConcurrent <= 0 {
		req.MaxConcurrent = 5
	}

	h.log.Info("Fleet SQL operation requested",
		zap.Int("max_concurrent", req.MaxConcurrent),
		zap.Int("sql_len", len(req.SQL)),
	)

	result, err := h.runner.RunSQL(c.Request.Context(), req.SQL, req.MaxConcurrent)
	if err != nil {
		h.log.Error("FleetOperationsHandler.RunSQL failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "fleet SQL operation failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

// RunHealthCheck handles POST /api/v1/platform/fleet/health-check.
//
// Checks connectivity and basic health of all active tenant databases.
// Returns a per-database status report with latency information.
//
// @Summary Fleet-wide database health check
// @Description Checks connectivity for every active tenant database in parallel
// @Tags Fleet Operations
// @Accept json
// @Produce json
// @Param body body runHealthCheckRequest false "Concurrency parameters"
// @Success 200 {object} services.FleetOperationResult "Fleet health check result"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/fleet/health-check [post]
func (h *FleetOperationsHandler) RunHealthCheck(c *gin.Context) {
	var req runHealthCheckRequest
	// Body is fully optional.
	_ = c.ShouldBindJSON(&req)

	if req.MaxConcurrent <= 0 {
		req.MaxConcurrent = 20
	}

	h.log.Info("Fleet health check requested",
		zap.Int("max_concurrent", req.MaxConcurrent),
	)

	result, err := h.runner.RunHealthCheck(c.Request.Context(), req.MaxConcurrent)
	if err != nil {
		h.log.Error("FleetOperationsHandler.RunHealthCheck failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "fleet health check failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

// GetCapacityReport handles GET /api/v1/platform/fleet/capacity.
//
// Returns per-host capacity metrics including utilization percentages and
// operator recommendations for when to expand or rebalance the fleet.
//
// @Summary Fleet capacity report
// @Description Returns capacity and utilization metrics for each database host
// @Tags Fleet Operations
// @Produce json
// @Success 200 {object} map[string]interface{} "Capacity report"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/fleet/capacity [get]
func (h *FleetOperationsHandler) GetCapacityReport(c *gin.Context) {
	reports, err := h.runner.GetCapacityReport(c.Request.Context())
	if err != nil {
		h.log.Error("FleetOperationsHandler.GetCapacityReport failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "capacity report failed: " + err.Error()})
		return
	}
	if reports == nil {
		reports = []services.HostCapacityReport{}
	}
	c.JSON(http.StatusOK, gin.H{
		"hosts": reports,
		"total": len(reports),
	})
}
