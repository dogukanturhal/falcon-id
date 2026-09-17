// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RealmDatabase is the data returned from a successful provisioning operation.
// Defined here so the handler has no compile-time dependency on a concrete service.
type RealmDatabase struct {
	ID           uuid.UUID `json:"id"`
	RealmID      uuid.UUID `json:"realm_id"`
	DatabaseName string    `json:"database_name"`
	Host         string    `json:"host"`
	Port         int       `json:"port"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

// RealmDatabaseHealth is the health info returned by GetDatabaseHealth.
type RealmDatabaseHealth struct {
	RealmID           uuid.UUID  `json:"realm_id"`
	Status            string     `json:"status"`
	Host              string     `json:"host,omitempty"`
	DatabaseName      string     `json:"database_name,omitempty"`
	PoolSize          int        `json:"pool_size"`
	SchemaVersion     *string    `json:"schema_version"`
	LastHealthCheck   *time.Time `json:"last_health_check"`
	HealthCheckStatus *string    `json:"health_check_status"`
}

// RealmMigrationStatus is the response payload for MigrateDatabase.
type RealmMigrationStatus struct {
	RealmID     uuid.UUID  `json:"realm_id"`
	Status      string     `json:"status"`
	SourceHost  string     `json:"source_host"`
	TargetHost  string     `json:"target_host"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	TablesCount int        `json:"tables_count,omitempty"`
	TotalRows   int64      `json:"total_rows,omitempty"`
}

// MigrateDatabaseRequest is the request body for MigrateDatabase.
type MigrateDatabaseRequest struct {
	// TargetRegion selects a target host via the placement engine (e.g. "tr-ank").
	// Mutually exclusive with TargetHostID.
	TargetRegion string `json:"target_region"`

	// TargetHostID pins the migration to a specific registered host. Takes
	// precedence over TargetRegion when both are supplied.
	TargetHostID *uuid.UUID `json:"target_host_id,omitempty"`

	// DropSourceAfterMigration controls whether the source database is dropped
	// after a successful copy and row-count verification. Defaults to false.
	DropSourceAfterMigration bool `json:"drop_source_after_migration,omitempty"`
}

// RealmDatabaseProvisioner is the interface the handler depends on.
// The concrete implementation (services.RealmDBProvisioner) must satisfy this interface.
type RealmDatabaseProvisioner interface {
	ProvisionDatabase(ctx context.Context, realmID uuid.UUID, realmSlug string, preferredRegion string) (*RealmDatabase, error)
	DecommissionDatabase(ctx context.Context, realmID uuid.UUID) error
	GetDatabaseHealth(ctx context.Context, realmID uuid.UUID) (*RealmDatabaseHealth, error)
}

// RealmDatabaseMigrator is the interface the handler depends on for cross-host
// database migration. Separated from RealmDatabaseProvisioner so the migrator
// can be injected independently (it may be nil when no multi-host config exists).
type RealmDatabaseMigrator interface {
	MigrateDatabase(ctx context.Context, realmID uuid.UUID, req MigrateDatabaseRequest) (*RealmMigrationStatus, error)
}

// RealmLookup resolves a realm's slug from its ID.
type RealmLookup interface {
	GetSlugByID(ctx context.Context, realmID uuid.UUID) (string, error)
}

// RealmDBHandler handles realm database management operations.
type RealmDBHandler struct {
	provisioner RealmDatabaseProvisioner
	realmLookup RealmLookup
	migrator    RealmDatabaseMigrator // optional; nil when not configured
}

// NewRealmDBHandler creates a new RealmDBHandler.
func NewRealmDBHandler(provisioner RealmDatabaseProvisioner, realmLookup RealmLookup) *RealmDBHandler {
	return &RealmDBHandler{provisioner: provisioner, realmLookup: realmLookup}
}

// SetMigrator wires the optional database migration service. When not set,
// MigrateDatabase returns HTTP 501 Not Implemented.
func (h *RealmDBHandler) SetMigrator(m RealmDatabaseMigrator) {
	h.migrator = m
}

// ProvisionDatabase creates a dedicated database for an enterprise realm.
//
// POST /platform/realms/:id/provision-database
//
// Request body (all fields optional):
//
//	{ "realm_slug": "acme-corp" }
//
// If realm_slug is not provided, it is resolved from the realm ID.
//
// Responses:
//
//	201 – database provisioned; body contains id, realm_id, database_name, host, status, created_at
//	400 – invalid realm ID
//	500 – provisioning failed
func (h *RealmDBHandler) ProvisionDatabase(c *gin.Context) {
	realmID, ok := parseRealmID(c)
	if !ok {
		return
	}

	var req struct {
		RealmSlug       string `json:"realm_slug"`
		PreferredRegion string `json:"preferred_region"`
	}
	// Ignore bind errors — body is optional
	_ = c.ShouldBindJSON(&req)

	realmSlug := req.RealmSlug
	if realmSlug == "" && h.realmLookup != nil {
		slug, err := h.realmLookup.GetSlugByID(c.Request.Context(), realmID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve realm slug: " + err.Error()})
			return
		}
		realmSlug = slug
	}
	if realmSlug == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "realm_slug is required"})
		return
	}

	rd, err := h.provisioner.ProvisionDatabase(c.Request.Context(), realmID, realmSlug, req.PreferredRegion)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":            rd.ID,
		"realm_id":      rd.RealmID,
		"database_name": rd.DatabaseName,
		"host":          rd.Host,
		"status":        rd.Status,
		"created_at":    rd.CreatedAt,
	})
}

// DecommissionDatabase marks a realm's dedicated database as decommissioned.
//
// DELETE /platform/realms/:id/database
//
// Responses:
//
//	200 – decommissioned successfully
//	400 – invalid realm ID
//	500 – decommission failed
func (h *RealmDBHandler) DecommissionDatabase(c *gin.Context) {
	realmID, ok := parseRealmID(c)
	if !ok {
		return
	}

	if err := h.provisioner.DecommissionDatabase(c.Request.Context(), realmID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "database decommissioned"})
}

// GetDatabaseHealth returns the health status for a realm's dedicated database.
//
// GET /platform/realms/:id/database-health
//
// Responses:
//
//	200 – health data returned
//	400 – invalid realm ID
func (h *RealmDBHandler) GetDatabaseHealth(c *gin.Context) {
	realmID, ok := parseRealmID(c)
	if !ok {
		return
	}

	health, err := h.provisioner.GetDatabaseHealth(c.Request.Context(), realmID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, health)
}

// MigrateDatabase moves a realm's dedicated database from its current host to a
// new host, copying all data using the pgx native COPY protocol.
//
// POST /platform/realms/:id/migrate-database
//
// Request body:
//
//	{
//	    "target_region":               "tr-ank",    // OR
//	    "target_host_id":              "<uuid>",    // explicit host
//	    "drop_source_after_migration": false        // optional
//	}
//
// Responses:
//
//	200 – migration completed; body contains source_host, target_host, tables_count, total_rows
//	400 – invalid realm ID or missing target
//	501 – migrator not configured (multi-host not available)
//	500 – migration failed
func (h *RealmDBHandler) MigrateDatabase(c *gin.Context) {
	realmID, ok := parseRealmID(c)
	if !ok {
		return
	}

	if h.migrator == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "database migration not configured for this installation"})
		return
	}

	var req MigrateDatabaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	if req.TargetRegion == "" && req.TargetHostID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "either target_region or target_host_id must be provided"})
		return
	}

	result, err := h.migrator.MigrateDatabase(c.Request.Context(), realmID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// parseRealmID extracts and validates the :id path parameter.
// On failure it writes a 400 response and returns (uuid.Nil, false).
func parseRealmID(c *gin.Context) (uuid.UUID, bool) {
	realmID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid realm ID"})
		return uuid.Nil, false
	}
	return realmID, true
}
