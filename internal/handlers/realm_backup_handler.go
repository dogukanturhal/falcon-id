// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// realm_backup_handler.go provides RealmBackupHandler, which exposes HTTP
// endpoints for per-tenant database backup and restore operations.
//
// Routes (registered in cmd/routes_admin.go under the realm group):
//
//	POST /platform/realms/:id/backup    — trigger a backup
//	GET  /platform/realms/:id/backups   — list available backups
//	POST /platform/realms/:id/restore   — restore from a backup file

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RealmBackupResult is the handler-layer view of a backup result.
// It deliberately avoids importing the services package so the handler
// depends only on an interface.
type RealmBackupResult struct {
	RealmID      uuid.UUID `json:"realm_id"`
	DatabaseName string    `json:"database_name"`
	BackupFile   string    `json:"backup_file"`
	Size         int64     `json:"size_bytes"`
	Tables       int       `json:"tables"`
	Rows         int64     `json:"rows"`
	CreatedAt    string    `json:"created_at"` // RFC 3339
	Duration     string    `json:"duration"`
}

// RealmRestoreResult is the handler-layer view of a restore result.
type RealmRestoreResult struct {
	RealmID      uuid.UUID `json:"realm_id"`
	DatabaseName string    `json:"database_name"`
	RestoredFrom string    `json:"restored_from"`
	Tables       int       `json:"tables"`
	Rows         int64     `json:"rows"`
	Duration     string    `json:"duration"`
}

// RealmBackupService is the interface the handler depends on.
// The concrete type is *services.TenantBackupService.
type RealmBackupService interface {
	// BackupRealm creates a new backup for the realm and returns metadata.
	BackupRealm(ctx context.Context, realmID uuid.UUID) (*RealmBackupResult, error)
	// RestoreRealm restores the realm's database from backupFile.
	RestoreRealm(ctx context.Context, realmID uuid.UUID, backupFile string) (*RealmRestoreResult, error)
	// ListBackups returns available backups for the realm, newest first.
	ListBackups(ctx context.Context, realmID uuid.UUID) ([]RealmBackupResult, error)
}

// RealmBackupHandler handles realm backup and restore HTTP requests.
type RealmBackupHandler struct {
	backup RealmBackupService
}

// NewRealmBackupHandler constructs a RealmBackupHandler.
func NewRealmBackupHandler(backup RealmBackupService) *RealmBackupHandler {
	return &RealmBackupHandler{backup: backup}
}

// BackupRealm creates a backup of a realm's dedicated database.
//
// POST /platform/realms/:id/backup
//
// No request body required.
//
// Responses:
//
//	202 – backup started and completed; body contains backup metadata
//	400 – invalid realm ID
//	500 – backup failed
func (h *RealmBackupHandler) BackupRealm(c *gin.Context) {
	realmID, ok := parseRealmID(c)
	if !ok {
		return
	}

	result, err := h.backup.BackupRealm(c.Request.Context(), realmID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, result)
}

// ListBackups returns the available backups for a realm.
//
// GET /platform/realms/:id/backups
//
// Responses:
//
//	200 – list of backup metadata objects (may be empty)
//	400 – invalid realm ID
//	500 – listing failed
func (h *RealmBackupHandler) ListBackups(c *gin.Context) {
	realmID, ok := parseRealmID(c)
	if !ok {
		return
	}

	results, err := h.backup.ListBackups(c.Request.Context(), realmID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"backups": results, "count": len(results)})
}

// RestoreRealm restores a realm's database from a backup.
//
// POST /platform/realms/:id/restore
//
// Request body:
//
//	{ "backup_file": "/tmp/hexxlock-backups/<realm-id>/20260320T123456Z" }
//
// Responses:
//
//	200 – restore completed; body contains restore metadata
//	400 – invalid realm ID or missing backup_file
//	500 – restore failed
func (h *RealmBackupHandler) RestoreRealm(c *gin.Context) {
	realmID, ok := parseRealmID(c)
	if !ok {
		return
	}

	var req struct {
		BackupFile string `json:"backup_file" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "backup_file is required"})
		return
	}

	result, err := h.backup.RestoreRealm(c.Request.Context(), realmID, req.BackupFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}
