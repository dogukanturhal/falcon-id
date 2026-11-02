// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

const (
	msgInvalidHostID = "invalid host ID"
)

// DatabaseHostHandler handles CRUD for database host registry.
type DatabaseHostHandler struct {
	repo       *repositories.DatabaseHostRepository
	encryption *crypto.EncryptionService
}

// NewDatabaseHostHandler creates a new DatabaseHostHandler.
func NewDatabaseHostHandler(repo *repositories.DatabaseHostRepository, encryption *crypto.EncryptionService) *DatabaseHostHandler {
	return &DatabaseHostHandler{repo: repo, encryption: encryption}
}

// List returns all database hosts (connection strings are never exposed).
func (h *DatabaseHostHandler) List(c *gin.Context) {
	hosts, err := h.repo.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list hosts"})
		return
	}
	c.JSON(http.StatusOK, hosts)
}

// GetByID returns a single database host.
func (h *DatabaseHostHandler) GetByID(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidHostID})
		return
	}
	host, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil || host == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}
	c.JSON(http.StatusOK, host)
}

// Create registers a new database host with encrypted connection string.
func (h *DatabaseHostHandler) Create(c *gin.Context) {
	var req models.CreateDatabaseHostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Encrypt connection string before storage.
	connStr := req.ConnectionString
	if h.encryption != nil {
		encrypted, err := h.encryption.Encrypt(connStr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt connection string"})
			return
		}
		connStr = encrypted
	}

	host := &models.RealmDatabaseHost{
		ID:                  uuid.New(),
		HostAlias:           req.HostAlias,
		ConnectionStringEnc: connStr,
		Region:              req.Region,
		DataResidencyZone:   req.DataResidencyZone,
		Provider:            req.Provider,
		MaxDatabases:        req.MaxDatabases,
		IsActive:            true,
		HealthStatus:        "unknown",
	}
	if host.Provider == "" {
		host.Provider = "self-hosted"
	}
	if host.MaxDatabases == 0 {
		host.MaxDatabases = 100
	}

	if err := h.repo.Create(c.Request.Context(), host); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create host"})
		return
	}
	c.JSON(http.StatusCreated, host)
}

// Delete removes a database host.
func (h *DatabaseHostHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidHostID})
		return
	}
	if err := h.repo.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete host"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "host deleted"})
}

// HealthCheck returns the current health status for a host.
func (h *DatabaseHostHandler) HealthCheck(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidHostID})
		return
	}
	host, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil || host == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"host_id": host.ID,
		"status":  host.HealthStatus,
		"alias":   host.HostAlias,
		"region":  host.Region,
	})
}
