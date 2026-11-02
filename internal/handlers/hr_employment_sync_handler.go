// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

type HREmploymentSyncHandler struct {
	service *services.HREmploymentSyncService
}

func NewHREmploymentSyncHandler(service *services.HREmploymentSyncService) *HREmploymentSyncHandler {
	return &HREmploymentSyncHandler{service: service}
}

func (h *HREmploymentSyncHandler) PutScope(c *gin.Context) {
	tenant, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant id"})
		return
	}
	var body models.HREmploymentScope
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	applied, err := h.service.ApplyScope(c.Request.Context(), tenant, body)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidHREmploymentScope):
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid HR sync scope", "code": "invalid_scope"})
		case errors.Is(err, repositories.ErrHREmploymentSyncScopeVersionConflict):
			c.JSON(http.StatusConflict, gin.H{"error": "HR sync scope version conflict", "code": "scope_version_conflict"})
		default:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "HR sync temporarily unavailable", "code": "hr_sync_unavailable"})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"applied": applied})
}

func (h *HREmploymentSyncHandler) PutEmployment(c *gin.Context) {
	tenant, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant id"})
		return
	}
	employee, err := uuid.Parse(c.Param("employeeId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid employee id"})
		return
	}
	var body models.HREmploymentDesiredState
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	result, err := h.service.ApplyDesired(c.Request.Context(), tenant, employee, body)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidHREmploymentDesiredState):
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid HR employment desired state", "code": "invalid_desired_state", "result": result})
		case errors.Is(err, repositories.ErrHREmploymentSyncEventPayloadConflict):
			c.JSON(http.StatusConflict, gin.H{"error": "HR employment sync event conflict", "code": "event_id_payload_conflict", "result": result})
		default:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "HR sync temporarily unavailable", "code": "hr_sync_unavailable", "result": result})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}
