// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"net/http"
)

func respondMFAFlowError(c *gin.Context, err error) {
	var flow *services.MFAFlowError
	if errors.As(err, &flow) {
		status := http.StatusUnauthorized
		message := "This sign-in attempt expired."
		if flow.Code == "mfa_code_invalid" {
			message = "Wrong code, try again."
		}
		if flow.Code == "mfa_rate_limited" {
			status = http.StatusTooManyRequests
			c.Header("Retry-After", "60")
			message = "Too many attempts. Please wait before trying again."
		}
		c.JSON(status, gin.H{"error": message, "code": flow.Code, "remaining_attempts": flow.RemainingAttempts})
		return
	}
	traceID := middleware.GetRequestID(c)
	if traceID == "" {
		traceID = uuid.NewString()
		c.Set(middleware.RequestIDKey, traceID)
	}
	c.Header("X-Request-ID", traceID)
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Authentication is temporarily unavailable. Please try again.", "code": "mfa_unavailable", "traceId": traceID})
}
