// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"net/http"
	"strings"
)

// Hosted pages use HttpOnly cookies and Prefer: return=minimal (RFC 7240).
// API/SDK callers still receive tokens, but never the duplicated user graph.
func writeMFACompletionResponse(c *gin.Context, response *models.LoginResponse) {
	c.Header("Cache-Control", "no-store")
	if strings.Contains(strings.ToLower(c.GetHeader("Prefer")), "return=minimal") {
		c.Header("Preference-Applied", "return=minimal")
		c.JSON(http.StatusOK, gin.H{"success": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "access_token": response.AccessToken, "token_type": "Bearer", "expires_in": response.ExpiresIn})
}
