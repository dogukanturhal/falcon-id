// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// errCodeTenantSuspended is the stable wire error code returned when the
// caller's tenant has been suspended (R1-GAPS row 27).
const errCodeTenantSuspended = "tenant_suspended"

// respondIfTenantSuspended writes the 403 tenant_suspended response and
// returns true when err is (or wraps) services.ErrTenantSuspended. Callers
// return immediately on true.
func respondIfTenantSuspended(c *gin.Context, err error) bool {
	if !errors.Is(err, services.ErrTenantSuspended) {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{
		"error":             errCodeTenantSuspended,
		"error_description": "This organization's account is suspended. Contact your administrator or support.",
	})
	return true
}
