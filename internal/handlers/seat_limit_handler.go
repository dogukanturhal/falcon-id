// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// SeatLimitHandler exposes Falcon's authoritative seat ledger. The internal
// PUT receives the computed limit from subscription-management (MAX included
// seats across active module plans plus seat packs); Falcon does not derive
// or guess limits from the nullable entitlement metadata mirror. Invitation
// and membership transactions maintain used/pending counters atomically.
//
// Routes: GET/PUT /internal/v1/tenants/:id/seat-limit, mounted under the
// existing internalTenants group (cmd/routes_admin.go), which already has
// ServiceAuth() at the group level; RequireScope("iam:seats:read"/"iam:seats:write")
// is added per-route. The /internal/v1/tenants/ prefix is already exempt
// from the X-Tenant-ID header gate (internal/middleware/tenant.go
// publicEndpoints), so no middleware change was needed for that part.
// GET /api/v1/tenants/me/seats exposes only the signed tenant's counters,
// under RequireAuth in cmd/routes.go, never a caller-supplied tenant ID.
type SeatLimitHandler struct {
	seatCounters seatCounterReaderWriter
	logger       *zap.Logger
}
type seatCounterReaderWriter interface {
	Get(context.Context, uuid.UUID) (*models.SeatCounters, error)
	SetSeatLimit(context.Context, uuid.UUID, int, *int64, *time.Time) (*models.SeatCounters, bool, error)
}

// NewSeatLimitHandler creates a new SeatLimitHandler.
func NewSeatLimitHandler(seatCounters *repositories.SeatCounterRepository, logger *zap.Logger) *SeatLimitHandler {
	return &SeatLimitHandler{seatCounters: seatCounters, logger: logger}
}

type seatLimitResponse struct {
	ReadOnly     bool       `json:"readOnly"`
	Notice       string     `json:"notice,omitempty"`
	TenantID     string     `json:"tenantId"`
	SeatsUsed    int        `json:"seatsUsed"`
	SeatsPending int        `json:"seatsPending"`
	SeatLimit    *int       `json:"seatLimit,omitempty"`
	Version      *int64     `json:"version,omitempty"`
	ComputedAt   *time.Time `json:"computedAt,omitempty"`
}

func toSeatLimitResponse(tenantID string, counters *models.SeatCounters) seatLimitResponse {
	if counters == nil {
		return seatLimitResponse{TenantID: tenantID}
	}
	response := seatLimitResponse{
		TenantID:     tenantID,
		SeatsUsed:    counters.SeatsUsed,
		SeatsPending: counters.SeatsPending,
		SeatLimit:    counters.SeatLimit,
		Version:      counters.SeatLimitVersion,
		ComputedAt:   counters.SeatLimitComputedAt,
	}
	if counters.SeatLimit != nil && counters.SeatsUsed+counters.SeatsPending > *counters.SeatLimit {
		response.ReadOnly = true
		response.Notice = "Seats exceed the plan limit. Existing members are retained; seat additions are read-only until usage is reduced or the plan is upgraded."
	}
	return response
}

// GetTenantSeats handles GET /api/v1/tenants/me/seats. This is the atomic
// Falcon ledger, not a count of a paginated user list. Pending invitations
// retain reservations until acceptance, revocation, decline or expiry.
// Tenant identity comes only from RequireAuth's validated session/JWT.
func (h *SeatLimitHandler) GetTenantSeats(c *gin.Context) {
	c.Header("Cache-Control", "private, no-store")
	user := middleware.GetCurrentUser(c)
	if user == nil || user.TenantID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	counters, err := h.seatCounters.Get(c.Request.Context(), user.TenantID)
	if err != nil {
		h.logger.Error("GetTenantSeats: failed", zap.Error(err))
		traceID := middleware.GetCorrelationID(c)
		if traceID == "" {
			traceID = uuid.NewString()
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read seat counters", "traceId": traceID})
		return
	}
	response := struct {
		SeatsUsed    int  `json:"seats_used"`
		SeatsPending int  `json:"seats_pending"`
		SeatLimit    *int `json:"seat_limit"`
	}{}
	if counters != nil {
		response.SeatsUsed = counters.SeatsUsed
		response.SeatsPending = counters.SeatsPending
		response.SeatLimit = counters.SeatLimit
	}
	c.JSON(http.StatusOK, response)
}

// GetSeatLimit handles GET /internal/v1/tenants/:id/seat-limit.
func (h *SeatLimitHandler) GetSeatLimit(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id", "code": "INVALID_TENANT_ID"})
		return
	}
	counters, err := h.seatCounters.Get(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("GetSeatLimit: failed", zap.Error(err), zap.String("tenant_id", tenantID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read seat counters"})
		return
	}
	if counters == nil {
		// No row yet (tenant predates the seat model, or has never had an
		// invitation/backfill touch it): report zeroed, unconfigured
		// counters rather than 404 — enforcement is OFF (seat_limit nil)
		// either way.
		c.JSON(http.StatusOK, seatLimitResponse{TenantID: tenantID.String()})
		return
	}
	c.JSON(http.StatusOK, toSeatLimitResponse(tenantID.String(), counters))
}

// SetSeatLimit handles PUT /internal/v1/tenants/:id/seat-limit.
//
// R1 "trial-aware seat caps" (spec 25 §4.5): when the request carries a
// version (subscription-management's computed-seat-limit feed, retried
// via its own outbox/reconciler sweep), a redelivered stale write is
// rejected with 409 and code "stale_seat_limit_version" rather than
// silently overwriting a newer value — see
// SeatCounterRepository.SetSeatLimit's doc comment for the atomic
// compare-and-write this relies on. An unversioned request (manual/
// operator PUT) is always applied, unchanged from pre-0014 behaviour.
func (h *SeatLimitHandler) SetSeatLimit(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id", "code": "INVALID_TENANT_ID"})
		return
	}
	var req models.SetSeatLimitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	counters, applied, err := h.seatCounters.SetSeatLimit(c.Request.Context(), tenantID, req.SeatLimit, req.Version, req.ComputedAt)
	if err != nil {
		h.logger.Error("SetSeatLimit: failed", zap.Error(err), zap.String("tenant_id", tenantID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to set seat limit"})
		return
	}
	if !applied {
		h.logger.Warn("SetSeatLimit: rejected stale version",
			zap.String("tenant_id", tenantID.String()),
			zap.Int64p("requested_version", req.Version),
		)
		resp := toSeatLimitResponse(tenantID.String(), counters)
		c.JSON(http.StatusConflict, gin.H{
			"error":   "seat limit version is stale; a newer value has already been applied",
			"code":    "stale_seat_limit_version",
			"current": resp,
		})
		return
	}
	c.JSON(http.StatusOK, toSeatLimitResponse(tenantID.String(), counters))
}
