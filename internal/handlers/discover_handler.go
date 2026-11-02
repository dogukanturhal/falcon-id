// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/metrics"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// DiscoverServiceInterface is the contract the handler depends on.
// Accepting an interface (not a concrete type) keeps the handler testable
// without touching the database or real identity providers.
type DiscoverServiceInterface interface {
	Discover(ctx context.Context, req *models.DiscoverRequest) (*models.DiscoverResponse, error)
}

// DiscoverHandler serves the Home Realm Discovery (HRD) endpoint.
// Given an email address it tells the login UI how the user should authenticate.
type DiscoverHandler struct {
	service DiscoverServiceInterface
	logger  *zap.Logger
}

// NewDiscoverHandler creates a DiscoverHandler wired to the given service.
// logger may be nil — in that case the handler uses a no-op zap to keep
// tests + bare-bones cmd wiring simple. Production wiring MUST pass the
// shared logger.Log from cmd/handlers.go.
func NewDiscoverHandler(service DiscoverServiceInterface, logger *zap.Logger) *DiscoverHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &DiscoverHandler{service: service, logger: logger}
}

// Discover handles POST /api/v1/auth/discover
//
// Request body:
//
//	{ "email": "user@example.com" }
//
// Response:
//
//	200 OK with DiscoverResponse on success.
//	400 Bad Request — malformed JSON, missing/invalid email.
//	502 Bad Gateway — upstream DB read failed (domain/tenant/user lookup).
//	500 Internal Server Error — anything else.
//
// Error handling — sentinel-typed via services.DiscoverError:
//
//   - ErrDiscoverInvalidEmail → 400. User-input bug, NOT a server error.
//     Pre-fix this was 500, which inflated the dashboards' server-error
//     rate every time a frontend sent "" or "@" by mistake.
//
//   - ErrDiscoverDomainLookup / ErrDiscoverTenantLookup / ErrDiscoverUserLookup
//     → 502. Backend DB read failed. 502 (not 500) is the canonical
//     code for "I'm fine, my upstream isn't" — matches Keycloak +
//     Ory Fosite + RFC 6749 §5.2 implicit guidance.
//
//   - Anything else (defensive) → 500.
//
// Every failure path logs ONCE at zap.Error level with the step + the
// wrapped error + the SQLSTATE code (when *pgconn.PgError). The handler
// never logs AND returns — exactly one log line per request per Dave
// Cheney's "handle errors once" principle.
//
// operational notes — the
// previous shape collapsed every failure into a generic 500 with no
// log line, making the underlying cause unrecoverable from telemetry.
func (h *DiscoverHandler) Discover(c *gin.Context) {
	var req models.DiscoverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		metrics.DiscoverRequests.WithLabelValues("bad_request", "false").Inc()
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"details": err.Error(),
		})
		return
	}

	// Server-side realm injection. The body field is `json:"-"` so a
	// malicious client cannot probe arbitrary realms by posting their
	// own RealmID — the value MUST come from the realm middleware's
	// context (subdomain / header / URL prefix per
	// middleware.RealmMiddleware). uuid.Nil = no realm scope, which is
	// the correct behaviour when realm support is disabled or the
	// request is identifier-first.
	req.RealmID = getRealmIDFromContext(c)

	resp, err := h.service.Discover(c.Request.Context(), &req)
	if err != nil {
		h.emitDiscoverFailure(c, &req, err)
		return
	}

	tenantKnown := "false"
	if resp != nil && resp.TenantID != nil {
		tenantKnown = "true"
	}
	metrics.DiscoverRequests.WithLabelValues("ok", tenantKnown).Inc()
	c.JSON(http.StatusOK, resp)
}

// emitDiscoverFailure is the single error-boundary for the handler.
// Logs + metrics + HTTP response in one place — never split across
// helpers to avoid the "log + return + log again upstream" double-emit
// trap.
func (h *DiscoverHandler) emitDiscoverFailure(c *gin.Context, req *models.DiscoverRequest, err error) {
	step := "unknown"
	code := "other"
	httpStatus := http.StatusInternalServerError
	clientBody := "discovery_failed"

	var de *services.DiscoverError
	if errors.As(err, &de) {
		step = string(de.Step)
		switch de.Step {
		case services.DiscoverStepInvalidEmail:
			httpStatus = http.StatusBadRequest
			clientBody = "invalid_email"
		case services.DiscoverStepDomainLookup,
			services.DiscoverStepTenantLookup,
			services.DiscoverStepUserLookup:
			httpStatus = http.StatusBadGateway
			clientBody = "upstream_unavailable"
		}
	}

	// Extract PostgreSQL SQLSTATE (e.g., "42P01") so the metric can
	// label by canonical Postgres error code without leaking message
	// text. errors.As walks the wrapped chain so DiscoverError → pgx
	// query error → PgError is reachable.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		code = pgErr.Code
	}

	metrics.DiscoverErrors.WithLabelValues(step, code).Inc()
	metrics.DiscoverRequests.WithLabelValues(step, "false").Inc()

	h.logger.Error("HRD discover failed",
		zap.String("step", step),
		zap.String("sqlstate", code),
		zap.String("email_domain", emailDomainTag(req)),
		zap.String("request_id", c.GetString("request_id")),
		zap.String("correlation_id", c.GetString("correlation_id")),
		zap.Error(err),
	)

	c.JSON(httpStatus, gin.H{"error": clientBody})
}

// emailDomainTag returns just the domain portion of the request email
// for log + metric correlation. Personal-mailbox local-part is NOT
// logged — GDPR + RFC 7493 say the local-part is PII (a stable
// pseudonym for the human), while the domain is a public routing fact.
//
// Returns "unknown" when the email is empty, has no @, or has an
// empty domain — these are the same conditions that produce
// ErrDiscoverInvalidEmail in the service, so we never accidentally
// log a malformed string as a "domain".
func emailDomainTag(req *models.DiscoverRequest) string {
	if req == nil {
		return "unknown"
	}
	e := req.Email
	for i := len(e) - 1; i >= 0; i-- {
		if e[i] == '@' {
			if i+1 < len(e) {
				return e[i+1:]
			}
			return "unknown"
		}
	}
	return "unknown"
}
