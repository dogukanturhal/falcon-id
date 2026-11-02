// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// externalStaffAccounts are the two non-Hexxlock accounts that sit in the
// internal tenant. They are listed in every report and NEVER seeded with
// any platform role; moving them out of the tenant is the operator's call.
var externalStaffAccounts = []string{
	"greennazarotel@gmail.com",
	"furkan.ozdemir@aviason.com",
}

// platformAuthorityRoster is the slice of PlatformAuthorityRepository the
// handler needs.
type platformAuthorityRoster interface {
	ListInternalUsers(ctx context.Context) ([]repositories.InternalUserAuthority, error)
}

// PlatformAuthorityHandler serves the OPS_STRICT_PLATFORM_ROLES readiness
// report and the standing-viewer seed under /internal/v1/platform-roles.
// Same auth chain as the rest of that group (service scope + the human
// operator from X-Actor-Assertion); identity comes from the verified actor.
type PlatformAuthorityHandler struct {
	roster    platformAuthorityRoster
	jit       *services.PlatformJITService
	authority *services.PlatformAuthority
	logger    *zap.Logger
}

// NewPlatformAuthorityHandler creates the handler.
func NewPlatformAuthorityHandler(roster platformAuthorityRoster, jit *services.PlatformJITService, authority *services.PlatformAuthority, logger *zap.Logger) *PlatformAuthorityHandler {
	return &PlatformAuthorityHandler{roster: roster, jit: jit, authority: authority, logger: logger}
}

type authorityUserRow struct {
	UserID        uuid.UUID `json:"user_id"`
	Email         string    `json:"email"`
	Username      string    `json:"username"`
	IsActive      bool      `json:"is_active"`
	PlatformRoles []string  `json:"platform_roles"`
	LegacyRoles   []string  `json:"legacy_roles"`
}

type authorityReport struct {
	StrictEnabled bool `json:"strict_enabled"`
	// ReliesOnLegacyPath are users whose platform-admin access today comes
	// ONLY from the legacy tenant role (platform_admin / iam_admin): with
	// OPS_STRICT_PLATFORM_ROLES on they lose it and must use JIT.
	ReliesOnLegacyPath []authorityUserRow `json:"relies_on_legacy_path"`
	// BreakGlass is the account that keeps its standing role under strict.
	BreakGlass []authorityUserRow `json:"break_glass"`
	// ExternalAccounts are the non-Hexxlock accounts in the internal
	// tenant; never seeded.
	ExternalAccounts []authorityUserRow `json:"external_accounts"`
	// MissingViewer are active internal users without the standing
	// platform_viewer row (the seed target).
	MissingViewer []authorityUserRow `json:"missing_viewer"`
	InternalUsers int                `json:"internal_users"`
}

func toRow(u repositories.InternalUserAuthority) authorityUserRow {
	if u.PlatformRoles == nil {
		u.PlatformRoles = []string{}
	}
	if u.LegacyRoles == nil {
		u.LegacyRoles = []string{}
	}
	return authorityUserRow{UserID: u.UserID, Email: u.Email, Username: u.Username, IsActive: u.IsActive, PlatformRoles: u.PlatformRoles, LegacyRoles: u.LegacyRoles}
}

func isExternalAccount(email string, extra []string) bool {
	for _, e := range append(append([]string{}, externalStaffAccounts...), extra...) {
		if strings.EqualFold(strings.TrimSpace(e), strings.TrimSpace(email)) {
			return true
		}
	}
	return false
}

func hasString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func (h *PlatformAuthorityHandler) buildReport(ctx context.Context, extraExternal []string) (*authorityReport, error) {
	users, err := h.roster.ListInternalUsers(ctx)
	if err != nil {
		return nil, err
	}
	rep := &authorityReport{
		StrictEnabled:      h.authority.Strict(),
		ReliesOnLegacyPath: []authorityUserRow{},
		BreakGlass:         []authorityUserRow{},
		ExternalAccounts:   []authorityUserRow{},
		MissingViewer:      []authorityUserRow{},
		InternalUsers:      len(users),
	}
	for _, u := range users {
		row := toRow(u)
		if isExternalAccount(u.Email, extraExternal) {
			rep.ExternalAccounts = append(rep.ExternalAccounts, row)
		}
		if h.authority.IsBreakGlassAccount(u.Email) {
			rep.BreakGlass = append(rep.BreakGlass, row)
		}
		// A JIT admin elevation is a materialised platform_admin row; the
		// legacy path matters for those holding a legacy role without one.
		if len(u.LegacyRoles) > 0 && !hasString(u.PlatformRoles, "platform_admin") && !h.authority.IsBreakGlassAccount(u.Email) {
			rep.ReliesOnLegacyPath = append(rep.ReliesOnLegacyPath, row)
		}
		if u.IsActive && strings.TrimSpace(u.Email) != "" && !isExternalAccount(u.Email, extraExternal) && !hasString(u.PlatformRoles, "platform_viewer") {
			rep.MissingViewer = append(rep.MissingViewer, row)
		}
	}
	return rep, nil
}

// LegacyReport handles GET /internal/v1/platform-roles/legacy-report.
// Read-only.
func (h *PlatformAuthorityHandler) LegacyReport(c *gin.Context) {
	if middleware.GetActorUserID(c) == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}
	rep, err := h.buildReport(c.Request.Context(), nil)
	if err != nil {
		h.logger.Error("PlatformAuthorityHandler.LegacyReport failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		return
	}
	c.JSON(http.StatusOK, rep)
}

// SeedViewers handles POST /internal/v1/platform-roles/seed-viewers.
// DRY-RUN BY DEFAULT: nothing is written unless the body says
// {"apply": true}. Seeds the standing platform_viewer role (the only
// standing role) for active internal-tenant users that lack it, excluding
// the external accounts. Idempotent. Returns the same report plus the
// users that were / would be seeded.
func (h *PlatformAuthorityHandler) SeedViewers(c *gin.Context) {
	actorID := middleware.GetActorUserID(c)
	if actorID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}
	var req struct {
		Apply bool `json:"apply"`
		// ExcludeEmails are extra accounts to leave unseeded (additive to
		// the built-in external list).
		ExcludeEmails []string `json:"exclude_emails"`
	}
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	rep, err := h.buildReport(c.Request.Context(), req.ExcludeEmails)
	if err != nil {
		h.logger.Error("PlatformAuthorityHandler.SeedViewers report failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		return
	}

	seeded := []authorityUserRow{}
	failed := []gin.H{}
	if req.Apply {
		for _, u := range rep.MissingViewer {
			if _, gErr := h.jit.GrantStandingRole(c.Request.Context(), actorID, u.UserID, "platform_viewer"); gErr != nil {
				h.logger.Error("PlatformAuthorityHandler.SeedViewers grant failed", zap.Error(gErr), zap.String("user_id", u.UserID.String()))
				failed = append(failed, gin.H{"user_id": u.UserID, "error": "grant_failed"})
				continue
			}
			seeded = append(seeded, u)
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"dry_run":    !req.Apply,
		"would_seed": rep.MissingViewer,
		"seeded":     seeded,
		"failed":     failed,
		"report":     rep,
	})
}
