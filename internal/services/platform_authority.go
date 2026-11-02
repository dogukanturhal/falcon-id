// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// PlatformAuthorityStore reads the platform roles in force for a user
// (repositories.PlatformAuthorityRepository satisfies it).
type PlatformAuthorityStore interface {
	ActiveRoles(ctx context.Context, userID uuid.UUID) ([]string, error)
	LatestActiveElevation(ctx context.Context, userID uuid.UUID) (*repositories.ActiveElevationRef, error)
	// HasStandingRole reports whether the iam_platform_roles row exists,
	// whether or not an elevation backs it.
	HasStandingRole(ctx context.Context, userID uuid.UUID, roleKey string) (bool, error)
}

// PlatformAuthority is the single place that decides who is a platform admin.
//
// Legacy mode (OPS_STRICT_PLATFORM_ROLES=false, the default): behaviour is
// exactly what it was - the is_platform_admin claim follows internal-tenant
// membership, and the gates additionally want the tenant role platform_admin
// or iam_admin. Every method of a nil *PlatformAuthority is the legacy answer,
// so unwired call sites (tests, partial deployments) are unchanged.
//
// Strict mode (OPS_STRICT_PLATFORM_ROLES=true): platform-admin authority comes
// only from iam_platform_roles (an active platform_admin elevation or
// break-glass grant). Tenant membership and the legacy tenant roles grant
// nothing. The single exception is the break-glass account
// (OPS_BREAK_GLASS_EMAIL), which keeps its standing tenant role.
type PlatformAuthority struct {
	strict          bool
	breakGlassEmail string // lower-cased; "" = none configured
	store           PlatformAuthorityStore
}

// NewPlatformAuthority builds the authority. A nil store in strict mode
// denies everyone except the break-glass account (fail-closed).
func NewPlatformAuthority(strict bool, breakGlassEmail string, store PlatformAuthorityStore) *PlatformAuthority {
	return &PlatformAuthority{
		strict:          strict,
		breakGlassEmail: strings.ToLower(strings.TrimSpace(breakGlassEmail)),
		store:           store,
	}
}

// Strict reports whether OPS_STRICT_PLATFORM_ROLES is on.
func (p *PlatformAuthority) Strict() bool { return p != nil && p.strict }

// IsBreakGlassAccount reports whether email is the configured break-glass
// account.
func (p *PlatformAuthority) IsBreakGlassAccount(email string) bool {
	if p == nil || p.breakGlassEmail == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(email), p.breakGlassEmail)
}

// AdminClaim returns the value of the is_platform_admin claim for a token
// being minted. Legacy: internal-tenant membership. Strict: only an active
// platform_admin role in iam_platform_roles, or the break-glass account.
func (p *PlatformAuthority) AdminClaim(ctx context.Context, userID, tenantID uuid.UUID, email string) bool {
	if !p.Strict() {
		return tenantID.String() == models.HexxlockInternalTenantID
	}
	return p.holdsAdmin(ctx, userID, tenantID, email)
}

// VerifyAdmin is the strict-mode live check used by the request middleware:
// does the principal hold platform_admin RIGHT NOW. Only call it when
// Strict() is true. The break-glass account must additionally still hold its
// standing legacy tenant role (legacyRoleHeld).
func (p *PlatformAuthority) VerifyAdmin(ctx context.Context, userID, tenantID uuid.UUID, email string, legacyRoleHeld bool) bool {
	if !p.Strict() {
		return false
	}
	if tenantID.String() != models.HexxlockInternalTenantID {
		return false
	}
	if p.IsBreakGlassAccount(email) {
		return legacyRoleHeld
	}
	return p.rolesContainAdmin(ctx, userID)
}

func (p *PlatformAuthority) holdsAdmin(ctx context.Context, userID, tenantID uuid.UUID, email string) bool {
	if tenantID.String() != models.HexxlockInternalTenantID {
		return false
	}
	if p.IsBreakGlassAccount(email) {
		return true
	}
	return p.rolesContainAdmin(ctx, userID)
}

func (p *PlatformAuthority) rolesContainAdmin(ctx context.Context, userID uuid.UUID) bool {
	if p == nil || p.store == nil {
		return false
	}
	roles, err := p.store.ActiveRoles(ctx, userID)
	if err != nil {
		logger.Log.Warn("platform authority: role lookup failed, denying (fail-closed)",
			zap.String("user_id", userID.String()), zap.Error(err))
		return false
	}
	for _, r := range roles {
		if r == string(models.PlatformRoleAdmin) {
			return true
		}
	}
	return false
}

// ActiveRoles exposes the roles in force for the operator token exchange.
func (p *PlatformAuthority) ActiveRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if p == nil || p.store == nil {
		return nil, nil
	}
	return p.store.ActiveRoles(ctx, userID)
}

// ActiveRolesFor is ActiveRoles plus the one standing exception: the
// break-glass account (OPS_BREAK_GLASS_EMAIL) also holds platform_admin when
// it has a standing iam_platform_roles row. Every other account stays
// JIT-only, so a standing non-viewer row for anyone else grants nothing.
func (p *PlatformAuthority) ActiveRolesFor(ctx context.Context, userID uuid.UUID, email string) ([]string, error) {
	roles, err := p.ActiveRoles(ctx, userID)
	if err != nil {
		return nil, err
	}
	admin := string(models.PlatformRoleAdmin)
	if p == nil || p.store == nil || !p.IsBreakGlassAccount(email) {
		return roles, nil
	}
	for _, r := range roles {
		if r == admin {
			return roles, nil
		}
	}
	ok, err := p.store.HasStandingRole(ctx, userID, admin)
	if err != nil {
		return nil, err
	}
	if ok {
		roles = append(roles, admin)
	}
	return roles, nil
}

// HoldsStandingBreakGlassAdmin reports whether email is the break-glass
// account AND it holds a standing platform_admin row in iam_platform_roles.
// That is the one standing admin the strict model honours.
func (p *PlatformAuthority) HoldsStandingBreakGlassAdmin(ctx context.Context, userID uuid.UUID, email string) (bool, error) {
	if p == nil || p.store == nil || !p.IsBreakGlassAccount(email) {
		return false, nil
	}
	return p.store.HasStandingRole(ctx, userID, string(models.PlatformRoleAdmin))
}

// LatestActiveElevation exposes the backing elevation for elev_id.
func (p *PlatformAuthority) LatestActiveElevation(ctx context.Context, userID uuid.UUID) (*repositories.ActiveElevationRef, error) {
	if p == nil || p.store == nil {
		return nil, nil
	}
	return p.store.LatestActiveElevation(ctx, userID)
}
