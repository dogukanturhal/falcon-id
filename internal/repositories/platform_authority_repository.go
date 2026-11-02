// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// PlatformAuthorityRepository answers "which platform-plane roles does this
// user hold RIGHT NOW" from iam_platform_roles (the standing viewer row plus
// rows materialised by active JIT elevations / break-glass grants). It backs
// OPS_STRICT_PLATFORM_ROLES, the operator token exchange and the legacy-admin
// report.
//
// iam_platform_roles / iam_jit_elevations are forced-RLS tables with a
// fixed-internal-tenant policy, so every read runs in a short transaction
// that sets app.current_tenant_id to the internal tenant first.
type PlatformAuthorityRepository struct {
	pool DBPool
}

// NewPlatformAuthorityRepository creates a repository backed by pool.
func NewPlatformAuthorityRepository(pool DBPool) *PlatformAuthorityRepository {
	return &PlatformAuthorityRepository{pool: pool}
}

// ActiveElevationRef is the elevation backing a non-viewer platform role.
type ActiveElevationRef struct {
	ID        uuid.UUID
	RoleKey   string
	ExpiresAt time.Time
}

func (r *PlatformAuthorityRepository) inPlatformTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("platform_authority_repository: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant_id', $1, true)`, models.HexxlockInternalTenantID); err != nil {
		return fmt.Errorf("platform_authority_repository: set tenant: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ActiveRoles returns the user's platform role keys that are in force now:
// the standing platform_viewer row, plus any other role whose iam_platform_roles
// row is backed by an active, unexpired elevation.
func (r *PlatformAuthorityRepository) ActiveRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	var roles []string
	err := r.inPlatformTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT pr.role_key
			  FROM iam_platform_roles pr
			 WHERE pr.user_id = $1
			   AND (pr.role_key = 'platform_viewer'
			        OR EXISTS (SELECT 1 FROM iam_jit_elevations e
			                    WHERE e.requester_id = pr.user_id
			                      AND e.role_key = pr.role_key
			                      AND e.status = 'active'
			                      AND e.expires_at > now()))`, userID)
		if err != nil {
			return fmt.Errorf("platform_authority_repository.ActiveRoles: query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				return fmt.Errorf("platform_authority_repository.ActiveRoles: scan: %w", err)
			}
			roles = append(roles, k)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return roles, nil
}

// HasStandingRole reports whether user holds an iam_platform_roles row for
// roleKey, regardless of any backing elevation. Only the break-glass account
// is allowed to rely on this (see PlatformAuthority.ActiveRolesFor).
func (r *PlatformAuthorityRepository) HasStandingRole(ctx context.Context, userID uuid.UUID, roleKey string) (bool, error) {
	var ok bool
	err := r.inPlatformTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM iam_platform_roles WHERE user_id = $1 AND role_key = $2)`,
			userID, roleKey).Scan(&ok); err != nil {
			return fmt.Errorf("platform_authority_repository.HasStandingRole: %w", err)
		}
		return nil
	})
	return ok, err
}

// LatestActiveElevation returns the active elevation with the latest expiry
// for the user, or nil when none is active (viewer-only sessions).
func (r *PlatformAuthorityRepository) LatestActiveElevation(ctx context.Context, userID uuid.UUID) (*ActiveElevationRef, error) {
	var ref *ActiveElevationRef
	err := r.inPlatformTx(ctx, func(tx pgx.Tx) error {
		var e ActiveElevationRef
		err := tx.QueryRow(ctx, `
			SELECT id, role_key, expires_at
			  FROM iam_jit_elevations
			 WHERE requester_id = $1 AND status = 'active' AND expires_at > now()
			 ORDER BY expires_at DESC
			 LIMIT 1`, userID).Scan(&e.ID, &e.RoleKey, &e.ExpiresAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("platform_authority_repository.LatestActiveElevation: %w", err)
		}
		ref = &e
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ref, nil
}

// InternalUserAuthority is one internal-tenant user in the legacy-admin report.
type InternalUserAuthority struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
	IsActive bool      `json:"is_active"`
	// PlatformRoles are the iam_platform_roles rows currently present.
	PlatformRoles []string `json:"platform_roles"`
	// LegacyRoles are the tenant-role names (platform_admin / iam_admin) that
	// today's bypass accepts - the access that OPS_STRICT_PLATFORM_ROLES removes.
	LegacyRoles []string `json:"legacy_roles"`
}

// ListInternalUsers returns every internal-tenant user with the platform
// rows and legacy admin roles they hold.
func (r *PlatformAuthorityRepository) ListInternalUsers(ctx context.Context) ([]InternalUserAuthority, error) {
	var out []InternalUserAuthority
	err := r.inPlatformTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT u.id, u.email, u.username, u.is_active,
			       COALESCE((SELECT array_agg(pr.role_key ORDER BY pr.role_key)
			                   FROM iam_platform_roles pr WHERE pr.user_id = u.id), '{}'),
			       COALESCE((SELECT array_agg(DISTINCT ro.name ORDER BY ro.name)
			                   FROM iam_user_roles ur
			                   JOIN iam_roles ro ON ro.id = ur.role_id
			                  WHERE ur.user_id = u.id
			                    AND (ur.expires_at IS NULL OR ur.expires_at > now())
			                    AND lower(ro.name) IN ('platform_admin', 'iam_admin')), '{}')
			  FROM iam_users u
			 WHERE u.tenant_id = $1
			 ORDER BY lower(u.email)`, uuid.MustParse(models.HexxlockInternalTenantID))
		if err != nil {
			return fmt.Errorf("platform_authority_repository.ListInternalUsers: query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var u InternalUserAuthority
			if err := rows.Scan(&u.UserID, &u.Email, &u.Username, &u.IsActive, &u.PlatformRoles, &u.LegacyRoles); err != nil {
				return fmt.Errorf("platform_authority_repository.ListInternalUsers: scan: %w", err)
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
