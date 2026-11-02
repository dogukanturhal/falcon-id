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

// PlatformElevationRepository persists iam_platform_roles and
// iam_jit_elevations rows.
type PlatformElevationRepository struct {
	pool DBPool
}

// NewPlatformElevationRepository creates a repository backed by pool.
func NewPlatformElevationRepository(pool DBPool) *PlatformElevationRepository {
	return &PlatformElevationRepository{pool: pool}
}

// ErrPlatformElevationNotFound is returned when a lookup finds no row.
var ErrPlatformElevationNotFound = errors.New("platform elevation not found")

// CreateElevation inserts a new pending (or, for break-glass, active)
// iam_jit_elevations row. Populates e.ID/CreatedAt/UpdatedAt.
func (r *PlatformElevationRepository) CreateElevation(ctx context.Context, e *models.PlatformElevation) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	now := time.Now().UTC()
	e.CreatedAt = now
	e.UpdatedAt = now

	_, err := r.pool.Exec(ctx,
		`INSERT INTO iam_jit_elevations
		 (id, requester_id, role_key, tenant_scope, reason, status,
		  approver_id, approved_at, requested_duration_seconds, expires_at,
		  is_break_glass, retroactive_approver_id, retroactive_approved_at,
		  break_glass_violation, spicedb_activate_zed_token, spicedb_revoke_zed_token,
		  created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		e.ID, e.RequesterID, string(e.RoleKey), e.TenantScope, e.Reason, string(e.Status),
		e.ApproverID, e.ApprovedAt, e.RequestedDurationSeconds, e.ExpiresAt,
		e.IsBreakGlass, e.RetroactiveApproverID, e.RetroactiveApprovedAt,
		e.BreakGlassViolation, e.SpiceDBActivateZedToken, e.SpiceDBRevokeZedToken,
		e.CreatedAt, e.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("platform_elevation_repository.CreateElevation: exec: %w", err)
	}
	return nil
}

const elevationColumns = `id, requester_id, role_key, tenant_scope, reason, status,
	approver_id, approved_at, requested_duration_seconds, expires_at,
	is_break_glass, retroactive_approver_id, retroactive_approved_at,
	break_glass_violation, spicedb_activate_zed_token, spicedb_revoke_zed_token,
	created_at, updated_at`

func scanElevation(row pgx.Row) (*models.PlatformElevation, error) {
	var e models.PlatformElevation
	var roleKey, status string
	err := row.Scan(
		&e.ID, &e.RequesterID, &roleKey, &e.TenantScope, &e.Reason, &status,
		&e.ApproverID, &e.ApprovedAt, &e.RequestedDurationSeconds, &e.ExpiresAt,
		&e.IsBreakGlass, &e.RetroactiveApproverID, &e.RetroactiveApprovedAt,
		&e.BreakGlassViolation, &e.SpiceDBActivateZedToken, &e.SpiceDBRevokeZedToken,
		&e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	e.RoleKey = models.PlatformRoleKey(roleKey)
	e.Status = models.PlatformElevationStatus(status)
	return &e, nil
}

// GetElevationByID returns a single elevation, or
// ErrPlatformElevationNotFound.
func (r *PlatformElevationRepository) GetElevationByID(ctx context.Context, id uuid.UUID) (*models.PlatformElevation, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+elevationColumns+` FROM iam_jit_elevations WHERE id = $1`, id)
	e, err := scanElevation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPlatformElevationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("platform_elevation_repository.GetElevationByID: %w", err)
	}
	return e, nil
}

// UpdateElevationStatus performs a compare-and-swap style status
// transition: it only applies when the row's CURRENT status matches
// expectedStatus, so two concurrent approve/activate calls can't both
// "win" (the second UPDATE affects zero rows and mutate returns
// ErrPlatformElevationNotFound). mutate may set any additional column.
func (r *PlatformElevationRepository) UpdateElevationStatus(
	ctx context.Context,
	id uuid.UUID,
	expectedStatus models.PlatformElevationStatus,
	newStatus models.PlatformElevationStatus,
	mutateSQL string,
	mutateArgs ...interface{},
) error {
	sql := `UPDATE iam_jit_elevations SET status = $1` + mutateSQL + ` WHERE id = $2 AND status = $3`
	// mutateSQL's extra SET clauses reference $4, $5, ... (see callers in
	// platform_jit_service.go), so mutateArgs MUST be appended AFTER the
	// $1/$2/$3 positional args, not before — a prior version of this
	// method appended mutateArgs first, which silently bound approver_id/
	// approved_at/expires_at etc. to the WRONG placeholder numbers
	// (id/expectedStatus), caught by
	// TestPlatformJITPostgres_FullLifecycle's real-Postgres run.
	args := []interface{}{string(newStatus), id, string(expectedStatus)}
	args = append(args, mutateArgs...)
	tag, err := r.pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("platform_elevation_repository.UpdateElevationStatus: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrPlatformElevationNotFound
	}
	return nil
}

// ListExpiredActive returns up to limit elevations with status='active'
// whose expires_at has passed - the auto-revoke sweep's query. Uses
// idx_iam_jit_elevations_sweep_active.
func (r *PlatformElevationRepository) ListExpiredActive(ctx context.Context, limit int) ([]*models.PlatformElevation, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+elevationColumns+` FROM iam_jit_elevations
		 WHERE status = 'active' AND expires_at < now()
		 ORDER BY expires_at ASC
		 LIMIT $1`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("platform_elevation_repository.ListExpiredActive: query: %w", err)
	}
	defer rows.Close()

	var out []*models.PlatformElevation
	for rows.Next() {
		e, err := scanElevation(rows)
		if err != nil {
			return nil, fmt.Errorf("platform_elevation_repository.ListExpiredActive: scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListBreakGlassSLAPending returns up to limit break-glass elevations that
// have not yet received retroactive approval and have not yet been
// flagged as a violation - the SLA sweep's query. Uses
// idx_iam_jit_elevations_break_glass_pending.
func (r *PlatformElevationRepository) ListBreakGlassSLAPending(ctx context.Context, limit int) ([]*models.PlatformElevation, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+elevationColumns+` FROM iam_jit_elevations
		 WHERE is_break_glass AND retroactive_approved_at IS NULL AND NOT break_glass_violation
		 ORDER BY created_at ASC
		 LIMIT $1`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("platform_elevation_repository.ListBreakGlassSLAPending: query: %w", err)
	}
	defer rows.Close()

	var out []*models.PlatformElevation
	for rows.Next() {
		e, err := scanElevation(rows)
		if err != nil {
			return nil, fmt.Errorf("platform_elevation_repository.ListBreakGlassSLAPending: scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListOpenForRequester returns pending/approved/active elevations for a
// requester (used by ListPendingElevations-style handler endpoints).
func (r *PlatformElevationRepository) ListOpenForRequester(ctx context.Context, requesterID uuid.UUID) ([]*models.PlatformElevation, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+elevationColumns+` FROM iam_jit_elevations
		 WHERE requester_id = $1 AND status IN ('pending','approved','active')
		 ORDER BY created_at DESC`, requesterID,
	)
	if err != nil {
		return nil, fmt.Errorf("platform_elevation_repository.ListOpenForRequester: query: %w", err)
	}
	defer rows.Close()

	var out []*models.PlatformElevation
	for rows.Next() {
		e, err := scanElevation(rows)
		if err != nil {
			return nil, fmt.Errorf("platform_elevation_repository.ListOpenForRequester: scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListPendingApprovals returns every elevation awaiting approval
// (status='pending', not break-glass - break-glass never waits for
// approval, only retroactive approval).
func (r *PlatformElevationRepository) ListPendingApprovals(ctx context.Context) ([]*models.PlatformElevation, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+elevationColumns+` FROM iam_jit_elevations
		 WHERE status = 'pending' AND NOT is_break_glass
		 ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("platform_elevation_repository.ListPendingApprovals: query: %w", err)
	}
	defer rows.Close()

	var out []*models.PlatformElevation
	for rows.Next() {
		e, err := scanElevation(rows)
		if err != nil {
			return nil, fmt.Errorf("platform_elevation_repository.ListPendingApprovals: scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- iam_platform_roles ---

// UpsertPlatformRole inserts (or, on user_id+role_key conflict, touches)
// a standing platform-role row. Goes through the same DB path whether it's
// a standing platform_viewer grant or a JIT-materialized role - the
// iam_platform_roles_enforce trigger (migration 0016) rejects the latter
// unless a matching active elevation already exists, so callers MUST
// activate the elevation row first in the same transaction.
func (r *PlatformElevationRepository) UpsertPlatformRole(ctx context.Context, role *models.PlatformRole) error {
	if role.GrantedAt.IsZero() {
		role.GrantedAt = time.Now().UTC()
	}
	_, err := r.pool.Exec(ctx,
		`INSERT INTO iam_platform_roles (user_id, role_key, granted_at, granted_by)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (user_id, role_key) DO UPDATE SET granted_at = EXCLUDED.granted_at, granted_by = EXCLUDED.granted_by`,
		role.UserID, string(role.RoleKey), role.GrantedAt, role.GrantedBy,
	)
	if err != nil {
		return fmt.Errorf("platform_elevation_repository.UpsertPlatformRole: exec: %w", err)
	}
	return nil
}

// DeletePlatformRole removes a materialized (JIT or break-glass) platform
// role row. Idempotent (DELETE of an absent row is a no-op).
func (r *PlatformElevationRepository) DeletePlatformRole(ctx context.Context, userID uuid.UUID, roleKey models.PlatformRoleKey) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM iam_platform_roles WHERE user_id = $1 AND role_key = $2`,
		userID, string(roleKey),
	)
	if err != nil {
		return fmt.Errorf("platform_elevation_repository.DeletePlatformRole: exec: %w", err)
	}
	return nil
}

// --- iam_jit_elevation_transitions (append-only hash chain) ---

// LastTransitionHash returns the entry_hash of the most recent transition
// row for elevationID, or "" if there is none yet (first transition in
// the chain).
func (r *PlatformElevationRepository) LastTransitionHash(ctx context.Context, elevationID uuid.UUID) (string, error) {
	var hash string
	err := r.pool.QueryRow(ctx,
		`SELECT entry_hash FROM iam_jit_elevation_transitions
		 WHERE elevation_id = $1 ORDER BY occurred_at DESC, id DESC LIMIT 1`,
		elevationID,
	).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("platform_elevation_repository.LastTransitionHash: %w", err)
	}
	return hash, nil
}

// AppendTransition inserts one append-only hash-chain row.
func (r *PlatformElevationRepository) AppendTransition(
	ctx context.Context,
	elevationID uuid.UUID,
	fromStatus *string,
	toStatus string,
	actorID *uuid.UUID,
	occurredAt time.Time,
	prevHash, entryHash string,
	detailsJSON []byte,
) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO iam_jit_elevation_transitions
		 (elevation_id, from_status, to_status, actor_id, occurred_at, prev_hash, entry_hash, details)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		elevationID, fromStatus, toStatus, actorID, occurredAt, prevHash, entryHash, detailsJSON,
	)
	if err != nil {
		return fmt.Errorf("platform_elevation_repository.AppendTransition: exec: %w", err)
	}
	return nil
}

// SetRetroactiveApproval records break-glass retroactive approval.
// Idempotent: a second call on an already-approved row is a no-op
// (WHERE retroactive_approved_at IS NULL guards it) - matches
// RetroactivelyApprove's own idempotent short-circuit in the service.
func (r *PlatformElevationRepository) SetRetroactiveApproval(ctx context.Context, elevationID, approverID uuid.UUID, approvedAt time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_jit_elevations
		 SET retroactive_approver_id = $1, retroactive_approved_at = $2
		 WHERE id = $3 AND retroactive_approved_at IS NULL`,
		approverID, approvedAt, elevationID,
	)
	if err != nil {
		return fmt.Errorf("platform_elevation_repository.SetRetroactiveApproval: exec: %w", err)
	}
	return nil
}

// FlagBreakGlassViolation sets break_glass_violation = true. Idempotent
// (WHERE NOT break_glass_violation guards a re-run of the SLA sweep from
// double-counting the metric for an already-flagged row - callers should
// check the returned RowsAffected-equivalent by checking the error is nil
// AND re-reading, but in practice the sweep only calls this once per row
// per pass because ListBreakGlassSLAPending excludes already-flagged rows).
func (r *PlatformElevationRepository) FlagBreakGlassViolation(ctx context.Context, elevationID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_jit_elevations SET break_glass_violation = true WHERE id = $1 AND NOT break_glass_violation`,
		elevationID,
	)
	if err != nil {
		return fmt.Errorf("platform_elevation_repository.FlagBreakGlassViolation: exec: %w", err)
	}
	return nil
}

// GetUserTenantID resolves a user's tenant_id. Satisfies
// services.platformUserTenantLookup - PlatformElevationRepository itself
// is passed as that dependency at wiring time, avoiding a second
// repository just for this one lookup.
func (r *PlatformElevationRepository) GetUserTenantID(ctx context.Context, userID uuid.UUID) (uuid.UUID, error) {
	var tenantID uuid.UUID
	err := r.pool.QueryRow(ctx, `SELECT tenant_id FROM iam_users WHERE id = $1`, userID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrPlatformElevationNotFound
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("platform_elevation_repository.GetUserTenantID: %w", err)
	}
	return tenantID, nil
}

// ListPlatformRoles returns every standing iam_platform_roles row.
func (r *PlatformElevationRepository) ListPlatformRoles(ctx context.Context) ([]*models.PlatformRole, error) {
	rows, err := r.pool.Query(ctx, `SELECT user_id, role_key, granted_at, granted_by FROM iam_platform_roles ORDER BY granted_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("platform_elevation_repository.ListPlatformRoles: query: %w", err)
	}
	defer rows.Close()

	var out []*models.PlatformRole
	for rows.Next() {
		var role models.PlatformRole
		var roleKey string
		if err := rows.Scan(&role.UserID, &roleKey, &role.GrantedAt, &role.GrantedBy); err != nil {
			return nil, fmt.Errorf("platform_elevation_repository.ListPlatformRoles: scan: %w", err)
		}
		role.RoleKey = models.PlatformRoleKey(roleKey)
		out = append(out, &role)
	}
	return out, rows.Err()
}

// --- Filtered/paginated listings (GET /internal/v1/jit-elevations, ---
// --- GET /internal/v1/break-glass)                                 ---

// ListElevations returns a filtered, paginated page of iam_jit_elevations
// rows, newest first, along with the total row count matching the
// filter (for pagination metadata). filter.BreakGlassOnly distinguishes
// the /jit-elevations listing (false) from the /break-glass listing
// (true) — see ElevationListFilter's doc comment. limit/offset are
// caller-validated (handler clamps limit to a sane cap); a limit <= 0
// here would produce an invalid `LIMIT 0` clause deliberately (no rows),
// so callers must not pass one.
func (r *PlatformElevationRepository) ListElevations(
	ctx context.Context,
	filter models.ElevationListFilter,
	limit, offset int,
) (models.ElevationListPage, error) {
	where := "WHERE 1=1"
	args := []interface{}{}
	if filter.BreakGlassOnly != nil {
		args = append(args, *filter.BreakGlassOnly)
		where += fmt.Sprintf(" AND is_break_glass = $%d", len(args))
	}
	if filter.Status != nil {
		args = append(args, string(*filter.Status))
		where += fmt.Sprintf(" AND status = $%d", len(args))
	}
	if filter.RequesterID != nil {
		args = append(args, *filter.RequesterID)
		where += fmt.Sprintf(" AND requester_id = $%d", len(args))
	}

	var total int
	countSQL := `SELECT count(*) FROM iam_jit_elevations ` + where
	if err := r.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return models.ElevationListPage{}, fmt.Errorf("platform_elevation_repository.ListElevations: count: %w", err)
	}

	pageArgs := append(append([]interface{}{}, args...), limit, offset)
	listSQL := fmt.Sprintf(
		`SELECT %s FROM iam_jit_elevations %s ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d`,
		elevationColumns, where, len(pageArgs)-1, len(pageArgs),
	)
	rows, err := r.pool.Query(ctx, listSQL, pageArgs...)
	if err != nil {
		return models.ElevationListPage{}, fmt.Errorf("platform_elevation_repository.ListElevations: query: %w", err)
	}
	defer rows.Close()

	var items []*models.PlatformElevation
	for rows.Next() {
		e, err := scanElevation(rows)
		if err != nil {
			return models.ElevationListPage{}, fmt.Errorf("platform_elevation_repository.ListElevations: scan: %w", err)
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return models.ElevationListPage{}, fmt.Errorf("platform_elevation_repository.ListElevations: rows: %w", err)
	}
	return models.ElevationListPage{Items: items, Total: total}, nil
}

// --- iam_jit_elevation_transitions (read side / audit endpoint) ---

// ListTransitions returns a paginated page of append-only hash-chain
// transition rows, newest first, optionally scoped to one elevation. It
// never mutates the chain — the only writer remains AppendTransition.
func (r *PlatformElevationRepository) ListTransitions(
	ctx context.Context,
	elevationID *uuid.UUID,
	limit, offset int,
) (models.TransitionListPage, error) {
	where := "WHERE 1=1"
	args := []interface{}{}
	if elevationID != nil {
		args = append(args, *elevationID)
		where += fmt.Sprintf(" AND elevation_id = $%d", len(args))
	}

	var total int
	countSQL := `SELECT count(*) FROM iam_jit_elevation_transitions ` + where
	if err := r.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return models.TransitionListPage{}, fmt.Errorf("platform_elevation_repository.ListTransitions: count: %w", err)
	}

	pageArgs := append(append([]interface{}{}, args...), limit, offset)
	listSQL := fmt.Sprintf(
		`SELECT id, elevation_id, from_status, to_status, actor_id, occurred_at, prev_hash, entry_hash, details
		 FROM iam_jit_elevation_transitions %s
		 ORDER BY occurred_at DESC, id DESC LIMIT $%d OFFSET $%d`,
		where, len(pageArgs)-1, len(pageArgs),
	)
	rows, err := r.pool.Query(ctx, listSQL, pageArgs...)
	if err != nil {
		return models.TransitionListPage{}, fmt.Errorf("platform_elevation_repository.ListTransitions: query: %w", err)
	}
	defer rows.Close()

	var items []*models.PlatformElevationTransition
	for rows.Next() {
		var t models.PlatformElevationTransition
		if err := rows.Scan(
			&t.ID, &t.ElevationID, &t.FromStatus, &t.ToStatus, &t.ActorID,
			&t.OccurredAt, &t.PrevHash, &t.EntryHash, &t.Details,
		); err != nil {
			return models.TransitionListPage{}, fmt.Errorf("platform_elevation_repository.ListTransitions: scan: %w", err)
		}
		items = append(items, &t)
	}
	if err := rows.Err(); err != nil {
		return models.TransitionListPage{}, fmt.Errorf("platform_elevation_repository.ListTransitions: rows: %w", err)
	}
	return models.TransitionListPage{Items: items, Total: total}, nil
}
