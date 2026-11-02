// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tenantstatus enforces tenant suspension inside falcon-id
// (R1-GAPS row 27). tenant-management's operator Suspend/Resume writes a
// full tenant-status snapshot to the example.tenant.status topic via its
// transactional outbox; this package persists it (iam_tenant_status), exposes
// a cached Gate that the login / token / refresh / session-validation paths
// consult, and revokes every session + OAuth token of a tenant at the moment
// it is suspended.
//
// Failure policy (deliberate): the gate fails OPEN for unknown state. A tenant
// with no iam_tenant_status row, or a transient read error with nothing cached,
// is treated as NOT suspended -- only a tenant explicitly recorded as
// suspended is blocked. Failing closed on "unknown" would turn a DB blip or a
// not-yet-migrated table into a platform-wide lockout.
package tenantstatus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	pgx "github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"

	"github.com/dogukanturhal/falcon-id/internal/sessionsweep"
)

// StatusSuspended is the only status value that blocks a tenant.
const StatusSuspended = "suspended"

// EndReasonTenantSuspended is stamped on iam_sessions.end_reason when a
// suspension revokes the tenant's sessions.
const EndReasonTenantSuspended = "tenant_suspended"

// ErrProtectedTenant is returned by Apply when an event tries to suspend a
// tenant that must never be suspended (the Hexxlock internal tenant and the
// shared consumer tenant).
var ErrProtectedTenant = errors.New("tenantstatus: protected tenant cannot be suspended")

// protectedTenants mirrors tenant-management's wellKnownTenantIDs.
var protectedTenants = map[uuid.UUID]struct{}{
	uuid.MustParse("00000000-0000-0000-0000-000000000002"): {}, // Hexxlock internal
	uuid.MustParse("00000000-0000-0000-0000-000000000004"): {}, // shared consumer tenant
}

// IsProtected reports whether tenantID can never be suspended.
func IsProtected(tenantID uuid.UUID) bool {
	_, ok := protectedTenants[tenantID]
	return ok
}

// DBTX is the database surface the repository needs (*pgxpool.Pool satisfies it).
type DBTX interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
}

// Event is one decoded example.tenant.status snapshot.
type Event struct {
	TenantID     uuid.UUID
	Status       string
	Reason       string
	AccessScope  string
	EventVersion int64
	EventTime    time.Time
}

// Suspended reports whether the event puts the tenant in the blocked state.
func (e Event) Suspended() bool {
	// Trial expiry revokes trial MODULES through their canonical snapshot,
	// not the identity/recovery shell or independent operator comp grants.
	// Operator/abuse/non-payment suspension still blocks and revokes sessions.
	return e.Status == StatusSuspended && !(e.AccessScope == "trial" && e.Reason == "trial_expired")
}

// Result is the outcome of Apply.
type Result int

const (
	// ResultApplied: the event advanced the stored state.
	ResultApplied Result = iota
	// ResultSkipped: stale or duplicate event_version; nothing changed.
	ResultSkipped
)

// Repository owns SQL access to iam_tenant_status.
type Repository struct {
	db DBTX
}

// NewRepository wires a Repository.
func NewRepository(db DBTX) *Repository { return &Repository{db: db} }

const upsertSQL = `
INSERT INTO iam_tenant_status (tenant_id, suspended, status, reason, event_version, source_updated_at)
VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6)
ON CONFLICT (tenant_id) DO UPDATE
   SET suspended         = EXCLUDED.suspended,
       status            = EXCLUDED.status,
       reason            = EXCLUDED.reason,
       event_version     = EXCLUDED.event_version,
       source_updated_at = EXCLUDED.source_updated_at,
       updated_at        = now()
 WHERE iam_tenant_status.event_version < EXCLUDED.event_version
RETURNING suspended`

const revokeSessionsSQL = `
UPDATE iam_sessions s
   SET is_active = false, ended_at = NOW(), end_reason = $2
  FROM iam_users u
 WHERE s.user_id = u.id
   AND u.tenant_id = $1
   AND s.is_active = true
RETURNING s.id, s.user_id`

// Tokens are swept by the tenant's client AND by the tenant's users: a token's
// tenant_id is its client's tenant, which differs for cross-tenant clients.
const revokeOAuthTokensSQL = `
UPDATE iam_oauth_tokens
   SET is_revoked = true, revoked_at = NOW()
 WHERE is_revoked = false
   AND (tenant_id = $1
        OR user_id IN (SELECT id FROM iam_users WHERE tenant_id = $1))`

// Apply persists the event if its event_version is strictly newer than the
// stored one, and -- in the SAME transaction -- revokes every active session
// and OAuth token (access + refresh) of the tenant when the applied state is
// suspended. Atomic: a crash can never leave the tenant marked suspended with
// live sessions, nor revoke sessions without recording the suspension. A
// redelivered or out-of-order event is a no-op (ResultSkipped), so the
// revocation also runs exactly once per suspension.
//
// A suspension for a protected tenant is rejected with ErrProtectedTenant
// without touching the database.
func (r *Repository) Apply(ctx context.Context, evt Event) (Result, error) {
	if evt.Suspended() && IsProtected(evt.TenantID) {
		return ResultSkipped, ErrProtectedTenant
	}
	eventTime := evt.EventTime
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return ResultSkipped, fmt.Errorf("tenantstatus: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var suspended bool
	err = tx.QueryRow(ctx, upsertSQL,
		evt.TenantID, evt.Suspended(), evt.Status, evt.Reason, evt.EventVersion, eventTime,
	).Scan(&suspended)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResultSkipped, nil // version guard rejected it
	}
	if err != nil {
		return ResultSkipped, fmt.Errorf("tenantstatus: upsert: %w", err)
	}

	if suspended {
		if _, err := sessionsweep.End(ctx, tx, revokeSessionsSQL, EndReasonTenantSuspended, "", evt.TenantID, EndReasonTenantSuspended); err != nil {
			return ResultSkipped, fmt.Errorf("tenantstatus: revoke sessions: %w", err)
		}
		if _, err := tx.Exec(ctx, revokeOAuthTokensSQL, evt.TenantID); err != nil {
			return ResultSkipped, fmt.Errorf("tenantstatus: revoke oauth tokens: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ResultSkipped, fmt.Errorf("tenantstatus: commit: %w", err)
	}
	return ResultApplied, nil
}

// IsSuspended reads the stored state. A missing row is (false, nil): unknown
// is not suspended.
func (r *Repository) IsSuspended(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	var suspended bool
	err := r.db.QueryRow(ctx,
		`SELECT suspended FROM iam_tenant_status WHERE tenant_id = $1`, tenantID).Scan(&suspended)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("tenantstatus: read: %w", err)
	}
	return suspended, nil
}
