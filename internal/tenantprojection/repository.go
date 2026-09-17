// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantprojection

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	pgx "github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

// DBTX is the minimal database interface required by Repository.
// Both *pgxpool.Pool and pgxmock.PgxPoolIface satisfy this interface,
// enabling unit tests without a real database.
type DBTX interface {
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// TenantEvent is the decoded payload from a tenant.created or tenant.updated
// Envelope's `data` field. The fields here map 1-to-1 with the iam_tenants
// columns that this reverse projection actually writes (status + metadata).
//
// Phase 3.2 (ADR 0029): Plan and Type were dropped from this struct after
// the iam_tenants.plan + iam_tenants.type columns were physically removed
// by the GitOps repository !699. The wire envelope (tenantPayload in
// subscriber.go) still tolerates those fields on the producer side for
// backward compatibility, but the projection consumer no longer reads or
// stores them — the local `tenants` table in platform-core is the
// canonical source of truth for both.
type TenantEvent struct {
	ID        uuid.UUID
	Status    string
	Metadata  []byte    // raw JSON; nil means "do not overwrite existing metadata"
	EventTime time.Time // used as the idempotency / monotonic version guard
}

// Repository owns all SQL access to iam_tenants for the reverse projection.
//
// Design constraints (per ADR 0029 Phase 1a):
//   - ApplyTenantUpsert is UPDATE-only. It never INSERTs. The signup adapter
//     (internal/repositories/tenant_repository.go:Create) is the only valid
//     INSERT path. If the tenant row does not exist, the call returns
//     UpsertResultOrphan.
//   - Idempotency guard: WHERE updated_at < eventTime rejects stale events.
//   - ApplyTenantDelete soft-deletes and is idempotent (already-deleted → skipped).
type Repository struct {
	db DBTX
}

// NewRepository creates a projection Repository backed by the given DBTX.
// Accepts *pgxpool.Pool in production; pgxmock in tests.
func NewRepository(db DBTX) *Repository {
	return &Repository{db: db}
}

// UpsertResult reports the outcome of an ApplyTenantUpsert or ApplyTenantDelete call.
type UpsertResult int

const (
	// UpsertResultApplied means the UPDATE touched one row.
	UpsertResultApplied UpsertResult = iota
	// UpsertResultSkipped means the row exists but is already at or beyond
	// the incoming event's timestamp (stale or duplicate event).
	UpsertResultSkipped
	// UpsertResultOrphan means no row with this tenant_id exists in iam_tenants.
	// This is a WARN-level anomaly: the signup adapter must run before the
	// projection consumer can update the row.
	UpsertResultOrphan
)

// ApplyTenantUpsert patches iam_tenants with status/metadata from the Kafka
// event. Plan + Type carried in the event are intentionally NOT written —
// see the Phase 3.1 note inside the function body. It returns:
//   - (UpsertResultApplied, nil) — row found and updated.
//   - (UpsertResultSkipped, nil) — row found, event is stale; no-op.
//   - (UpsertResultOrphan, nil)  — row not found; caller WARN-logs and skips.
//   - (_, non-nil error)         — genuine DB failure; caller retries.
func (r *Repository) ApplyTenantUpsert(ctx context.Context, evt TenantEvent) (UpsertResult, error) {
	// Phase 1: existence probe. We separate existence from the UPDATE so we
	// can distinguish "no row" (orphan) from "row exists but updated_at guard
	// fired" (stale). A single UPDATE-WHERE cannot distinguish these two cases
	// because both yield RowsAffected == 0.
	exists, err := r.tenantExists(ctx, evt.ID)
	if err != nil {
		return UpsertResultOrphan, fmt.Errorf("ApplyTenantUpsert: existence check: %w", err)
	}
	if !exists {
		return UpsertResultOrphan, nil
	}

	// Phase 2: conditional UPDATE. Only advances when the event timestamp is
	// strictly newer than the stored updated_at, guaranteeing that concurrent
	// pods in the same consumer group (or a restart replay) never regress state.
	//
	// Phase 3.1 (ADR 0029): plan + type columns are intentionally NOT written.
	// Those columns are scheduled for removal from iam_tenants in Phase 3 (the
	// local `tenants` table in platform-core's tenant-management database is
	// the canonical SoR for both). Continuing to write them here would either
	//   - fail with SQLSTATE 42703 after Phase 3 drops the columns, or
	//   - re-introduce divergence if the consumer ever raced a Phase 1b writer.
	// The event still carries Plan + Type for wire compatibility; we just
	// discard them here. Status and metadata remain because legacy IAM
	// readers (account lock / suspension UX) still pivot on them.
	//
	// Metadata: $3 is a text parameter that Postgres casts to jsonb. We pass
	// NULL when the caller supplies no metadata, so the column value is
	// preserved exactly as the signup adapter left it.
	const q = `
		UPDATE iam_tenants
		SET
			status     = $2,
			metadata   = CASE
				WHEN $3::text IS NOT NULL THEN $3::text::jsonb
				ELSE metadata
			END,
			updated_at = NOW()
		WHERE id         = $1
		  AND updated_at < $4
	`
	var metaArg interface{}
	if len(evt.Metadata) > 0 {
		metaArg = string(evt.Metadata)
	}

	tag, err := r.db.Exec(ctx, q,
		evt.ID,
		evt.Status,
		metaArg, // nil = NULL in pgx
		evt.EventTime,
	)
	if err != nil {
		return UpsertResultOrphan, fmt.Errorf("ApplyTenantUpsert: exec: %w", err)
	}

	if tag.RowsAffected() == 0 {
		// Row exists (confirmed above) but updated_at >= eventTime.
		return UpsertResultSkipped, nil
	}
	return UpsertResultApplied, nil
}

// ApplyTenantDelete soft-deletes a tenant by setting status='deleted'. The
// WHERE status != 'deleted' clause makes the call idempotent: a second delete
// on an already-deleted tenant returns UpsertResultSkipped.
func (r *Repository) ApplyTenantDelete(ctx context.Context, tenantID uuid.UUID) (UpsertResult, error) {
	exists, err := r.tenantExists(ctx, tenantID)
	if err != nil {
		return UpsertResultOrphan, fmt.Errorf("ApplyTenantDelete: existence check: %w", err)
	}
	if !exists {
		return UpsertResultOrphan, nil
	}

	const q = `
		UPDATE iam_tenants
		SET    status     = 'deleted',
		       updated_at = NOW()
		WHERE  id         = $1
		  AND  status    != 'deleted'
	`
	tag, err := r.db.Exec(ctx, q, tenantID)
	if err != nil {
		return UpsertResultOrphan, fmt.Errorf("ApplyTenantDelete: exec: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return UpsertResultSkipped, nil
	}
	return UpsertResultApplied, nil
}

// tenantExists returns true when a row with the given id is present in
// iam_tenants, regardless of status or plan.
//
// We check for both pgx.ErrNoRows (returned by pgxpool.Pool) AND the
// error message string "no rows in result set" (returned by pgxmock in
// test mode) so the repository works identically in both environments.
func (r *Repository) tenantExists(ctx context.Context, id uuid.UUID) (bool, error) {
	const q = `SELECT 1 FROM iam_tenants WHERE id = $1 LIMIT 1`
	var sentinel int
	err := r.db.QueryRow(ctx, q, id).Scan(&sentinel)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) || err.Error() == "no rows in result set" {
		return false, nil
	}
	return false, fmt.Errorf("tenantExists: %w", err)
}
