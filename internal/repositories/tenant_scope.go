// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WithTenantScope runs fn in a transaction whose app.current_tenant_id is
// tenantID. iam_user_memberships and tenant_seat_counters have FORCE RLS
// with a tenant-only policy (0013) and falcon_id_app is NOBYPASSRLS, so any
// statement against them outside such a scope sees and changes nothing.
// The guest/R1 write paths (invitation accept from a partner tenant, seat
// counters, external-member list/revoke, the expiry sweep, the internal
// seat-limit API, the SpiceDB reconciler) run on the raw pool or inside a
// transaction that never had the GUC set, so the repositories that own those
// tables scope every statement themselves through this helper.
//
// When db is already a pgx.Tx, Begin opens a savepoint: the statements stay
// in the caller's transaction (all-or-nothing is preserved) and the GUC,
// set with set_config(..., true), stays transaction-local either way so it
// never leaks onto a pooled connection.
func WithTenantScope(ctx context.Context, db DBTX, tenantID uuid.UUID, fn func(pgx.Tx) error) error {
	if tenantID == uuid.Nil {
		return errors.New("WithTenantScope: nil tenant id")
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("WithTenantScope: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit makes rollback a no-op
	if err := setTenantScope(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("WithTenantScope: commit: %w", err)
	}
	return nil
}

func setTenantScope(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID.String()); err != nil {
		return fmt.Errorf("set app.current_tenant_id: %w", err)
	}
	var actual string
	if err := tx.QueryRow(ctx, "SELECT current_setting('app.current_tenant_id', true)").Scan(&actual); err != nil {
		return fmt.Errorf("verify app.current_tenant_id: %w", err)
	}
	if actual != tenantID.String() {
		return fmt.Errorf("verify app.current_tenant_id: expected %s, got %q", tenantID, actual)
	}
	return nil
}
