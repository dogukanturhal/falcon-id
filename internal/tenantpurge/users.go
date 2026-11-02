// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantpurge

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	sharedpurge "github.com/dogukanturhal/platform-shared/tenantpurge"
)

// userPlan classifies the accounts around a tenant that is being purged.
type userPlan struct {
	// Delete are home users of the tenant with no membership anywhere else: the
	// account is erased.
	Delete []string
	// Rehome maps home users that also belong to a surviving tenant to the tenant
	// that becomes their home. The account is kept, only the membership here goes.
	Rehome map[string]string
	// Visitors counts users with a membership here whose home is another tenant;
	// only the membership (and its roles) is released.
	Visitors int64
}

const pgFKViolation = "23503"
const pgInsufficientPrivilege = "42501"

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func scanStrings(ctx context.Context, tx sharedpurge.Tx, q string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func scanCount(ctx context.Context, tx sharedpurge.Tx, q string, args ...any) (int64, error) {
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var n int64
	if rows.Next() {
		if err := rows.Scan(&n); err != nil {
			return 0, err
		}
	}
	return n, rows.Err()
}

func setTenantScope(ctx context.Context, tx sharedpurge.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID)
	return err
}

// classifyUsers reads the tenant's accounts. tx must be scoped to tenantID
// (app.current_tenant_id). iam_user_memberships is FORCE RLS keyed on that setting,
// so memberships in other tenants are read by scoping the transaction to each
// surviving tenant in turn; the scope is restored to tenantID before returning.
func classifyUsers(ctx context.Context, tx sharedpurge.Tx, tenantID string) (userPlan, error) {
	plan := userPlan{Rehome: map[string]string{}}
	home, err := scanStrings(ctx, tx, `SELECT id::text FROM iam_users WHERE tenant_id = $1::uuid`, tenantID)
	if err != nil {
		return plan, fmt.Errorf("list home users: %w", err)
	}
	if home == nil {
		home = []string{} // a nil slice would bind as NULL
	}
	plan.Visitors, err = scanCount(ctx, tx,
		`SELECT count(*) FROM iam_user_memberships WHERE tenant_id = $1::uuid AND NOT (user_id = ANY($2::text[]::uuid[]))`,
		tenantID, home)
	if err != nil {
		return plan, fmt.Errorf("count visiting members: %w", err)
	}
	if len(home) == 0 {
		return plan, nil
	}

	others, err := scanStrings(ctx, tx, `SELECT id::text FROM iam_tenants WHERE id <> $1::uuid ORDER BY created_at, id`, tenantID)
	if err != nil {
		return plan, fmt.Errorf("list surviving tenants: %w", err)
	}
	for _, other := range others {
		if err := setTenantScope(ctx, tx, other); err != nil {
			return plan, fmt.Errorf("scope to surviving tenant: %w", err)
		}
		// Prefer an active membership, then the oldest one.
		rows, err := tx.Query(ctx,
			`SELECT user_id::text FROM iam_user_memberships WHERE user_id = ANY($1::text[]::uuid[]) ORDER BY (status = 'active') DESC, created_at`,
			home)
		if err != nil {
			return plan, fmt.Errorf("read memberships: %w", err)
		}
		for rows.Next() {
			var uid string
			if err := rows.Scan(&uid); err != nil {
				rows.Close()
				return plan, fmt.Errorf("read memberships: %w", err)
			}
			if _, ok := plan.Rehome[uid]; !ok {
				plan.Rehome[uid] = other
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return plan, fmt.Errorf("read memberships: %w", err)
		}
	}
	if err := setTenantScope(ctx, tx, tenantID); err != nil {
		return plan, fmt.Errorf("restore tenant scope: %w", err)
	}
	for _, uid := range home {
		if _, ok := plan.Rehome[uid]; !ok {
			plan.Delete = append(plan.Delete, uid)
		}
	}
	return plan, nil
}

// retainedAudit are the security-log tables whose rows survive the purge; their
// user references are anonymised instead of deleted.
var retainedAudit = []string{
	"iam_audit_log", "iam_admin_audit_log", "realm_audit_log", "iam_idp_scope_audit_log", "immutable_audit_log",
}

// immutableTables hold append-only evidence a DB trigger refuses to change; they
// are neither touched nor swept.
var immutableTables = map[string]struct{}{"platform_admin_audit_log": {}, "iam_jit_elevation_transitions": {}}

func isRetainedAudit(table string) bool {
	for _, t := range retainedAudit {
		if t == table {
			return true
		}
	}
	return strings.HasPrefix(table, "iam_audit_log_") // partitions of the legacy partitioned log
}

// savepoint runs fn inside a savepoint and rolls back to it on error.
func savepoint(ctx context.Context, tx sharedpurge.Tx, fn func() error) error {
	if _, err := tx.Exec(ctx, "SAVEPOINT tenant_purge_sp"); err != nil {
		return err
	}
	if err := fn(); err != nil {
		if _, rerr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT tenant_purge_sp"); rerr != nil {
			return rerr
		}
		_, _ = tx.Exec(ctx, "RELEASE SAVEPOINT tenant_purge_sp")
		return err
	}
	_, err := tx.Exec(ctx, "RELEASE SAVEPOINT tenant_purge_sp")
	return err
}

// rehomeUsers moves kept accounts to the surviving tenant that becomes their home.
func rehomeUsers(ctx context.Context, tx sharedpurge.Tx, tenantID string, plan userPlan) error {
	for uid, target := range plan.Rehome {
		n, err := tx.Exec(ctx, `UPDATE iam_users SET tenant_id = $2::uuid, updated_at = now() WHERE id = $1::uuid AND tenant_id = $3::uuid`, uid, target, tenantID)
		if err != nil {
			return fmt.Errorf("re-home kept account: %w", err)
		}
		if n != 1 {
			return fmt.Errorf("re-home kept account: %d rows updated, want 1", n)
		}
	}
	return nil
}

// anonymiseAudit strips actor PII from the retained security log of the tenant.
// The hash chain covers sequence, tenant, action, time and details only, so it
// stays verifiable. A role without UPDATE on the log is tolerated (warned by the
// caller): the rows are kept either way.
func anonymiseAudit(ctx context.Context, tx sharedpurge.Tx, tenantID string) (skipped bool, err error) {
	err = savepoint(ctx, tx, func() error {
		_, e := tx.Exec(ctx, `UPDATE iam_audit_log SET user_id = NULL, target_user_id = NULL, ip_address = NULL, user_agent = NULL, country_code = NULL
WHERE tenant_id = $1::uuid AND (user_id IS NOT NULL OR target_user_id IS NOT NULL OR ip_address IS NOT NULL OR user_agent IS NOT NULL OR country_code IS NOT NULL)`, tenantID)
		return e
	})
	if pgCode(err) == pgInsufficientPrivilege {
		return true, nil
	}
	return false, err
}

type userColumn struct {
	Table, Column string
	Nullable      bool
}

// eraseUserReferences removes everything that still points at the accounts about
// to be deleted: first rows behind NO ACTION/RESTRICT foreign keys to iam_users
// (retrying in rounds, children before parents), then the widened sweep over
// every other uuid column named like a user reference. Retained security-log
// tables get the reference nulled instead.
func eraseUserReferences(ctx context.Context, tx sharedpurge.Tx, ids []string) (map[string]int64, error) {
	counts := map[string]int64{}
	if len(ids) == 0 {
		return counts, nil
	}
	fkRows, err := tx.Query(ctx, `SELECT cc.relname, a.attname, k.confdeltype::text
FROM pg_constraint k
JOIN pg_class cc ON cc.oid = k.conrelid
JOIN pg_namespace n ON n.oid = cc.relnamespace
JOIN pg_class pc ON pc.oid = k.confrelid
JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = k.conkey[1]
WHERE k.contype = 'f' AND n.nspname = 'public' AND pc.relname = 'iam_users' AND pc.relnamespace = n.oid
  AND array_length(k.conkey, 1) = 1 AND k.conparentid = 0 AND cc.relname <> 'iam_users'`)
	if err != nil {
		return nil, fmt.Errorf("list user foreign keys: %w", err)
	}
	fkCols := map[string]struct{}{}
	var blocking []userColumn
	for fkRows.Next() {
		var table, col, rule string
		if err := fkRows.Scan(&table, &col, &rule); err != nil {
			fkRows.Close()
			return nil, fmt.Errorf("list user foreign keys: %w", err)
		}
		fkCols[table+"."+col] = struct{}{}
		if rule == "a" || rule == "r" {
			blocking = append(blocking, userColumn{Table: table, Column: col})
		}
	}
	err = fkRows.Err()
	fkRows.Close()
	if err != nil {
		return nil, fmt.Errorf("list user foreign keys: %w", err)
	}

	// Blocking children: delete in rounds; a delete that hits another foreign key
	// waits until that child was cleared.
	pending := blocking
	for len(pending) > 0 {
		var next []userColumn
		for _, uc := range pending {
			if _, immutable := immutableTables[uc.Table]; immutable {
				return nil, fmt.Errorf("append-only table %s references an account being deleted", uc.Table)
			}
			var n int64
			err := savepoint(ctx, tx, func() error {
				var e error
				n, e = tx.Exec(ctx, "DELETE FROM "+quoteIdent(uc.Table)+" WHERE "+quoteIdent(uc.Column)+" = ANY($1::text[]::uuid[])", ids)
				return e
			})
			switch {
			case err == nil:
				counts[uc.Table] += n
			case pgCode(err) == pgFKViolation:
				next = append(next, uc)
			default:
				return nil, fmt.Errorf("delete %s rows of deleted accounts: %w", uc.Table, err)
			}
		}
		if len(next) == len(pending) {
			return nil, fmt.Errorf("cannot clear user references: %d tables still blocked (first: %s.%s)", len(next), next[0].Table, next[0].Column)
		}
		pending = next
	}

	// Widened sweep: user-reference columns without a foreign key to iam_users.
	colRows, err := tx.Query(ctx, `SELECT c.table_name, c.column_name, c.is_nullable
FROM information_schema.columns c
JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE' AND c.data_type = 'uuid'
  AND (c.column_name IN ('user_id', 'target_user_id') OR c.column_name LIKE '%\_user\_id')
ORDER BY c.table_name, c.column_name`)
	if err != nil {
		return nil, fmt.Errorf("list user columns: %w", err)
	}
	var loose []userColumn
	for colRows.Next() {
		var table, col, nullable string
		if err := colRows.Scan(&table, &col, &nullable); err != nil {
			colRows.Close()
			return nil, fmt.Errorf("list user columns: %w", err)
		}
		if _, ok := fkCols[table+"."+col]; ok {
			continue
		}
		if _, immutable := immutableTables[table]; immutable {
			continue
		}
		loose = append(loose, userColumn{Table: table, Column: col, Nullable: nullable == "YES"})
	}
	err = colRows.Err()
	colRows.Close()
	if err != nil {
		return nil, fmt.Errorf("list user columns: %w", err)
	}
	for _, uc := range loose {
		var n int64
		var e error
		switch {
		case isRetainedAudit(uc.Table):
			if !uc.Nullable {
				continue
			}
			e = savepoint(ctx, tx, func() error {
				var ue error
				n, ue = tx.Exec(ctx, "UPDATE "+quoteIdent(uc.Table)+" SET "+quoteIdent(uc.Column)+" = NULL WHERE "+quoteIdent(uc.Column)+" = ANY($1::text[]::uuid[])", ids)
				return ue
			})
			if pgCode(e) == pgInsufficientPrivilege {
				e = nil // the role cannot update the log; the rows stay as they are
			}
		default:
			n, e = tx.Exec(ctx, "DELETE FROM "+quoteIdent(uc.Table)+" WHERE "+quoteIdent(uc.Column)+" = ANY($1::text[]::uuid[])", ids)
		}
		if e != nil {
			return nil, fmt.Errorf("clear %s.%s for deleted accounts: %w", uc.Table, uc.Column, e)
		}
		if n > 0 {
			counts[uc.Table] += n
		}
	}
	return counts, nil
}
