// SPDX-License-Identifier: AGPL-3.0-or-later

// Package database provides RLS (Row Level Security) middleware for PostgreSQL
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/shared/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmoiron/sqlx"
)

// ErrRLSContextMismatch is returned when the sentinel context guard detects
// that the PostgreSQL session variable does not match the expected tenant/realm
// UUID after SET LOCAL. This indicates a connection pooler bug, session leak,
// or replay attack.
var ErrRLSContextMismatch = errors.New("RLS context guard: session variable does not match expected value")

// RLSMiddleware creates a Gin middleware that sets app.current_tenant_id and
// (when available) app.current_realm_id for PostgreSQL RLS.
// This middleware MUST be applied AFTER auth middleware OR tenant extractor middleware.
//
// REGISTERED as of the RLS-enforcement change (cmd/routes.go,
// applyGlobalMiddleware): this function IS mounted globally via
// router.Use(database.RLSMiddleware(dataPlanePool)) for any request that has
// a tenant_id in context. The stale "NOT CURRENTLY REGISTERED" note that
// used to live here (dated 2026-09-21) predates that wiring and was left
// uncorrected by the commit that did the wiring; it is removed here because
// it no longer describes the code. Registering this middleware alone still
// does not make every repository query run inside its transaction -
// repositories must separately be converted to consume "db_tx"/"pgx_tx" out
// of gin context (e.g. via each repository's WithDB(tx) clone method, see
// internal/repositories/withdb.go) instead of querying the raw pool.
//
// CRITICAL: For each request with a tenant_id in context (from JWT or X-Tenant-ID header),
// this middleware opens an explicit transaction and executes, inside it:
//
//	SET LOCAL app.current_tenant_id = '<tenant_uuid>'
//
// When a realm_id is present in the gin context (set by RealmMiddleware), it also executes:
//
//	SET LOCAL app.current_realm_id = '<realm_uuid>'
//
// SET LOCAL only takes effect for the remainder of the current transaction block;
// outside of one it is a silent no-op (PostgreSQL emits
// "WARNING: SET LOCAL can only be used in transaction blocks" and the setting
// is discarded before the next statement runs on that connection). A prior
// version of this middleware called SET LOCAL on a bare acquired connection
// with no enclosing BEGIN, so the tenant/realm GUCs were never actually
// applied. This version opens the transaction explicitly and verifies each
// GUC with a read-back (matching the pattern already used by
// WithTenantContextPgx / WithTenantContextSQLX below) before letting the
// request proceed, and commits or rolls back the transaction once the
// downstream handler chain returns.
//
// This is REQUIRED for Row Level Security (RLS) policies that filter by:
//
//	tenant_id = current_setting('app.current_tenant_id', true)::UUID
//
// WITHOUT this middleware being both registered AND actually used by the
// repository layer, RLS policies with a fail-closed shape will block ALL
// rows, causing 0-row queries.
//
// Usage:
//
//	router.Use(authMiddleware.RequireAuth())
//	router.Use(realmMiddleware.ExtractRealm())
//	router.Use(database.RLSMiddleware(db))
//	router.POST("/api/resource", handler.Create)
//
// Supports: *sql.DB, *sqlx.DB, *pgxpool.Pool
func RLSMiddleware(db interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract tenant ID from context (set by auth middleware or TenantExtractor)
		tenantIDVal, exists := c.Get(auth.TenantIDKey)
		if !exists {
			// Try alternate key "tenant_id" (used by some services)
			tenantIDVal, exists = c.Get("tenant_id")
			if !exists {
				// No tenant ID - skip RLS setting (for system-level/public endpoints)
				c.Next()
				return
			}
		}

		tenantID, ok := tenantIDVal.(uuid.UUID)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid tenant ID type in context",
			})
			return
		}

		// Skip nil UUID (system context)
		if tenantID == uuid.Nil {
			c.Next()
			return
		}

		// Extract realm ID from context (set by RealmMiddleware)
		var realmID uuid.UUID
		if realmIDVal, realmExists := c.Get("realm_id"); realmExists {
			if rid, ok := realmIDVal.(uuid.UUID); ok && rid != uuid.Nil {
				realmID = rid
			}
		}

		// Set tenant (and optionally realm) context inside an explicit
		// transaction that spans the request lifecycle. SET LOCAL is only
		// meaningful inside a transaction block (see doc comment above).
		switch v := db.(type) {
		case *sql.DB:
			tx, txErr := v.BeginTx(c.Request.Context(), nil)
			if txErr != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to begin database transaction",
				})
				return
			}

			if err := setAndVerifyGUCSQL(c.Request.Context(), tx, tenantID, realmID); err != nil {
				_ = tx.Rollback()
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to set tenant context for RLS",
				})
				return
			}

			c.Set("db_tx", tx)
			defer func() {
				if r := recover(); r != nil {
					_ = tx.Rollback()
					panic(r)
				}
				finishSQLTx(tx, c)
			}()
			c.Next()

		case *sqlx.DB:
			tx, txErr := v.BeginTxx(c.Request.Context(), nil)
			if txErr != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to begin database transaction",
				})
				return
			}

			if err := setAndVerifyGUCSQL(c.Request.Context(), tx.Tx, tenantID, realmID); err != nil {
				_ = tx.Rollback()
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to set tenant context for RLS",
				})
				return
			}

			c.Set("db_tx", tx)
			defer func() {
				if r := recover(); r != nil {
					_ = tx.Rollback()
					panic(r)
				}
				finishSQLXTx(tx, c)
			}()
			c.Next()

		case *pgxpool.Pool:
			tx, txErr := v.Begin(c.Request.Context())
			if txErr != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to begin database transaction",
				})
				return
			}

			if err := setAndVerifyGUCPgx(c.Request.Context(), tx, tenantID, realmID); err != nil {
				_ = tx.Rollback(c.Request.Context())
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to set tenant context for RLS",
				})
				return
			}

			c.Set("pgx_tx", tx)
			defer func() {
				if r := recover(); r != nil {
					_ = tx.Rollback(context.Background())
					panic(r)
				}
				finishPgxTx(tx, c)
			}()
			c.Next()

		default:
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Unsupported database type for RLS middleware",
			})
			return
		}
	}
}

// sqlExecer is satisfied by both *sql.Tx and the pieces of *sqlx.Tx we need.
type sqlExecer interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// setAndVerifyGUCSQL sets app.current_tenant_id (and optionally
// app.current_realm_id) via SET LOCAL on tx and reads each back to confirm
// the setting actually took effect, guarding against the SET-LOCAL-outside-
// a-transaction failure mode this middleware previously had.
func setAndVerifyGUCSQL(ctx context.Context, tx sqlExecer, tenantID uuid.UUID, realmID uuid.UUID) error {
	// set_config(name, value, is_local) -- NOT "SET LOCAL x = $1". Postgres's
	// SET command is a utility statement that does not accept bind
	// parameters at all (confirmed live: "PREPARE x(text) AS SET LOCAL
	// app.current_tenant_id = $1" fails with "syntax error at or near
	// SET"). set_config() is a regular function call, so it supports bind
	// parameters through the normal extended query protocol, and its third
	// argument (is_local=true) gives the exact same transaction-scoped
	// semantics as SET LOCAL.
	if _, err := tx.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID.String()); err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}
	var actual string
	if err := tx.QueryRowContext(ctx, "SELECT current_setting('app.current_tenant_id', true)").Scan(&actual); err != nil {
		return fmt.Errorf("RLS context guard: failed to read back tenant_id: %w", err)
	}
	if actual != tenantID.String() {
		return fmt.Errorf("%w: expected %s, got %q", ErrRLSContextMismatch, tenantID, actual)
	}

	if realmID != uuid.Nil {
		if _, err := tx.ExecContext(ctx, "SELECT set_config('app.current_realm_id', $1, true)", realmID.String()); err != nil {
			return fmt.Errorf("failed to set app.current_realm_id: %w", err)
		}
		if err := tx.QueryRowContext(ctx, "SELECT current_setting('app.current_realm_id', true)").Scan(&actual); err != nil {
			return fmt.Errorf("RLS context guard: failed to read back realm_id: %w", err)
		}
		if actual != realmID.String() {
			return fmt.Errorf("%w: expected realm %s, got %q", ErrRLSContextMismatch, realmID, actual)
		}
	}
	return nil
}

// setAndVerifyGUCPgx is the pgx.Tx equivalent of setAndVerifyGUCSQL.
func setAndVerifyGUCPgx(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, realmID uuid.UUID) error {
	// See the comment in setAndVerifyGUCSQL above: SET LOCAL does not
	// support bind parameters, so this must go through set_config().
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID.String()); err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}
	var actual string
	if err := tx.QueryRow(ctx, "SELECT current_setting('app.current_tenant_id', true)").Scan(&actual); err != nil {
		return fmt.Errorf("RLS context guard: failed to read back tenant_id: %w", err)
	}
	if actual != tenantID.String() {
		return fmt.Errorf("%w: expected %s, got %q", ErrRLSContextMismatch, tenantID, actual)
	}

	if realmID != uuid.Nil {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.current_realm_id', $1, true)", realmID.String()); err != nil {
			return fmt.Errorf("failed to set app.current_realm_id: %w", err)
		}
		if err := tx.QueryRow(ctx, "SELECT current_setting('app.current_realm_id', true)").Scan(&actual); err != nil {
			return fmt.Errorf("RLS context guard: failed to read back realm_id: %w", err)
		}
		if actual != realmID.String() {
			return fmt.Errorf("%w: expected realm %s, got %q", ErrRLSContextMismatch, realmID, actual)
		}
	}
	return nil
}

// finishSQLTx commits the request-scoped transaction on a clean response and
// rolls it back otherwise (handler error/abort, or a non-2xx/3xx status the
// handler set deliberately).
//
// finishSQLTx must never run directly on a panicking request: at the point
// this function's caller (RLSMiddleware) would invoke it, a panic has not
// yet been converted into a 5xx response, because an outer recovery
// middleware's own deferred recover() only fires after every deferred call
// registered deeper in the stack (including this middleware's) has already
// run - c.Writer.Status() is still whatever it was before the panic. The
// caller therefore wraps the call to finishSQLTx in its own deferred
// recover() that detects a panic, rolls back, and re-panics BEFORE reaching
// this function - see the defer in RLSMiddleware's *sql.DB case. Before that
// defer existed, this middleware called finishSQLTx unconditionally
// (non-deferred, right after c.Next()), so a downstream panic skipped the
// call to it entirely and left the transaction (and its pooled connection)
// never committed or rolled back - reproduced locally in
// rls_middleware_panic_leak_local_test.go
// (TestRLSMiddleware_PanicDoesNotLeakConnection).
func finishSQLTx(tx *sql.Tx, c *gin.Context) {
	if c.IsAborted() || c.Writer.Status() >= http.StatusBadRequest {
		_ = tx.Rollback()
		return
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
	}
}

// finishSQLXTx is the *sqlx.Tx equivalent of finishSQLTx.
func finishSQLXTx(tx *sqlx.Tx, c *gin.Context) {
	if c.IsAborted() || c.Writer.Status() >= http.StatusBadRequest {
		_ = tx.Rollback()
		return
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
	}
}

// finishPgxTx is the pgx.Tx equivalent of finishSQLTx.
func finishPgxTx(tx pgx.Tx, c *gin.Context) {
	ctx := context.Background()
	if c.IsAborted() || c.Writer.Status() >= http.StatusBadRequest {
		_ = tx.Rollback(ctx)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		_ = tx.Rollback(ctx)
	}
}

// RLSMiddlewarePgxPool creates RLS middleware specifically for pgxpool.Pool
// This is a convenience function for services using pgx
func RLSMiddlewarePgxPool(pool *pgxpool.Pool) gin.HandlerFunc {
	return RLSMiddleware(pool)
}

// SetRLSContext sets app.current_tenant_id (and optionally app.current_realm_id) on a
// sql.DB connection for RLS. Use SET LOCAL to scope the setting to the current transaction.
// The realmID parameter is variadic for backward compatibility; only the first value is used.
func SetRLSContext(ctx context.Context, db *sql.DB, tenantID uuid.UUID, realmID ...uuid.UUID) error {
	_, err := db.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}

	if len(realmID) > 0 && realmID[0] != uuid.Nil {
		_, err = db.ExecContext(ctx, "SELECT set_config('app.current_realm_id', $1, true)", realmID[0].String())
		if err != nil {
			return fmt.Errorf("failed to set app.current_realm_id: %w", err)
		}
	}

	return nil
}

// SetRLSContextSQLX sets app.current_tenant_id (and optionally app.current_realm_id) on a
// sqlx.DB connection for RLS.
// The realmID parameter is variadic for backward compatibility; only the first value is used.
func SetRLSContextSQLX(ctx context.Context, db *sqlx.DB, tenantID uuid.UUID, realmID ...uuid.UUID) error {
	_, err := db.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}

	if len(realmID) > 0 && realmID[0] != uuid.Nil {
		_, err = db.ExecContext(ctx, "SELECT set_config('app.current_realm_id', $1, true)", realmID[0].String())
		if err != nil {
			return fmt.Errorf("failed to set app.current_realm_id: %w", err)
		}
	}

	return nil
}

// SetRLSContextPgx sets app.current_tenant_id (and optionally app.current_realm_id) on a
// pgxpool connection for RLS.
// The realmID parameter is variadic for backward compatibility; only the first value is used.
func SetRLSContextPgx(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, realmID ...uuid.UUID) error {
	_, err := pool.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}

	if len(realmID) > 0 && realmID[0] != uuid.Nil {
		_, err = pool.Exec(ctx, "SELECT set_config('app.current_realm_id', $1, true)", realmID[0].String())
		if err != nil {
			return fmt.Errorf("failed to set app.current_realm_id: %w", err)
		}
	}

	return nil
}

// WithTenantContext wraps a database operation with RLS context using a transaction.
// Use this in repositories when RLS middleware is not available (e.g., background jobs).
// This uses a transaction to ensure the SET LOCAL setting is properly scoped.
//
// The realmID parameter is variadic for backward compatibility; only the first value is used.
//
// Example:
//
//	err := database.WithTenantContext(ctx, r.db, tenantID, func(tx *sql.Tx) error {
//	    return tx.QueryRowContext(ctx, "SELECT * FROM table WHERE id = $1", id).Scan(&result)
//	})
func WithTenantContext(ctx context.Context, db *sql.DB, tenantID uuid.UUID, fn func(tx *sql.Tx) error, realmID ...uuid.UUID) error {
	// Begin transaction
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // Rollback if not committed

	// Set tenant context with LOCAL scope (transaction-scoped)
	_, err = tx.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}

	// Sentinel guard: read back and verify the setting took effect.
	var actual string
	if err := tx.QueryRowContext(ctx, "SELECT current_setting('app.current_tenant_id', true)").Scan(&actual); err != nil {
		return fmt.Errorf("RLS context guard: failed to read back tenant_id: %w", err)
	}
	if actual != tenantID.String() {
		return fmt.Errorf("%w: expected %s, got %q", ErrRLSContextMismatch, tenantID, actual)
	}

	if len(realmID) > 0 && realmID[0] != uuid.Nil {
		_, err = tx.ExecContext(ctx, "SELECT set_config('app.current_realm_id', $1, true)", realmID[0].String())
		if err != nil {
			return fmt.Errorf("failed to set app.current_realm_id: %w", err)
		}

		// Sentinel guard for realm_id
		if err := tx.QueryRowContext(ctx, "SELECT current_setting('app.current_realm_id', true)").Scan(&actual); err != nil {
			return fmt.Errorf("RLS context guard: failed to read back realm_id: %w", err)
		}
		if actual != realmID[0].String() {
			return fmt.Errorf("%w: expected realm %s, got %q", ErrRLSContextMismatch, realmID[0], actual)
		}
	}

	// Execute function
	if err := fn(tx); err != nil {
		return err
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// WithTenantContextSQLX wraps a database operation with RLS context for sqlx.DB.
// The realmID parameter is variadic for backward compatibility; only the first value is used.
//
// SECURITY: Includes sentinel read-back to verify the session variable matches.
func WithTenantContextSQLX(ctx context.Context, db *sqlx.DB, tenantID uuid.UUID, fn func(tx *sqlx.Tx) error, realmID ...uuid.UUID) error {
	// Begin transaction
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Set tenant context with LOCAL scope
	_, err = tx.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}

	// Sentinel guard: read back and verify the setting took effect.
	var actual string
	if err := tx.QueryRowContext(ctx, "SELECT current_setting('app.current_tenant_id', true)").Scan(&actual); err != nil {
		return fmt.Errorf("RLS context guard: failed to read back tenant_id: %w", err)
	}
	if actual != tenantID.String() {
		return fmt.Errorf("%w: expected %s, got %q", ErrRLSContextMismatch, tenantID, actual)
	}

	if len(realmID) > 0 && realmID[0] != uuid.Nil {
		_, err = tx.ExecContext(ctx, "SELECT set_config('app.current_realm_id', $1, true)", realmID[0].String())
		if err != nil {
			return fmt.Errorf("failed to set app.current_realm_id: %w", err)
		}

		// Sentinel guard for realm_id
		if err := tx.QueryRowContext(ctx, "SELECT current_setting('app.current_realm_id', true)").Scan(&actual); err != nil {
			return fmt.Errorf("RLS context guard: failed to read back realm_id: %w", err)
		}
		if actual != realmID[0].String() {
			return fmt.Errorf("%w: expected realm %s, got %q", ErrRLSContextMismatch, realmID[0], actual)
		}
	}

	// Execute function
	if err := fn(tx); err != nil {
		return err
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// WithTenantContextPgx wraps a database operation with RLS context for pgxpool.
// The realmID parameter is variadic for backward compatibility; only the first value is used.
//
// SECURITY: After SET LOCAL, a sentinel read-back verifies that the session
// variable matches the expected tenant UUID. This catches connection pooler
// session leaks (e.g., PgBouncer without DISCARD ALL) that could silently
// expose cross-tenant data.
func WithTenantContextPgx(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, fn func(tx pgx.Tx) error, realmID ...uuid.UUID) error {
	// Begin transaction
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Set tenant context with LOCAL scope
	_, err = tx.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}

	// Sentinel guard: read back and verify the setting took effect.
	var actual string
	if err := tx.QueryRow(ctx, "SELECT current_setting('app.current_tenant_id', true)").Scan(&actual); err != nil {
		return fmt.Errorf("RLS context guard: failed to read back tenant_id: %w", err)
	}
	if actual != tenantID.String() {
		return fmt.Errorf("%w: expected %s, got %q", ErrRLSContextMismatch, tenantID, actual)
	}

	if len(realmID) > 0 && realmID[0] != uuid.Nil {
		_, err = tx.Exec(ctx, "SELECT set_config('app.current_realm_id', $1, true)", realmID[0].String())
		if err != nil {
			return fmt.Errorf("failed to set app.current_realm_id: %w", err)
		}

		// Sentinel guard for realm_id
		if err := tx.QueryRow(ctx, "SELECT current_setting('app.current_realm_id', true)").Scan(&actual); err != nil {
			return fmt.Errorf("RLS context guard: failed to read back realm_id: %w", err)
		}
		if actual != realmID[0].String() {
			return fmt.Errorf("%w: expected realm %s, got %q", ErrRLSContextMismatch, realmID[0], actual)
		}
	}

	// Execute function
	if err := fn(tx); err != nil {
		return err
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// TenantAwareDB wraps a database connection and automatically sets RLS context
// for both tenant and (optionally) realm on every operation.
type TenantAwareDB struct {
	db       *sqlx.DB
	tenantID uuid.UUID
	realmID  uuid.UUID
}

// NewTenantAwareDB creates a database wrapper that automatically sets RLS context.
// The optional realmID parameter adds app.current_realm_id to every transaction;
// only the first value is used.
func NewTenantAwareDB(db *sqlx.DB, tenantID uuid.UUID, realmID ...uuid.UUID) *TenantAwareDB {
	t := &TenantAwareDB{
		db:       db,
		tenantID: tenantID,
	}
	if len(realmID) > 0 {
		t.realmID = realmID[0]
	}
	return t
}

// withContext is a convenience helper that forwards the stored realmID to
// WithTenantContextSQLX so callers don't repeat the variadic pattern.
func (t *TenantAwareDB) withContext(ctx context.Context, fn func(tx *sqlx.Tx) error) error {
	if t.realmID != uuid.Nil {
		return WithTenantContextSQLX(ctx, t.db, t.tenantID, fn, t.realmID)
	}
	return WithTenantContextSQLX(ctx, t.db, t.tenantID, fn)
}

// Exec executes a query with tenant context set
func (t *TenantAwareDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	var result sql.Result
	err := t.withContext(context.Background(), func(tx *sqlx.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(context.Background(), query, args...)
		return execErr
	})
	return result, err
}

// ExecContext executes a query with tenant context set
func (t *TenantAwareDB) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	var result sql.Result
	err := t.withContext(ctx, func(tx *sqlx.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(ctx, query, args...)
		return execErr
	})
	return result, err
}

// Query executes a query with tenant context set
func (t *TenantAwareDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	var rows *sql.Rows
	err := t.withContext(context.Background(), func(tx *sqlx.Tx) error {
		var queryErr error
		rows, queryErr = tx.QueryContext(context.Background(), query, args...)
		return queryErr
	})
	return rows, err
}

// QueryContext executes a query with tenant context set
func (t *TenantAwareDB) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	var rows *sql.Rows
	err := t.withContext(ctx, func(tx *sqlx.Tx) error {
		var queryErr error
		rows, queryErr = tx.QueryContext(ctx, query, args...)
		return queryErr
	})
	return rows, err
}

// Get executes a GET query with tenant context (sqlx specific)
func (t *TenantAwareDB) Get(dest interface{}, query string, args ...interface{}) error {
	return t.withContext(context.Background(), func(tx *sqlx.Tx) error {
		return tx.Get(dest, query, args...)
	})
}

// GetContext executes a GET query with tenant context (sqlx specific)
func (t *TenantAwareDB) GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	return t.withContext(ctx, func(tx *sqlx.Tx) error {
		return tx.GetContext(ctx, dest, query, args...)
	})
}

// Select executes a SELECT query with tenant context (sqlx specific)
func (t *TenantAwareDB) Select(dest interface{}, query string, args ...interface{}) error {
	return t.withContext(context.Background(), func(tx *sqlx.Tx) error {
		return tx.Select(dest, query, args...)
	})
}

// SelectContext executes a SELECT query with tenant context (sqlx specific)
func (t *TenantAwareDB) SelectContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	return t.withContext(ctx, func(tx *sqlx.Tx) error {
		return tx.SelectContext(ctx, dest, query, args...)
	})
}
