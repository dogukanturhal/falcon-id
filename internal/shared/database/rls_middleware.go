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
// CRITICAL: For each request with a tenant_id in context (from JWT or X-Tenant-ID header),
// this middleware acquires a connection and executes:
//
//	SET LOCAL app.current_tenant_id = '<tenant_uuid>'
//
// When a realm_id is present in the gin context (set by RealmMiddleware), it also executes:
//
//	SET LOCAL app.current_realm_id = '<realm_uuid>'
//
// This is REQUIRED for Row Level Security (RLS) policies that filter by:
//
//	tenant_id = current_setting('app.current_tenant_id', true)::UUID
//
// WITHOUT this middleware, RLS policies will block ALL rows, causing 0-row queries.
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

		// Set tenant (and optionally realm) context on the database connection.
		// IMPORTANT: We must acquire a connection for the request lifecycle.
		var err error
		switch v := db.(type) {
		case *sql.DB:
			// For sql.DB, acquire connection and defer release
			conn, connErr := v.Conn(c.Request.Context())
			if connErr != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to acquire database connection",
				})
				return
			}
			defer conn.Close() //nolint:errcheck

			// Set LOCAL to ensure the setting is transaction-scoped
			_, err = conn.ExecContext(c.Request.Context(), "SET LOCAL app.current_tenant_id = $1", tenantID.String())
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to set tenant context for RLS",
				})
				return
			}

			if realmID != uuid.Nil {
				_, err = conn.ExecContext(c.Request.Context(), "SET LOCAL app.current_realm_id = $1", realmID.String())
				if err != nil {
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"error": "Failed to set realm context for RLS",
					})
					return
				}
			}

			// Store connection in context for reuse
			c.Set("db_conn", conn)

		case *sqlx.DB:
			// For sqlx.DB, acquire connection and defer release
			conn, connErr := v.Conn(c.Request.Context())
			if connErr != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to acquire database connection",
				})
				return
			}
			defer conn.Close() //nolint:errcheck

			_, err = conn.ExecContext(c.Request.Context(), "SET LOCAL app.current_tenant_id = $1", tenantID.String())
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to set tenant context for RLS",
				})
				return
			}

			if realmID != uuid.Nil {
				_, err = conn.ExecContext(c.Request.Context(), "SET LOCAL app.current_realm_id = $1", realmID.String())
				if err != nil {
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"error": "Failed to set realm context for RLS",
					})
					return
				}
			}

			c.Set("db_conn", conn)

		case *pgxpool.Pool:
			// For pgxpool, acquire connection and defer release
			conn, connErr := v.Acquire(c.Request.Context())
			if connErr != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to acquire database connection",
				})
				return
			}
			defer conn.Release()

			_, err = conn.Exec(c.Request.Context(), "SET LOCAL app.current_tenant_id = $1", tenantID.String())
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to set tenant context for RLS",
				})
				return
			}

			if realmID != uuid.Nil {
				_, err = conn.Exec(c.Request.Context(), "SET LOCAL app.current_realm_id = $1", realmID.String())
				if err != nil {
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"error": "Failed to set realm context for RLS",
					})
					return
				}
			}

			// Store connection in context for reuse
			c.Set("pgx_conn", conn)

		default:
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Unsupported database type for RLS middleware",
			})
			return
		}

		c.Next()
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
	_, err := db.ExecContext(ctx, "SET LOCAL app.current_tenant_id = $1", tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}

	if len(realmID) > 0 && realmID[0] != uuid.Nil {
		_, err = db.ExecContext(ctx, "SET LOCAL app.current_realm_id = $1", realmID[0].String())
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
	_, err := db.ExecContext(ctx, "SET LOCAL app.current_tenant_id = $1", tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}

	if len(realmID) > 0 && realmID[0] != uuid.Nil {
		_, err = db.ExecContext(ctx, "SET LOCAL app.current_realm_id = $1", realmID[0].String())
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
	_, err := pool.Exec(ctx, "SET LOCAL app.current_tenant_id = $1", tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set app.current_tenant_id: %w", err)
	}

	if len(realmID) > 0 && realmID[0] != uuid.Nil {
		_, err = pool.Exec(ctx, "SET LOCAL app.current_realm_id = $1", realmID[0].String())
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
	_, err = tx.ExecContext(ctx, "SET LOCAL app.current_tenant_id = $1", tenantID.String())
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
		_, err = tx.ExecContext(ctx, "SET LOCAL app.current_realm_id = $1", realmID[0].String())
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
	_, err = tx.ExecContext(ctx, "SET LOCAL app.current_tenant_id = $1", tenantID.String())
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
		_, err = tx.ExecContext(ctx, "SET LOCAL app.current_realm_id = $1", realmID[0].String())
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
	_, err = tx.Exec(ctx, "SET LOCAL app.current_tenant_id = $1", tenantID.String())
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
		_, err = tx.Exec(ctx, "SET LOCAL app.current_realm_id = $1", realmID[0].String())
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
