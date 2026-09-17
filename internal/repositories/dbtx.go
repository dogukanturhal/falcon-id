// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"

	pgx "github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

// DBTX is the minimal database interface required by all repositories.
// Both *pgxpool.Pool and pgxmock.PgxPoolIface implement this interface.
type DBTX interface {
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// DBPool is an alias for DBTX, used by some repositories.
type DBPool = DBTX
