// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// citusPoolQuerier is the minimal pgxpool interface required by CitusSchemaSharding.
// Using an interface rather than *pgxpool.Pool directly allows unit tests to
// substitute pgxmock without touching the production pool.
type citusPoolQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// CitusSchemaSharding handles Citus schema-based sharding for the bridge isolation mode.
//
// In Citus 12+, schema-based sharding distributes entire schemas across worker
// nodes, making it ideal for multi-tenant SaaS where each tenant has a separate
// schema. All tables created inside a distributed schema are automatically
// co-located, so no per-table distribution calls are required.
//
// Reference: https://docs.citusdata.com/en/stable/develop/api_udf.html#citus-schema-distribute
type CitusSchemaSharding struct {
	pool    *pgxpool.Pool    // used when constructed via NewCitusSchemaSharding
	querier citusPoolQuerier // used in tests; takes precedence over pool when non-nil
	logger  *zap.Logger
}

// NewCitusSchemaSharding creates a CitusSchemaSharding backed by the given pool.
// The pool must be connected to the Citus coordinator node.
func NewCitusSchemaSharding(pool *pgxpool.Pool, logger *zap.Logger) *CitusSchemaSharding {
	return &CitusSchemaSharding{
		pool:   pool,
		logger: logger,
	}
}

// db returns the active querier: the injected mock if present, otherwise the pool.
func (c *CitusSchemaSharding) db() citusPoolQuerier {
	if c.querier != nil {
		return c.querier
	}
	return c.pool
}

// IsCitusAvailable reports whether the Citus extension is installed and active
// on the database the pool is connected to. Returns false on any query error so
// that callers can treat unavailability as a non-fatal condition.
func (c *CitusSchemaSharding) IsCitusAvailable(ctx context.Context) bool {
	var exists bool
	err := c.db().QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'citus')",
	).Scan(&exists)
	return err == nil && exists
}

// DistributeSchema registers a tenant schema for Citus schema-based sharding.
// It calls citus_schema_distribute(), which is the Citus 12+ API that tells the
// coordinator to shard all tables inside the named schema across worker nodes.
// Subsequent CREATE TABLE statements inside the schema are automatically
// distributed without any additional steps.
//
// The schemaName argument must be an unquoted PostgreSQL identifier; the
// function passes it as a regnamespace cast so the coordinator validates it.
func (c *CitusSchemaSharding) DistributeSchema(ctx context.Context, schemaName string) error {
	_, err := c.db().Exec(ctx,
		"SELECT citus_schema_distribute($1::regnamespace)", schemaName,
	)
	if err != nil {
		return fmt.Errorf("citus: distribute schema %q: %w", schemaName, err)
	}
	c.logger.Info("Distributed schema via Citus", zap.String("schema", schemaName))
	return nil
}

// UndistributeSchema removes a schema from Citus distribution.
// It calls citus_schema_undistribute(), pulling all shards back to the
// coordinator. This must be called before DROP SCHEMA so that the coordinator
// can clean up its internal metadata. The operation is best-effort during
// deprovisioning; failures are logged but do not block schema deletion.
func (c *CitusSchemaSharding) UndistributeSchema(ctx context.Context, schemaName string) error {
	_, err := c.db().Exec(ctx,
		"SELECT citus_schema_undistribute($1::regnamespace)", schemaName,
	)
	if err != nil {
		return fmt.Errorf("citus: undistribute schema %q: %w", schemaName, err)
	}
	c.logger.Info("Undistributed schema from Citus", zap.String("schema", schemaName))
	return nil
}

// RebalanceIfNeeded triggers an asynchronous shard rebalance on the Citus
// coordinator if the cluster has uneven distribution. The rebalance runs in the
// background; this call returns as soon as the rebalance job is submitted.
//
// Errors are treated as non-fatal and are only logged at WARN level, because
// rebalancing may already be in progress or may not be required at all.
func (c *CitusSchemaSharding) RebalanceIfNeeded(ctx context.Context) error {
	_, err := c.db().Exec(ctx, "SELECT citus_rebalance_start()")
	if err != nil {
		c.logger.Warn("Citus rebalance not triggered (may already be running or not needed)",
			zap.Error(err),
		)
		return nil // Non-fatal — rebalancing is best-effort.
	}
	return nil
}

// containsCitus reports whether the supplied extension list includes "citus".
// It is used by ProductDBProvisioner to decide whether to attempt schema-based
// sharding in bridge isolation mode.
func containsCitus(extensions []string) bool {
	for _, ext := range extensions {
		if ext == "citus" {
			return true
		}
	}
	return false
}
