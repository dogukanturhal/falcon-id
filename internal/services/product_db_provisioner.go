// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const sslModeDisable = "disable"

// ProductDBProvisionerConfig holds configuration for product database provisioning.
type ProductDBProvisionerConfig struct {
	DefaultSSLMode            string
	DefaultPoolSize           int
	DefaultMaxIdleConns       int
	DefaultConnMaxLifetimeMin int
}

// ProductDBProvisioner handles creating and dropping per-product databases
// for tenants, supporting the three isolation modes: pool, bridge, silo.
type ProductDBProvisioner struct {
	masterPool *pgxpool.Pool
	encryption *crypto.EncryptionService
	config     ProductDBProvisionerConfig
	// log is used for structured Citus-related warnings; it mirrors logger.Log
	// when nil-safe access through the package global is insufficient (e.g. in
	// unit tests that construct the struct directly).  NewProductDBProvisioner
	// always sets this to logger.Log.
	log *zap.Logger
}

// NewProductDBProvisioner creates a new product database provisioner.
func NewProductDBProvisioner(
	masterPool *pgxpool.Pool,
	encryption *crypto.EncryptionService,
	config ProductDBProvisionerConfig,
) *ProductDBProvisioner {
	if config.DefaultSSLMode == "" {
		config.DefaultSSLMode = sslModeDisable
	}
	if config.DefaultPoolSize == 0 {
		config.DefaultPoolSize = 10
	}
	if config.DefaultMaxIdleConns == 0 {
		config.DefaultMaxIdleConns = 5
	}
	if config.DefaultConnMaxLifetimeMin == 0 {
		config.DefaultConnMaxLifetimeMin = 30
	}
	return &ProductDBProvisioner{
		masterPool: masterPool,
		encryption: encryption,
		config:     config,
		log:        logger.Log,
	}
}

// effectiveLogger returns the provisioner's logger, falling back to the
// package-global logger.Log.  This avoids nil-pointer panics when tests
// construct the struct directly without calling NewProductDBProvisioner.
func (p *ProductDBProvisioner) effectiveLogger() *zap.Logger {
	if p.log != nil {
		return p.log
	}
	return logger.Log
}

// ProvisionResult contains the details of a provisioned database.
type ProvisionResult struct {
	Host          string
	DatabaseName  string
	Schema        string
	Username      string
	ConnectionEnc []byte
}

// ProvisionProductDatabase creates a database (or schema) for a product instance.
// The isolation mode determines the strategy:
//   - "silo":   CREATE DATABASE per tenant (full isolation)
//   - "bridge": CREATE SCHEMA per tenant in a shared product database
//   - "pool":   Shared database with RLS (no additional provisioning needed)
//
// When isolation is "bridge" and the manifest lists "citus" in RequiredExtensions,
// the provisioner additionally calls citus_schema_distribute() on the new schema
// so that Citus 12+ can shard all tables within it across worker nodes.  The
// Citus step is non-fatal: if Citus is unavailable the schema remains fully
// usable as a standard PostgreSQL schema.
func (p *ProductDBProvisioner) ProvisionProductDatabase(
	ctx context.Context,
	tenantID uuid.UUID,
	productSlug string,
	manifest *models.ProductManifest,
	isolationOverride string,
) (*ProvisionResult, error) {
	isolation := "pool"
	if manifest != nil && manifest.Database != nil {
		isolation = manifest.Database.IsolationDefault
	}
	if isolationOverride != "" {
		isolation = isolationOverride
	}

	safeTenant := sanitizeSlug(tenantID.String()[:8])
	safeProduct := sanitizeSlug(productSlug)

	switch isolation {
	case models.IsolationSilo:
		return p.provisionSilo(ctx, safeProduct, safeTenant, tenantID)
	case models.IsolationBridge:
		return p.provisionBridge(ctx, safeProduct, safeTenant, manifest)
	case models.IsolationPool:
		return p.provisionPool(ctx, safeProduct)
	default:
		return nil, fmt.Errorf("unknown isolation mode: %s", isolation)
	}
}

// provisionSilo creates a dedicated database per tenant per product.
// tenantID is used to derive a tenant-specific encryption key for the connection string,
// limiting blast radius if a single tenant's derived key is compromised.
func (p *ProductDBProvisioner) provisionSilo(ctx context.Context, product, tenant string, tenantID uuid.UUID) (*ProvisionResult, error) {
	dbName := fmt.Sprintf("hexxlock_%s_%s", product, tenant)
	username := fmt.Sprintf("prod_%s_%s", product, tenant)

	// Truncate to fit PostgreSQL's 63-char identifier limit.
	if len(dbName) > 63 {
		dbName = dbName[:63]
	}
	if len(username) > 63 {
		username = username[:63]
	}

	password, err := generateSecurePassword(32)
	if err != nil {
		return nil, fmt.Errorf("generate password: %w", err)
	}

	logger.Log.Info("Provisioning silo database for product",
		zap.String("database", dbName),
		zap.String("username", username),
	)

	// Create role.
	_, err = p.masterPool.Exec(ctx,
		fmt.Sprintf("CREATE ROLE %s WITH LOGIN PASSWORD '%s'", quoteIdent(username), password),
	)
	if err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}

	// Create database.
	_, err = p.masterPool.Exec(ctx,
		fmt.Sprintf("CREATE DATABASE %s OWNER %s", quoteIdent(dbName), quoteIdent(username)),
	)
	if err != nil {
		p.rollbackRole(ctx, username)
		return nil, fmt.Errorf("create database: %w", err)
	}

	masterCfg := p.masterPool.Config()
	host := masterCfg.ConnConfig.Host

	// Encrypt the connection string with a tenant-specific derived key.
	// Each tenant gets a unique AES key via HKDF, so compromising one tenant's
	// derived key does not expose other tenants' silo connection strings.
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		username, password, host, masterCfg.ConnConfig.Port, dbName, p.config.DefaultSSLMode,
	)
	var connEnc []byte
	if p.encryption != nil {
		tenantEnc, err := p.encryption.DeriveTenantKey(tenantID)
		if err != nil {
			p.rollbackDatabase(ctx, dbName, username)
			return nil, fmt.Errorf("derive tenant encryption key: %w", err)
		}
		encrypted, err := tenantEnc.Encrypt(connStr)
		if err != nil {
			p.rollbackDatabase(ctx, dbName, username)
			return nil, fmt.Errorf("encrypt connection string: %w", err)
		}
		connEnc = []byte(encrypted)
	}

	return &ProvisionResult{
		Host:          host,
		DatabaseName:  dbName,
		Schema:        "public",
		Username:      username,
		ConnectionEnc: connEnc,
	}, nil
}

// provisionBridge creates a schema per tenant in a shared product database.
//
// When the product manifest declares "citus" in RequiredExtensions, the method
// also calls citus_schema_distribute() so Citus 12+ shards the schema across
// worker nodes.  This step is best-effort: if Citus is not installed or the
// call fails the schema remains usable as a regular PostgreSQL schema and the
// error is logged at WARN level rather than propagated.
func (p *ProductDBProvisioner) provisionBridge(
	ctx context.Context,
	product, tenant string,
	manifest *models.ProductManifest,
) (*ProvisionResult, error) {
	dbName := fmt.Sprintf("hexxlock_%s", product)
	schemaName := fmt.Sprintf("tenant_%s", tenant)

	if len(schemaName) > 63 {
		schemaName = schemaName[:63]
	}

	masterCfg := p.masterPool.Config()
	host := masterCfg.ConnConfig.Host

	logger.Log.Info("Provisioning bridge schema for product",
		zap.String("database", dbName),
		zap.String("schema", schemaName),
	)

	// The shared product database must already exist.  Create the tenant schema.
	_, err := p.masterPool.Exec(ctx,
		fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", quoteIdent(schemaName)),
	)
	if err != nil {
		return nil, fmt.Errorf("create schema %s: %w", schemaName, err)
	}

	// Citus schema-based sharding (non-fatal enhancement).
	// When the manifest requires the "citus" extension, register the new schema
	// with the Citus coordinator so that tables created inside it are
	// automatically distributed across worker nodes (Citus 12+ feature).
	if manifest != nil && manifest.Database != nil &&
		containsCitus(manifest.Database.RequiredExtensions) {
		sharding := NewCitusSchemaSharding(p.masterPool, p.effectiveLogger())
		if sharding.IsCitusAvailable(ctx) {
			if err := sharding.DistributeSchema(ctx, schemaName); err != nil {
				p.effectiveLogger().Warn(
					"Citus schema distribution failed (non-fatal, schema still usable without distribution)",
					zap.String("schema", schemaName),
					zap.Error(err),
				)
				// Non-fatal: continue with a standard (non-distributed) schema.
			}
		}
	}

	return &ProvisionResult{
		Host:         host,
		DatabaseName: dbName,
		Schema:       schemaName,
		Username:     masterCfg.ConnConfig.User,
	}, nil
}

// provisionPool returns the shared database details (no additional resources created).
func (p *ProductDBProvisioner) provisionPool(_ context.Context, product string) (*ProvisionResult, error) {
	dbName := fmt.Sprintf("hexxlock_%s", product)
	masterCfg := p.masterPool.Config()

	logger.Log.Info("Using shared pool database for product",
		zap.String("database", dbName),
	)

	return &ProvisionResult{
		Host:         masterCfg.ConnConfig.Host,
		DatabaseName: dbName,
		Schema:       "public",
		Username:     masterCfg.ConnConfig.User,
	}, nil
}

// ConnectToInstanceDB creates a pgxpool.Pool connected to the database backing
// the given product instance. The returned pool must be closed by the caller.
//
//   - Silo mode (encrypted connection string present): decrypts and connects.
//   - Bridge mode (schema != "public"): connects to the shared product DB with
//     search_path set to the tenant schema. Uses MaxConns=1 so SET search_path
//     affects all subsequent operations on the pool.
//   - Pool mode: connects to the shared product DB with default "public" schema.
func (p *ProductDBProvisioner) ConnectToInstanceDB(ctx context.Context, pi *models.ProductInstance) (*pgxpool.Pool, error) {
	// Silo mode: has encrypted connection string with dedicated credentials.
	if len(pi.ConnectionStringEnc) > 0 {
		connStr, err := p.decryptConnectionString(pi.TenantID, string(pi.ConnectionStringEnc))
		if err != nil {
			return nil, err
		}
		config, err := pgxpool.ParseConfig(connStr)
		if err != nil {
			return nil, fmt.Errorf("parse silo connection string: %w", err)
		}
		config.MaxConns = 2
		return pgxpool.NewWithConfig(ctx, config)
	}

	// Bridge / pool mode: build DSN from master pool config + product database name.
	if pi.DatabaseName == nil || *pi.DatabaseName == "" {
		return nil, fmt.Errorf("no database name set on product instance")
	}

	masterCfg := p.masterPool.Config().ConnConfig
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		masterCfg.User, masterCfg.Password,
		masterCfg.Host, masterCfg.Port,
		*pi.DatabaseName, p.config.DefaultSSLMode,
	)

	schema := ""
	if pi.DatabaseSchema != nil && *pi.DatabaseSchema != "" && *pi.DatabaseSchema != "public" {
		schema = *pi.DatabaseSchema
	}

	if schema == "" {
		// Pool mode: bound pool size for short-lived migration connections.
		config, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			return nil, fmt.Errorf("parse pool dsn: %w", err)
		}
		config.MaxConns = 2
		return pgxpool.NewWithConfig(ctx, config)
	}

	// Bridge mode: set search_path on a single-connection pool so the
	// SET persists across all operations (migrator runs sequentially).
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("connect to product database: %w", err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf("SET search_path TO %s, public", quoteIdent(schema))); err != nil {
		pool.Close()
		return nil, fmt.Errorf("set search_path to %s: %w", schema, err)
	}
	return pool, nil
}

// decryptConnectionString decrypts an encrypted connection string using per-tenant derived key
// with fallback to the base encryption key for backward compatibility.
func (p *ProductDBProvisioner) decryptConnectionString(tenantID uuid.UUID, encConnStr string) (string, error) {
	if p.encryption == nil {
		return encConnStr, nil
	}
	tenantEnc, err := p.encryption.DeriveTenantKey(tenantID)
	if err != nil {
		return "", fmt.Errorf("derive tenant encryption key: %w", err)
	}
	decrypted, err := tenantEnc.Decrypt(encConnStr)
	if err != nil {
		// Fallback: try base key for backward compat with pre-migration data.
		decrypted, err = p.encryption.Decrypt(encConnStr)
		if err != nil {
			return "", fmt.Errorf("decrypt connection string: %w", err)
		}
	}
	return decrypted, nil
}

// DeprovisionProductDatabase removes the database resources for a product instance.
//   - Bridge mode: undistributes the Citus schema (if applicable) then drops it.
//   - Silo mode: drops the dedicated database and role.
//   - Pool mode: no database resources to clean up.
//
// The manifest parameter is optional (nil is safe).  When provided and the
// product requires Citus, citus_schema_undistribute() is attempted before the
// DROP SCHEMA so the coordinator can clean up its metadata.  This step is
// best-effort and does not block schema deletion if it fails.
func (p *ProductDBProvisioner) DeprovisionProductDatabase(
	ctx context.Context,
	instance *models.ProductInstance,
	manifest *models.ProductManifest,
) error {
	if instance.DatabaseName == nil || *instance.DatabaseName == "" {
		return nil // nothing to deprovision
	}

	dbName := *instance.DatabaseName
	schema := ""
	if instance.DatabaseSchema != nil {
		schema = *instance.DatabaseSchema
	}
	username := ""
	if instance.DatabaseUsername != nil {
		username = *instance.DatabaseUsername
	}

	// Determine isolation mode from the provisioned state.
	// Silo: has a unique database name with tenant suffix + dedicated username.
	// Bridge: has a schema that is not "public".
	// Pool: schema is "public" and username matches master.
	if schema != "" && schema != "public" {
		return p.deprovisionBridge(ctx, dbName, schema, manifest)
	}

	if username != "" && username != p.masterPool.Config().ConnConfig.User {
		// Silo mode: drop database and role.
		logger.Log.Info("Deprovisioning silo database",
			zap.String("database", dbName),
			zap.String("username", username),
		)
		p.rollbackDatabase(ctx, dbName, username)
		return nil
	}

	// Pool mode: nothing to clean up.
	return nil
}

// deprovisionBridge undistributes a Citus schema (if applicable) and drops it.
// The manifest parameter is optional; a nil manifest simply skips the Citus step.
func (p *ProductDBProvisioner) deprovisionBridge(
	ctx context.Context,
	dbName, schemaName string,
	manifest *models.ProductManifest,
) error {
	logger.Log.Info("Deprovisioning bridge schema",
		zap.String("database", dbName),
		zap.String("schema", schemaName),
	)

	// Attempt to remove the schema from Citus distribution before dropping it.
	// This is best-effort: failures are logged but do not block the DROP.
	if manifest != nil && manifest.Database != nil &&
		containsCitus(manifest.Database.RequiredExtensions) {
		sharding := NewCitusSchemaSharding(p.masterPool, p.effectiveLogger())
		if sharding.IsCitusAvailable(ctx) {
			if err := sharding.UndistributeSchema(ctx, schemaName); err != nil {
				p.effectiveLogger().Warn(
					"Citus schema undistribution failed (non-fatal, proceeding with DROP SCHEMA)",
					zap.String("schema", schemaName),
					zap.Error(err),
				)
			}
		}
	}

	_, err := p.masterPool.Exec(ctx,
		fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", quoteIdent(schemaName)),
	)
	return err
}

func (p *ProductDBProvisioner) rollbackDatabase(ctx context.Context, dbName, username string) {
	// Terminate active connections.
	_, _ = p.masterPool.Exec(ctx,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1",
		dbName,
	)
	if _, err := p.masterPool.Exec(ctx,
		fmt.Sprintf("DROP DATABASE IF EXISTS %s", quoteIdent(dbName)),
	); err != nil {
		logger.Log.Error("Failed to drop database during rollback",
			zap.String("database", dbName),
			zap.Error(err),
		)
	}
	p.rollbackRole(ctx, username)
}

func (p *ProductDBProvisioner) rollbackRole(ctx context.Context, username string) {
	if _, err := p.masterPool.Exec(ctx,
		fmt.Sprintf("DROP ROLE IF EXISTS %s", quoteIdent(username)),
	); err != nil {
		logger.Log.Error("Failed to drop role during rollback",
			zap.String("username", username),
			zap.Error(err),
		)
	}
}
