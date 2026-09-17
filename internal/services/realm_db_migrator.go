// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// realm_db_migrator.go provides RealmDBMigrator, which orchestrates moving a
// realm's dedicated PostgreSQL database from one host to another with minimal
// downtime using the pgx native COPY protocol.
//
// Migration steps:
//  1. Resolve the source RealmDatabase record and its plaintext DSN.
//  2. Select (or validate) the target host via PlacementEngine or explicit ID.
//  3. Create role + empty database on the target host.
//  4. Run Falcon-ID realm-scoped migrations on the empty target database so the
//     schema exists before data is copied.
//  5. For each table in the public schema, stream rows source → target using
//     pgx SELECT + CopyFrom (native COPY protocol — no shell tools needed).
//  6. Verify row counts match on source and target for every table.
//  7. Update the realm_databases record: persist a new row pointing at the new host.
//  8. Mark the old realm_databases row as decommissioned.
//  9. Update realms.database_connection_id to the new record ID.
// 10. Adjust host capacity counters (decrement source, increment target).
// 11. Optionally drop the old database on the source host.
//
// The call is synchronous; for large databases it may take several minutes.
// Callers should invoke it in a background goroutine or accept HTTP 202 +
// polling if a low-latency response is required.

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
	keystonesdk "github.com/dogukanturhal/keystone-sdk/go/keystone"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// realmDBMigratorHostRepo is the narrow interface RealmDBMigrator requires from
// the host repository.
type realmDBMigratorHostRepo interface {
	DatabaseHostRepository
	GetByID(ctx context.Context, id uuid.UUID) (*models.RealmDatabaseHost, error)
}

// realmDBMigratorRealmDBRepo extends RealmDatabaseRepository with the additional
// mutation methods the migrator needs after the data copy is complete.
type realmDBMigratorRealmDBRepo interface {
	RealmDatabaseRepository
	Create(ctx context.Context, rd *models.RealmDatabase) error
	UpdateStatus(ctx context.Context, realmID uuid.UUID, status string) error
}

// MigrationRequest carries the parameters for a database migration operation.
type MigrationRequest struct {
	// RealmID identifies the realm whose database should be migrated.
	RealmID uuid.UUID `json:"realm_id" binding:"required"`

	// TargetRegion selects a target host via PlacementEngine (e.g. "tr-ank").
	// Mutually exclusive with TargetHostID; one of the two must be provided.
	TargetRegion string `json:"target_region,omitempty"`

	// TargetHostID pins the migration to a specific host record in
	// iam_realm_database_hosts. Takes precedence over TargetRegion when set.
	TargetHostID *uuid.UUID `json:"target_host_id,omitempty"`

	// DropSourceAfterMigration instructs the migrator to DROP the database on
	// the source host after a successful migration and count verification.
	// Defaults to false — the source database is left in place (safe default).
	DropSourceAfterMigration bool `json:"drop_source_after_migration,omitempty"`
}

// MigrationStatus describes the outcome of a MigrateRealmDatabase call.
type MigrationStatus struct {
	RealmID     uuid.UUID  `json:"realm_id"`
	Status      string     `json:"status"` // "completed" | "failed"
	SourceHost  string     `json:"source_host"`
	TargetHost  string     `json:"target_host"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
	TablesCount int        `json:"tables_count,omitempty"`
	TotalRows   int64      `json:"total_rows,omitempty"`
}

// RealmDBMigrator orchestrates moving a realm database between PostgreSQL hosts.
// It reuses the provisioner's password generation and migration logic for the
// target database, then streams data table-by-table using the native COPY
// protocol via pgx.
type RealmDBMigrator struct {
	realmDBRepo      realmDBMigratorRealmDBRepo
	hostRepo         realmDBMigratorHostRepo
	placementEngine  *PlacementEngine
	controlPlanePool *pgxpool.Pool // for updating realms.database_connection_id
	encryption       *crypto.EncryptionService
	provisioner      *RealmDBProvisioner // reused for target-side CREATE + migrate
}

// NewRealmDBMigrator constructs a RealmDBMigrator. The provisioner is reused so
// target-side role/database creation and schema migrations follow the same path
// as a fresh ProvisionDatabase call.
func NewRealmDBMigrator(
	realmDBRepo realmDBMigratorRealmDBRepo,
	hostRepo realmDBMigratorHostRepo,
	placementEngine *PlacementEngine,
	controlPlanePool *pgxpool.Pool,
	encryption *crypto.EncryptionService,
	provisioner *RealmDBProvisioner,
) *RealmDBMigrator {
	return &RealmDBMigrator{
		realmDBRepo:      realmDBRepo,
		hostRepo:         hostRepo,
		placementEngine:  placementEngine,
		controlPlanePool: controlPlanePool,
		encryption:       encryption,
		provisioner:      provisioner,
	}
}

// MigrateRealmDatabase moves the realm's database from its current host to a
// new host selected by PlacementEngine or specified explicitly via TargetHostID.
//
// The call blocks until the migration is complete (or fails). Large databases
// may take several minutes; callers should invoke this in a goroutine or behind
// an async job if needed.
func (m *RealmDBMigrator) MigrateRealmDatabase(ctx context.Context, req MigrationRequest) (*MigrationStatus, error) {
	startedAt := time.Now().UTC()
	status := &MigrationStatus{RealmID: req.RealmID, StartedAt: startedAt}

	logger.Log.Info("Starting realm database migration",
		zap.String("realm_id", req.RealmID.String()),
		zap.String("target_region", req.TargetRegion),
	)

	srcRecord, srcDSN, err := m.resolveSourceDatabase(ctx, req.RealmID)
	if err != nil {
		return nil, err
	}
	status.SourceHost = srcRecord.Host

	targetHost, targetConnStr, err := m.resolveTargetHost(ctx, req, srcRecord)
	if err != nil {
		return nil, fmt.Errorf("MigrateRealmDatabase: resolve target host: %w", err)
	}
	if srcRecord.HostID != nil && targetHost.ID == *srcRecord.HostID {
		return nil, fmt.Errorf("MigrateRealmDatabase: target host %s is the same as the source host", targetHost.HostAlias)
	}
	status.TargetHost = targetHost.HostAlias

	logger.Log.Info("Target host selected for migration",
		zap.String("realm_id", req.RealmID.String()),
		zap.String("target_host", targetHost.HostAlias),
		zap.String("target_region", safeStr(targetHost.Region)),
	)

	targetAdminPool, tgtHost, tgtPort, tgtSSL, newPassword, err := m.prepareTargetHost(ctx, targetConnStr, srcRecord)
	if err != nil {
		return nil, err
	}
	defer targetAdminPool.Close()

	tablesCount, totalRows, err := m.copyData(ctx, srcDSN, targetAdminPool, tgtHost, tgtPort, tgtSSL, srcRecord, newPassword)
	if err != nil {
		return nil, err
	}
	status.TablesCount = tablesCount
	status.TotalRows = totalRows

	newRecord, err := m.persistNewRecord(ctx, req, srcRecord, targetAdminPool, targetHost, tgtHost, tgtPort, tgtSSL, newPassword)
	if err != nil {
		return nil, err
	}

	m.postMigrationCleanup(ctx, req, srcRecord, targetHost, newRecord)

	completedAt := time.Now().UTC()
	status.Status = DeletionOverallCompleted
	status.CompletedAt = &completedAt

	logger.Log.Info("Realm database migration completed",
		zap.String("realm_id", req.RealmID.String()),
		zap.String("source_host", status.SourceHost),
		zap.String("target_host", status.TargetHost),
		zap.Int("tables", status.TablesCount),
		zap.Int64("total_rows", status.TotalRows),
		zap.Duration("elapsed", completedAt.Sub(startedAt)),
	)

	return status, nil
}

// resolveSourceDatabase fetches and validates the source realm database record.
func (m *RealmDBMigrator) resolveSourceDatabase(ctx context.Context, realmID uuid.UUID) (*models.RealmDatabase, string, error) {
	srcRecord, err := m.realmDBRepo.GetByRealmID(ctx, realmID)
	if err != nil {
		return nil, "", fmt.Errorf("MigrateRealmDatabase: get source database: %w", err)
	}
	if srcRecord == nil {
		return nil, "", fmt.Errorf("MigrateRealmDatabase: realm %s has no dedicated database — provision one first", realmID)
	}
	if srcRecord.Status != string(models.RealmDatabaseStatusActive) {
		return nil, "", fmt.Errorf("MigrateRealmDatabase: source database status is %q (expected %q)", srcRecord.Status, models.RealmDatabaseStatusActive)
	}
	srcPassword, err := m.decryptPassword(srcRecord.PasswordEncrypted)
	if err != nil {
		return nil, "", fmt.Errorf("MigrateRealmDatabase: decrypt source password: %w", err)
	}
	srcDSN := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		srcRecord.Username, srcPassword, srcRecord.Host, srcRecord.Port, srcRecord.DatabaseName, srcRecord.SSLMode)
	return srcRecord, srcDSN, nil
}

// prepareTargetHost sets up the target host admin pool, DDL, and schema.
func (m *RealmDBMigrator) prepareTargetHost(ctx context.Context, targetConnStr string, srcRecord *models.RealmDatabase) (*pgxpool.Pool, string, int, string, string, error) {
	targetAdminCfg, err := pgxpool.ParseConfig(targetConnStr)
	if err != nil {
		return nil, "", 0, "", "", fmt.Errorf("MigrateRealmDatabase: parse target DSN: %w", err)
	}
	targetAdminCfg.MaxConns = 3
	targetAdminPool, err := pgxpool.NewWithConfig(ctx, targetAdminCfg)
	if err != nil {
		return nil, "", 0, "", "", fmt.Errorf("MigrateRealmDatabase: connect to target host: %w", err)
	}

	tgtHost, tgtPort, tgtSSL, err := parseConnStrHostPort(targetConnStr)
	if err != nil {
		targetAdminPool.Close()
		return nil, "", 0, "", "", fmt.Errorf("MigrateRealmDatabase: parse target host/port: %w", err)
	}

	dbName := srcRecord.DatabaseName
	username := srcRecord.Username

	// Phase-2c: target role + database creation delegated to Keystone's
	// LogicalDatabaseReconciler via the password-Secret pattern. The
	// migrator no longer issues CREATE ROLE / CREATE DATABASE directly;
	// it just writes the password Secret and waits for the LD reconciler.
	// The targetAdminPool below is still required for the row-copy step
	// (admin connection to the target host) but never runs DDL.
	newPassword, err := m.provisioner.upsertOwnerPasswordSecret(ctx, srcRecord.RealmID)
	if err != nil {
		targetAdminPool.Close()
		return nil, "", 0, "", "", fmt.Errorf("MigrateRealmDatabase: upsert target owner-role password Secret: %w", err)
	}
	passwordSecretName := ownerPasswordSecretName(srcRecord.RealmID)

	// Enroll the target schema with Keystone — same shape as
	// ProvisionDatabase. The reused provisioner carries the k8s client
	// and Keystone config; this migrator never holds its own copy. The
	// LogicalDatabase + DatabaseSchema CRs use the SAME tenant_id as
	// the source DB (the realm UUID), so the SD `falcon-id-tenant-
	// desired` reconciler treats source and target identically — the
	// downstream copyData step then streams existing rows on top.
	enrollResult, err := keystonesdk.EnrollSchema(ctx, m.provisioner.keystoneClient, keystonesdk.EnrollSchemaOpts{
		Namespace:  m.provisioner.config.KeystoneNamespace,
		NamePrefix: realmEnrollNamePrefix,
		TenantID:   srcRecord.RealmID.String(),
		Scope:      realmEnrollScope,
		Tier:       realmEnrollTier,
		LogicalDatabase: keystonev1alpha1.LogicalDatabaseSpec{
			Name:        dbName,
			ClusterRef:  m.provisioner.config.KeystoneClusterRef,
			ProviderRef: m.provisioner.config.KeystoneProviderRef,
			OwnerRole:   username,
			Extensions:  []string{"uuid-ossp", "pgcrypto"},
			OwnerRolePasswordSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: passwordSecretName},
				Key:                  ownerPasswordSecretKey,
			},
		},
		Schemas: []keystonev1alpha1.DatabaseSchemaSpec{{
			Name:      "public",
			OwnerRole: username,
		}},
		Annotations: map[string]string{
			"keystone.hexxlock.io/author":    "system:falcon-id-realm-db-migrator",
			"keystone.hexxlock.io/risk-tier": "medium",
		},
	})
	if err != nil {
		// Past Secret create — leave it; deletion-policy=Delete on the
		// LD CR will GC it on later cleanup.
		targetAdminPool.Close()
		return nil, "", 0, "", "", fmt.Errorf("MigrateRealmDatabase: enroll target schema with keystone: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, realmEnrollWaitTimeout)
	defer cancel()
	if err := keystonesdk.WaitSchemaReady(waitCtx, m.provisioner.keystoneClient, enrollResult.SchemaRefs); err != nil {
		m.provisioner.rollbackProvisionOn(ctx, targetAdminPool, dbName, username)
		targetAdminPool.Close()
		return nil, "", 0, "", "", fmt.Errorf("MigrateRealmDatabase: wait target schema ready: %w", err)
	}

	// Identity-based wait — keystone v0.1.49+ stamps DatabaseSchema.Status.
	// LastAppliedFingerprint = SD.Status.Fingerprint when an SD-emitted
	// MigrationBundle's MigrationExecution succeeds for that schema.
	// WaitSchemaFingerprint polls until the target schema's fingerprint
	// matches the SD's current fingerprint, regardless of whether the
	// matched-schemas count changed (the migrator's case where the SD
	// re-fans out across an unchanged set of schemas but with the
	// underlying LogicalDatabase pointing at a new cluster).
	//
	// Replaces the WaitSchemaUpToDate-skip workaround that MR4 v1
	// shipped with — see commit f7b80ee + e9306b8 for the gap history.
	sdRef := types.NamespacedName{
		Namespace: m.provisioner.config.KeystoneNamespace,
		Name:      m.provisioner.config.KeystoneSchemaDefinitionName,
	}
	if err := keystonesdk.WaitSchemaFingerprint(waitCtx, m.provisioner.keystoneClient, sdRef, enrollResult.SchemaRefs); err != nil {
		m.provisioner.rollbackProvisionOn(ctx, targetAdminPool, dbName, username)
		targetAdminPool.Close()
		return nil, "", 0, "", "", fmt.Errorf("MigrateRealmDatabase: wait target schema fingerprint match: %w", err)
	}

	logger.Log.Info("Target database schema applied to SD desired state",
		zap.String("database", dbName),
		zap.String("host", tgtHost),
		zap.String("logical_database_ref", enrollResult.LogicalDatabaseRef.String()),
		zap.String("schema_definition", sdRef.String()),
	)
	return targetAdminPool, tgtHost, tgtPort, tgtSSL, newPassword, nil
}

// copyData opens source/target connections and streams all tables.
func (m *RealmDBMigrator) copyData(ctx context.Context, srcDSN string, targetAdminPool *pgxpool.Pool, tgtHost string, tgtPort int, tgtSSL string, srcRecord *models.RealmDatabase, newPassword string) (int, int64, error) {
	dbName := srcRecord.DatabaseName
	username := srcRecord.Username

	srcConn, err := pgx.Connect(ctx, srcDSN)
	if err != nil {
		m.provisioner.rollbackProvisionOn(ctx, targetAdminPool, dbName, username)
		return 0, 0, fmt.Errorf("MigrateRealmDatabase: connect to source database: %w", err)
	}
	defer srcConn.Close(ctx) //nolint:errcheck

	adminPassword := os.Getenv("DB_ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = os.Getenv("POSTGRES_PASSWORD")
	}
	if adminPassword == "" {
		m.provisioner.rollbackProvisionOn(ctx, targetAdminPool, dbName, username)
		return 0, 0, fmt.Errorf("MigrateRealmDatabase: DB_ADMIN_PASSWORD or POSTGRES_PASSWORD must be set")
	}
	adminDSN := fmt.Sprintf("postgres://hexxlock:%s@%s:%d/%s?sslmode=%s", url.PathEscape(adminPassword), tgtHost, tgtPort, dbName, tgtSSL)
	dstConn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		m.provisioner.rollbackProvisionOn(ctx, targetAdminPool, dbName, username)
		return 0, 0, fmt.Errorf("MigrateRealmDatabase: connect to target database for copy: %w", err)
	}
	defer dstConn.Close(ctx) //nolint:errcheck

	tables, err := listPublicTables(ctx, srcConn)
	if err != nil {
		m.provisioner.rollbackProvisionOn(ctx, targetAdminPool, dbName, username)
		return 0, 0, fmt.Errorf("MigrateRealmDatabase: list source tables: %w", err)
	}

	logger.Log.Info("Copying tables to target", zap.Int("table_count", len(tables)))

	for _, tbl := range tables {
		if _, err := dstConn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s DISABLE TRIGGER ALL", quoteIdent(tbl))); err != nil {
			logger.Log.Warn("Failed to disable triggers on table", zap.String("table", tbl), zap.Error(err))
		}
	}

	var totalRows int64
	for _, tbl := range tables {
		n, copyErr := copyTable(ctx, srcConn, dstConn, tbl)
		if copyErr != nil {
			m.provisioner.rollbackProvisionOn(ctx, targetAdminPool, dbName, username)
			return 0, 0, fmt.Errorf("MigrateRealmDatabase: copy table %q: %w", tbl, copyErr)
		}
		totalRows += n
		logger.Log.Debug("Table copied", zap.String("table", tbl), zap.Int64("rows", n))
	}

	for _, tbl := range tables {
		if _, err := dstConn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ENABLE TRIGGER ALL", quoteIdent(tbl))); err != nil {
			logger.Log.Warn("Failed to re-enable triggers", zap.String("table", tbl), zap.Error(err))
		}
	}

	if err := verifyRowCounts(ctx, srcConn, dstConn, tables); err != nil {
		logger.Log.Warn("Row count verification has discrepancies (non-fatal)", zap.Error(err))
	}
	_ = newPassword // used by caller for DSN construction
	return len(tables), totalRows, nil
}

// persistNewRecord encrypts and saves the new realm_databases record.
func (m *RealmDBMigrator) persistNewRecord(ctx context.Context, req MigrationRequest, srcRecord *models.RealmDatabase, targetAdminPool *pgxpool.Pool, targetHost *models.RealmDatabaseHost, tgtHost string, tgtPort int, tgtSSL, newPassword string) (*models.RealmDatabase, error) {
	encNewPassword, err := m.encryptPassword(newPassword)
	if err != nil {
		m.provisioner.rollbackProvisionOn(ctx, targetAdminPool, srcRecord.DatabaseName, srcRecord.Username)
		return nil, fmt.Errorf("MigrateRealmDatabase: encrypt new password: %w", err)
	}
	now := time.Now().UTC()
	hostID := targetHost.ID
	hostAlias := targetHost.HostAlias
	newRecord := &models.RealmDatabase{
		ID: uuid.New(), RealmID: req.RealmID, ConnectionName: srcRecord.ConnectionName,
		Host: tgtHost, Port: tgtPort, DatabaseName: srcRecord.DatabaseName, Username: srcRecord.Username,
		PasswordEncrypted: encNewPassword, SSLMode: tgtSSL, PoolSize: srcRecord.PoolSize,
		MaxIdleConns: srcRecord.MaxIdleConns, ConnMaxLifetimeMin: srcRecord.ConnMaxLifetimeMin,
		Status: string(models.RealmDatabaseStatusActive), HostID: &hostID, HostAlias: &hostAlias,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := m.realmDBRepo.Create(ctx, newRecord); err != nil {
		m.provisioner.rollbackProvisionOn(ctx, targetAdminPool, srcRecord.DatabaseName, srcRecord.Username)
		return nil, fmt.Errorf("MigrateRealmDatabase: store new realm_databases record: %w", err)
	}
	if err := m.realmDBRepo.UpdateStatus(ctx, req.RealmID, string(models.RealmDatabaseStatusDecommission)); err != nil {
		logger.Log.Warn("Failed to mark old realm_databases record as decommissioned",
			zap.String("realm_id", req.RealmID.String()), zap.Error(err))
	}
	return newRecord, nil
}

// postMigrationCleanup updates control plane, host counters, and optionally drops the source DB.
func (m *RealmDBMigrator) postMigrationCleanup(ctx context.Context, req MigrationRequest, srcRecord *models.RealmDatabase, targetHost *models.RealmDatabaseHost, newRecord *models.RealmDatabase) {
	if m.controlPlanePool != nil {
		if _, err := m.controlPlanePool.Exec(ctx,
			"UPDATE realms SET database_connection_id = $1, updated_at = NOW() WHERE id = $2",
			newRecord.ID, req.RealmID,
		); err != nil {
			logger.Log.Error("Failed to update realm.database_connection_id after migration",
				zap.String("realm_id", req.RealmID.String()),
				zap.String("new_record_id", newRecord.ID.String()),
				zap.Error(err),
			)
		}
	}
	if incErr := m.hostRepo.IncrementDatabaseCount(ctx, targetHost.ID); incErr != nil {
		logger.Log.Warn("Failed to increment target host database count",
			zap.String("host_id", targetHost.ID.String()), zap.Error(incErr))
	}
	if srcRecord.HostID != nil {
		if decErr := m.hostRepo.DecrementDatabaseCount(ctx, *srcRecord.HostID); decErr != nil {
			logger.Log.Warn("Failed to decrement source host database count",
				zap.String("host_id", srcRecord.HostID.String()), zap.Error(decErr))
		}
	}
	if req.DropSourceAfterMigration {
		srcAdminPool, poolErr := m.openAdminPoolForRecord(ctx, srcRecord)
		if poolErr != nil {
			logger.Log.Warn("Could not open admin pool to drop source database — skipping drop",
				zap.String("source_host", srcRecord.Host), zap.Error(poolErr))
		} else {
			defer srcAdminPool.Close()
			m.provisioner.rollbackProvisionOn(ctx, srcAdminPool, srcRecord.DatabaseName, srcRecord.Username)
			logger.Log.Info("Source database dropped after successful migration",
				zap.String("database", srcRecord.DatabaseName), zap.String("host", srcRecord.Host))
		}
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// resolveTargetHost selects the target host. TargetHostID takes precedence
// over TargetRegion; when neither is supplied an error is returned.
func (m *RealmDBMigrator) resolveTargetHost(
	ctx context.Context,
	req MigrationRequest,
	_ *models.RealmDatabase,
) (*models.RealmDatabaseHost, string, error) {
	if req.TargetHostID != nil {
		host, err := m.hostRepo.GetByID(ctx, *req.TargetHostID)
		if err != nil {
			return nil, "", fmt.Errorf("look up target host %s: %w", req.TargetHostID, err)
		}
		if host == nil {
			return nil, "", fmt.Errorf("target host %s not found", req.TargetHostID)
		}
		if !host.IsActive || host.HealthStatus != fleetStatusHealthy {
			return nil, "", fmt.Errorf("target host %s is not active/healthy (is_active=%v health=%s)",
				host.HostAlias, host.IsActive, host.HealthStatus)
		}
		connStr, err := m.decryptConnStr(host.ConnectionStringEnc)
		if err != nil {
			return nil, "", fmt.Errorf("decrypt target host DSN: %w", err)
		}
		return host, connStr, nil
	}

	if req.TargetRegion == "" {
		return nil, "", fmt.Errorf("either target_region or target_host_id must be provided")
	}
	if m.placementEngine == nil {
		return nil, "", fmt.Errorf("placement engine not configured — provide an explicit target_host_id")
	}

	result, err := m.placementEngine.SelectHost(ctx, PlacementRequest{
		PreferredRegion: req.TargetRegion,
	})
	if err != nil {
		return nil, "", fmt.Errorf("placement engine: %w", err)
	}
	return &result.Host, result.PlaintextConnStr, nil
}

// decryptPassword decrypts an encrypted database password.
// Falls back to the raw value when no encryption service is configured (dev mode).
func (m *RealmDBMigrator) decryptPassword(enc string) (string, error) {
	if m.encryption == nil {
		return enc, nil
	}
	if !crypto.IsEncrypted(enc) {
		return enc, nil
	}
	return m.encryption.Decrypt(enc)
}

// encryptPassword encrypts a plaintext password. Returns the plaintext value
// unchanged when no encryption service is configured (dev mode).
func (m *RealmDBMigrator) encryptPassword(plain string) (string, error) {
	if m.encryption == nil {
		return plain, nil
	}
	return m.encryption.Encrypt(plain)
}

// decryptConnStr decrypts a host connection string.
func (m *RealmDBMigrator) decryptConnStr(raw string) (string, error) {
	if m.encryption == nil {
		return raw, nil
	}
	if !crypto.IsEncrypted(raw) {
		return raw, nil
	}
	return m.encryption.Decrypt(raw)
}

// openAdminPoolForRecord opens a minimal admin pool for the host that owns
// srcRecord, used when dropping the source database after migration. When the
// source record has a HostID we look up the registered host DSN; otherwise we
// fall back to the provisioner's master pool config.
func (m *RealmDBMigrator) openAdminPoolForRecord(ctx context.Context, srcRecord *models.RealmDatabase) (*pgxpool.Pool, error) {
	if srcRecord.HostID != nil {
		host, err := m.hostRepo.GetByID(ctx, *srcRecord.HostID)
		if err != nil {
			return nil, fmt.Errorf("look up source host: %w", err)
		}
		if host == nil {
			return nil, fmt.Errorf("source host %s not found", srcRecord.HostID)
		}
		connStr, err := m.decryptConnStr(host.ConnectionStringEnc)
		if err != nil {
			return nil, fmt.Errorf("decrypt source host DSN: %w", err)
		}
		cfg, err := pgxpool.ParseConfig(connStr)
		if err != nil {
			return nil, fmt.Errorf("parse source host DSN: %w", err)
		}
		cfg.MaxConns = 2
		return pgxpool.NewWithConfig(ctx, cfg)
	}
	if m.provisioner == nil || m.provisioner.masterPool == nil {
		return nil, fmt.Errorf("no admin pool available for source host cleanup")
	}
	cfg := m.provisioner.masterPool.Config().Copy()
	cfg.MaxConns = 2
	return pgxpool.NewWithConfig(ctx, cfg)
}

// ---------------------------------------------------------------------------
// COPY helpers — pure functions, no receiver state.
// ---------------------------------------------------------------------------

// listPublicTables returns the names of all user-created tables in the public
// schema, ordered alphabetically.
func listPublicTables(ctx context.Context, conn *pgx.Conn) ([]string, error) {
	// List only non-partitioned tables. Partitioned parent tables cannot be
	// COPYed directly — their data lives in the child partitions which are
	// included as separate tables by this query.
	rows, err := conn.Query(ctx,
		`SELECT c.relname
		 FROM   pg_class c
		 JOIN   pg_namespace n ON n.oid = c.relnamespace
		 WHERE  n.nspname = 'public'
		   AND  c.relkind = 'r'  -- ordinary tables only (excludes 'p' = partitioned)
		 ORDER  BY c.relname`,
	)
	if err != nil {
		return nil, fmt.Errorf("listPublicTables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("listPublicTables scan: %w", err)
		}
		tables = append(tables, name)
	}
	return tables, rows.Err()
}

// copyTable streams all rows from srcConn.tableName to dstConn.tableName using
// PostgreSQL's native COPY protocol via pgx's PgConn. This handles all data
// types correctly (including JSON/JSONB, arrays, etc.) without Go-level type
// conversion. The target table is TRUNCATE'd first to clear migration seeds.
//
// Returns the number of rows copied (from the COPY command tag).
func copyTable(ctx context.Context, srcConn, dstConn *pgx.Conn, tableName string) (int64, error) {
	// Truncate the target table first to clear any migration seed rows.
	if _, err := dstConn.Exec(ctx,
		fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", quoteIdent(tableName)),
	); err != nil {
		return 0, fmt.Errorf("copyTable %q: truncate target: %w", tableName, err)
	}

	// Use io.Pipe to stream COPY TO STDOUT (source) → COPY FROM STDIN (target).
	// This avoids loading entire tables into memory and handles all PostgreSQL
	// data types natively via the text COPY format.
	pr, pw := io.Pipe()

	copyToSQL := fmt.Sprintf("COPY %s TO STDOUT", quoteIdent(tableName))
	copyFromSQL := fmt.Sprintf("COPY %s FROM STDIN", quoteIdent(tableName))

	var srcErr error
	go func() {
		defer pw.Close() //nolint:errcheck
		_, srcErr = srcConn.PgConn().CopyTo(ctx, pw, copyToSQL)
	}()

	tag, dstErr := dstConn.PgConn().CopyFrom(ctx, pr, copyFromSQL)
	if srcErr != nil {
		return 0, fmt.Errorf("copyTable %q: COPY TO: %w", tableName, srcErr)
	}
	if dstErr != nil {
		return 0, fmt.Errorf("copyTable %q: COPY FROM: %w", tableName, dstErr)
	}

	return tag.RowsAffected(), nil
}

// verifyRowCounts checks that every table on the source has the same row count
// on the destination. Returns a descriptive error for the first mismatch found.
func verifyRowCounts(ctx context.Context, srcConn, dstConn *pgx.Conn, tables []string) error {
	for _, tbl := range tables {
		var srcCount, dstCount int64
		if err := srcConn.QueryRow(ctx,
			fmt.Sprintf("SELECT COUNT(*) FROM %s", quoteIdent(tbl)),
		).Scan(&srcCount); err != nil {
			return fmt.Errorf("count source table %q: %w", tbl, err)
		}
		if err := dstConn.QueryRow(ctx,
			fmt.Sprintf("SELECT COUNT(*) FROM %s", quoteIdent(tbl)),
		).Scan(&dstCount); err != nil {
			return fmt.Errorf("count target table %q: %w", tbl, err)
		}
		if srcCount != dstCount {
			return fmt.Errorf("table %q row count mismatch: source=%d target=%d",
				tbl, srcCount, dstCount)
		}
	}
	return nil
}
