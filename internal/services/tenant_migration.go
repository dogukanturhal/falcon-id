// SPDX-License-Identifier: AGPL-3.0-or-later

// Package services provides business logic for the Falcon-ID IAM service.
// This file implements the tenant migration service for Phase 4A of the
// Enterprise Realm Database Isolation plan.
package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// iamMigrationTables is the ordered list of IAM tables that must be migrated
// when moving a tenant from one realm database to another.
//
// The order respects foreign-key dependencies: parent tables appear before
// child tables so that referential integrity is maintained during import even
// if the target database enforces FK constraints.
var iamMigrationTables = []string{
	"iam_organizations",
	"iam_users",
	"iam_roles",
	"iam_permissions", // shared but may have tenant-scoped custom perms
	"iam_user_roles",
	"iam_role_permissions",
	"iam_groups",
	"iam_user_groups",
	"iam_sessions",
	"iam_refresh_tokens",
	"iam_api_keys",
	"iam_user_devices",
	"iam_magic_links",
	"iam_invitations",
	"iam_consent_records",
	"iam_delegations",
	"iam_impersonation_sessions",
	"iam_identity_providers",
	"iam_ldap_configs",
	"iam_oauth_providers",
	"iam_saml_service_providers",
	"iam_password_policies",
	"iam_rate_limiting_rules",
	"iam_ip_rules",
	"iam_webhooks",
	"iam_service_accounts",
	"iam_audit_log",
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

// RealmDatabaseRepositoryInterface abstracts the realm_databases repository
// for use by TenantMigrationService. It is satisfied by both the concrete
// RealmDatabaseRepository and the manual mock used in provisioner tests.
//
// Note: This declaration extends the existing RealmDatabaseRepository interface
// defined in realm_db_provisioner.go. It is a separate named type to avoid
// redefining the identifier in the same package while keeping the migration
// service self-contained.
type RealmDatabaseRepositoryInterface interface {
	GetByRealmID(ctx context.Context, realmID uuid.UUID) (*models.RealmDatabase, error)
	Create(ctx context.Context, rd *models.RealmDatabase) error
	UpdateStatus(ctx context.Context, realmID uuid.UUID, status string) error
	UpdateHealthCheck(ctx context.Context, realmID uuid.UUID, status string, message string) error
}

// MigrationSessionCacheInterface abstracts the Redis session cache operations
// needed by the migration service to invalidate stale session data after a
// tenant has been switched to a new realm database.
type MigrationSessionCacheInterface interface {
	// InvalidateTenantSessions removes all cached session data for the given
	// tenant so that every in-flight request is forced to re-authenticate
	// against the new database.
	InvalidateTenantSessions(ctx context.Context, tenantID uuid.UUID) error

	// InvalidateRealmSessions removes cached session data scoped to the given
	// realm so that realm-level caches are flushed after the switch.
	InvalidateRealmSessions(ctx context.Context, realmID uuid.UUID) error
}

// MigrationDataSource abstracts the per-table export, import, and
// verification operations that TenantMigrationService coordinates.
//
// The interface makes all database interactions mockable in unit tests:
// implementations use the pgx COPY protocol for bulk I/O; tests inject a
// mock that returns pre-built rows and checksums.
type MigrationDataSource interface {
	// ExportTable reads all rows belonging to tenantID from tableName in the
	// source database and returns them as a slice of column maps alongside an
	// MD5 checksum of the exported data.
	ExportTable(ctx context.Context, tableName string, tenantID uuid.UUID) ([]map[string]interface{}, string, error)

	// ImportTable writes rows into tableName on the target database and
	// returns the number of rows successfully inserted.
	ImportTable(ctx context.Context, tableName string, rows []map[string]interface{}) (int64, error)

	// VerifyTable computes the MD5 checksum of the tenant-scoped rows that
	// were written to tableName on the target database and compares it against
	// expectedChecksum. A mismatch causes an error to be returned.
	VerifyTable(ctx context.Context, tableName string, tenantID uuid.UUID, expectedChecksum string) error
}

// ---------------------------------------------------------------------------
// TenantMigrationService
// ---------------------------------------------------------------------------

// TenantMigrationService orchestrates moving a tenant's IAM data between realm
// databases (shared-to-dedicated or dedicated-to-dedicated). It coordinates:
//
//  1. Exporting all tenant-scoped rows from the source database.
//  2. Importing those rows into the target database.
//  3. Verifying data integrity via MD5 checksums.
//  4. Switching the active realm connection record in the control plane.
//  5. Flushing Redis caches for the tenant and source realm.
//
// On any failure during export or import the migration is aborted and the
// source database is left untouched. No write is made to the realm_databases
// table until all tables are successfully migrated and verified.
type TenantMigrationService struct {
	realmDBRepo  RealmDatabaseRepositoryInterface
	sessionCache MigrationSessionCacheInterface
	logger       *zap.Logger
}

// NewTenantMigrationService creates a new TenantMigrationService.
func NewTenantMigrationService(
	realmDBRepo RealmDatabaseRepositoryInterface,
	sessionCache MigrationSessionCacheInterface,
	logger *zap.Logger,
) *TenantMigrationService {
	return &TenantMigrationService{
		realmDBRepo:  realmDBRepo,
		sessionCache: sessionCache,
		logger:       logger,
	}
}

// MigrateTenant moves all IAM data for tenantID from the source realm database
// to the target realm database.
//
// Parameters:
//   - ctx:            caller-supplied context; cancellation aborts the migration.
//   - tenantID:       the tenant whose rows are being migrated.
//   - sourceRealmID:  the realm the tenant is currently assigned to.
//   - targetRealmID:  the realm the tenant will be assigned to after migration.
//   - dataSource:     abstraction over source/target DB I/O (inject mock in tests).
//   - progressFn:     optional callback invoked after each significant phase change;
//     pass nil to disable progress tracking.
//
// Returns a non-nil error if any table export, import, or verification step fails.
// On failure, no changes are made to the realm_databases table and no session
// caches are flushed so the source data remains fully operational.
func (s *TenantMigrationService) MigrateTenant(
	ctx context.Context,
	tenantID uuid.UUID,
	sourceRealmID uuid.UUID,
	targetRealmID uuid.UUID,
	dataSource MigrationDataSource,
	progressFn func(models.MigrationProgress),
) error {
	startedAt := time.Now().UTC()

	progress := models.MigrationProgress{
		ID:            uuid.New(),
		TenantID:      tenantID,
		SourceRealmID: sourceRealmID,
		TargetRealmID: targetRealmID,
		TablesTotal:   len(iamMigrationTables),
		StartedAt:     startedAt,
	}

	s.logger.Info("TenantMigration: starting",
		zap.String("tenant_id", tenantID.String()),
		zap.String("source_realm_id", sourceRealmID.String()),
		zap.String("target_realm_id", targetRealmID.String()),
		zap.Int("tables_total", len(iamMigrationTables)),
	)

	// emit is a helper that fires progressFn when it is non-nil.
	emit := func(phase models.MigrationPhase) {
		progress.Phase = phase
		if progressFn != nil {
			progressFn(progress)
		}
	}

	// -----------------------------------------------------------------------
	// Phase: export + import + verify (table by table)
	// -----------------------------------------------------------------------

	emit(models.MigrationPhaseExporting)

	for _, tableName := range iamMigrationTables {
		select {
		case <-ctx.Done():
			return s.fail(&progress, progressFn, fmt.Errorf("MigrateTenant: context cancelled: %w", ctx.Err()))
		default:
		}

		// --- Export ---
		rows, checksum, err := dataSource.ExportTable(ctx, tableName, tenantID)
		if err != nil {
			return s.fail(&progress, progressFn,
				fmt.Errorf("MigrateTenant: ExportTable %q: %w", tableName, err))
		}
		progress.RowsExported += int64(len(rows))

		// --- Import ---
		emit(models.MigrationPhaseImporting)

		imported, err := dataSource.ImportTable(ctx, tableName, rows)
		if err != nil {
			return s.fail(&progress, progressFn,
				fmt.Errorf("MigrateTenant: ImportTable %q: %w", tableName, err))
		}
		progress.RowsImported += imported

		// --- Verify ---
		emit(models.MigrationPhaseVerifying)

		if err := dataSource.VerifyTable(ctx, tableName, tenantID, checksum); err != nil {
			return s.fail(&progress, progressFn,
				fmt.Errorf("MigrateTenant: VerifyTable %q: %w", tableName, err))
		}

		progress.TablesCompleted++
		s.logger.Info("TenantMigration: table completed",
			zap.String("table", tableName),
			zap.Int64("rows_exported", int64(len(rows))),
			zap.Int64("rows_imported", imported),
			zap.String("checksum", checksum),
		)

		// Emit exporting phase again for the next table (unless this was the last one).
		if progress.TablesCompleted < len(iamMigrationTables) {
			emit(models.MigrationPhaseExporting)
		}
	}

	// -----------------------------------------------------------------------
	// Phase: switch connection
	// -----------------------------------------------------------------------

	emit(models.MigrationPhaseSwitching)

	if err := s.switchConnection(ctx, targetRealmID); err != nil {
		return s.fail(&progress, progressFn,
			fmt.Errorf("MigrateTenant: switchConnection: %w", err))
	}

	// -----------------------------------------------------------------------
	// Phase: invalidate caches
	// -----------------------------------------------------------------------

	if err := s.invalidateCaches(ctx, tenantID, sourceRealmID); err != nil {
		// Cache invalidation failure is logged but does not abort: the data is
		// already safely in the target DB and the realm record is updated.
		// Stale sessions will expire naturally via Redis TTL.
		s.logger.Warn("TenantMigration: cache invalidation failed (non-fatal)",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
	}

	// -----------------------------------------------------------------------
	// Phase: completed
	// -----------------------------------------------------------------------

	now := time.Now().UTC()
	progress.CompletedAt = &now
	emit(models.MigrationPhaseCompleted)

	s.logger.Info("TenantMigration: completed",
		zap.String("tenant_id", tenantID.String()),
		zap.Int64("rows_exported", progress.RowsExported),
		zap.Int64("rows_imported", progress.RowsImported),
		zap.Duration("duration", now.Sub(startedAt)),
	)

	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// switchConnection updates the realm_databases record for targetRealmID to
// active status, signalling that the connection router should start directing
// this tenant's traffic to the new database.
func (s *TenantMigrationService) switchConnection(ctx context.Context, targetRealmID uuid.UUID) error {
	if err := s.realmDBRepo.UpdateStatus(ctx, targetRealmID, string(models.RealmDatabaseStatusActive)); err != nil {
		return fmt.Errorf("switchConnection: UpdateStatus: %w", err)
	}
	s.logger.Info("TenantMigration: realm connection switched",
		zap.String("target_realm_id", targetRealmID.String()),
	)
	return nil
}

// invalidateCaches removes tenant-scoped and realm-scoped session data from
// Redis so that in-flight requests must re-authenticate against the new
// database. Both invalidation calls are attempted even if the first fails.
func (s *TenantMigrationService) invalidateCaches(ctx context.Context, tenantID, realmID uuid.UUID) error {
	var errs []error

	if err := s.sessionCache.InvalidateTenantSessions(ctx, tenantID); err != nil {
		errs = append(errs, fmt.Errorf("InvalidateTenantSessions: %w", err))
	}

	if err := s.sessionCache.InvalidateRealmSessions(ctx, realmID); err != nil {
		errs = append(errs, fmt.Errorf("InvalidateRealmSessions: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalidateCaches: %v", errs)
	}
	return nil
}

// fail transitions the progress to a terminal failure phase, fires the
// progress callback, logs the error, and returns the (wrapped) error to the
// caller. It is a convenience helper to avoid repetition in MigrateTenant.
func (s *TenantMigrationService) fail(
	progress *models.MigrationProgress,
	progressFn func(models.MigrationProgress),
	err error,
) error {
	now := time.Now().UTC()
	progress.Phase = models.MigrationPhaseRolledBack
	progress.ErrorMessage = err.Error()
	progress.CompletedAt = &now

	if progressFn != nil {
		progressFn(*progress)
	}

	s.logger.Error("TenantMigration: failed",
		zap.String("tenant_id", progress.TenantID.String()),
		zap.String("phase", string(progress.Phase)),
		zap.Error(err),
	)
	return err
}
