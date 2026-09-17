// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock: RealmDatabaseRepositoryInterface
// ---------------------------------------------------------------------------

// mockMigrationRealmDBRepo is a testify/mock implementation of
// RealmDatabaseRepositoryInterface. It is scoped to the migration tests to
// avoid collisions with the manual struct mock used in realm_db_provisioner_test.go.
type mockMigrationRealmDBRepo struct {
	mock.Mock
}

func (m *mockMigrationRealmDBRepo) GetByRealmID(ctx context.Context, realmID uuid.UUID) (*models.RealmDatabase, error) {
	args := m.Called(ctx, realmID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RealmDatabase), args.Error(1)
}

func (m *mockMigrationRealmDBRepo) Create(ctx context.Context, rd *models.RealmDatabase) error {
	args := m.Called(ctx, rd)
	return args.Error(0)
}

func (m *mockMigrationRealmDBRepo) UpdateStatus(ctx context.Context, realmID uuid.UUID, status string) error {
	args := m.Called(ctx, realmID, status)
	return args.Error(0)
}

func (m *mockMigrationRealmDBRepo) UpdateHealthCheck(ctx context.Context, realmID uuid.UUID, status string, message string) error {
	args := m.Called(ctx, realmID, status, message)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Mock: SessionCacheInterface
// ---------------------------------------------------------------------------

// mockMigrationSessionCache is a testify/mock implementation of
// SessionCacheInterface for the tenant migration tests.
type mockMigrationSessionCache struct {
	mock.Mock
}

func (m *mockMigrationSessionCache) InvalidateTenantSessions(ctx context.Context, tenantID uuid.UUID) error {
	args := m.Called(ctx, tenantID)
	return args.Error(0)
}

func (m *mockMigrationSessionCache) InvalidateRealmSessions(ctx context.Context, realmID uuid.UUID) error {
	args := m.Called(ctx, realmID)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Mock: TenantMigrationDataSource
// ---------------------------------------------------------------------------

// mockMigrationDataSource stands in for the source/target database operations
// (exportTable, importTable, verifyTable) during unit tests.
type mockMigrationDataSource struct {
	mock.Mock
}

func (m *mockMigrationDataSource) ExportTable(ctx context.Context, tableName string, tenantID uuid.UUID) ([]map[string]interface{}, string, error) {
	args := m.Called(ctx, tableName, tenantID)
	if args.Get(0) == nil {
		return nil, args.String(1), args.Error(2)
	}
	return args.Get(0).([]map[string]interface{}), args.String(1), args.Error(2)
}

func (m *mockMigrationDataSource) ImportTable(ctx context.Context, tableName string, rows []map[string]interface{}) (int64, error) {
	args := m.Called(ctx, tableName, rows)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockMigrationDataSource) VerifyTable(ctx context.Context, tableName string, tenantID uuid.UUID, expectedChecksum string) error {
	args := m.Called(ctx, tableName, tenantID, expectedChecksum)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestMigrationService constructs a TenantMigrationService wired with the
// provided mocks. The logger is a no-op zap logger to keep test output clean.
func newTestMigrationService(
	realmDBRepo RealmDatabaseRepositoryInterface,
	sessionCache MigrationSessionCacheInterface,
) *TenantMigrationService {
	logger := zap.NewNop()
	return NewTenantMigrationService(realmDBRepo, sessionCache, logger)
}

// buildFakeRows creates a trivial export result: n rows each with a single
// "tenant_id" column matching the provided tenantID.
func buildFakeRows(tenantID uuid.UUID, n int) []map[string]interface{} {
	rows := make([]map[string]interface{}, n)
	for i := 0; i < n; i++ {
		rows[i] = map[string]interface{}{"tenant_id": tenantID.String()}
	}
	return rows
}

// ---------------------------------------------------------------------------
// TestTenantMigrationService_MigrateTenant_ExportsAllTableData
//
// Verifies that MigrateTenant calls ExportTable for every entry in
// iamMigrationTables. Each table must be visited exactly once.
// ---------------------------------------------------------------------------

func TestTenantMigrationService_MigrateTenant_ExportsAllTableData(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tenantID := uuid.New()
	sourceRealmID := uuid.New()
	targetRealmID := uuid.New()

	realmDBRepo := new(mockMigrationRealmDBRepo)
	sessionCache := new(mockMigrationSessionCache)
	dataSource := new(mockMigrationDataSource)

	svc := newTestMigrationService(realmDBRepo, sessionCache)

	// All tables export successfully with a handful of rows.
	fakeRows := buildFakeRows(tenantID, 3)
	fakeChecksum := "abc123"

	for _, tbl := range iamMigrationTables {
		dataSource.On("ExportTable", ctx, tbl, tenantID).Return(fakeRows, fakeChecksum, nil).Once()
		dataSource.On("ImportTable", ctx, tbl, fakeRows).Return(int64(len(fakeRows)), nil).Once()
		dataSource.On("VerifyTable", ctx, tbl, tenantID, fakeChecksum).Return(nil).Once()
	}

	// switchConnection: update realm record and invalidate caches.
	realmDBRepo.On("UpdateStatus", ctx, targetRealmID, string(models.RealmDatabaseStatusActive)).Return(nil).Once()
	sessionCache.On("InvalidateTenantSessions", ctx, tenantID).Return(nil).Once()
	sessionCache.On("InvalidateRealmSessions", ctx, sourceRealmID).Return(nil).Once()

	var progressSnapshots []models.MigrationProgress
	progressFn := func(p models.MigrationProgress) {
		progressSnapshots = append(progressSnapshots, p)
	}

	err := svc.MigrateTenant(ctx, tenantID, sourceRealmID, targetRealmID, dataSource, progressFn)
	require.NoError(t, err)

	// Every table in iamMigrationTables must have been exported.
	dataSource.AssertNumberOfCalls(t, "ExportTable", len(iamMigrationTables))
	dataSource.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestTenantMigrationService_MigrateTenant_VerifiesDataIntegrity
//
// Verifies that VerifyTable is called with the checksum produced by ExportTable
// and that a checksum mismatch causes the migration to fail.
// ---------------------------------------------------------------------------

func TestTenantMigrationService_MigrateTenant_VerifiesDataIntegrity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tenantID := uuid.New()
	sourceRealmID := uuid.New()
	targetRealmID := uuid.New()

	realmDBRepo := new(mockMigrationRealmDBRepo)
	sessionCache := new(mockMigrationSessionCache)
	dataSource := new(mockMigrationDataSource)

	svc := newTestMigrationService(realmDBRepo, sessionCache)

	fakeRows := buildFakeRows(tenantID, 5)
	goodChecksum := "deadbeef"

	// First table: export and import succeed, but VerifyTable returns a mismatch error.
	firstTable := iamMigrationTables[0]
	dataSource.On("ExportTable", ctx, firstTable, tenantID).Return(fakeRows, goodChecksum, nil).Once()
	dataSource.On("ImportTable", ctx, firstTable, fakeRows).Return(int64(5), nil).Once()
	dataSource.On("VerifyTable", ctx, firstTable, tenantID, goodChecksum).
		Return(errors.New("checksum mismatch: source=deadbeef target=00000000")).Once()

	// No further calls expected after the first verification failure.

	var lastProgress models.MigrationProgress
	progressFn := func(p models.MigrationProgress) {
		lastProgress = p
	}

	err := svc.MigrateTenant(ctx, tenantID, sourceRealmID, targetRealmID, dataSource, progressFn)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")

	// The final progress snapshot must reflect a failed or rolled_back phase.
	assert.True(t,
		lastProgress.Phase == models.MigrationPhaseFailed ||
			lastProgress.Phase == models.MigrationPhaseRolledBack,
		"expected failed or rolled_back phase, got %q", lastProgress.Phase,
	)

	dataSource.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestTenantMigrationService_MigrateTenant_SwitchesRealmConnection
//
// After all tables are migrated and verified, UpdateStatus must be called on
// the targetRealmID to activate it, and both session invalidation methods must
// be called so in-flight requests are forced to re-authenticate against the
// new database.
// ---------------------------------------------------------------------------

func TestTenantMigrationService_MigrateTenant_SwitchesRealmConnection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tenantID := uuid.New()
	sourceRealmID := uuid.New()
	targetRealmID := uuid.New()

	realmDBRepo := new(mockMigrationRealmDBRepo)
	sessionCache := new(mockMigrationSessionCache)
	dataSource := new(mockMigrationDataSource)

	svc := newTestMigrationService(realmDBRepo, sessionCache)

	fakeRows := buildFakeRows(tenantID, 2)
	checksum := "cafebabe"

	for _, tbl := range iamMigrationTables {
		dataSource.On("ExportTable", ctx, tbl, tenantID).Return(fakeRows, checksum, nil).Once()
		dataSource.On("ImportTable", ctx, tbl, fakeRows).Return(int64(2), nil).Once()
		dataSource.On("VerifyTable", ctx, tbl, tenantID, checksum).Return(nil).Once()
	}

	// Connection switch expectations.
	realmDBRepo.On("UpdateStatus", ctx, targetRealmID, string(models.RealmDatabaseStatusActive)).Return(nil).Once()
	sessionCache.On("InvalidateTenantSessions", ctx, tenantID).Return(nil).Once()
	sessionCache.On("InvalidateRealmSessions", ctx, sourceRealmID).Return(nil).Once()

	err := svc.MigrateTenant(ctx, tenantID, sourceRealmID, targetRealmID, dataSource, nil)
	require.NoError(t, err)

	realmDBRepo.AssertExpectations(t)
	sessionCache.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestTenantMigrationService_MigrateTenant_RollsBackOnImportFailure
//
// When ImportTable returns an error for any table the migration must:
//  1. Not proceed to further tables.
//  2. Not call UpdateStatus on the realm DB repo (source data is untouched).
//  3. Return a non-nil error to the caller.
// ---------------------------------------------------------------------------

func TestTenantMigrationService_MigrateTenant_RollsBackOnImportFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tenantID := uuid.New()
	sourceRealmID := uuid.New()
	targetRealmID := uuid.New()

	realmDBRepo := new(mockMigrationRealmDBRepo)
	sessionCache := new(mockMigrationSessionCache)
	dataSource := new(mockMigrationDataSource)

	svc := newTestMigrationService(realmDBRepo, sessionCache)

	fakeRows := buildFakeRows(tenantID, 10)
	checksum := "aabbccdd"

	// First table: export succeeds, import fails.
	firstTable := iamMigrationTables[0]
	importErr := errors.New("target database: connection reset by peer")
	dataSource.On("ExportTable", ctx, firstTable, tenantID).Return(fakeRows, checksum, nil).Once()
	dataSource.On("ImportTable", ctx, firstTable, fakeRows).Return(int64(0), importErr).Once()

	// UpdateStatus must NOT be called — source data is untouched.
	realmDBRepo.AssertNotCalled(t, "UpdateStatus", mock.Anything, mock.Anything, mock.Anything)

	// Session cache must NOT be touched on rollback.
	sessionCache.AssertNotCalled(t, "InvalidateTenantSessions", mock.Anything, mock.Anything)
	sessionCache.AssertNotCalled(t, "InvalidateRealmSessions", mock.Anything, mock.Anything)

	var finalProgress models.MigrationProgress
	progressFn := func(p models.MigrationProgress) {
		finalProgress = p
	}

	err := svc.MigrateTenant(ctx, tenantID, sourceRealmID, targetRealmID, dataSource, progressFn)

	require.Error(t, err)
	assert.True(t,
		finalProgress.Phase == models.MigrationPhaseFailed ||
			finalProgress.Phase == models.MigrationPhaseRolledBack,
		"expected failed or rolled_back phase, got %q", finalProgress.Phase,
	)

	dataSource.AssertExpectations(t)
	realmDBRepo.AssertExpectations(t)
	sessionCache.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestTenantMigrationService_MigrateTenant_InvalidatesCaches
//
// After a successful migration the service must flush Redis session data for
// the tenant and for the source realm so that no stale session context pointing
// at the old database survives in the cache.
// ---------------------------------------------------------------------------

func TestTenantMigrationService_MigrateTenant_InvalidatesCaches(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tenantID := uuid.New()
	sourceRealmID := uuid.New()
	targetRealmID := uuid.New()

	realmDBRepo := new(mockMigrationRealmDBRepo)
	sessionCache := new(mockMigrationSessionCache)
	dataSource := new(mockMigrationDataSource)

	svc := newTestMigrationService(realmDBRepo, sessionCache)

	fakeRows := buildFakeRows(tenantID, 1)
	checksum := "11223344"

	for _, tbl := range iamMigrationTables {
		dataSource.On("ExportTable", ctx, tbl, tenantID).Return(fakeRows, checksum, nil).Once()
		dataSource.On("ImportTable", ctx, tbl, fakeRows).Return(int64(1), nil).Once()
		dataSource.On("VerifyTable", ctx, tbl, tenantID, checksum).Return(nil).Once()
	}

	realmDBRepo.On("UpdateStatus", ctx, targetRealmID, string(models.RealmDatabaseStatusActive)).Return(nil).Once()

	// Both cache invalidation calls are mandatory.
	sessionCache.On("InvalidateTenantSessions", ctx, tenantID).Return(nil).Once()
	sessionCache.On("InvalidateRealmSessions", ctx, sourceRealmID).Return(nil).Once()

	err := svc.MigrateTenant(ctx, tenantID, sourceRealmID, targetRealmID, dataSource, nil)
	require.NoError(t, err)

	sessionCache.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestTenantMigrationService_MigrateTenant_TracksProgress
//
// Verifies that the progress callback fires with the correct phase transitions
// and that the TablesTotal, TablesCompleted, RowsExported, and RowsImported
// counters are updated monotonically.
// ---------------------------------------------------------------------------

func TestTenantMigrationService_MigrateTenant_TracksProgress(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tenantID := uuid.New()
	sourceRealmID := uuid.New()
	targetRealmID := uuid.New()

	realmDBRepo := new(mockMigrationRealmDBRepo)
	sessionCache := new(mockMigrationSessionCache)
	dataSource := new(mockMigrationDataSource)

	svc := newTestMigrationService(realmDBRepo, sessionCache)

	fakeRows := buildFakeRows(tenantID, 7)
	checksum := "99887766"

	for _, tbl := range iamMigrationTables {
		dataSource.On("ExportTable", ctx, tbl, tenantID).Return(fakeRows, checksum, nil).Once()
		dataSource.On("ImportTable", ctx, tbl, fakeRows).Return(int64(7), nil).Once()
		dataSource.On("VerifyTable", ctx, tbl, tenantID, checksum).Return(nil).Once()
	}

	realmDBRepo.On("UpdateStatus", ctx, targetRealmID, string(models.RealmDatabaseStatusActive)).Return(nil).Once()
	sessionCache.On("InvalidateTenantSessions", ctx, tenantID).Return(nil).Once()
	sessionCache.On("InvalidateRealmSessions", ctx, sourceRealmID).Return(nil).Once()

	var snapshots []models.MigrationProgress
	progressFn := func(p models.MigrationProgress) {
		snapshots = append(snapshots, p)
	}

	startBefore := time.Now()
	err := svc.MigrateTenant(ctx, tenantID, sourceRealmID, targetRealmID, dataSource, progressFn)
	require.NoError(t, err)

	// At least one progress snapshot must exist.
	require.NotEmpty(t, snapshots, "expected at least one progress callback")

	// All snapshots must carry the correct tenantID / realm IDs.
	for i, snap := range snapshots {
		assert.Equal(t, tenantID, snap.TenantID, "snapshot %d: wrong tenant_id", i)
		assert.Equal(t, sourceRealmID, snap.SourceRealmID, "snapshot %d: wrong source_realm_id", i)
		assert.Equal(t, targetRealmID, snap.TargetRealmID, "snapshot %d: wrong target_realm_id", i)
		assert.Equal(t, len(iamMigrationTables), snap.TablesTotal, "snapshot %d: wrong tables_total", i)
		assert.True(t, snap.StartedAt.Equal(startBefore) || snap.StartedAt.After(startBefore),
			"snapshot %d: StartedAt must not be before test start", i)
	}

	// The very first snapshot must be in the exporting phase.
	assert.Equal(t, models.MigrationPhaseExporting, snapshots[0].Phase,
		"first progress callback must use exporting phase")

	// The final snapshot must be completed.
	last := snapshots[len(snapshots)-1]
	assert.Equal(t, models.MigrationPhaseCompleted, last.Phase,
		"last progress callback must use completed phase")
	assert.Equal(t, len(iamMigrationTables), last.TablesCompleted,
		"all tables must be marked completed at the end")
	assert.NotNil(t, last.CompletedAt, "CompletedAt must be set on the completed snapshot")

	// Row counts must be monotonically increasing across snapshots.
	for i := 1; i < len(snapshots); i++ {
		assert.GreaterOrEqual(t, snapshots[i].RowsExported, snapshots[i-1].RowsExported,
			"RowsExported must not decrease between snapshots %d and %d", i-1, i)
		assert.GreaterOrEqual(t, snapshots[i].RowsImported, snapshots[i-1].RowsImported,
			"RowsImported must not decrease between snapshots %d and %d", i-1, i)
	}

	dataSource.AssertExpectations(t)
}
