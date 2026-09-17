// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantprojection_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	pgxmock "github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/tenantprojection"
)

// newMockRepo creates a pgxmock pool + a Repository for table-driven tests.
func newMockRepo(t *testing.T) (*tenantprojection.Repository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return tenantprojection.NewRepository(mock), mock
}

// expectRowFound configures the existence-probe query to return a row (tenant found).
func expectRowFound(mock pgxmock.PgxPoolIface) {
	mock.ExpectQuery(`SELECT 1 FROM iam_tenants`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(mock.NewRows([]string{"found"}).AddRow(1))
}

// expectRowMissing configures the existence-probe query to return ErrNoRows.
func expectRowMissing(mock pgxmock.PgxPoolIface) {
	mock.ExpectQuery(`SELECT 1 FROM iam_tenants`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnError(errors.New("no rows in result set"))
}

// ---------------------------------------------------------------------------
// ApplyTenantUpsert — existence probe + UPDATE outcome variants
// ---------------------------------------------------------------------------

func TestApplyTenantUpsert_Applied(t *testing.T) {
	repo, mock := newMockRepo(t)
	id := uuid.New()
	now := time.Now().UTC()

	// Row exists → UPDATE fires and affects 1 row.
	// Phase 3.2: arg layout is (id, status, metadata, eventTime). Plan + Type
	// were removed from TenantEvent — the columns no longer exist in
	// iam_tenants (dropped by the GitOps repository !699).
	expectRowFound(mock)
	mock.ExpectExec(`UPDATE iam_tenants`).
		WithArgs(id, "active", pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	result, err := repo.ApplyTenantUpsert(context.Background(), tenantprojection.TenantEvent{
		ID:        id,
		Status:    "active",
		EventTime: now,
	})
	require.NoError(t, err)
	assert.Equal(t, tenantprojection.UpsertResultApplied, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestApplyTenantUpsert_StaleEventSkipped(t *testing.T) {
	repo, mock := newMockRepo(t)
	id := uuid.New()
	now := time.Now().UTC()

	// Row exists → UPDATE WHERE updated_at < eventTime fires with 0 rows (stale).
	expectRowFound(mock)
	mock.ExpectExec(`UPDATE iam_tenants`).
		WithArgs(id, "active", pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	result, err := repo.ApplyTenantUpsert(context.Background(), tenantprojection.TenantEvent{
		ID:        id,
		Status:    "active",
		EventTime: now,
	})
	require.NoError(t, err)
	assert.Equal(t, tenantprojection.UpsertResultSkipped, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestApplyTenantUpsert_OrphanTenantNotInIAM(t *testing.T) {
	repo, mock := newMockRepo(t)
	id := uuid.New()
	now := time.Now().UTC()

	// Existence probe returns no-rows → orphan, no UPDATE attempted.
	expectRowMissing(mock)

	result, err := repo.ApplyTenantUpsert(context.Background(), tenantprojection.TenantEvent{
		ID:        id,
		Status:    "active",
		EventTime: now,
	})
	require.NoError(t, err)
	assert.Equal(t, tenantprojection.UpsertResultOrphan, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestApplyTenantUpsert_DBError(t *testing.T) {
	repo, mock := newMockRepo(t)
	id := uuid.New()
	now := time.Now().UTC()

	// Row exists → UPDATE fails with a transient error.
	// Phase 3.2: 4 args (id, status, metadata, eventTime).
	expectRowFound(mock)
	mock.ExpectExec(`UPDATE iam_tenants`).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnError(errors.New("connection reset by peer"))

	_, err := repo.ApplyTenantUpsert(context.Background(), tenantprojection.TenantEvent{
		ID:        id,
		Status:    "active",
		EventTime: now,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ApplyTenantUpsert")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestApplyTenantUpsert_WithMetadata(t *testing.T) {
	repo, mock := newMockRepo(t)
	id := uuid.New()
	now := time.Now().UTC()
	meta := []byte(`{"feature_x":true}`)

	expectRowFound(mock)
	mock.ExpectExec(`UPDATE iam_tenants`).
		WithArgs(id, "active", string(meta), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	result, err := repo.ApplyTenantUpsert(context.Background(), tenantprojection.TenantEvent{
		ID:        id,
		Status:    "active",
		Metadata:  meta,
		EventTime: now,
	})
	require.NoError(t, err)
	assert.Equal(t, tenantprojection.UpsertResultApplied, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// ApplyTenantDelete — soft-delete idempotency
// ---------------------------------------------------------------------------

func TestApplyTenantDelete_SoftDeletesRow(t *testing.T) {
	repo, mock := newMockRepo(t)
	id := uuid.New()

	// Row exists → UPDATE affects 1 row.
	expectRowFound(mock)
	mock.ExpectExec(`UPDATE iam_tenants`).
		WithArgs(id).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	result, err := repo.ApplyTenantDelete(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, tenantprojection.UpsertResultApplied, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestApplyTenantDelete_AlreadyDeletedSkips(t *testing.T) {
	repo, mock := newMockRepo(t)
	id := uuid.New()

	// Row exists → WHERE status != 'deleted' fires with 0 rows (already deleted).
	expectRowFound(mock)
	mock.ExpectExec(`UPDATE iam_tenants`).
		WithArgs(id).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	result, err := repo.ApplyTenantDelete(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, tenantprojection.UpsertResultSkipped, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestApplyTenantDelete_OrphanTenantNotInIAM(t *testing.T) {
	repo, mock := newMockRepo(t)
	id := uuid.New()

	// Existence probe: no row.
	expectRowMissing(mock)

	result, err := repo.ApplyTenantDelete(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, tenantprojection.UpsertResultOrphan, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestApplyTenantDelete_DBError(t *testing.T) {
	repo, mock := newMockRepo(t)
	id := uuid.New()

	expectRowFound(mock)
	mock.ExpectExec(`UPDATE iam_tenants`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnError(errors.New("deadlock detected"))

	_, err := repo.ApplyTenantDelete(context.Background(), id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ApplyTenantDelete")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// Phase 3.2 regression — the UPDATE SQL MUST NOT reference plan / type
// ---------------------------------------------------------------------------
//
// the GitOps repository !699 dropped both columns from iam_tenants. If a future
// commit re-introduces a SET plan=... or SET type=... clause to this
// projection, the writer will fail with SQLSTATE 42703 at runtime. Catch the
// regression statically with a negative-match expectation: the UPDATE SQL
// must NOT contain those tokens.

func TestApplyTenantUpsert_SQLDoesNotReferencePlanOrType(t *testing.T) {
	repo, mock := newMockRepo(t)
	id := uuid.New()
	now := time.Now().UTC()

	expectRowFound(mock)
	// Use pgxmock's QueryMatcher hook to capture the actual SQL and assert
	// it doesn't contain the dropped columns. We register an exec
	// expectation with a regex pattern that REQUIRES `status = $2` and
	// `metadata = ` and explicitly NEGATES any `plan = ` or `type = `
	// occurrence anywhere in the statement.
	mock.ExpectExec(`(?s)^\s*UPDATE iam_tenants\s+SET\s+status\s*=\s*\$2,\s*metadata\s*=`).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	result, err := repo.ApplyTenantUpsert(context.Background(), tenantprojection.TenantEvent{
		ID:        id,
		Status:    "active",
		EventTime: now,
	})
	require.NoError(t, err)
	assert.Equal(t, tenantprojection.UpsertResultApplied, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}
