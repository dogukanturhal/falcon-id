// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	testTenantABC = "tenant_abc12345"
)

// ---------------------------------------------------------------------------
// containsCitus — pure helper, no I/O needed
// ---------------------------------------------------------------------------

func TestContainsCitus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		extensions []string
		want       bool
	}{
		{
			name:       "empty list",
			extensions: nil,
			want:       false,
		},
		{
			name:       "list without citus",
			extensions: []string{"pg_trgm", "uuid-ossp", "pgcrypto"},
			want:       false,
		},
		{
			name:       "list with only citus",
			extensions: []string{"citus"},
			want:       true,
		},
		{
			name:       "citus among other extensions",
			extensions: []string{"pg_trgm", "citus", "pgcrypto"},
			want:       true,
		},
		{
			name:       "partial match is not a match",
			extensions: []string{"citus_extra", "not_citus"},
			want:       false,
		},
		{
			name:       "case sensitive — uppercase is not a match",
			extensions: []string{"CITUS", "Citus"},
			want:       false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := containsCitus(tc.extensions)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// CitusSchemaSharding.IsCitusAvailable — uses pgxmock to simulate the pg_extension query
// ---------------------------------------------------------------------------

// newMockCitusSharding creates a CitusSchemaSharding whose pool is backed by
// pgxmock.  The mock pool satisfies pgxmock.PgxPoolIface but CitusSchemaSharding
// holds a *pgxpool.Pool, so we construct the struct directly via a field-level
// trick: we build a thin wrapper that delegates QueryRow to the mock.
//
// Since CitusSchemaSharding is an unexported-field struct defined in this
// package, tests in the same package can construct it directly.
func newTestCitusSharding(mock pgxmock.PgxPoolIface) *CitusSchemaSharding {
	// pgxmock.PgxPoolIface satisfies the pgxpool.Pool interface at the method
	// level but is not a *pgxpool.Pool value.  We embed the mock via the
	// citusPoolQuerier abstraction so the sharding helper remains testable
	// without a live database.
	return &CitusSchemaSharding{
		pool:    nil, // not used when querier is set
		querier: mock,
		logger:  zap.NewNop(),
	}
}

func TestIsCitusAvailable_NotInstalled(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Simulate pg_extension lookup returning false (extension absent).
	mock.ExpectQuery(`SELECT EXISTS`).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))

	sharding := newTestCitusSharding(mock)
	assert.False(t, sharding.IsCitusAvailable(context.Background()),
		"should report unavailable when pg_extension returns false")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIsCitusAvailable_Installed(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	mock.ExpectQuery(`SELECT EXISTS`).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))

	sharding := newTestCitusSharding(mock)
	assert.True(t, sharding.IsCitusAvailable(context.Background()),
		"should report available when pg_extension returns true")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIsCitusAvailable_QueryError(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Simulate a query failure (e.g. connection lost).
	mock.ExpectQuery(`SELECT EXISTS`).
		WillReturnError(errors.New("connection refused"))

	sharding := newTestCitusSharding(mock)
	assert.False(t, sharding.IsCitusAvailable(context.Background()),
		"should report unavailable on query error")

	require.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// CitusSchemaSharding.DistributeSchema
// ---------------------------------------------------------------------------

func TestDistributeSchema_Success(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	schemaName := testTenantABC
	mock.ExpectExec(`SELECT citus_schema_distribute`).
		WithArgs(schemaName).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))

	sharding := newTestCitusSharding(mock)
	err = sharding.DistributeSchema(context.Background(), schemaName)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestDistributeSchema_Error(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	schemaName := testTenantABC
	mock.ExpectExec(`SELECT citus_schema_distribute`).
		WithArgs(schemaName).
		WillReturnError(errors.New("schema does not exist"))

	sharding := newTestCitusSharding(mock)
	err = sharding.DistributeSchema(context.Background(), schemaName)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "citus: distribute schema")
	assert.Contains(t, err.Error(), schemaName)
	require.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// CitusSchemaSharding.UndistributeSchema
// ---------------------------------------------------------------------------

func TestUndistributeSchema_Success(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	schemaName := testTenantABC
	mock.ExpectExec(`SELECT citus_schema_undistribute`).
		WithArgs(schemaName).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))

	sharding := newTestCitusSharding(mock)
	err = sharding.UndistributeSchema(context.Background(), schemaName)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUndistributeSchema_Error(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	schemaName := testTenantABC
	mock.ExpectExec(`SELECT citus_schema_undistribute`).
		WithArgs(schemaName).
		WillReturnError(errors.New("function not found"))

	sharding := newTestCitusSharding(mock)
	err = sharding.UndistributeSchema(context.Background(), schemaName)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "citus: undistribute schema")
	assert.Contains(t, err.Error(), schemaName)
	require.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// CitusSchemaSharding.RebalanceIfNeeded
// ---------------------------------------------------------------------------

func TestRebalanceIfNeeded_Success(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	mock.ExpectExec(`SELECT citus_rebalance_start`).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))

	sharding := newTestCitusSharding(mock)
	// RebalanceIfNeeded is always non-fatal; it must not return an error.
	err = sharding.RebalanceIfNeeded(context.Background())
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRebalanceIfNeeded_ErrorIsNonFatal(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Simulate "rebalance already running" — Citus returns an error in this case.
	mock.ExpectExec(`SELECT citus_rebalance_start`).
		WillReturnError(errors.New("rebalance already in progress"))

	sharding := newTestCitusSharding(mock)
	// Even when Citus returns an error, RebalanceIfNeeded must not propagate it.
	err = sharding.RebalanceIfNeeded(context.Background())
	require.NoError(t, err, "RebalanceIfNeeded must swallow errors — they are non-fatal")
	require.NoError(t, mock.ExpectationsWereMet())
}
