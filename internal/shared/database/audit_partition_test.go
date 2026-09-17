// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration
// +build integration

package database_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditLogRealmIndex_Exists(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Check that the realm_created index exists
	var exists bool
	err = pool.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE tablename = 'iam_audit_log'
			AND indexname = 'idx_iam_audit_log_realm_created'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	assert.True(t, exists, "idx_iam_audit_log_realm_created should exist")

	// Check that the tenant_realm_created index exists
	err = pool.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE tablename = 'iam_audit_log'
			AND indexname = 'idx_iam_audit_log_tenant_realm_created'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	assert.True(t, exists, "idx_iam_audit_log_tenant_realm_created should exist")
}
