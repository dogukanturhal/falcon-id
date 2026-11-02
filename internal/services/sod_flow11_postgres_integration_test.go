// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FLOW-11 S8: test the existing additive seeds as SQL, not only with a regexp catalogue check.
func TestSoDReevaluatorPostgres_Flow11CrossModuleDefaultsAreIdempotentAndDetectConflicts(t *testing.T) {
	p := newSoDPG(t)
	ctx := context.Background()
	migration, err := os.ReadFile("../migrations/0023_iam_sod_seed_fix.sql")
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		tx, err := p.pool.Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, string(migration))
		if err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		require.NoError(t, tx.Commit(ctx))
	}
	for _, pair := range [][2]string{
		{"mm:vendors:update", "preaccounting:payments:create"},
		{"mm:purchase_orders:create", "mm:invoice-match:override"},
		{"payroll:runs:calculate", "payroll:runs:pay"},
		{"preaccounting:expenses:create", "preaccounting:expenses:approve"},
	} {
		t.Run(pair[0]+"_"+pair[1], func(t *testing.T) {
			var count int
			var mode string
			require.NoError(t, p.pool.QueryRow(ctx, `SELECT count(*), min(mode) FROM iam_sod_rules
				WHERE tenant_id IS NULL AND is_default AND disabled_at IS NULL AND permission_a=$1 AND permission_b=$2`, pair[0], pair[1]).Scan(&count, &mode))
			assert.Equal(t, 1, count, "applying the existing seed migration twice must not duplicate defaults")
			assert.Equal(t, "warn", mode, "cross-module defaults record conflicts without silently blocking work")
			user := p.user(t)
			p.assign(t, user, p.role(t, pair[0]), "NULL")
			require.NoError(t, p.reeval.RunDaily(ctx))
			assert.Equal(t, 0, p.openViolations(t, user), "maker permission alone is not a conflict")
			p.assign(t, user, p.role(t, pair[1]), "NULL")
			require.NoError(t, p.reeval.RunDaily(ctx))
			assert.Equal(t, 1, p.openViolations(t, user), "both catalogue permissions must trigger the seeded cross-module rule")
			require.NoError(t, p.reeval.RunDaily(ctx))
			assert.Equal(t, 1, p.openViolations(t, user), "daily re-evaluation must not duplicate open violations")
		})
	}
}
