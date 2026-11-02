// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantstatus

import (
	"context"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBpayTrialExpiryPreservesAuthRecoveryWhileOperatorSuspensionBlocks(t *testing.T) {
	require.False(t, (Event{Status: "suspended", Reason: "trial_expired", AccessScope: "trial"}).Suspended())
	require.True(t, (Event{Status: "suspended", Reason: "trial_expired", AccessScope: "tenant"}).Suspended(), "operator reason text cannot downgrade suspension scope")
	require.True(t, (Event{Status: "suspended", Reason: "trial_expired"}).Suspended(), "old/unscoped events remain fail-closed")
	require.True(t, (Event{Status: "suspended", Reason: "abuse", AccessScope: "trial"}).Suspended())
}

func TestBpayTrialScopeKeepsRecoverySessionsWhileFullScopeRevokes(t *testing.T) {
	pool := newPG(t)
	repo := NewRepository(pool)
	user := seed(t, pool, uuid.New())
	ctx := context.Background()
	trial := evt(user.tenant, "suspended", 10)
	trial.Reason, trial.AccessScope = "trial_expired", "trial"
	_, err := repo.Apply(ctx, trial)
	require.NoError(t, err)
	suspended, err := repo.IsSuspended(ctx, user.tenant)
	require.NoError(t, err)
	require.False(t, suspended)
	sessions, tokens := counts(t, pool, user)
	require.Equal(t, 2, sessions)
	require.Equal(t, 2, tokens)
	operator := evt(user.tenant, "suspended", 20)
	operator.Reason, operator.AccessScope = "trial_expired", "tenant"
	_, err = repo.Apply(ctx, operator)
	require.NoError(t, err)
	sessions, tokens = counts(t, pool, user)
	require.Zero(t, sessions)
	require.Zero(t, tokens)
}
