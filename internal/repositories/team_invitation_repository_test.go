// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
)

func TestPendingInvitationUniqueViolation_MapsOnlyPlannedIndex(t *testing.T) {
	err := &pgconn.PgError{
		Code:           "23505",
		ConstraintName: "idx_iam_team_invitations_pending_tenant_email_normalized_unique",
	}
	assert.True(t, IsPendingInvitationUniqueViolation(err))
	assert.True(t, IsPendingInvitationUniqueViolation(fmt.Errorf("insert: %w", err)))
	assert.False(t, IsPendingInvitationUniqueViolation(&pgconn.PgError{Code: "23505", ConstraintName: "other_unique_key"}))
	assert.False(t, IsPendingInvitationUniqueViolation(errors.New("duplicate key idx_iam_team_invitations_pending_tenant_email_normalized_unique")))
}
