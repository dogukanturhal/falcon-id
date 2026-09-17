// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func TestTeamInvitationMatchesUserBindsTenantAndCanonicalEmail(t *testing.T) {
	tenantID := uuid.New()
	invitation := &models.TeamInvitation{TenantID: tenantID, Email: " member@example.test "}

	assert.True(t, teamInvitationMatchesUser(
		&models.CurrentUser{TenantID: tenantID, Email: "Member@Example.Test"}, invitation))
	assert.False(t, teamInvitationMatchesUser(
		&models.CurrentUser{TenantID: uuid.New(), Email: "member@example.test"}, invitation))
	assert.False(t, teamInvitationMatchesUser(
		&models.CurrentUser{TenantID: tenantID, Email: "other@example.test"}, invitation))
}
