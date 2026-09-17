// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestTenantUserWithRoles_UnknownPrincipalDoesNotImplyServiceAccount(t *testing.T) {
	grantID := uuid.New()
	user := TenantUserWithRoles{
		Email:           "automation@example.test",
		PrincipalType:   "unknown",
		PrincipalSource: "unknown",
		Roles: []RoleRef{{
			ID:       grantID,
			Name:     "legacy-grant",
			Editable: false,
			Reason:   "grant source is not managed by this tenant",
			Source:   RoleSourceUnknown,
		}},
	}

	body, err := json.Marshal(user)
	assert.NoError(t, err)
	assert.Contains(t, string(body), `"principalType":"unknown"`)
	assert.Contains(t, string(body), `"principalSource":"unknown"`)
	assert.Contains(t, string(body), `"source":"unknown"`)
}

func TestCanonicalInvitationEmail(t *testing.T) {
	assert.Equal(t, "member@example.test", CanonicalInvitationEmail("  Member@Example.Test  "))
	assert.Empty(t, CanonicalInvitationEmail(" \t\n "))
}

func TestTeamInvitationTokenDigest(t *testing.T) {
	digest := TeamInvitationTokenDigest("secret")
	assert.Equal(t, "sha256:2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b", digest)
	assert.NotContains(t, digest, "secret")
}
