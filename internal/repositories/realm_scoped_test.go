// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build future_session_repo

package repositories

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &UserRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	// Original must be untouched
	assert.Nil(t, repo.realmID)
}

func TestSessionRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &SessionRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestRoleRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &RoleRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestPermissionRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &PermissionRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestGroupRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &GroupRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestAPIKeyRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &APIKeyRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestWebhookRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &WebhookRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestServiceAccountRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &ServiceAccountRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestDeviceRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &DeviceRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestOrganizationRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &OrganizationRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestTokenRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &TokenRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestInvitationRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &InvitationRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestDelegationRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &DelegationRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestImpersonationRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &ImpersonationRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestConsentRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &ConsentRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestMagicLinkRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &MagicLinkRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestIPRuleRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &IPRuleRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}

func TestPasswordPolicyRepository_WithRealmID_ClonesCorrectly(t *testing.T) {
	realmID := uuid.New()
	repo := &PasswordPolicyRepository{}
	scoped := repo.WithRealmID(realmID)

	require.NotNil(t, scoped.realmID)
	assert.Equal(t, realmID, *scoped.realmID)
	assert.Nil(t, repo.realmID)
}
