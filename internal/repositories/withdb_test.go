// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build future_session_repo

package repositories

import (
	"testing"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withdb_test.go verifies the WithDB / WithDBPool cloning methods added in
// withdb.go. Each test:
//   1. Constructs a repository with an initial mock pool ("original").
//   2. Creates a second mock pool ("realm").
//   3. Calls WithDB / WithDBPool to obtain a clone.
//   4. Asserts that the clone's field points to the new pool and the original
//      repository's field still points to its own pool.

func newMockPool(t *testing.T) pgxmock.PgxPoolIface {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock
}

// ---------------------------------------------------------------------------
// db-field repositories (DBPool interface)
// ---------------------------------------------------------------------------

func TestUserRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &UserRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db, "original must keep its pool")
	assert.Same(t, realmPool, clone.db, "clone must hold the realm pool")
	assert.Nil(t, clone.realmID, "realmID must not be carried over implicitly")
}

func TestRoleRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &RoleRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestSessionRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &SessionRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestTokenRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &TokenRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestTenantRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &TenantRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestRealmRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &RealmRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestConsentRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &ConsentRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestDelegationRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &DelegationRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestDeviceRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &DeviceRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestImpersonationRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &ImpersonationRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestInvitationRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &InvitationRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestMagicLinkRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &MagicLinkRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestMFARepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &MFARepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestPasswordPolicyRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &PasswordPolicyRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

func TestPermissionRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &PermissionRepository{db: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.db)
	assert.Same(t, realmPool, clone.db)
}

// ---------------------------------------------------------------------------
// pool-field repositories (DBPool interface)
// ---------------------------------------------------------------------------

func TestAPIKeyRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &APIKeyRepository{pool: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.pool)
	assert.Same(t, realmPool, clone.pool)
}

func TestGroupRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &GroupRepository{pool: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.pool)
	assert.Same(t, realmPool, clone.pool)
}

func TestIPRuleRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &IPRuleRepository{pool: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.pool)
	assert.Same(t, realmPool, clone.pool)
}

func TestOrganizationRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &OrganizationRepository{pool: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.pool)
	assert.Same(t, realmPool, clone.pool)
}

func TestServiceAccountRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &ServiceAccountRepository{pool: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.pool)
	assert.Same(t, realmPool, clone.pool)
}

func TestWebhookRepository_WithDB(t *testing.T) {
	t.Parallel()
	original := newMockPool(t)
	realmPool := newMockPool(t)

	repo := &WebhookRepository{pool: original}
	clone := repo.WithDB(realmPool)

	assert.Same(t, original, repo.pool)
	assert.Same(t, realmPool, clone.pool)
}

// ---------------------------------------------------------------------------
// WithDB preserves existing realmID scoping
// ---------------------------------------------------------------------------

func TestWithDB_PreservesRealmIDScope(t *testing.T) {
	t.Parallel()
	// Verify that WithDB and WithRealmID compose correctly: realm scoping
	// applied before a DB swap must survive the swap.
	original := newMockPool(t)
	realmPool := newMockPool(t)
	realmID := uuid.New()

	repo := &UserRepository{db: original}
	scoped := repo.WithRealmID(realmID)
	swapped := scoped.WithDB(realmPool)

	assert.Equal(t, &realmID, swapped.realmID, "realmID must be preserved after WithDB")
	assert.Same(t, realmPool, swapped.db, "pool must be updated after WithDB")
	assert.Same(t, original, scoped.db, "intermediate clone must keep original pool")
}

// TestWithDB_IsolatesCloneFromOriginal verifies that mutations to the clone
// do not propagate back to the original repository.
func TestWithDB_IsolatesCloneFromOriginal(t *testing.T) {
	t.Parallel()
	pool1 := newMockPool(t)
	pool2 := newMockPool(t)
	pool3 := newMockPool(t)

	repo := &ConsentRepository{db: pool1}
	clone1 := repo.WithDB(pool2)
	clone2 := clone1.WithDB(pool3)

	// Each generation must hold its own pool.
	assert.Same(t, pool1, repo.db)
	assert.Same(t, pool2, clone1.db)
	assert.Same(t, pool3, clone2.db)
}
