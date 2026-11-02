// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// fakeSpiceDB is a single, shared, stateful in-memory stand-in for SpiceDB.
// It implements BOTH interfaces that matter for this test:
//   - jitSpiceDBClient (WriteUserRoleUntil/DeleteUserRole), the primitives
//     JITAccessService.ActivateGrant/ExpireGrants/RevokeGrant call.
//   - SpiceDBChecker (CheckPermission/...), the primitive
//     AuthorizationEngine.CheckPermission/CheckResourcePermission call.
//
// Because both sides read and write the SAME relationship set, this proves
// an actual causal link end-to-end: a JITAccessService write/delete call is
// what AuthorizationEngine's *own* check reflects — not two independently
// asserted facts that merely happen to agree.
type fakeSpiceDB struct {
	mu    sync.Mutex
	roles map[string]bool // key: tenantID|userID|roleID -> member
}

func newFakeSpiceDB() *fakeSpiceDB {
	return &fakeSpiceDB{roles: make(map[string]bool)}
}

func relKey(tenantID, userID, roleID uuid.UUID) string {
	return tenantID.String() + "|" + userID.String() + "|" + roleID.String()
}

// --- jitSpiceDBClient ---

func (f *fakeSpiceDB) WriteUserRoleUntil(_ context.Context, tenantID, userID, roleID uuid.UUID, _ time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roles[relKey(tenantID, userID, roleID)] = true
	return "zedtoken-write", nil
}

func (f *fakeSpiceDB) DeleteUserRole(_ context.Context, tenantID, userID, roleID uuid.UUID) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.roles, relKey(tenantID, userID, roleID))
	return "zedtoken-delete", nil
}

// --- SpiceDBChecker ---
//
// A role-membership check is modeled as CheckPermission(tenant, user,
// objectType="role", objectID=roleID.String(), permission="member") — this
// is exactly the shape AuthorizationEngine.CheckResourcePermission passes
// straight through to SpiceDBChecker.CheckPermission with no translation
// layer, so it is a faithful stand-in for "is this role currently granted
// to this user via SpiceDB".

func (f *fakeSpiceDB) CheckPermission(_ context.Context, tenantID, userID uuid.UUID, objectType, objectID, permission string) (bool, error) {
	if objectType != "role" || permission != "member" {
		return false, nil
	}
	roleID, err := uuid.Parse(objectID)
	if err != nil {
		return false, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.roles[relKey(tenantID, userID, roleID)], nil
}

func (f *fakeSpiceDB) CheckPermissionConsistent(ctx context.Context, tenantID, userID uuid.UUID, objectType, objectID, permission, _ string) (bool, error) {
	return f.CheckPermission(ctx, tenantID, userID, objectType, objectID, permission)
}

func (f *fakeSpiceDB) CheckBulkPermissions(ctx context.Context, tenantID, userID uuid.UUID, objectType string, objectIDs []string, permission string) (map[string]bool, error) {
	out := make(map[string]bool, len(objectIDs))
	for _, id := range objectIDs {
		allowed, _ := f.CheckPermission(ctx, tenantID, userID, objectType, id, permission)
		out[id] = allowed
	}
	return out, nil
}

// newJITExpiryTestRig wires a JITAccessService and a real AuthorizationEngine
// against the SAME fakeSpiceDB, plus a repo mock, so the test below can
// activate/expire a grant through the service and observe the effect through
// the engine's own CheckResourcePermission — the actual runtime call path
// (AuthorizationEngine.CheckPermission is SpiceDB-only; nothing here reads
// iam_user_roles or any DB table for the authorization decision).
func newJITExpiryTestRig(t *testing.T) (*JITAccessService, AuthorizationEngine, *mockJITRepo, *fakeSpiceDB) {
	t.Helper()
	fake := newFakeSpiceDB()
	repo := new(mockJITRepo)
	userRoles := new(mockJITUserRoleWriter)
	userRoles.On("AddTimeBoundRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(uuid.New(), nil).Maybe()
	userRoles.On("RemoveTimeBoundRole", mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Maybe()
	eligible := new(mockJITEligibleRepo)
	stepUp := new(mockJITStepUpRepo)

	svc := NewJITAccessService(repo, eligible, stepUp, userRoles, fake, nil, zap.NewNop())
	svc.SetRoleRevokeDrainer(&jitTestDrainer{repo: repo, client: fake})

	cfg := &config.Config{}
	engine := NewAuthorizationEngine(nil, nil, nil, nil, fake, cfg)

	return svc, engine, repo, fake
}

// TestJITExpiry_EnforcedThroughAuthorizationEngine is the required
// behavioral proof that an expired JIT grant is actually denied by
// AuthorizationEngine.CheckPermission's real code path (via
// CheckResourcePermission, which maps 1:1 onto SpiceDBChecker.CheckPermission
// with no string-translation layer) — not merely absent from a database row.
//
// Flow:
//  1. Activate an approved grant -> JITAccessService.ActivateGrant writes the
//     role#member relationship into the SAME SpiceDB backing the engine.
//  2. Assert the engine's own CheckResourcePermission call now allows it.
//  3. Run JITAccessService.ExpireGrants (the background sweeper's job) on the
//     now-expired grant -> it deletes that SAME relationship.
//  4. Assert the engine's own CheckResourcePermission call now denies it.
//
// See TestJITExpiry_Control_SweepNotRun below for the required negative
// control: skipping step 3 must leave the check Allowed, proving step 4's
// "Denied" result is caused by the sweep, not by some unrelated time-based
// side effect of the check itself.
func TestJITExpiry_EnforcedThroughAuthorizationEngine(t *testing.T) {
	svc, engine, repo, _ := newJITExpiryTestRig(t)
	ctx := context.Background()

	grant := makeGrant(models.JITAccessStatusApproved, -1*time.Second) // already past expires_at once active

	repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil).Once()
	repo.On("Activate", mock.Anything, grant.ID).Return(nil)

	req := ResourcePermissionRequest{
		UserID:       grant.UserID,
		TenantID:     grant.TenantID,
		ResourceType: "role",
		ResourceID:   grant.RoleID.String(),
		Action:       "member",
	}

	// Force ExpiresAt to a moment safely in the future for activation itself
	// (ActivateGrant refuses to activate an already-expired grant — that is
	// a separate guard, covered by TestJITAccessService_ActivateGrant_Expired).
	// Here we want a grant that is valid NOW, then expires shortly after, so
	// ActivateGrant succeeds and ExpireGrants later picks it up.
	grant.ExpiresAt = time.Now().Add(50 * time.Millisecond)

	require.NoError(t, svc.ActivateGrant(ctx, grant.ID, grant.TenantID))
	grant.Status = models.JITAccessStatusActive

	preExpiry, err := engine.CheckResourcePermission(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, preExpiry)
	assert.True(t, preExpiry.Allowed, "engine must allow the role check immediately after activation")

	// Let the grant's expires_at pass, then run the sweep exactly as the
	// background loop in cmd/background.go does.
	time.Sleep(75 * time.Millisecond)
	repo.On("ListExpiredActive", mock.Anything, 100).Return([]*models.JITAccessGrant{grant}, nil).Once()
	repo.On("FinalizeGrant", mock.Anything, grant.ID, models.JITAccessStatusExpired).Return(nil)

	require.NoError(t, svc.ExpireGrants(ctx))

	postExpiry, err := engine.CheckResourcePermission(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, postExpiry)
	assert.False(t, postExpiry.Allowed, "engine must deny the role check once ExpireGrants has run past expires_at")

	repo.AssertExpectations(t)
}

// TestJITExpiry_Control_SweepNotRun is the negative control demanded
// alongside the test above: if the expiry sweep is skipped (e.g. the
// background loop in cmd/background.go were removed, or crashed, or its
// interval were larger than the grant's lifetime), the SpiceDB relationship
// is NEVER deleted and AuthorizationEngine keeps allowing the check even
// though grant.ExpiresAt has passed and grant.IsExpired() (a pure struct
// method, no I/O) would independently report true. This is what makes the
// "Denied" assertion above meaningful: without an explicit deletion call,
// the same wall-clock passage of time does not, by itself, revoke access.
func TestJITExpiry_Control_SweepNotRun(t *testing.T) {
	svc, engine, repo, _ := newJITExpiryTestRig(t)
	ctx := context.Background()

	grant := makeGrant(models.JITAccessStatusApproved, 50*time.Millisecond)

	repo.On("GetByID", mock.Anything, grant.ID).Return(grant, nil).Once()
	repo.On("Activate", mock.Anything, grant.ID).Return(nil)

	req := ResourcePermissionRequest{
		UserID:       grant.UserID,
		TenantID:     grant.TenantID,
		ResourceType: "role",
		ResourceID:   grant.RoleID.String(),
		Action:       "member",
	}

	require.NoError(t, svc.ActivateGrant(ctx, grant.ID, grant.TenantID))

	preExpiry, err := engine.CheckResourcePermission(ctx, req)
	require.NoError(t, err)
	assert.True(t, preExpiry.Allowed)

	// Wall-clock passes the grant's expires_at, exactly as in the enforced
	// test above, but ExpireGrants is deliberately never called.
	time.Sleep(75 * time.Millisecond)
	require.True(t, grant.IsExpired(), "sanity check: the grant IS logically expired at this point")

	stillAllowed, err := engine.CheckResourcePermission(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, stillAllowed)
	assert.True(t, stillAllowed.Allowed,
		"control: without the sweep actually deleting the SpiceDB relationship, "+
			"the engine keeps allowing access even though the grant is logically expired — "+
			"this is what the sweep in TestJITExpiry_EnforcedThroughAuthorizationEngine exists to prevent")

	repo.AssertExpectations(t)
	repo.AssertNotCalled(t, "ListExpiredActive")
}
