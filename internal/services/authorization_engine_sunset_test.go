// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// authorization_engine_sunset_test.go tests the sunset-permission enforcement
// introduced for GAP 8.
//
// When a permission has passed its SunsetAt date, CheckPermission must deny
// the request immediately (before querying SpiceDB) and set an informative
// reason.  If no SunsetChecker is wired, the engine behaves exactly as before
// (no change to existing behaviour).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ─── MockSunsetChecker ────────────────────────────────────────────────────────

// MockSunsetChecker implements SunsetChecker for unit testing.
type MockSunsetChecker struct {
	mock.Mock
}

func (m *MockSunsetChecker) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Permission), args.Error(1)
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// sunsetTime returns a time in the past (already sunset).
func pastSunset() *time.Time {
	t := time.Now().Add(-24 * time.Hour)
	return &t
}

// futureSunset returns a time in the future (not yet sunset).
func futureSunset() *time.Time {
	t := time.Now().Add(24 * time.Hour)
	return &t
}

// newTestEngineWithSunset creates an engine wired with a SunsetChecker.
func newTestEngineWithSunset(
	spicedbChecker SpiceDBChecker,
	sunsetChecker SunsetChecker,
) AuthorizationEngine {
	cfg := &config.Config{}
	return NewAuthorizationEngineWithSunset(nil, nil, nil, nil, spicedbChecker, cfg, sunsetChecker)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

// TestCheckPermission_SunsetPermission_DeniedImmediately verifies that when
// a permission is past its sunset date the engine denies without calling SpiceDB.
func TestCheckPermission_SunsetPermission_DeniedImmediately(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	mockSunset := new(MockSunsetChecker)
	engine := newTestEngineWithSunset(mockSpiceDB, mockSunset)

	userID := uuid.New()
	tenantID := uuid.New()

	// The permission is past its sunset date.
	sunsetPerm := &models.Permission{
		Name:     "crm:contacts:read",
		SunsetAt: pastSunset(),
	}
	mockSunset.On("GetPermissionByName", mock.Anything, "crm:contacts:read").
		Return(sunsetPerm, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed, "sunset permission must be denied")
	assert.Contains(t, result.Reason, "sunset", "reason should mention sunset")
	assert.Equal(t, "spicedb", result.Source)

	// SpiceDB must NOT be called when the permission is sunset.
	mockSpiceDB.AssertNotCalled(t, "CheckPermission")
	mockSpiceDB.AssertNotCalled(t, "CheckPermissionConsistent")
}

// TestCheckPermission_NotYetSunset_ProceedsToSpiceDB verifies that a permission
// with a SunsetAt in the future still proceeds to SpiceDB for evaluation.
func TestCheckPermission_NotYetSunset_ProceedsToSpiceDB(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	mockSunset := new(MockSunsetChecker)
	engine := newTestEngineWithSunset(mockSpiceDB, mockSunset)

	userID := uuid.New()
	tenantID := uuid.New()

	// SunsetAt is in the future — permission is still active.
	activePerm := &models.Permission{
		Name:     "crm:contacts:read",
		SunsetAt: futureSunset(),
	}
	mockSunset.On("GetPermissionByName", mock.Anything, "crm:contacts:read").
		Return(activePerm, nil)

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check").
		Return(true, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)

	// SpiceDB must be called because the permission has not yet sunset.
	mockSpiceDB.AssertCalled(t, "CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check")
}

// TestCheckPermission_NoSunsetAt_ProceedsToSpiceDB verifies that a permission
// with no SunsetAt (nil) is not blocked by the sunset check.
func TestCheckPermission_NoSunsetAt_ProceedsToSpiceDB(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	mockSunset := new(MockSunsetChecker)
	engine := newTestEngineWithSunset(mockSpiceDB, mockSunset)

	userID := uuid.New()
	tenantID := uuid.New()

	// No sunset date — permission is permanently active.
	activePerm := &models.Permission{
		Name:     "crm:contacts:read",
		SunsetAt: nil,
	}
	mockSunset.On("GetPermissionByName", mock.Anything, "crm:contacts:read").
		Return(activePerm, nil)

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check").
		Return(true, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	mockSpiceDB.AssertCalled(t, "CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check")
}

// TestCheckPermission_PermissionNotFoundInDB_ProceedsToSpiceDB verifies that
// when the SunsetChecker returns nil (permission not found in DB), the engine
// does NOT block the check — it falls through to SpiceDB.  This prevents a
// DB miss from becoming an accidental deny.
func TestCheckPermission_PermissionNotFoundInDB_ProceedsToSpiceDB(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	mockSunset := new(MockSunsetChecker)
	engine := newTestEngineWithSunset(mockSpiceDB, mockSunset)

	userID := uuid.New()
	tenantID := uuid.New()

	// Permission lookup returns nil — not found.
	mockSunset.On("GetPermissionByName", mock.Anything, "crm:contacts:read").
		Return((*models.Permission)(nil), nil)

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check").
		Return(true, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed, "DB miss must not block access")
	mockSpiceDB.AssertCalled(t, "CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check")
}

// TestCheckPermission_SunsetCheckerError_ProceedsToSpiceDB verifies that when
// the SunsetChecker itself returns an error the engine does NOT block the
// check — it falls through to SpiceDB (fail-open for the sunset guard, since
// the fail-closed guarantee lives in SpiceDB).
func TestCheckPermission_SunsetCheckerError_ProceedsToSpiceDB(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	mockSunset := new(MockSunsetChecker)
	engine := newTestEngineWithSunset(mockSpiceDB, mockSunset)

	userID := uuid.New()
	tenantID := uuid.New()

	// DB error while checking sunset status.
	mockSunset.On("GetPermissionByName", mock.Anything, "crm:contacts:read").
		Return((*models.Permission)(nil), assert.AnError)

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check").
		Return(true, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed, "sunset lookup error must not block access")
	mockSpiceDB.AssertCalled(t, "CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check")
}

// TestCheckPermission_NilSunsetChecker_BehavesLikeBefore verifies that when no
// SunsetChecker is provided, CheckPermission behaves exactly as it did before
// GAP 8 (i.e., existing tests are unaffected).
func TestCheckPermission_NilSunsetChecker_BehavesLikeBefore(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	// newTestEngine (existing helper) does NOT set a SunsetChecker.
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check").
		Return(true, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed, "nil SunsetChecker must not block access")
}

// TestCheckPermission_SunsetPermission_ZedTokenIgnored verifies that even when
// a ZedToken is supplied (consistent check path), a sunset permission is still
// denied without calling SpiceDB.
func TestCheckPermission_SunsetPermission_ZedTokenIgnored(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	mockSunset := new(MockSunsetChecker)
	engine := newTestEngineWithSunset(mockSpiceDB, mockSunset)

	userID := uuid.New()
	tenantID := uuid.New()

	sunsetPerm := &models.Permission{
		Name:     "crm:contacts:read",
		SunsetAt: pastSunset(),
	}
	mockSunset.On("GetPermissionByName", mock.Anything, "crm:contacts:read").
		Return(sunsetPerm, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{ //nolint:gosec // test fixture value, not a real credential
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
		ZedToken:   "some_zed_token",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "sunset")
	mockSpiceDB.AssertNotCalled(t, "CheckPermission")
	mockSpiceDB.AssertNotCalled(t, "CheckPermissionConsistent")
}
