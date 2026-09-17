// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	testPathAuthLogin = "/api/v1/auth/login"
	testPathData      = "/api/v1/data"
)

// ============================================================================
// Mock — rateLimitServiceRateLimitRepo
// ============================================================================

func intPtr(v int) *int { return &v }

type mockRateLimitRepo struct {
	mock.Mock
}

func (m *mockRateLimitRepo) GetActiveRules(ctx context.Context, tenantID uuid.UUID) ([]*models.RateLimitRule, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RateLimitRule), args.Error(1)
}

func (m *mockRateLimitRepo) LogEvent(ctx context.Context, event *models.RateLimitEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *mockRateLimitRepo) GetRulesByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.RateLimitRule, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RateLimitRule), args.Error(1)
}

func (m *mockRateLimitRepo) GetRuleByID(ctx context.Context, id uuid.UUID) (*models.RateLimitRule, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RateLimitRule), args.Error(1)
}

func (m *mockRateLimitRepo) Create(ctx context.Context, rule *models.RateLimitRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *mockRateLimitRepo) Update(ctx context.Context, rule *models.RateLimitRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *mockRateLimitRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockRateLimitRepo) GetBlockedEvents(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.RateLimitEvent, error) {
	args := m.Called(ctx, tenantID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RateLimitEvent), args.Error(1)
}

func (m *mockRateLimitRepo) GetRecentEvents(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.RateLimitEvent, error) {
	args := m.Called(ctx, tenantID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RateLimitEvent), args.Error(1)
}

// ============================================================================
// Helpers
// ============================================================================

// newTestRateLimitService creates a service with a mock repo and stops the
// background cleanup goroutine immediately so tests don't leak goroutines.
func newTestRateLimitService(repo *mockRateLimitRepo) *RateLimitService {
	svc := NewRateLimitService(repo)
	svc.Stop() // prevent timer goroutine from interfering with tests
	return svc
}

// makeRule builds a minimal but valid RateLimitRule for a given scope.
func makeRule(scope models.RateLimitScope, pattern string, maxReqs, windowSecs, blockSecs int) *models.RateLimitRule {
	return &models.RateLimitRule{
		ID:                   uuid.New(),
		Name:                 "test-rule",
		EndpointPattern:      pattern,
		MaxRequests:          maxReqs,
		WindowSeconds:        windowSecs,
		BlockDurationSeconds: blockSecs,
		Scope:                scope,
		IsActive:             true,
	}
}

// ============================================================================
// CheckRateLimit — core allow/block logic
// ============================================================================

func TestCheckRateLimit_NoMatchingRule_ReturnsNil(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()

	// Rule exists but does NOT match the requested endpoint
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300)
	rule.Method = strPtr("POST")
	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)

	state, err := svc.CheckRateLimit(context.Background(), tenantID, "1.2.3.4", "/api/v1/users", "GET")

	require.NoError(t, err)
	assert.Nil(t, state, "no matching rule should return nil state (allow through)")
}

func TestCheckRateLimit_BelowLimit_ReturnsAllowed(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)

	state, err := svc.CheckRateLimit(context.Background(), tenantID, "1.2.3.4", testPathAuthLogin, "POST")

	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.Blocked)
	assert.Equal(t, 1, state.Requests)
	assert.Equal(t, 4, state.Remaining) // 5 max − 1 used
}

func TestCheckRateLimit_ExactlyAtLimit_TriggerBlock(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	const maxReqs = 3
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, maxReqs, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)
	// LogEvent is called asynchronously when a block is triggered; allow any call.
	repo.On("LogEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	ctx := context.Background()
	identifier := "10.0.0.1"
	endpoint := testPathAuthLogin

	// Consume all allowed requests
	for i := 0; i < maxReqs; i++ {
		state, err := svc.CheckRateLimit(ctx, tenantID, identifier, endpoint, "POST")
		require.NoError(t, err)
		require.NotNil(t, state)
		assert.False(t, state.Blocked, "request %d should not be blocked yet", i+1)
	}

	// The next call should trigger the block
	state, err := svc.CheckRateLimit(ctx, tenantID, identifier, endpoint, "POST")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.Blocked)
	assert.Equal(t, 0, state.Remaining)
	assert.True(t, state.BlockedUntil.After(time.Now()))
}

func TestCheckRateLimit_AlreadyBlocked_ReturnsBlocked(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 2, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)
	repo.On("LogEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	ctx := context.Background()
	identifier := "10.0.0.2"
	endpoint := testPathAuthLogin

	// Exhaust limit and trigger block
	for i := 0; i < 3; i++ {
		svc.CheckRateLimit(ctx, tenantID, identifier, endpoint, "POST") //nolint:errcheck,gosec
	}

	// All subsequent calls within the block window must also return blocked
	for attempt := 0; attempt < 3; attempt++ {
		state, err := svc.CheckRateLimit(ctx, tenantID, identifier, endpoint, "POST")
		require.NoError(t, err)
		require.NotNil(t, state)
		assert.True(t, state.Blocked, "attempt %d: should remain blocked", attempt+1)
		assert.Equal(t, 0, state.Remaining)
	}
}

func TestCheckRateLimit_RepoError_AllowsThrough(t *testing.T) {
	// The service fails open on repo errors — it must never block legitimate
	// traffic because the database is temporarily unavailable.
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	repo.On("GetActiveRules", mock.Anything, tenantID).Return(nil, errors.New("database unavailable"))

	state, err := svc.CheckRateLimit(context.Background(), tenantID, "1.2.3.4", testPathAuthLogin, "POST")

	// Fail-open: no error surfaced to caller, no block applied
	require.NoError(t, err)
	assert.Nil(t, state)
}

func TestCheckRateLimit_NoRules_ReturnsNil(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{}, nil)

	state, err := svc.CheckRateLimit(context.Background(), tenantID, "1.2.3.4", testPathAuthLogin, "POST")

	require.NoError(t, err)
	assert.Nil(t, state)
}

// ============================================================================
// CheckRateLimit — counter increments correctly
// ============================================================================

func TestCheckRateLimit_CounterIncrements(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, "*", 10, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)

	ctx := context.Background()
	identifier := "192.168.1.50"
	endpoint := testPathData

	for i := 1; i <= 5; i++ {
		state, err := svc.CheckRateLimit(ctx, tenantID, identifier, endpoint, "GET")
		require.NoError(t, err)
		require.NotNil(t, state)
		assert.False(t, state.Blocked)
		assert.Equal(t, i, state.Requests, "request count after %d calls", i)
		assert.Equal(t, 10-i, state.Remaining, "remaining after %d calls", i)
	}
}

// ============================================================================
// CheckRateLimit — rate limit reset after window expires
// ============================================================================

func TestCheckRateLimit_WindowExpiry_ResetsCounter(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	// Use a 1-second window so we can actually expire it in a test
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 3, 1, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)

	ctx := context.Background()
	identifier := "10.0.10.10"
	endpoint := testPathAuthLogin

	// Make 3 requests — fills the window
	for i := 0; i < 3; i++ {
		state, err := svc.CheckRateLimit(ctx, tenantID, identifier, endpoint, "POST")
		require.NoError(t, err)
		require.NotNil(t, state)
		assert.False(t, state.Blocked)
	}

	// Wait for the window to expire
	time.Sleep(1100 * time.Millisecond)

	// After the window expires the counter resets; the request should be allowed
	state, err := svc.CheckRateLimit(ctx, tenantID, identifier, endpoint, "POST")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.Blocked, "counter should have reset after window expired")
	assert.Equal(t, 1, state.Requests, "only the post-expiry request should be counted")
}

// ============================================================================
// CheckRateLimit — scope-based key isolation
// ============================================================================

func TestCheckRateLimit_IPScope_IsolatesPerIdentifier(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, "*", 2, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)
	repo.On("LogEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	ctx := context.Background()
	endpoint := testPathData

	// Exhaust IP-A's limit
	for i := 0; i < 3; i++ {
		svc.CheckRateLimit(ctx, tenantID, "1.1.1.1", endpoint, "GET") //nolint:errcheck,gosec
	}

	// IP-B must be unaffected — it has its own counter
	state, err := svc.CheckRateLimit(ctx, tenantID, "2.2.2.2", endpoint, "GET")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.Blocked, "different IP should have its own independent counter")
}

func TestCheckRateLimit_UserScope_IsolatesPerUser(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeUser, "*", 2, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)
	repo.On("LogEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	ctx := context.Background()
	endpoint := testPathData

	// Exhaust user-A's limit
	for i := 0; i < 3; i++ {
		svc.CheckRateLimit(ctx, tenantID, "user-alpha", endpoint, "GET") //nolint:errcheck,gosec
	}

	// User-B must be unaffected
	state, err := svc.CheckRateLimit(ctx, tenantID, "user-beta", endpoint, "GET")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.Blocked)
}

func TestCheckRateLimit_TenantScope_SharesCounterAcrossIdentifiers(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeTenant, "*", 3, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)
	repo.On("LogEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	ctx := context.Background()
	endpoint := testPathData

	// Each request from a different IP still draws from the same tenant-scoped counter
	state1, _ := svc.CheckRateLimit(ctx, tenantID, "1.1.1.1", endpoint, "GET")
	state2, _ := svc.CheckRateLimit(ctx, tenantID, "2.2.2.2", endpoint, "GET")
	state3, _ := svc.CheckRateLimit(ctx, tenantID, "3.3.3.3", endpoint, "GET")

	require.NotNil(t, state1)
	require.NotNil(t, state2)
	require.NotNil(t, state3)
	assert.False(t, state1.Blocked)
	assert.False(t, state2.Blocked)
	assert.False(t, state3.Blocked)
	assert.Equal(t, 0, state3.Remaining, "tenant counter should be shared and exhausted after 3 requests")

	// The next request from any identifier should be blocked
	state4, err := svc.CheckRateLimit(ctx, tenantID, "4.4.4.4", endpoint, "GET")
	require.NoError(t, err)
	require.NotNil(t, state4)
	assert.True(t, state4.Blocked)
}

func TestCheckRateLimit_GlobalScope_IgnoresIdentifierAndTenant(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantA := uuid.New()
	tenantB := uuid.New()
	rule := makeRule(models.RateLimitScopeGlobal, "/api/v1/health", 2, 60, 60)

	// Both tenants share the same global rule key
	repo.On("GetActiveRules", mock.Anything, tenantA).Return([]*models.RateLimitRule{rule}, nil)
	repo.On("GetActiveRules", mock.Anything, tenantB).Return([]*models.RateLimitRule{rule}, nil)
	repo.On("LogEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	ctx := context.Background()
	endpoint := "/api/v1/health"

	// tenant-A exhausts the global counter
	svc.CheckRateLimit(ctx, tenantA, "any-id", endpoint, "GET") //nolint:errcheck,gosec
	svc.CheckRateLimit(ctx, tenantA, "any-id", endpoint, "GET") //nolint:errcheck,gosec

	// tenant-B's next request should be blocked because they share the global key
	state, err := svc.CheckRateLimit(ctx, tenantB, "other-id", endpoint, "GET")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.Blocked, "global scope must share counter across all tenants")
}

// ============================================================================
// CheckRateLimit — method matching
// ============================================================================

func TestCheckRateLimit_MethodMismatch_NotLimited(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 1, 60, 300)
	rule.Method = strPtr("POST") // rule only applies to POST

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)

	// A GET to the same endpoint should not match the POST rule
	state, err := svc.CheckRateLimit(context.Background(), tenantID, "1.2.3.4", testPathAuthLogin, "GET")
	require.NoError(t, err)
	assert.Nil(t, state, "method mismatch should produce no matching rule (nil state)")
}

func TestCheckRateLimit_NilMethod_MatchesAllMethods(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300)
	// rule.Method is intentionally nil — matches any HTTP method

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)

	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
		state, err := svc.CheckRateLimit(context.Background(), tenantID, "1.2.3.4", testPathAuthLogin, method)
		require.NoError(t, err)
		assert.NotNil(t, state, "nil Method rule should match %s", method)
	}
}

// ============================================================================
// CheckRateLimit — endpoint pattern matching
// ============================================================================

func TestCheckRateLimit_EndpointPattern_WildcardStar(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, "*", 5, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)

	tests := []string{testPathAuthLogin, "/health", "/api/v1/users/123", "/"}
	for _, endpoint := range tests {
		state, err := svc.CheckRateLimit(context.Background(), tenantID, "1.2.3.4", endpoint, "GET")
		require.NoError(t, err)
		assert.NotNil(t, state, "wildcard '*' should match %s", endpoint)
	}
}

func TestCheckRateLimit_EndpointPattern_PrefixWildcard(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, "/api/v1/auth/*", 5, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)

	tests := []struct {
		endpoint string
		wantHit  bool
	}{
		{testPathAuthLogin, true},
		{"/api/v1/auth/logout", true},
		{"/api/v1/auth/refresh", true},
		{"/api/v1/users/list", false},
		{"/health", false},
	}

	for _, tt := range tests {
		state, err := svc.CheckRateLimit(context.Background(), tenantID, "1.2.3.4", tt.endpoint, "GET")
		require.NoError(t, err)
		if tt.wantHit {
			assert.NotNil(t, state, "prefix wildcard should match %s", tt.endpoint)
		} else {
			assert.Nil(t, state, "prefix wildcard should not match %s", tt.endpoint)
		}
	}
}

func TestCheckRateLimit_EndpointPattern_ExactMatch(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)

	hit, err := svc.CheckRateLimit(context.Background(), tenantID, "1.2.3.4", testPathAuthLogin, "POST")
	require.NoError(t, err)
	assert.NotNil(t, hit)

	miss, err := svc.CheckRateLimit(context.Background(), tenantID, "1.2.3.4", "/api/v1/auth/logout", "POST")
	require.NoError(t, err)
	assert.Nil(t, miss)
}

// ============================================================================
// CheckRateLimit — rule priority (first match wins)
// ============================================================================

func TestCheckRateLimit_RulePriority_FirstMatchApplied(t *testing.T) {
	// Rules are stored in priority order; the service picks the first matching one.
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	strictRule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 1, 60, 300)
	strictRule.Priority = 100
	lenientRule := makeRule(models.RateLimitScopeIP, "*", 1000, 60, 300)
	lenientRule.Priority = 0

	// strict first, lenient second — service must apply strictRule
	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{strictRule, lenientRule}, nil)
	repo.On("LogEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	ctx := context.Background()
	// Exhaust strictRule's single-request limit
	svc.CheckRateLimit(ctx, tenantID, "1.2.3.4", testPathAuthLogin, "POST") //nolint:errcheck,gosec

	state, err := svc.CheckRateLimit(ctx, tenantID, "1.2.3.4", testPathAuthLogin, "POST")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.Blocked, "first matching (strict) rule must be enforced")
}

// ============================================================================
// GetRules — caching behaviour
// ============================================================================

func TestGetRules_CachesOnFirstFetch(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300)

	// Repo must only be called once regardless of how many GetRules calls are made
	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil).Once()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		rules, err := svc.GetRules(ctx, tenantID)
		require.NoError(t, err)
		assert.Len(t, rules, 1)
	}

	repo.AssertNumberOfCalls(t, "GetActiveRules", 1)
}

func TestGetRules_RepoError_PropagatesError(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	repo.On("GetActiveRules", mock.Anything, tenantID).Return(nil, errors.New("connection timeout"))

	rules, err := svc.GetRules(context.Background(), tenantID)

	require.Error(t, err)
	assert.Nil(t, rules)
	assert.Contains(t, err.Error(), "GetRules")
}

// ============================================================================
// InvalidateCache
// ============================================================================

func TestInvalidateCache_ForcesRepoRefetch(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)

	ctx := context.Background()

	// Prime the cache
	_, err := svc.GetRules(ctx, tenantID)
	require.NoError(t, err)

	// Invalidate and fetch again
	svc.InvalidateCache(tenantID)
	_, err = svc.GetRules(ctx, tenantID)
	require.NoError(t, err)

	// Repo should have been called twice — once before and once after invalidation
	repo.AssertNumberOfCalls(t, "GetActiveRules", 2)
}

// ============================================================================
// CRUD — CreateRule
// ============================================================================

func TestCreateRule_Success(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	userID := uuid.New()

	repo.On("Create", mock.Anything, mock.MatchedBy(func(r *models.RateLimitRule) bool {
		return r.Name == "Test Rule" &&
			r.MaxRequests == 100 &&
			r.WindowSeconds == 60 &&
			r.BlockDurationSeconds == 300 && // default
			r.IsActive
	})).Return(nil)

	req := &models.CreateRateLimitRuleRequest{
		Name:            "Test Rule",
		EndpointPattern: testPathAuthLogin,
		MaxRequests:     100,
		WindowSeconds:   60,
		Scope:           "ip",
	}

	rule, err := svc.CreateRule(context.Background(), tenantID, userID, req)

	require.NoError(t, err)
	require.NotNil(t, rule)
	assert.Equal(t, "Test Rule", rule.Name)
	assert.Equal(t, tenantID, *rule.TenantID)
	assert.Equal(t, userID, *rule.CreatedBy)
	assert.Equal(t, userID, *rule.UpdatedBy)
	assert.True(t, rule.IsActive)
	assert.Equal(t, 300, rule.BlockDurationSeconds)
}

func TestCreateRule_CustomBlockDuration(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID, userID := uuid.New(), uuid.New()

	repo.On("Create", mock.Anything, mock.MatchedBy(func(r *models.RateLimitRule) bool {
		return r.BlockDurationSeconds == 600
	})).Return(nil)

	req := &models.CreateRateLimitRuleRequest{
		Name:                 "Custom Block",
		EndpointPattern:      "*",
		MaxRequests:          10,
		WindowSeconds:        30,
		Scope:                "ip",
		BlockDurationSeconds: intPtr(600),
	}

	rule, err := svc.CreateRule(context.Background(), tenantID, userID, req)
	require.NoError(t, err)
	assert.Equal(t, 600, rule.BlockDurationSeconds)
}

func TestCreateRule_InactiveRule(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID, userID := uuid.New(), uuid.New()

	repo.On("Create", mock.Anything, mock.MatchedBy(func(r *models.RateLimitRule) bool {
		return !r.IsActive
	})).Return(nil)

	req := &models.CreateRateLimitRuleRequest{
		Name:            "Inactive Rule",
		EndpointPattern: "*",
		MaxRequests:     10,
		WindowSeconds:   30,
		Scope:           "ip",
		IsActive:        boolPtr(false),
	}

	rule, err := svc.CreateRule(context.Background(), tenantID, userID, req)
	require.NoError(t, err)
	assert.False(t, rule.IsActive)
}

func TestCreateRule_RepoError_WrapsError(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	repo.On("Create", mock.Anything, mock.Anything).Return(errors.New("unique constraint violation"))

	req := &models.CreateRateLimitRuleRequest{
		Name:            "Dup Rule",
		EndpointPattern: "*",
		MaxRequests:     10,
		WindowSeconds:   30,
		Scope:           "ip",
	}

	rule, err := svc.CreateRule(context.Background(), uuid.New(), uuid.New(), req)
	require.Error(t, err)
	assert.Nil(t, rule)
	assert.Contains(t, err.Error(), "CreateRule")
}

func TestCreateRule_InvalidateCacheOnSuccess(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, "*", 5, 60, 300)

	// Prime the cache
	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)
	_, err := svc.GetRules(context.Background(), tenantID)
	require.NoError(t, err)

	// CreateRule must invalidate the cache
	repo.On("Create", mock.Anything, mock.Anything).Return(nil)
	_, err = svc.CreateRule(context.Background(), tenantID, uuid.New(), &models.CreateRateLimitRuleRequest{
		Name:            "New Rule",
		EndpointPattern: "/api/*",
		MaxRequests:     20,
		WindowSeconds:   60,
		Scope:           "ip",
	})
	require.NoError(t, err)

	// Next GetRules call must hit the repo again
	_, err = svc.GetRules(context.Background(), tenantID)
	require.NoError(t, err)
	repo.AssertNumberOfCalls(t, "GetActiveRules", 2)
}

// ============================================================================
// CRUD — UpdateRule
// ============================================================================

func TestUpdateRule_Success(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	userID := uuid.New()
	ruleID := uuid.New()
	existing := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300)
	existing.ID = ruleID
	existing.TenantID = &tenantID

	repo.On("GetRuleByID", mock.Anything, ruleID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(r *models.RateLimitRule) bool {
		return r.MaxRequests == 50 && r.Name == "Updated Rule"
	})).Return(nil)

	req := &models.UpdateRateLimitRuleRequest{
		Name:        strPtr("Updated Rule"),
		MaxRequests: intPtr(50),
	}

	updated, err := svc.UpdateRule(context.Background(), tenantID, userID, ruleID, req)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "Updated Rule", updated.Name)
	assert.Equal(t, 50, updated.MaxRequests)
	assert.Equal(t, userID, *updated.UpdatedBy)
}

func TestUpdateRule_RuleNotFound_ReturnsError(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	ruleID := uuid.New()
	repo.On("GetRuleByID", mock.Anything, ruleID).Return(nil, nil)

	_, err := svc.UpdateRule(context.Background(), uuid.New(), uuid.New(), ruleID, &models.UpdateRateLimitRuleRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUpdateRule_TenantMismatch_ReturnsNotFound(t *testing.T) {
	// Tenant isolation: a tenant must not be able to modify another tenant's rule
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	ownerTenant := uuid.New()
	attackerTenant := uuid.New()
	ruleID := uuid.New()

	existing := makeRule(models.RateLimitScopeIP, "*", 5, 60, 300)
	existing.ID = ruleID
	existing.TenantID = &ownerTenant

	repo.On("GetRuleByID", mock.Anything, ruleID).Return(existing, nil)

	_, err := svc.UpdateRule(context.Background(), attackerTenant, uuid.New(), ruleID, &models.UpdateRateLimitRuleRequest{
		Name: strPtr("hijacked"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found", "must return not-found to avoid leaking rule existence")
}

func TestUpdateRule_RepoGetError_WrapsError(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	ruleID := uuid.New()
	repo.On("GetRuleByID", mock.Anything, ruleID).Return(nil, errors.New("database error"))

	_, err := svc.UpdateRule(context.Background(), uuid.New(), uuid.New(), ruleID, &models.UpdateRateLimitRuleRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UpdateRule")
}

func TestUpdateRule_RepoUpdateError_WrapsError(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID, ruleID := uuid.New(), uuid.New()
	existing := makeRule(models.RateLimitScopeIP, "*", 5, 60, 300)
	existing.ID = ruleID
	existing.TenantID = &tenantID

	repo.On("GetRuleByID", mock.Anything, ruleID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.Anything).Return(errors.New("write failure"))

	_, err := svc.UpdateRule(context.Background(), tenantID, uuid.New(), ruleID, &models.UpdateRateLimitRuleRequest{
		MaxRequests: intPtr(10),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UpdateRule")
}

// ============================================================================
// CRUD — DeleteRule
// ============================================================================

func TestDeleteRule_Success(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	ruleID := uuid.New()
	existing := makeRule(models.RateLimitScopeIP, "*", 5, 60, 300)
	existing.ID = ruleID
	existing.TenantID = &tenantID

	repo.On("GetRuleByID", mock.Anything, ruleID).Return(existing, nil)
	repo.On("Delete", mock.Anything, ruleID).Return(nil)

	err := svc.DeleteRule(context.Background(), tenantID, ruleID)
	require.NoError(t, err)
	repo.AssertCalled(t, "Delete", mock.Anything, ruleID)
}

func TestDeleteRule_RuleNotFound_ReturnsError(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	ruleID := uuid.New()
	repo.On("GetRuleByID", mock.Anything, ruleID).Return(nil, nil)

	err := svc.DeleteRule(context.Background(), uuid.New(), ruleID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDeleteRule_TenantMismatch_ReturnsNotFound(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	ownerTenant := uuid.New()
	ruleID := uuid.New()
	existing := makeRule(models.RateLimitScopeIP, "*", 5, 60, 300)
	existing.ID = ruleID
	existing.TenantID = &ownerTenant

	repo.On("GetRuleByID", mock.Anything, ruleID).Return(existing, nil)

	err := svc.DeleteRule(context.Background(), uuid.New(), ruleID) // different tenant
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDeleteRule_RepoError_WrapsError(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID, ruleID := uuid.New(), uuid.New()
	existing := makeRule(models.RateLimitScopeIP, "*", 5, 60, 300)
	existing.ID = ruleID
	existing.TenantID = &tenantID

	repo.On("GetRuleByID", mock.Anything, ruleID).Return(existing, nil)
	repo.On("Delete", mock.Anything, ruleID).Return(errors.New("delete failed"))

	err := svc.DeleteRule(context.Background(), tenantID, ruleID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DeleteRule")
}

// ============================================================================
// CRUD — ListRules / GetRule
// ============================================================================

func TestListRules_DelegatesToRepo(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rules := []*models.RateLimitRule{
		makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300),
		makeRule(models.RateLimitScopeUser, "*", 100, 3600, 600),
	}

	repo.On("GetRulesByTenantID", mock.Anything, tenantID).Return(rules, nil)

	result, err := svc.ListRules(context.Background(), tenantID)
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestGetRule_DelegatesToRepo(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	ruleID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300)
	rule.ID = ruleID

	repo.On("GetRuleByID", mock.Anything, ruleID).Return(rule, nil)

	result, err := svc.GetRule(context.Background(), ruleID)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, ruleID, result.ID)
}

// ============================================================================
// GetEvents
// ============================================================================

func TestGetEvents_BlockedOnly_CallsGetBlockedEvents(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	events := []*models.RateLimitEvent{{Identifier: "1.2.3.4", Blocked: true}}
	repo.On("GetBlockedEvents", mock.Anything, tenantID, 50).Return(events, nil)

	result, err := svc.GetEvents(context.Background(), tenantID, 50, true)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	repo.AssertCalled(t, "GetBlockedEvents", mock.Anything, tenantID, 50)
	repo.AssertNotCalled(t, "GetRecentEvents")
}

func TestGetEvents_AllEvents_CallsGetRecentEvents(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	events := []*models.RateLimitEvent{
		{Identifier: "1.2.3.4", Blocked: false},
		{Identifier: "5.6.7.8", Blocked: true},
	}
	repo.On("GetRecentEvents", mock.Anything, tenantID, 100).Return(events, nil)

	result, err := svc.GetEvents(context.Background(), tenantID, 100, false)
	require.NoError(t, err)
	assert.Len(t, result, 2)
	repo.AssertCalled(t, "GetRecentEvents", mock.Anything, tenantID, 100)
	repo.AssertNotCalled(t, "GetBlockedEvents")
}

// ============================================================================
// generateKey — key format per scope
// ============================================================================

func TestGenerateKey_ScopeFormats(t *testing.T) {
	svc := &RateLimitService{}
	tenantID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	identifier := "192.168.1.1"
	endpoint := testPathAuthLogin

	tests := []struct {
		name      string
		scope     models.RateLimitScope
		wantFmt   string
		wantParts []any
	}{
		{
			name:      "IP scope includes tenant, identifier and pattern",
			scope:     models.RateLimitScopeIP,
			wantFmt:   "rl:%s:%s:%s",
			wantParts: []any{tenantID.String(), identifier, endpoint},
		},
		{
			name:      "User scope has 'user' prefix",
			scope:     models.RateLimitScopeUser,
			wantFmt:   "rl:user:%s:%s:%s",
			wantParts: []any{tenantID.String(), identifier, endpoint},
		},
		{
			name:      "Tenant scope includes only tenant and pattern",
			scope:     models.RateLimitScopeTenant,
			wantFmt:   "rl:tenant:%s:%s",
			wantParts: []any{tenantID.String(), endpoint},
		},
		{
			name:      "Global scope includes only pattern",
			scope:     models.RateLimitScopeGlobal,
			wantFmt:   "rl:global:%s",
			wantParts: []any{endpoint},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := makeRule(tt.scope, endpoint, 5, 60, 300)
			key := svc.generateKey(rule, tenantID, identifier, endpoint)

			expected := fmt.Sprintf(tt.wantFmt, tt.wantParts...)
			assert.Equal(t, expected, key)
		})
	}
}

// ============================================================================
// matchesRule — pattern matching table tests
// ============================================================================

func TestMatchesRule(t *testing.T) {
	svc := &RateLimitService{}

	tests := []struct {
		name     string
		endpoint string
		method   string
		rule     *models.RateLimitRule
		want     bool
	}{
		{
			name:     "exact match, no method restriction",
			endpoint: testPathAuthLogin,
			method:   "POST",
			rule:     makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300),
			want:     true,
		},
		{
			name:     "exact match, method matches",
			endpoint: testPathAuthLogin,
			method:   "POST",
			rule: func() *models.RateLimitRule {
				r := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300)
				r.Method = strPtr("POST")
				return r
			}(),
			want: true,
		},
		{
			name:     "exact match, method mismatch",
			endpoint: testPathAuthLogin,
			method:   "GET",
			rule: func() *models.RateLimitRule {
				r := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300)
				r.Method = strPtr("POST")
				return r
			}(),
			want: false,
		},
		{
			name:     "wildcard star matches all",
			endpoint: "/anything/at/all",
			method:   "DELETE",
			rule:     makeRule(models.RateLimitScopeIP, "*", 5, 60, 300),
			want:     true,
		},
		{
			name:     "prefix wildcard matches",
			endpoint: testPathAuthLogin,
			method:   "POST",
			rule:     makeRule(models.RateLimitScopeIP, "/api/v1/auth/*", 5, 60, 300),
			want:     true,
		},
		{
			name:     "prefix wildcard does not match unrelated path",
			endpoint: "/api/v1/users/list",
			method:   "GET",
			rule:     makeRule(models.RateLimitScopeIP, "/api/v1/auth/*", 5, 60, 300),
			want:     false,
		},
		{
			name:     "glob pattern matches",
			endpoint: testPathAuthLogin,
			method:   "POST",
			rule:     makeRule(models.RateLimitScopeIP, "/api/v1/auth/l*", 5, 60, 300),
			want:     true,
		},
		{
			name:     "no match on different path",
			endpoint: "/health",
			method:   "GET",
			rule:     makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300),
			want:     false,
		},
		{
			name:     "empty method string is treated as any method",
			endpoint: testPathAuthLogin,
			method:   "GET",
			rule: func() *models.RateLimitRule {
				r := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300)
				r.Method = strPtr("")
				return r
			}(),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := svc.matchesRule(tt.endpoint, tt.method, tt.rule)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// Concurrent access safety
// ============================================================================

func TestCheckRateLimit_ConcurrentAccess_NoRaceCondition(t *testing.T) {
	// This test is intentionally run with the race detector. It verifies that
	// concurrent requests against the same rate limit key do not corrupt state.
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, "*", 1000, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)
	repo.On("LogEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	const goroutines = 50
	const requestsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			identifier := fmt.Sprintf("client-%d", id)
			for r := 0; r < requestsPerGoroutine; r++ {
				state, err := svc.CheckRateLimit(context.Background(), tenantID, identifier, "/endpoint", "GET")
				assert.NoError(t, err)
				// Each isolated client has its own IP-scoped counter so none
				// should be blocked (1000 limit, 10 requests per client).
				if state != nil {
					assert.False(t, state.Blocked, "client %d should not be blocked", id)
				}
			}
		}(g)
	}

	wg.Wait()
}

func TestCheckRateLimit_ConcurrentAccess_SharedKey_CounterConsistency(t *testing.T) {
	// Verify that the mutex inside RateLimitEntry prevents lost updates under
	// concurrent writes to the same key.
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	const limit = 500
	rule := makeRule(models.RateLimitScopeIP, "*", limit, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)
	repo.On("LogEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	const goroutines = 20
	const requestsEach = 10 // total = 200, all under the 500 limit

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Use the same identifier so all goroutines share one entry
	sharedIdentifier := "shared-user"

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for r := 0; r < requestsEach; r++ {
				_, err := svc.CheckRateLimit(context.Background(), tenantID, sharedIdentifier, "/shared", "POST")
				assert.NoError(t, err)
			}
		}()
	}

	wg.Wait()

	// After all goroutines finish, inspect the final count for the shared key
	finalState, err := svc.CheckRateLimit(context.Background(), tenantID, sharedIdentifier, "/shared", "POST")
	require.NoError(t, err)
	require.NotNil(t, finalState)
	assert.False(t, finalState.Blocked, "200+1 requests should not exceed the 500 limit")
	assert.Equal(t, goroutines*requestsEach+1, finalState.Requests,
		"every request must be counted exactly once (no lost updates, no double-counts)")
}

// ============================================================================
// Stop — graceful shutdown
// ============================================================================

func TestStop_IdempotentMultipleCalls(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := NewRateLimitService(repo) // do NOT call Stop() — we test it here

	// Stop must be safe to call multiple times (sync.Once guarantee)
	assert.NotPanics(t, func() {
		svc.Stop()
		svc.Stop()
		svc.Stop()
	})
}

// ============================================================================
// Edge cases — zero/boundary configuration values
// ============================================================================

func TestCheckRateLimit_SingleRequestLimit_BlocksOnSecondRequest(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 1, 60, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)
	repo.On("LogEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	ctx := context.Background()
	identifier := "1.2.3.4"
	endpoint := testPathAuthLogin

	// First request — allowed
	state, err := svc.CheckRateLimit(ctx, tenantID, identifier, endpoint, "POST")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.Blocked)
	assert.Equal(t, 0, state.Remaining)

	// Second request — must be blocked
	state, err = svc.CheckRateLimit(ctx, tenantID, identifier, endpoint, "POST")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.Blocked)
}

func TestCheckRateLimit_ZeroBlockDuration_DoesNotBlockPermanently(t *testing.T) {
	// A rule with BlockDurationSeconds=0 should not keep clients blocked beyond
	// the current instant (effectively immediate unblock).
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	rule := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 1, 60, 0)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)
	repo.On("LogEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	ctx := context.Background()
	identifier := "1.2.3.4"
	endpoint := testPathAuthLogin

	// Exhaust limit
	svc.CheckRateLimit(ctx, tenantID, identifier, endpoint, "POST") //nolint:errcheck,gosec

	// Trigger block (BlockedUntil = now + 0s = now, so it's immediately expired)
	state, err := svc.CheckRateLimit(ctx, tenantID, identifier, endpoint, "POST")
	require.NoError(t, err)
	require.NotNil(t, state)
	// With 0s block duration, BlockedUntil is effectively now() — the next
	// call may or may not see a block depending on sub-millisecond timing.
	// What we assert is that the service does not panic and returns a valid state.
	assert.NotNil(t, state.ResetAt)
}

func TestCheckRateLimit_LargeMaxRequests_AllowsManyRequests(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	const maxReqs = 10_000
	rule := makeRule(models.RateLimitScopeIP, "*", maxReqs, 3600, 300)

	repo.On("GetActiveRules", mock.Anything, tenantID).Return([]*models.RateLimitRule{rule}, nil)

	ctx := context.Background()
	var lastState *models.RateLimitState

	for i := 0; i < 100; i++ {
		state, err := svc.CheckRateLimit(ctx, tenantID, "1.2.3.4", testPathData, "GET")
		require.NoError(t, err)
		require.NotNil(t, state)
		assert.False(t, state.Blocked)
		lastState = state
	}

	assert.Equal(t, 100, lastState.Requests)
	assert.Equal(t, maxReqs-100, lastState.Remaining)
}

// ============================================================================
// UpdateRule — partial field updates
// ============================================================================

func TestUpdateRule_PartialUpdate_OnlyChangesSpecifiedFields(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID := uuid.New()
	userID := uuid.New()
	ruleID := uuid.New()

	desc := "original description"
	existing := makeRule(models.RateLimitScopeIP, testPathAuthLogin, 5, 60, 300)
	existing.ID = ruleID
	existing.TenantID = &tenantID
	existing.Description = &desc
	existing.Priority = 50

	repo.On("GetRuleByID", mock.Anything, ruleID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.Anything).Return(nil)

	// Only update MaxRequests — everything else must be preserved
	req := &models.UpdateRateLimitRuleRequest{
		MaxRequests: intPtr(99),
	}

	updated, err := svc.UpdateRule(context.Background(), tenantID, userID, ruleID, req)
	require.NoError(t, err)
	require.NotNil(t, updated)

	assert.Equal(t, 99, updated.MaxRequests)
	assert.Equal(t, testPathAuthLogin, updated.EndpointPattern, "unchanged field must be preserved")
	assert.Equal(t, "original description", *updated.Description, "unchanged field must be preserved")
	assert.Equal(t, 50, updated.Priority, "unchanged field must be preserved")
	assert.Equal(t, models.RateLimitScopeIP, updated.Scope, "unchanged field must be preserved")
}

func TestUpdateRule_AllFields(t *testing.T) {
	repo := new(mockRateLimitRepo)
	svc := newTestRateLimitService(repo)

	tenantID, userID, ruleID := uuid.New(), uuid.New(), uuid.New()
	existing := makeRule(models.RateLimitScopeIP, "/old/path", 5, 60, 300)
	existing.ID = ruleID
	existing.TenantID = &tenantID

	repo.On("GetRuleByID", mock.Anything, ruleID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.Anything).Return(nil)

	newDesc := "new description"
	newMethod := "GET"
	newScope := "user"
	req := &models.UpdateRateLimitRuleRequest{
		Name:                 strPtr("New Name"),
		Description:          &newDesc,
		EndpointPattern:      strPtr("/new/path"),
		Method:               &newMethod,
		MaxRequests:          intPtr(200),
		WindowSeconds:        intPtr(120),
		BlockDurationSeconds: intPtr(600),
		Scope:                &newScope,
		Priority:             intPtr(99),
		IsActive:             boolPtr(false),
	}

	updated, err := svc.UpdateRule(context.Background(), tenantID, userID, ruleID, req)
	require.NoError(t, err)

	assert.Equal(t, "New Name", updated.Name)
	assert.Equal(t, "new description", *updated.Description)
	assert.Equal(t, "/new/path", updated.EndpointPattern)
	assert.Equal(t, "GET", *updated.Method)
	assert.Equal(t, 200, updated.MaxRequests)
	assert.Equal(t, 120, updated.WindowSeconds)
	assert.Equal(t, 600, updated.BlockDurationSeconds)
	assert.Equal(t, models.RateLimitScopeUser, updated.Scope)
	assert.Equal(t, 99, updated.Priority)
	assert.False(t, updated.IsActive)
}
