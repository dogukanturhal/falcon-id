// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock: ipRuleServiceIPRuleRepo
// ---------------------------------------------------------------------------

type MockIPRuleRepo struct {
	mock.Mock
}

func (m *MockIPRuleRepo) GetActiveRules(ctx context.Context, tenantID uuid.UUID) ([]*models.IPRule, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.IPRule), args.Error(1)
}

func (m *MockIPRuleRepo) IncrementHitCount(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockIPRuleRepo) LogAction(ctx context.Context, log *models.IPRuleLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockIPRuleRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.IPRule, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.IPRule), args.Error(1)
}

func (m *MockIPRuleRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.IPRule, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.IPRule), args.Error(1)
}

func (m *MockIPRuleRepo) Create(ctx context.Context, rule *models.IPRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *MockIPRuleRepo) Update(ctx context.Context, rule *models.IPRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *MockIPRuleRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockIPRuleRepo) GetDeniedLogs(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.IPRuleLog, error) {
	args := m.Called(ctx, tenantID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.IPRuleLog), args.Error(1)
}

func (m *MockIPRuleRepo) GetRecentLogs(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.IPRuleLog, error) {
	args := m.Called(ctx, tenantID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.IPRuleLog), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newIPRuleService(repo *MockIPRuleRepo) *IPRuleService {
	return NewIPRuleService(repo)
}

func ipRuleAllow(tenantID uuid.UUID, pattern string) *models.IPRule {
	return &models.IPRule{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Name:      "allow-rule",
		IPPattern: pattern,
		RuleType:  models.IPRuleTypeAllow,
		Priority:  100,
		IsActive:  true,
		AppliesTo: models.IPRuleAppliesToAll,
	}
}

func ipRuleDeny(tenantID uuid.UUID, pattern string) *models.IPRule {
	return &models.IPRule{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Name:      "deny-rule",
		IPPattern: pattern,
		RuleType:  models.IPRuleTypeDeny,
		Priority:  50,
		IsActive:  true,
		AppliesTo: models.IPRuleAppliesToAll,
	}
}

// ---------------------------------------------------------------------------
// Tests: CreateRule
// ---------------------------------------------------------------------------

func TestIPRuleService_CreateRule_ValidIPAddress(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	userID := uuid.New()

	req := &models.CreateIPRuleRequest{
		Name:      "block-ip",
		IPPattern: "192.168.1.1",
		RuleType:  "deny",
	}

	repo.On("Create", ctx, mock.AnythingOfType("*models.IPRule")).Return(nil)

	rule, err := svc.CreateRule(ctx, tenantID, userID, req)

	require.NoError(t, err)
	require.NotNil(t, rule)
	assert.Equal(t, "192.168.1.1", rule.IPPattern)
	assert.Equal(t, models.IPRuleTypeDeny, rule.RuleType)
	repo.AssertExpectations(t)
}

func TestIPRuleService_CreateRule_ValidCIDR(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	userID := uuid.New()

	req := &models.CreateIPRuleRequest{
		Name:      "allow-subnet",
		IPPattern: "10.0.0.0/8",
		RuleType:  "allow",
	}

	repo.On("Create", ctx, mock.AnythingOfType("*models.IPRule")).Return(nil)

	rule, err := svc.CreateRule(ctx, tenantID, userID, req)

	require.NoError(t, err)
	require.NotNil(t, rule)
	assert.Equal(t, "10.0.0.0/8", rule.IPPattern)
	assert.Equal(t, models.IPRuleTypeAllow, rule.RuleType)
	repo.AssertExpectations(t)
}

func TestIPRuleService_CreateRule_InvalidPattern(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	userID := uuid.New()

	tests := []struct {
		pattern string
		desc    string
	}{
		{"not-an-ip", "plain string"},
		{"999.999.999.999", "invalid octets"},
		{"192.168.1.0/33", "invalid CIDR prefix"},
		{"", "empty string"},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			req := &models.CreateIPRuleRequest{
				Name:      "test-rule",
				IPPattern: tc.pattern,
				RuleType:  "deny",
			}

			rule, err := svc.CreateRule(ctx, tenantID, userID, req)
			assert.Error(t, err)
			assert.Nil(t, rule)
			assert.Contains(t, err.Error(), "invalid IP pattern")
		})
	}
}

func TestIPRuleService_CreateRule_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	userID := uuid.New()

	req := &models.CreateIPRuleRequest{
		Name:      "fail-rule",
		IPPattern: "192.168.1.100",
		RuleType:  "deny",
	}

	repo.On("Create", ctx, mock.AnythingOfType("*models.IPRule")).Return(errors.New("db error"))

	rule, err := svc.CreateRule(ctx, tenantID, userID, req)

	assert.Error(t, err)
	assert.Nil(t, rule)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: CheckIP
// ---------------------------------------------------------------------------

func TestIPRuleService_CheckIP_AllowedByRule(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	allowRule := ipRuleAllow(tenantID, "192.168.1.0/24")

	repo.On("GetActiveRules", ctx, tenantID).Return([]*models.IPRule{allowRule}, nil)
	// IncrementHitCount is called asynchronously in a goroutine; allow but don't require it.
	repo.On("IncrementHitCount", mock.Anything, allowRule.ID).Return(nil).Maybe()

	result, err := svc.CheckIP(ctx, tenantID, "192.168.1.50", models.IPRuleAppliesToAll)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, allowRule.ID, result.RuleID)
}

func TestIPRuleService_CheckIP_BlockedByRule(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	denyRule := ipRuleDeny(tenantID, "10.0.0.0/16")

	repo.On("GetActiveRules", ctx, tenantID).Return([]*models.IPRule{denyRule}, nil)
	repo.On("IncrementHitCount", mock.Anything, denyRule.ID).Return(nil).Maybe()

	result, err := svc.CheckIP(ctx, tenantID, "10.0.5.5", models.IPRuleAppliesToAll)

	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, denyRule.ID, result.RuleID)
}

func TestIPRuleService_CheckIP_NoRuleDefaultAllow(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	repo.On("GetActiveRules", ctx, tenantID).Return([]*models.IPRule{}, nil)

	result, err := svc.CheckIP(ctx, tenantID, "1.2.3.4", models.IPRuleAppliesToAll)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestIPRuleService_CheckIP_ExactIPMatch(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	denyRule := ipRuleDeny(tenantID, "203.0.113.42")

	repo.On("GetActiveRules", ctx, tenantID).Return([]*models.IPRule{denyRule}, nil)
	repo.On("IncrementHitCount", mock.Anything, denyRule.ID).Return(nil).Maybe()

	// Exact match — should be denied
	result, err := svc.CheckIP(ctx, tenantID, "203.0.113.42", models.IPRuleAppliesToAll)
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	// Different IP — cache still has rules, no rule matches → allow (no IncrementHitCount)
	result2, err := svc.CheckIP(ctx, tenantID, "203.0.113.43", models.IPRuleAppliesToAll)
	require.NoError(t, err)
	assert.True(t, result2.Allowed)
}

func TestIPRuleService_CheckIP_AppliesToFilter(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()

	// Rule applies to 'admin' only
	adminOnlyRule := &models.IPRule{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Name:      "admin-deny",
		IPPattern: "192.168.0.0/24",
		RuleType:  models.IPRuleTypeDeny,
		IsActive:  true,
		AppliesTo: models.IPRuleAppliesToAdmin,
	}

	repo.On("GetActiveRules", ctx, tenantID).Return([]*models.IPRule{adminOnlyRule}, nil).Once()
	// Rule doesn't apply to API context so IncrementHitCount is never called
	repo.On("IncrementHitCount", mock.Anything, adminOnlyRule.ID).Return(nil).Maybe()

	// When checking with 'api' context, rule should not apply → allowed
	result, err := svc.CheckIP(ctx, tenantID, "192.168.0.10", models.IPRuleAppliesToAPI)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// ---------------------------------------------------------------------------
// Tests: DeleteRule
// ---------------------------------------------------------------------------

func TestIPRuleService_DeleteRule_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	ruleID := uuid.New()
	rule := &models.IPRule{
		ID:        ruleID,
		TenantID:  tenantID,
		IPPattern: "10.0.0.0/8",
	}

	repo.On("GetByID", ctx, ruleID).Return(rule, nil)
	repo.On("Delete", ctx, ruleID).Return(nil)

	err := svc.DeleteRule(ctx, tenantID, ruleID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestIPRuleService_DeleteRule_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	ruleID := uuid.New()

	repo.On("GetByID", ctx, ruleID).Return((*models.IPRule)(nil), nil)

	err := svc.DeleteRule(ctx, tenantID, ruleID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IP rule not found")
	repo.AssertExpectations(t)
}

func TestIPRuleService_DeleteRule_WrongTenant(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	otherTenantID := uuid.New()
	ruleID := uuid.New()

	rule := &models.IPRule{
		ID:        ruleID,
		TenantID:  otherTenantID, // different tenant
		IPPattern: "10.0.0.1",
	}

	repo.On("GetByID", ctx, ruleID).Return(rule, nil)

	err := svc.DeleteRule(ctx, tenantID, ruleID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IP rule not found")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ListRules
// ---------------------------------------------------------------------------

func TestIPRuleService_ListRules_ByTenant(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	rules := []*models.IPRule{
		ipRuleAllow(tenantID, "192.168.1.0/24"),
		ipRuleDeny(tenantID, "10.0.0.0/8"),
	}

	repo.On("GetByTenantID", ctx, tenantID).Return(rules, nil)

	result, err := svc.ListRules(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, result, 2)
	repo.AssertExpectations(t)
}

func TestIPRuleService_ListRules_Empty(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	repo.On("GetByTenantID", ctx, tenantID).Return([]*models.IPRule{}, nil)

	result, err := svc.ListRules(ctx, tenantID)

	require.NoError(t, err)
	assert.Empty(t, result)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetRules (with cache)
// ---------------------------------------------------------------------------

func TestIPRuleService_GetRules_CachesResult(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	rules := []*models.IPRule{ipRuleAllow(tenantID, "172.16.0.0/12")}

	// Repo called once; second call hits cache
	repo.On("GetActiveRules", ctx, tenantID).Return(rules, nil).Once()

	r1, err := svc.GetRules(ctx, tenantID)
	require.NoError(t, err)
	assert.Len(t, r1, 1)

	r2, err := svc.GetRules(ctx, tenantID)
	require.NoError(t, err)
	assert.Len(t, r2, 1)

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: UpdateRule
// ---------------------------------------------------------------------------

func TestIPRuleService_UpdateRule_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	userID := uuid.New()
	ruleID := uuid.New()

	existing := &models.IPRule{
		ID:        ruleID,
		TenantID:  tenantID,
		Name:      "old-name",
		IPPattern: "192.168.1.0/24",
		RuleType:  models.IPRuleTypeAllow,
	}

	newName := "new-name"
	newPattern := "10.0.0.0/8"
	req := &models.UpdateIPRuleRequest{
		Name:      &newName,
		IPPattern: &newPattern,
	}

	repo.On("GetByID", ctx, ruleID).Return(existing, nil)
	repo.On("Update", ctx, mock.AnythingOfType("*models.IPRule")).Return(nil)

	rule, err := svc.UpdateRule(ctx, tenantID, userID, ruleID, req)

	require.NoError(t, err)
	assert.Equal(t, "new-name", rule.Name)
	assert.Equal(t, "10.0.0.0/8", rule.IPPattern)
	repo.AssertExpectations(t)
}

func TestIPRuleService_UpdateRule_InvalidPattern(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	userID := uuid.New()
	ruleID := uuid.New()

	existing := &models.IPRule{
		ID:        ruleID,
		TenantID:  tenantID,
		IPPattern: "192.168.1.0/24",
	}

	badPattern := "not-valid"
	req := &models.UpdateIPRuleRequest{
		IPPattern: &badPattern,
	}

	repo.On("GetByID", ctx, ruleID).Return(existing, nil)

	rule, err := svc.UpdateRule(ctx, tenantID, userID, ruleID, req)

	assert.Error(t, err)
	assert.Nil(t, rule)
	assert.Contains(t, err.Error(), "invalid IP pattern")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetLogs
// ---------------------------------------------------------------------------

func TestIPRuleService_GetLogs_AllLogs(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	logs := []*models.IPRuleLog{
		{IPAddress: "1.2.3.4", Action: "allowed"},
		{IPAddress: "5.6.7.8", Action: "denied"},
	}

	repo.On("GetRecentLogs", ctx, tenantID, 10).Return(logs, nil)

	result, err := svc.GetLogs(ctx, tenantID, 10, false)

	require.NoError(t, err)
	assert.Len(t, result, 2)
	repo.AssertExpectations(t)
}

func TestIPRuleService_GetLogs_DeniedOnly(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	logs := []*models.IPRuleLog{
		{IPAddress: "5.6.7.8", Action: "denied"},
	}

	repo.On("GetDeniedLogs", ctx, tenantID, 5).Return(logs, nil)

	result, err := svc.GetLogs(ctx, tenantID, 5, true)

	require.NoError(t, err)
	assert.Len(t, result, 1)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: InvalidateCache
// ---------------------------------------------------------------------------

func TestIPRuleService_InvalidateCache(t *testing.T) {
	ctx := context.Background()
	repo := new(MockIPRuleRepo)
	svc := newIPRuleService(repo)

	tenantID := uuid.New()
	rules := []*models.IPRule{ipRuleAllow(tenantID, "192.168.0.0/16")}

	// First call populates cache
	repo.On("GetActiveRules", ctx, tenantID).Return(rules, nil)

	_, err := svc.GetRules(ctx, tenantID)
	require.NoError(t, err)

	// Invalidate cache
	svc.InvalidateCache(tenantID)

	// Second call must hit repo again
	repo.On("GetActiveRules", ctx, tenantID).Return(rules, nil)
	_, err = svc.GetRules(ctx, tenantID)
	require.NoError(t, err)

	repo.AssertExpectations(t)
}
