// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ---------------------------------------------------------------------------
// Fake IP rule repository (implements the private ipRuleServiceIPRuleRepo).
// ---------------------------------------------------------------------------

type fakeIPRuleRepo struct {
	getActiveRulesFn    func(ctx context.Context, tenantID uuid.UUID) ([]*models.IPRule, error)
	incrementHitCountFn func(ctx context.Context, id uuid.UUID) error
	logActionFn         func(ctx context.Context, log *models.IPRuleLog) error
	getByTenantIDFn     func(ctx context.Context, tenantID uuid.UUID) ([]*models.IPRule, error)
	getByIDFn           func(ctx context.Context, id uuid.UUID) (*models.IPRule, error)
	createFn            func(ctx context.Context, rule *models.IPRule) error
	updateFn            func(ctx context.Context, rule *models.IPRule) error
	deleteFn            func(ctx context.Context, id uuid.UUID) error
	getDeniedLogsFn     func(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.IPRuleLog, error)
	getRecentLogsFn     func(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.IPRuleLog, error)
}

func (r *fakeIPRuleRepo) GetActiveRules(ctx context.Context, tenantID uuid.UUID) ([]*models.IPRule, error) {
	if r.getActiveRulesFn != nil {
		return r.getActiveRulesFn(ctx, tenantID)
	}
	return nil, nil
}

func (r *fakeIPRuleRepo) IncrementHitCount(ctx context.Context, id uuid.UUID) error {
	if r.incrementHitCountFn != nil {
		return r.incrementHitCountFn(ctx, id)
	}
	return nil
}

func (r *fakeIPRuleRepo) LogAction(ctx context.Context, log *models.IPRuleLog) error {
	if r.logActionFn != nil {
		return r.logActionFn(ctx, log)
	}
	return nil
}

func (r *fakeIPRuleRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.IPRule, error) {
	if r.getByTenantIDFn != nil {
		return r.getByTenantIDFn(ctx, tenantID)
	}
	return nil, nil
}

func (r *fakeIPRuleRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.IPRule, error) {
	if r.getByIDFn != nil {
		return r.getByIDFn(ctx, id)
	}
	return nil, nil
}

func (r *fakeIPRuleRepo) Create(ctx context.Context, rule *models.IPRule) error {
	if r.createFn != nil {
		return r.createFn(ctx, rule)
	}
	return nil
}

func (r *fakeIPRuleRepo) Update(ctx context.Context, rule *models.IPRule) error {
	if r.updateFn != nil {
		return r.updateFn(ctx, rule)
	}
	return nil
}

func (r *fakeIPRuleRepo) Delete(ctx context.Context, id uuid.UUID) error {
	if r.deleteFn != nil {
		return r.deleteFn(ctx, id)
	}
	return nil
}

func (r *fakeIPRuleRepo) GetDeniedLogs(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.IPRuleLog, error) {
	if r.getDeniedLogsFn != nil {
		return r.getDeniedLogsFn(ctx, tenantID, limit)
	}
	return nil, nil
}

func (r *fakeIPRuleRepo) GetRecentLogs(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.IPRuleLog, error) {
	if r.getRecentLogsFn != nil {
		return r.getRecentLogsFn(ctx, tenantID, limit)
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// Helper: build middleware backed by a fake rule set.
// ---------------------------------------------------------------------------

func newIPFilterMiddleware(repo *fakeIPRuleRepo) *IPFilterMiddleware {
	svc := services.NewIPRuleService(repo)
	return NewIPFilterMiddleware(svc)
}

// ipRuleAllow returns an allow rule for the given IP pattern.
func ipRuleAllow(pattern string) *models.IPRule {
	return &models.IPRule{
		ID:        uuid.New(),
		Name:      "allow-" + pattern,
		IPPattern: pattern,
		RuleType:  models.IPRuleTypeAllow,
		IsActive:  true,
		AppliesTo: models.IPRuleAppliesToAll,
	}
}

// ipRuleDeny returns a deny rule for the given IP pattern.
func ipRuleDeny(pattern string) *models.IPRule {
	return &models.IPRule{
		ID:        uuid.New(),
		Name:      "deny-" + pattern,
		IPPattern: pattern,
		RuleType:  models.IPRuleTypeDeny,
		IsActive:  true,
		AppliesTo: models.IPRuleAppliesToAll,
	}
}

// runIPFilter fires a GET against the IP-filter middleware with the given
// client IP and optional tenant_id in gin context.
func runIPFilter(m *IPFilterMiddleware, clientIP string, tenantID *uuid.UUID) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	router.GET("/test",
		func(c *gin.Context) {
			if tenantID != nil {
				c.Set("tenant_id", *tenantID)
			}
			c.Next()
		},
		m.IPFilter(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = clientIP + ":9999"
	router.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// Tests: no tenant context
// ---------------------------------------------------------------------------

func TestIPFilter_NoTenantInContext_PassesThrough(t *testing.T) {
	// When no tenant_id is in context the middleware must not block.
	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			t.Fatal("GetActiveRules must not be called without a tenant context")
			return nil, nil
		},
	}
	m := newIPFilterMiddleware(repo)

	w := runIPFilter(m, "10.0.0.1", nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: whitelist (allow) rules
// ---------------------------------------------------------------------------

func TestIPFilter_AllowedIPInWhitelistMode_Passes(t *testing.T) {
	tenantID := uuid.New()
	ruleID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			r := ipRuleAllow("192.168.1.50")
			r.ID = ruleID
			return []*models.IPRule{r}, nil
		},
		incrementHitCountFn: func(_ context.Context, _ uuid.UUID) error { return nil },
		logActionFn:         func(_ context.Context, _ *models.IPRuleLog) error { return nil },
	}
	m := newIPFilterMiddleware(repo)

	w := runIPFilter(m, "192.168.1.50", &tenantID)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestIPFilter_BlockedIPInWhitelistMode_Returns403(t *testing.T) {
	// Only 10.0.0.1 is allowed; 10.0.0.2 should be blocked because the deny
	// rule matches it (simulating a whitelist where unlisted IPs are denied).
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			return []*models.IPRule{ipRuleDeny("10.0.0.2")}, nil
		},
		incrementHitCountFn: func(_ context.Context, _ uuid.UUID) error { return nil },
		logActionFn:         func(_ context.Context, _ *models.IPRuleLog) error { return nil },
	}
	m := newIPFilterMiddleware(repo)

	w := runIPFilter(m, "10.0.0.2", &tenantID)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: blacklist (deny) rules
// ---------------------------------------------------------------------------

func TestIPFilter_AllowedIPInBlacklistMode_Passes(t *testing.T) {
	// The deny rule targets a different IP; this IP is not matched → default allow.
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			return []*models.IPRule{ipRuleDeny("10.0.0.99")}, nil
		},
		incrementHitCountFn: func(_ context.Context, _ uuid.UUID) error { return nil },
		logActionFn:         func(_ context.Context, _ *models.IPRuleLog) error { return nil },
	}
	m := newIPFilterMiddleware(repo)

	w := runIPFilter(m, "10.0.0.1", &tenantID)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestIPFilter_BlockedIPInBlacklistMode_Returns403(t *testing.T) {
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			return []*models.IPRule{ipRuleDeny("10.0.0.1")}, nil
		},
		incrementHitCountFn: func(_ context.Context, _ uuid.UUID) error { return nil },
		logActionFn:         func(_ context.Context, _ *models.IPRuleLog) error { return nil },
	}
	m := newIPFilterMiddleware(repo)

	w := runIPFilter(m, "10.0.0.1", &tenantID)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: empty rule set
// ---------------------------------------------------------------------------

func TestIPFilter_EmptyRuleSet_AllIPsAllowed(t *testing.T) {
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			return []*models.IPRule{}, nil // no rules
		},
	}
	m := newIPFilterMiddleware(repo)

	ips := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1", "1.2.3.4"}
	for _, ip := range ips {
		t.Run(ip, func(t *testing.T) {
			w := runIPFilter(m, ip, &tenantID)
			assert.Equal(t, http.StatusOK, w.Code, "IP %s should pass when rule set is empty", ip)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: CIDR patterns
// ---------------------------------------------------------------------------

func TestIPFilter_IPInCIDRAllowRule_Passes(t *testing.T) {
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			return []*models.IPRule{ipRuleAllow("10.0.0.0/8")}, nil
		},
		incrementHitCountFn: func(_ context.Context, _ uuid.UUID) error { return nil },
		logActionFn:         func(_ context.Context, _ *models.IPRuleLog) error { return nil },
	}
	m := newIPFilterMiddleware(repo)

	// 10.1.2.3 is inside 10.0.0.0/8
	w := runIPFilter(m, "10.1.2.3", &tenantID)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestIPFilter_IPNotInCIDRDenyRule_Passes(t *testing.T) {
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			return []*models.IPRule{ipRuleDeny("192.168.0.0/24")}, nil
		},
		incrementHitCountFn: func(_ context.Context, _ uuid.UUID) error { return nil },
		logActionFn:         func(_ context.Context, _ *models.IPRuleLog) error { return nil },
	}
	m := newIPFilterMiddleware(repo)

	// 192.168.1.1 is NOT in 192.168.0.0/24 → should not be blocked
	w := runIPFilter(m, "192.168.1.1", &tenantID)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestIPFilter_IPInCIDRDenyRule_Returns403(t *testing.T) {
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			return []*models.IPRule{ipRuleDeny("192.168.0.0/24")}, nil
		},
		incrementHitCountFn: func(_ context.Context, _ uuid.UUID) error { return nil },
		logActionFn:         func(_ context.Context, _ *models.IPRuleLog) error { return nil },
	}
	m := newIPFilterMiddleware(repo)

	// 192.168.0.50 IS in 192.168.0.0/24 → should be blocked
	w := runIPFilter(m, "192.168.0.50", &tenantID)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: private / internal IP ranges
// ---------------------------------------------------------------------------

func TestIPFilter_PrivateIPWithNoRule_Passes(t *testing.T) {
	// Private IPs should be treated like any other IP – the default is to allow
	// when no rule matches.
	tenantID := uuid.New()

	privateIPs := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"127.0.0.1",
	}

	for _, ip := range privateIPs {
		t.Run(ip, func(t *testing.T) {
			repo := &fakeIPRuleRepo{
				getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
					return nil, nil
				},
			}
			m := newIPFilterMiddleware(repo)
			w := runIPFilter(m, ip, &tenantID)
			assert.Equal(t, http.StatusOK, w.Code, "private IP %s should pass with no rules", ip)
		})
	}
}

func TestIPFilter_PrivateIPWithDenyRule_Returns403(t *testing.T) {
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			return []*models.IPRule{ipRuleDeny("10.0.0.0/8")}, nil
		},
		incrementHitCountFn: func(_ context.Context, _ uuid.UUID) error { return nil },
		logActionFn:         func(_ context.Context, _ *models.IPRuleLog) error { return nil },
	}
	m := newIPFilterMiddleware(repo)

	w := runIPFilter(m, "10.0.0.1", &tenantID)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: repo errors are fatal (fail-closed)
// ---------------------------------------------------------------------------

func TestIPFilter_RepoError_FailsClosed503(t *testing.T) {
	// SECURITY: When the IP rule store returns an error the middleware must
	// abort with 503 rather than allowing the request through.  Failing open
	// would let an attacker bypass IP restrictions by forcing a transient error.
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			return nil, assert.AnError
		},
	}
	m := newIPFilterMiddleware(repo)

	w := runIPFilter(m, "1.2.3.4", &tenantID)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: tenant_id type handling
// ---------------------------------------------------------------------------

func TestIPFilter_TenantIDAsString_HandledGracefully(t *testing.T) {
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			return nil, nil // no rules → default allow
		},
	}
	m := newIPFilterMiddleware(repo)

	// Inject tenant_id as a string (some middleware paths do this).
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test",
		func(c *gin.Context) {
			c.Set("tenant_id", tenantID.String()) // string, not uuid.UUID
			c.Next()
		},
		m.IPFilter(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestIPFilter_TenantIDInvalidString_PassesThrough(t *testing.T) {
	// An invalid UUID string should cause the middleware to skip IP filtering.
	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			t.Fatal("GetActiveRules must not be called with an invalid tenant_id")
			return nil, nil
		},
	}
	m := newIPFilterMiddleware(repo)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test",
		func(c *gin.Context) {
			c.Set("tenant_id", "not-a-valid-uuid")
			c.Next()
		},
		m.IPFilter(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: determineAppliesTo path classification
// ---------------------------------------------------------------------------

func TestIPFilter_DetermineAppliesTo_AdminPath(t *testing.T) {
	// determineAppliesTo is a pure function on the middleware struct; we only
	// need a constructed middleware to call it – no repo interaction required.
	m := newIPFilterMiddleware(&fakeIPRuleRepo{})

	tests := []struct {
		path     string
		expected models.IPRuleAppliesTo
	}{
		{"/api/admin/users", models.IPRuleAppliesToAdmin},
		{"/api/users", models.IPRuleAppliesToAPI},
		{"/dashboard", models.IPRuleAppliesToUser},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			result := m.determineAppliesTo(tt.path)
			assert.Equal(t, tt.expected, result, "path %q should map to %q", tt.path, tt.expected)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: rule priority – first match wins
// ---------------------------------------------------------------------------

func TestIPFilter_FirstMatchWins_AllowBeforeDeny(t *testing.T) {
	// If an allow rule for 10.0.0.1 appears before a deny rule for the
	// same IP, the allow should win.
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			allow := ipRuleAllow("10.0.0.1")
			deny := ipRuleDeny("10.0.0.1")
			return []*models.IPRule{allow, deny}, nil
		},
		incrementHitCountFn: func(_ context.Context, _ uuid.UUID) error { return nil },
		logActionFn:         func(_ context.Context, _ *models.IPRuleLog) error { return nil },
	}
	m := newIPFilterMiddleware(repo)

	w := runIPFilter(m, "10.0.0.1", &tenantID)
	assert.Equal(t, http.StatusOK, w.Code, "allow rule appearing first should win")
}

func TestIPFilter_FirstMatchWins_DenyBeforeAllow(t *testing.T) {
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			deny := ipRuleDeny("10.0.0.1")
			allow := ipRuleAllow("10.0.0.1")
			return []*models.IPRule{deny, allow}, nil
		},
		incrementHitCountFn: func(_ context.Context, _ uuid.UUID) error { return nil },
		logActionFn:         func(_ context.Context, _ *models.IPRuleLog) error { return nil },
	}
	m := newIPFilterMiddleware(repo)

	w := runIPFilter(m, "10.0.0.1", &tenantID)
	assert.Equal(t, http.StatusForbidden, w.Code, "deny rule appearing first should win")
}

// ---------------------------------------------------------------------------
// Tests: 403 response body
// ---------------------------------------------------------------------------

func TestIPFilter_DeniedResponse_HasExpectedBody(t *testing.T) {
	tenantID := uuid.New()

	repo := &fakeIPRuleRepo{
		getActiveRulesFn: func(_ context.Context, _ uuid.UUID) ([]*models.IPRule, error) {
			return []*models.IPRule{ipRuleDeny("5.5.5.5")}, nil
		},
		incrementHitCountFn: func(_ context.Context, _ uuid.UUID) error { return nil },
		logActionFn:         func(_ context.Context, _ *models.IPRuleLog) error { return nil },
	}
	m := newIPFilterMiddleware(repo)

	w := runIPFilter(m, "5.5.5.5", &tenantID)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "Access denied")
}
