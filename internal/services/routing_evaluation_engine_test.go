// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	testTimezoneUTC = "UTC"
)

// mockRoutingRuleRepo implements RoutingRuleRepo for testing.
type mockRoutingRuleRepo struct {
	rules []models.EnhancedIDPRoutingRule
}

func (m *mockRoutingRuleRepo) ListEnabledByTenant(_ context.Context, _ uuid.UUID) ([]models.EnhancedIDPRoutingRule, error) {
	return m.rules, nil
}

// mockNetworkZoneRepo implements NetworkZoneRepo for testing.
type mockNetworkZoneRepo struct {
	zones []models.NetworkZone
}

func (m *mockNetworkZoneRepo) ListEnabledByTenant(_ context.Context, _ uuid.UUID) ([]models.NetworkZone, error) {
	return m.zones, nil
}

// =====================================================================
// Existing Tests (migration 125 baseline)
// =====================================================================

func TestRoutingEvaluationEngine_EmailDomainMatch(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()

	ruleRepo := &mockRoutingRuleRepo{
		rules: []models.EnhancedIDPRoutingRule{
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                  uuid.New(),
					TenantID:            tenantID,
					IdentityProviderID:  providerID,
					RuleType:            "email_domain",
					RuleValue:           "corp.example.com",
					Priority:            10,
					IsEnabled:           true,
					ProviderType:        "saml",
					ProviderDisplayName: "Corporate SAML",
				},
				Action: models.RoutingActionRedirect,
			},
		},
	}

	engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

	result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
		TenantID:    tenantID,
		EmailDomain: "corp.example.com",
		DeviceType:  "desktop",
	})

	assert.NoError(t, err)
	assert.True(t, result.Matched)
	assert.Equal(t, models.RoutingActionRedirect, result.Action)
	assert.Equal(t, &providerID, result.ProviderID)
	assert.Equal(t, 1, result.RulesEvaluated)
}

func TestRoutingEvaluationEngine_NoMatch(t *testing.T) {
	tenantID := uuid.New()

	ruleRepo := &mockRoutingRuleRepo{
		rules: []models.EnhancedIDPRoutingRule{
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                 uuid.New(),
					TenantID:           tenantID,
					IdentityProviderID: uuid.New(),
					RuleType:           "email_domain",
					RuleValue:          "corp.example.com",
					Priority:           10,
					IsEnabled:          true,
				},
				Action: models.RoutingActionRedirect,
			},
		},
	}

	engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

	result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
		TenantID:    tenantID,
		EmailDomain: "other.example.com",
		DeviceType:  "desktop",
	})

	assert.NoError(t, err)
	assert.False(t, result.Matched)
	assert.Equal(t, models.RoutingActionAllow, result.Action)
	assert.Equal(t, 1, result.RulesEvaluated)
}

func TestRoutingEvaluationEngine_MultiCriteriaAND(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()
	desktop := "desktop"
	corporate := "corporate"

	ruleRepo := &mockRoutingRuleRepo{
		rules: []models.EnhancedIDPRoutingRule{
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                 uuid.New(),
					TenantID:           tenantID,
					IdentityProviderID: providerID,
					RuleType:           "email_domain",
					RuleValue:          "corp.example.com",
					Priority:           10,
					IsEnabled:          true,
					ProviderType:       "saml",
				},
				DeviceType:  &desktop,
				NetworkZone: &corporate,
				Action:      models.RoutingActionRedirect,
			},
		},
	}

	engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

	// All criteria match
	t.Run("all criteria match", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:    tenantID,
			EmailDomain: "corp.example.com",
			DeviceType:  "desktop",
			NetworkZone: "corporate",
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)
	})

	// Device type mismatch
	t.Run("device type mismatch", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:    tenantID,
			EmailDomain: "corp.example.com",
			DeviceType:  "mobile",
			NetworkZone: "corporate",
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})

	// Network zone mismatch
	t.Run("network zone mismatch", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:    tenantID,
			EmailDomain: "corp.example.com",
			DeviceType:  "desktop",
			NetworkZone: "external",
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})
}

func TestRoutingEvaluationEngine_PriorityOrder(t *testing.T) {
	tenantID := uuid.New()
	highPriorityProvider := uuid.New()
	lowPriorityProvider := uuid.New()

	ruleRepo := &mockRoutingRuleRepo{
		rules: []models.EnhancedIDPRoutingRule{
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                 uuid.New(),
					TenantID:           tenantID,
					IdentityProviderID: highPriorityProvider,
					RuleType:           "email_domain",
					RuleValue:          "corp.example.com",
					Priority:           1, // Higher priority
					IsEnabled:          true,
				},
				Action: models.RoutingActionDeny,
			},
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                 uuid.New(),
					TenantID:           tenantID,
					IdentityProviderID: lowPriorityProvider,
					RuleType:           "email_domain",
					RuleValue:          "corp.example.com",
					Priority:           100, // Lower priority
					IsEnabled:          true,
				},
				Action: models.RoutingActionRedirect,
			},
		},
	}

	engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

	result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
		TenantID:    tenantID,
		EmailDomain: "corp.example.com",
	})

	assert.NoError(t, err)
	assert.True(t, result.Matched)
	assert.Equal(t, models.RoutingActionDeny, result.Action)
	assert.Equal(t, &highPriorityProvider, result.ProviderID)
	assert.Equal(t, 1, result.RulesEvaluated, "should short-circuit on first match")
}

func TestRoutingEvaluationEngine_WildcardConditions(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()

	// Rule with no device_type or network_zone (wildcards)
	ruleRepo := &mockRoutingRuleRepo{
		rules: []models.EnhancedIDPRoutingRule{
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                 uuid.New(),
					TenantID:           tenantID,
					IdentityProviderID: providerID,
					RuleType:           "email_domain",
					RuleValue:          "corp.example.com",
					Priority:           10,
					IsEnabled:          true,
				},
				DeviceType:  nil, // Wildcard
				NetworkZone: nil, // Wildcard
				Action:      models.RoutingActionStepUpMFA,
			},
		},
	}

	engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

	result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
		TenantID:    tenantID,
		EmailDomain: "corp.example.com",
		DeviceType:  "mobile",
		NetworkZone: "external",
	})

	assert.NoError(t, err)
	assert.True(t, result.Matched, "wildcard conditions should match any value")
	assert.Equal(t, models.RoutingActionStepUpMFA, result.Action)
}

func TestRoutingEvaluationEngine_ApplicationContext(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()
	appID := uuid.New()
	otherAppID := uuid.New()

	ruleRepo := &mockRoutingRuleRepo{
		rules: []models.EnhancedIDPRoutingRule{
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                 uuid.New(),
					TenantID:           tenantID,
					IdentityProviderID: providerID,
					RuleType:           "email_domain",
					RuleValue:          "corp.example.com",
					Priority:           10,
					IsEnabled:          true,
				},
				ApplicationID: &appID,
				Action:        models.RoutingActionRedirect,
			},
		},
	}

	engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

	// Matching application
	t.Run("matching application", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:      tenantID,
			EmailDomain:   "corp.example.com",
			ApplicationID: &appID,
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)
	})

	// Different application
	t.Run("different application", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:      tenantID,
			EmailDomain:   "corp.example.com",
			ApplicationID: &otherAppID,
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})

	// No application context in request (rule requires specific app)
	t.Run("no application in request", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:    tenantID,
			EmailDomain: "corp.example.com",
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})
}

func TestRoutingEvaluationEngine_NetworkZoneResolution(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()
	corporate := "corporate"

	zoneRepo := &mockNetworkZoneRepo{
		zones: []models.NetworkZone{
			{
				ID:         uuid.New(),
				TenantID:   tenantID,
				Name:       "Office Network",
				ZoneType:   "corporate",
				CIDRRanges: []string{"10.0.0.0/8", "192.168.1.0/24"},
				IsEnabled:  true,
			},
			{
				ID:         uuid.New(),
				TenantID:   tenantID,
				Name:       "VPN",
				ZoneType:   "vpn",
				CIDRRanges: []string{"172.16.0.0/12"},
				IsEnabled:  true,
			},
		},
	}

	ruleRepo := &mockRoutingRuleRepo{
		rules: []models.EnhancedIDPRoutingRule{
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                 uuid.New(),
					TenantID:           tenantID,
					IdentityProviderID: providerID,
					RuleType:           "email_domain",
					RuleValue:          "corp.example.com",
					Priority:           10,
					IsEnabled:          true,
				},
				NetworkZone: &corporate,
				Action:      models.RoutingActionAllow,
			},
		},
	}

	engine := NewRoutingEvaluationEngine(ruleRepo, zoneRepo, nil)

	// Corporate IP should match corporate zone
	t.Run("corporate IP", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:    tenantID,
			EmailDomain: "corp.example.com",
			ClientIP:    "10.1.2.3",
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)
	})

	// External IP should not match corporate zone
	t.Run("external IP", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:    tenantID,
			EmailDomain: "corp.example.com",
			ClientIP:    "203.0.113.50",
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})
}

func TestClassifyDevice(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		expected  string
	}{
		{
			name:      "Chrome on Windows desktop",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			expected:  "desktop",
		},
		{
			name:      "Safari on iPhone",
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			expected:  "mobile",
		},
		{
			name:      "Safari on iPad",
			userAgent: "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			expected:  "tablet",
		},
		{
			name:      "Chrome on Android phone",
			userAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
			expected:  "mobile",
		},
		{
			name:      "Chrome on Android tablet",
			userAgent: "Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Safari/537.36",
			expected:  "tablet",
		},
		{
			name:      "Firefox on macOS",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
			expected:  "desktop",
		},
		{
			name:      "Unknown user agent",
			userAgent: "some-api-client/1.0",
			expected:  "unknown",
		},
		{
			name:      "Empty user agent",
			userAgent: "",
			expected:  "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyDevice(tt.userAgent)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNetworkZone_ContainsIP(t *testing.T) {
	zone := &models.NetworkZone{
		CIDRRanges: []string{"10.0.0.0/8", "192.168.1.0/24"},
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.1.2.3", true},
		{"10.255.255.255", true},
		{"192.168.1.100", true},
		{"192.168.2.1", false},
		{"203.0.113.50", false},
		{"invalid-ip", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			assert.Equal(t, tt.expected, zone.ContainsIP(tt.ip))
		})
	}
}

// =====================================================================
// Risk-Based Routing Tests (migration 128)
// =====================================================================

func TestMatchesRiskLevel(t *testing.T) {
	tests := []struct {
		name     string
		required string
		actual   string
		expected bool
	}{
		// Exact matches
		{name: "low matches low", required: "low", actual: "low", expected: true},
		{name: "medium matches medium", required: "medium", actual: "medium", expected: true},
		{name: "high matches high", required: "high", actual: "high", expected: true},
		{name: "critical matches critical", required: "critical", actual: "critical", expected: true},

		// Higher-than-threshold (should match)
		{name: "required low, actual medium", required: "low", actual: "medium", expected: true},
		{name: "required low, actual high", required: "low", actual: "high", expected: true},
		{name: "required low, actual critical", required: "low", actual: "critical", expected: true},
		{name: "required medium, actual high", required: "medium", actual: "high", expected: true},
		{name: "required medium, actual critical", required: "medium", actual: "critical", expected: true},
		{name: "required high, actual critical", required: "high", actual: "critical", expected: true},

		// Lower-than-threshold (should NOT match)
		{name: "required medium, actual low", required: "medium", actual: "low", expected: false},
		{name: "required high, actual low", required: "high", actual: "low", expected: false},
		{name: "required high, actual medium", required: "high", actual: "medium", expected: false},
		{name: "required critical, actual low", required: "critical", actual: "low", expected: false},
		{name: "required critical, actual medium", required: "critical", actual: "medium", expected: false},
		{name: "required critical, actual high", required: "critical", actual: "high", expected: false},

		// Empty/unknown actual level (fail-closed)
		{name: "empty actual level", required: "low", actual: "", expected: false},
		{name: "unknown actual level", required: "low", actual: "unknown_level", expected: false},
		{name: "unknown required level", required: "unknown_level", actual: "high", expected: false},

		// Case insensitivity
		{name: "case insensitive required", required: "MEDIUM", actual: "high", expected: true},
		{name: "case insensitive actual", required: "medium", actual: "HIGH", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesRiskLevel(tt.required, tt.actual)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRoutingEvaluationEngine_RiskBasedRouting(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()
	medium := "medium"
	high := "high"

	t.Run("sign-in risk matches when actual risk meets threshold", func(t *testing.T) {
		ruleRepo := &mockRoutingRuleRepo{
			rules: []models.EnhancedIDPRoutingRule{
				{
					IDPRoutingRule: models.IDPRoutingRule{
						ID:                 uuid.New(),
						TenantID:           tenantID,
						IdentityProviderID: providerID,
						RuleType:           "email_domain",
						RuleValue:          "corp.example.com",
						Priority:           10,
						IsEnabled:          true,
					},
					SignInRiskLevel: &medium,
					Action:          models.RoutingActionStepUpMFA,
				},
			},
		}

		engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

		// High risk exceeds medium threshold
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			SignInRiskLevel: "high",
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)
		assert.Equal(t, models.RoutingActionStepUpMFA, result.Action)
	})

	t.Run("sign-in risk does not match when actual risk below threshold", func(t *testing.T) {
		ruleRepo := &mockRoutingRuleRepo{
			rules: []models.EnhancedIDPRoutingRule{
				{
					IDPRoutingRule: models.IDPRoutingRule{
						ID:                 uuid.New(),
						TenantID:           tenantID,
						IdentityProviderID: providerID,
						RuleType:           "email_domain",
						RuleValue:          "corp.example.com",
						Priority:           10,
						IsEnabled:          true,
					},
					SignInRiskLevel: &high,
					Action:          models.RoutingActionDeny,
				},
			},
		}

		engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

		// Low risk is below high threshold
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			SignInRiskLevel: "low",
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})

	t.Run("user risk level matching", func(t *testing.T) {
		ruleRepo := &mockRoutingRuleRepo{
			rules: []models.EnhancedIDPRoutingRule{
				{
					IDPRoutingRule: models.IDPRoutingRule{
						ID:                 uuid.New(),
						TenantID:           tenantID,
						IdentityProviderID: providerID,
						RuleType:           "email_domain",
						RuleValue:          "corp.example.com",
						Priority:           10,
						IsEnabled:          true,
					},
					UserRiskLevel: &high,
					Action:        models.RoutingActionDeny,
				},
			},
		}

		engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

		// Critical exceeds high threshold
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:      tenantID,
			EmailDomain:   "corp.example.com",
			UserRiskLevel: "critical",
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)
		assert.Equal(t, models.RoutingActionDeny, result.Action)

		// Medium is below high threshold
		result, err = engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:      tenantID,
			EmailDomain:   "corp.example.com",
			UserRiskLevel: "medium",
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})

	t.Run("NULL risk level is wildcard", func(t *testing.T) {
		ruleRepo := &mockRoutingRuleRepo{
			rules: []models.EnhancedIDPRoutingRule{
				{
					IDPRoutingRule: models.IDPRoutingRule{
						ID:                 uuid.New(),
						TenantID:           tenantID,
						IdentityProviderID: providerID,
						RuleType:           "email_domain",
						RuleValue:          "corp.example.com",
						Priority:           10,
						IsEnabled:          true,
					},
					SignInRiskLevel: nil, // Wildcard
					UserRiskLevel:   nil, // Wildcard
					Action:          models.RoutingActionRedirect,
				},
			},
		}

		engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

		// Should match regardless of risk levels
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			SignInRiskLevel: "critical",
			UserRiskLevel:   "high",
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)

		// Should also match with no risk context
		result, err = engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:    tenantID,
			EmailDomain: "corp.example.com",
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)
	})

	t.Run("risk rule does not match when risk context is empty (fail-closed)", func(t *testing.T) {
		ruleRepo := &mockRoutingRuleRepo{
			rules: []models.EnhancedIDPRoutingRule{
				{
					IDPRoutingRule: models.IDPRoutingRule{
						ID:                 uuid.New(),
						TenantID:           tenantID,
						IdentityProviderID: providerID,
						RuleType:           "email_domain",
						RuleValue:          "corp.example.com",
						Priority:           10,
						IsEnabled:          true,
					},
					SignInRiskLevel: &medium,
					Action:          models.RoutingActionStepUpMFA,
				},
			},
		}

		engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

		// No risk context provided -- risk rule should NOT match (fail-closed)
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:    tenantID,
			EmailDomain: "corp.example.com",
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})

	t.Run("combined sign-in and user risk", func(t *testing.T) {
		ruleRepo := &mockRoutingRuleRepo{
			rules: []models.EnhancedIDPRoutingRule{
				{
					IDPRoutingRule: models.IDPRoutingRule{
						ID:                 uuid.New(),
						TenantID:           tenantID,
						IdentityProviderID: providerID,
						RuleType:           "email_domain",
						RuleValue:          "corp.example.com",
						Priority:           10,
						IsEnabled:          true,
					},
					SignInRiskLevel: &medium,
					UserRiskLevel:   &high,
					Action:          models.RoutingActionDeny,
				},
			},
		}

		engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

		// Both thresholds met
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			SignInRiskLevel: "high",
			UserRiskLevel:   "critical",
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)

		// Sign-in risk met but user risk not
		result, err = engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			SignInRiskLevel: "critical",
			UserRiskLevel:   "medium", // Below 'high' threshold
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})
}

// =====================================================================
// Time-Based Routing Tests (migration 128)
// =====================================================================

func TestMatchesTimeWindow(t *testing.T) {
	utc := testTimezoneUTC

	tests := []struct {
		name     string
		start    string
		end      string
		tz       *string
		evalTime time.Time
		expected bool
	}{
		// Normal range (same-day window)
		{
			name:     "within business hours",
			start:    "09:00:00",
			end:      "17:00:00",
			tz:       &utc,
			evalTime: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC), // Tuesday 12:00 UTC
			expected: true,
		},
		{
			name:     "at start of window (inclusive)",
			start:    "09:00:00",
			end:      "17:00:00",
			tz:       &utc,
			evalTime: time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC),
			expected: true,
		},
		{
			name:     "at end of window (exclusive)",
			start:    "09:00:00",
			end:      "17:00:00",
			tz:       &utc,
			evalTime: time.Date(2026, 3, 4, 17, 0, 0, 0, time.UTC),
			expected: false,
		},
		{
			name:     "before business hours",
			start:    "09:00:00",
			end:      "17:00:00",
			tz:       &utc,
			evalTime: time.Date(2026, 3, 4, 7, 30, 0, 0, time.UTC),
			expected: false,
		},
		{
			name:     "after business hours",
			start:    "09:00:00",
			end:      "17:00:00",
			tz:       &utc,
			evalTime: time.Date(2026, 3, 4, 20, 0, 0, 0, time.UTC),
			expected: false,
		},

		// Overnight range
		{
			name:     "overnight range: within late evening",
			start:    "22:00:00",
			end:      "06:00:00",
			tz:       &utc,
			evalTime: time.Date(2026, 3, 4, 23, 30, 0, 0, time.UTC),
			expected: true,
		},
		{
			name:     "overnight range: within early morning",
			start:    "22:00:00",
			end:      "06:00:00",
			tz:       &utc,
			evalTime: time.Date(2026, 3, 5, 3, 0, 0, 0, time.UTC),
			expected: true,
		},
		{
			name:     "overnight range: outside (daytime)",
			start:    "22:00:00",
			end:      "06:00:00",
			tz:       &utc,
			evalTime: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC),
			expected: false,
		},
		{
			name:     "overnight range: at start (inclusive)",
			start:    "22:00:00",
			end:      "06:00:00",
			tz:       &utc,
			evalTime: time.Date(2026, 3, 4, 22, 0, 0, 0, time.UTC),
			expected: true,
		},
		{
			name:     "overnight range: at end (exclusive)",
			start:    "22:00:00",
			end:      "06:00:00",
			tz:       &utc,
			evalTime: time.Date(2026, 3, 5, 6, 0, 0, 0, time.UTC),
			expected: false,
		},

		// HH:MM format (without seconds)
		{
			name:     "HH:MM format within range",
			start:    "09:00",
			end:      "17:00",
			tz:       &utc,
			evalTime: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesTimeWindow(tt.start, tt.end, tt.tz, tt.evalTime)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchesTimeWindow_Timezone(t *testing.T) {
	istanbul := "Europe/Istanbul" // UTC+3

	t.Run("timezone shifts evaluation", func(t *testing.T) {
		// Rule: 09:00-17:00 Istanbul time
		// Eval: 08:00 UTC = 11:00 Istanbul -> within range
		result := matchesTimeWindow("09:00:00", "17:00:00", &istanbul,
			time.Date(2026, 3, 4, 8, 0, 0, 0, time.UTC))
		assert.True(t, result)
	})

	t.Run("timezone makes time outside range", func(t *testing.T) {
		// Rule: 09:00-17:00 Istanbul time
		// Eval: 05:00 UTC = 08:00 Istanbul -> before range
		result := matchesTimeWindow("09:00:00", "17:00:00", &istanbul,
			time.Date(2026, 3, 4, 5, 0, 0, 0, time.UTC))
		assert.False(t, result)
	})

	t.Run("invalid timezone fails closed", func(t *testing.T) {
		badTz := "Invalid/Timezone"
		result := matchesTimeWindow("09:00:00", "17:00:00", &badTz,
			time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC))
		assert.False(t, result)
	})

	t.Run("nil timezone defaults to UTC", func(t *testing.T) {
		result := matchesTimeWindow("09:00:00", "17:00:00", nil,
			time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC))
		assert.True(t, result)
	})
}

func TestMatchesDayOfWeek(t *testing.T) {
	utc := testTimezoneUTC

	tests := []struct {
		name     string
		days     []int64
		tz       *string
		evalTime time.Time
		expected bool
	}{
		{
			name:     "Monday matches [Monday]",
			days:     []int64{1}, // Monday
			tz:       &utc,
			evalTime: time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC), // Monday
			expected: true,
		},
		{
			name:     "Tuesday does not match [Monday]",
			days:     []int64{1}, // Monday
			tz:       &utc,
			evalTime: time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC), // Tuesday
			expected: false,
		},
		{
			name:     "weekday rule matches Wednesday",
			days:     []int64{1, 2, 3, 4, 5}, // Mon-Fri
			tz:       &utc,
			evalTime: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC), // Wednesday
			expected: true,
		},
		{
			name:     "weekday rule does not match Saturday",
			days:     []int64{1, 2, 3, 4, 5}, // Mon-Fri
			tz:       &utc,
			evalTime: time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC), // Saturday
			expected: false,
		},
		{
			name:     "weekend rule matches Sunday",
			days:     []int64{0, 6}, // Sunday, Saturday
			tz:       &utc,
			evalTime: time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC), // Sunday
			expected: true,
		},
		{
			name:     "empty days slice (wildcard)",
			days:     []int64{},
			tz:       &utc,
			evalTime: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC),
			expected: false, // Empty is treated as no match (engine checks len>0 before calling)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesDayOfWeek(tt.days, tt.tz, tt.evalTime)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchesDayOfWeek_Timezone(t *testing.T) {
	t.Run("timezone can shift the day", func(t *testing.T) {
		// It's Monday 23:30 UTC = Tuesday 02:30 in Istanbul (UTC+3)
		istanbul := "Europe/Istanbul"
		evalTime := time.Date(2026, 3, 2, 23, 30, 0, 0, time.UTC) // Monday UTC

		// Rule says Tuesday (2) in Istanbul time -> should match
		result := matchesDayOfWeek([]int64{2}, &istanbul, evalTime)
		assert.True(t, result, "should be Tuesday in Istanbul timezone")

		// Rule says Monday (1) in Istanbul time -> should NOT match
		result = matchesDayOfWeek([]int64{1}, &istanbul, evalTime)
		assert.False(t, result, "should no longer be Monday in Istanbul timezone")
	})
}

func TestRoutingEvaluationEngine_TimeBasedRouting(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()
	utc := testTimezoneUTC
	businessStart := "09:00:00"
	businessEnd := "17:00:00"

	t.Run("rule matches within time window", func(t *testing.T) {
		ruleRepo := &mockRoutingRuleRepo{
			rules: []models.EnhancedIDPRoutingRule{
				{
					IDPRoutingRule: models.IDPRoutingRule{
						ID:                 uuid.New(),
						TenantID:           tenantID,
						IdentityProviderID: providerID,
						RuleType:           "email_domain",
						RuleValue:          "corp.example.com",
						Priority:           10,
						IsEnabled:          true,
					},
					TimeStart: &businessStart,
					TimeEnd:   &businessEnd,
					Timezone:  &utc,
					Action:    models.RoutingActionAllow,
				},
			},
		}

		engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:       tenantID,
			EmailDomain:    "corp.example.com",
			EvaluationTime: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC),
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)
	})

	t.Run("rule does not match outside time window", func(t *testing.T) {
		ruleRepo := &mockRoutingRuleRepo{
			rules: []models.EnhancedIDPRoutingRule{
				{
					IDPRoutingRule: models.IDPRoutingRule{
						ID:                 uuid.New(),
						TenantID:           tenantID,
						IdentityProviderID: providerID,
						RuleType:           "email_domain",
						RuleValue:          "corp.example.com",
						Priority:           10,
						IsEnabled:          true,
					},
					TimeStart: &businessStart,
					TimeEnd:   &businessEnd,
					Timezone:  &utc,
					Action:    models.RoutingActionAllow,
				},
			},
		}

		engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:       tenantID,
			EmailDomain:    "corp.example.com",
			EvaluationTime: time.Date(2026, 3, 4, 20, 0, 0, 0, time.UTC), // 8 PM
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})

	t.Run("day-of-week filter", func(t *testing.T) {
		weekdays := pq.Int64Array{1, 2, 3, 4, 5} // Mon-Fri

		ruleRepo := &mockRoutingRuleRepo{
			rules: []models.EnhancedIDPRoutingRule{
				{
					IDPRoutingRule: models.IDPRoutingRule{
						ID:                 uuid.New(),
						TenantID:           tenantID,
						IdentityProviderID: providerID,
						RuleType:           "email_domain",
						RuleValue:          "corp.example.com",
						Priority:           10,
						IsEnabled:          true,
					},
					DaysOfWeek: weekdays,
					Timezone:   &utc,
					Action:     models.RoutingActionAllow,
				},
			},
		}

		engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

		// Wednesday
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:       tenantID,
			EmailDomain:    "corp.example.com",
			EvaluationTime: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC), // Wednesday
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)

		// Saturday
		result, err = engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:       tenantID,
			EmailDomain:    "corp.example.com",
			EvaluationTime: time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC), // Saturday
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})

	t.Run("NULL time window is wildcard", func(t *testing.T) {
		ruleRepo := &mockRoutingRuleRepo{
			rules: []models.EnhancedIDPRoutingRule{
				{
					IDPRoutingRule: models.IDPRoutingRule{
						ID:                 uuid.New(),
						TenantID:           tenantID,
						IdentityProviderID: providerID,
						RuleType:           "email_domain",
						RuleValue:          "corp.example.com",
						Priority:           10,
						IsEnabled:          true,
					},
					TimeStart:  nil, // Wildcard
					TimeEnd:    nil, // Wildcard
					DaysOfWeek: nil, // Wildcard
					Action:     models.RoutingActionRedirect,
				},
			},
		}

		engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

		// Should match at any time
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:       tenantID,
			EmailDomain:    "corp.example.com",
			EvaluationTime: time.Date(2026, 3, 8, 3, 0, 0, 0, time.UTC), // Sunday 3 AM
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)
	})
}

func TestRoutingEvaluationEngine_OvernightTimeWindow(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()
	utc := testTimezoneUTC
	nightStart := "22:00:00"
	nightEnd := "06:00:00"

	ruleRepo := &mockRoutingRuleRepo{
		rules: []models.EnhancedIDPRoutingRule{
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                 uuid.New(),
					TenantID:           tenantID,
					IdentityProviderID: providerID,
					RuleType:           "email_domain",
					RuleValue:          "corp.example.com",
					Priority:           10,
					IsEnabled:          true,
				},
				TimeStart: &nightStart,
				TimeEnd:   &nightEnd,
				Timezone:  &utc,
				Action:    models.RoutingActionStepUpMFA,
			},
		},
	}

	engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

	// 23:00 UTC - within overnight window
	result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
		TenantID:       tenantID,
		EmailDomain:    "corp.example.com",
		EvaluationTime: time.Date(2026, 3, 4, 23, 0, 0, 0, time.UTC),
	})
	assert.NoError(t, err)
	assert.True(t, result.Matched, "23:00 should be within overnight window")

	// 03:00 UTC - within overnight window (early morning)
	result, err = engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
		TenantID:       tenantID,
		EmailDomain:    "corp.example.com",
		EvaluationTime: time.Date(2026, 3, 5, 3, 0, 0, 0, time.UTC),
	})
	assert.NoError(t, err)
	assert.True(t, result.Matched, "03:00 should be within overnight window")

	// 12:00 UTC - outside overnight window
	result, err = engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
		TenantID:       tenantID,
		EmailDomain:    "corp.example.com",
		EvaluationTime: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC),
	})
	assert.NoError(t, err)
	assert.False(t, result.Matched, "12:00 should be outside overnight window")
}

// =====================================================================
// Combined Tests: Risk + Time + Existing Criteria
// =====================================================================

func TestRoutingEvaluationEngine_CombinedRiskTimeDeviceNetwork(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()
	mobile := "mobile"
	external := "external"
	medium := "medium"
	utc := testTimezoneUTC
	nightStart := "22:00:00"
	nightEnd := "06:00:00"
	weekdays := pq.Int64Array{1, 2, 3, 4, 5} // Mon-Fri

	// Rule: Block mobile + external + medium+ risk + off-hours + weekdays
	// This simulates: "Block risky mobile access from external networks during off-hours on weekdays"
	ruleRepo := &mockRoutingRuleRepo{
		rules: []models.EnhancedIDPRoutingRule{
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                 uuid.New(),
					TenantID:           tenantID,
					IdentityProviderID: providerID,
					RuleType:           "email_domain",
					RuleValue:          "corp.example.com",
					Priority:           1,
					IsEnabled:          true,
				},
				DeviceType:      &mobile,
				NetworkZone:     &external,
				SignInRiskLevel: &medium,
				TimeStart:       &nightStart,
				TimeEnd:         &nightEnd,
				DaysOfWeek:      weekdays,
				Timezone:        &utc,
				Action:          models.RoutingActionDeny,
			},
		},
	}

	engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

	t.Run("all criteria match", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			DeviceType:      "mobile",
			NetworkZone:     "external",
			SignInRiskLevel: "high",
			EvaluationTime:  time.Date(2026, 3, 3, 23, 30, 0, 0, time.UTC), // Tuesday 23:30
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)
		assert.Equal(t, models.RoutingActionDeny, result.Action)
	})

	t.Run("device type mismatch breaks combined rule", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			DeviceType:      "desktop", // Rule requires mobile
			NetworkZone:     "external",
			SignInRiskLevel: "high",
			EvaluationTime:  time.Date(2026, 3, 3, 23, 30, 0, 0, time.UTC),
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})

	t.Run("risk level too low breaks combined rule", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			DeviceType:      "mobile",
			NetworkZone:     "external",
			SignInRiskLevel: "low", // Below medium threshold
			EvaluationTime:  time.Date(2026, 3, 3, 23, 30, 0, 0, time.UTC),
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})

	t.Run("outside time window breaks combined rule", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			DeviceType:      "mobile",
			NetworkZone:     "external",
			SignInRiskLevel: "high",
			EvaluationTime:  time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC), // Wednesday noon
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})

	t.Run("weekend breaks combined rule (weekdays only)", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			DeviceType:      "mobile",
			NetworkZone:     "external",
			SignInRiskLevel: "high",
			EvaluationTime:  time.Date(2026, 3, 7, 23, 30, 0, 0, time.UTC), // Saturday 23:30
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})

	t.Run("email domain mismatch breaks combined rule", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "other.example.com", // Wrong domain
			DeviceType:      "mobile",
			NetworkZone:     "external",
			SignInRiskLevel: "high",
			EvaluationTime:  time.Date(2026, 3, 3, 23, 30, 0, 0, time.UTC),
		})
		assert.NoError(t, err)
		assert.False(t, result.Matched)
	})
}

func TestRoutingEvaluationEngine_MultiRuleWithRiskPriority(t *testing.T) {
	tenantID := uuid.New()
	mfaProvider := uuid.New()
	denyProvider := uuid.New()
	allowProvider := uuid.New()
	high := "high"
	critical := "critical"

	// Three rules with different risk levels and priorities:
	// 1. Critical risk -> deny (highest priority)
	// 2. High risk -> step-up MFA
	// 3. Any risk -> allow (catch-all)
	ruleRepo := &mockRoutingRuleRepo{
		rules: []models.EnhancedIDPRoutingRule{
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                 uuid.New(),
					TenantID:           tenantID,
					IdentityProviderID: denyProvider,
					RuleType:           "email_domain",
					RuleValue:          "corp.example.com",
					Priority:           1,
					IsEnabled:          true,
				},
				SignInRiskLevel: &critical,
				Action:          models.RoutingActionDeny,
			},
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                 uuid.New(),
					TenantID:           tenantID,
					IdentityProviderID: mfaProvider,
					RuleType:           "email_domain",
					RuleValue:          "corp.example.com",
					Priority:           10,
					IsEnabled:          true,
				},
				SignInRiskLevel: &high,
				Action:          models.RoutingActionStepUpMFA,
			},
			{
				IDPRoutingRule: models.IDPRoutingRule{
					ID:                 uuid.New(),
					TenantID:           tenantID,
					IdentityProviderID: allowProvider,
					RuleType:           "email_domain",
					RuleValue:          "corp.example.com",
					Priority:           100,
					IsEnabled:          true,
				},
				Action: models.RoutingActionAllow, // No risk condition (wildcard)
			},
		},
	}

	engine := NewRoutingEvaluationEngine(ruleRepo, &mockNetworkZoneRepo{}, nil)

	t.Run("critical risk triggers deny", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			SignInRiskLevel: "critical",
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)
		assert.Equal(t, models.RoutingActionDeny, result.Action)
		assert.Equal(t, 1, result.RulesEvaluated)
	})

	t.Run("high risk triggers step-up MFA (skips deny rule)", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			SignInRiskLevel: "high",
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)
		assert.Equal(t, models.RoutingActionStepUpMFA, result.Action)
		assert.Equal(t, 2, result.RulesEvaluated)
	})

	t.Run("low risk falls through to catch-all allow", func(t *testing.T) {
		result, err := engine.Evaluate(context.Background(), &models.RoutingEvaluationContext{
			TenantID:        tenantID,
			EmailDomain:     "corp.example.com",
			SignInRiskLevel: "low",
		})
		assert.NoError(t, err)
		assert.True(t, result.Matched)
		assert.Equal(t, models.RoutingActionAllow, result.Action)
		assert.Equal(t, 3, result.RulesEvaluated)
	})
}

func TestParseTimeOfDay(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		expectErr  bool
		expectHour int
		expectMin  int
		expectSec  int
	}{
		{name: "HH:MM:SS format", input: "09:30:45", expectHour: 9, expectMin: 30, expectSec: 45},
		{name: "HH:MM format", input: "09:30", expectHour: 9, expectMin: 30, expectSec: 0},
		{name: "midnight", input: "00:00:00", expectHour: 0, expectMin: 0, expectSec: 0},
		{name: "end of day", input: "23:59:59", expectHour: 23, expectMin: 59, expectSec: 59},
		{name: "invalid format", input: "9am", expectErr: true},
		{name: "empty string", input: "", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tod, err := parseTimeOfDay(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectHour, tod.hour)
				assert.Equal(t, tt.expectMin, tod.minute)
				assert.Equal(t, tt.expectSec, tod.second)
			}
		})
	}
}
