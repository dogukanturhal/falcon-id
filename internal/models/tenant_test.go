// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== TenantType constants ====================

func TestTenantTypeConstants(t *testing.T) {
	assert.Equal(t, TenantType("customer"), TenantTypeCustomer)
	assert.Equal(t, TenantType("internal"), TenantTypeInternal)
	assert.Equal(t, TenantType("trial"), TenantTypeTrial)
	assert.Equal(t, TenantType("partner"), TenantTypePartner)
	assert.Equal(t, TenantType("demo"), TenantTypeDemo)
}

// ==================== Tenant.IsInternalTenant ====================

func TestTenant_IsInternalTenant(t *testing.T) {
	tests := []struct {
		name     string
		tenant   Tenant
		expected bool
	}{
		{
			name:     "should return true when type is internal",
			tenant:   Tenant{Type: TenantTypeInternal},
			expected: true,
		},
		{
			name:     "should return false when type is customer",
			tenant:   Tenant{Type: TenantTypeCustomer},
			expected: false,
		},
		{
			name:     "should return false when type is trial",
			tenant:   Tenant{Type: TenantTypeTrial},
			expected: false,
		},
		{
			name:     "should return false when type is partner",
			tenant:   Tenant{Type: TenantTypePartner},
			expected: false,
		},
		{
			name:     "should return false when type is demo",
			tenant:   Tenant{Type: TenantTypeDemo},
			expected: false,
		},
		{
			name:     "should return false when type is empty",
			tenant:   Tenant{Type: ""},
			expected: false,
		},
		{
			name:     "should return false for unknown type",
			tenant:   Tenant{Type: "unknown"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.tenant.IsInternalTenant())
		})
	}
}

// TestTenant_IsInternalTenant_PointerReceiver verifies the method works on a pointer receiver.
func TestTenant_IsInternalTenant_PointerReceiver(t *testing.T) {
	t.Run("pointer receiver returns true for internal type", func(t *testing.T) {
		tenant := &Tenant{Type: TenantTypeInternal}
		assert.True(t, tenant.IsInternalTenant())
	})

	t.Run("pointer receiver returns false for non-internal type", func(t *testing.T) {
		tenant := &Tenant{Type: TenantTypeCustomer}
		assert.False(t, tenant.IsInternalTenant())
	})
}

// ==================== Tenant.HasUnlimitedUsers ====================

func TestTenant_HasUnlimitedUsers(t *testing.T) {
	tests := []struct {
		name     string
		tenant   Tenant
		expected bool
	}{
		{
			name:     "should return true when MaxUsers is -1",
			tenant:   Tenant{MaxUsers: -1},
			expected: true,
		},
		{
			name:     "should return false when MaxUsers is 0",
			tenant:   Tenant{MaxUsers: 0},
			expected: false,
		},
		{
			name:     "should return false when MaxUsers is 1",
			tenant:   Tenant{MaxUsers: 1},
			expected: false,
		},
		{
			name:     "should return false when MaxUsers is 100",
			tenant:   Tenant{MaxUsers: 100},
			expected: false,
		},
		{
			name:     "should return false when MaxUsers is a large positive value",
			tenant:   Tenant{MaxUsers: 1_000_000},
			expected: false,
		},
		{
			name:     "should return false when MaxUsers is -2",
			tenant:   Tenant{MaxUsers: -2},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.tenant.HasUnlimitedUsers())
		})
	}
}

// ==================== Tenant.HasUnlimitedStorage ====================

func TestTenant_HasUnlimitedStorage(t *testing.T) {
	tests := []struct {
		name     string
		tenant   Tenant
		expected bool
	}{
		{
			name:     "should return true when MaxStorage is -1",
			tenant:   Tenant{MaxStorage: -1},
			expected: true,
		},
		{
			name:     "should return false when MaxStorage is 0",
			tenant:   Tenant{MaxStorage: 0},
			expected: false,
		},
		{
			name:     "should return false when MaxStorage is 1",
			tenant:   Tenant{MaxStorage: 1},
			expected: false,
		},
		{
			name:     "should return false when MaxStorage is a large positive value (e.g. 10 GB)",
			tenant:   Tenant{MaxStorage: 10 * 1024 * 1024 * 1024},
			expected: false,
		},
		{
			name:     "should return false when MaxStorage is -2",
			tenant:   Tenant{MaxStorage: -2},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.tenant.HasUnlimitedStorage())
		})
	}
}

// ==================== Tenant.IsBillingRequired ====================

func TestTenant_IsBillingRequired(t *testing.T) {
	tests := []struct {
		name     string
		tenant   Tenant
		expected bool
	}{
		// Billing is required for customer tenants that are not billing exempt.
		{
			name: "should return true for customer tenant without billing exemption",
			tenant: Tenant{
				Type:          TenantTypeCustomer,
				BillingExempt: false,
			},
			expected: true,
		},
		// BillingExempt overrides the customer type.
		{
			name: "should return false for customer tenant with billing exemption",
			tenant: Tenant{
				Type:          TenantTypeCustomer,
				BillingExempt: true,
			},
			expected: false,
		},
		// Internal tenants never require billing.
		{
			name: "should return false for internal tenant without billing exemption",
			tenant: Tenant{
				Type:          TenantTypeInternal,
				BillingExempt: false,
			},
			expected: false,
		},
		{
			name: "should return false for internal tenant with billing exemption",
			tenant: Tenant{
				Type:          TenantTypeInternal,
				BillingExempt: true,
			},
			expected: false,
		},
		// Trial tenants.
		{
			name: "should return false for trial tenant without billing exemption",
			tenant: Tenant{
				Type:          TenantTypeTrial,
				BillingExempt: false,
			},
			expected: false,
		},
		// Demo tenants.
		{
			name: "should return false for demo tenant without billing exemption",
			tenant: Tenant{
				Type:          TenantTypeDemo,
				BillingExempt: false,
			},
			expected: false,
		},
		// Partner tenants are not customers so billing is not required.
		{
			name: "should return false for partner tenant without billing exemption",
			tenant: Tenant{
				Type:          TenantTypePartner,
				BillingExempt: false,
			},
			expected: false,
		},
		{
			name: "should return false for partner tenant with billing exemption",
			tenant: Tenant{
				Type:          TenantTypePartner,
				BillingExempt: true,
			},
			expected: false,
		},
		// Zero-value tenant.
		{
			name:     "should return false for zero-value tenant",
			tenant:   Tenant{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.tenant.IsBillingRequired())
		})
	}
}

// ==================== Tenant struct field mapping ====================

func TestTenant_StructFields(t *testing.T) {
	t.Run("should carry all optional pointer fields correctly", func(t *testing.T) {
		id := uuid.New()
		now := time.Now().Truncate(time.Second)
		domain := "acme.example.com"
		billingEmail := "billing@acme.example.com"
		stripeID := "cus_abc123"
		trialEnd := now.Add(14 * 24 * time.Hour)
		suspendedAt := now.Add(-2 * time.Hour)
		cancelledAt := now.Add(-1 * time.Hour)

		tenant := &Tenant{
			ID:               id,
			Name:             "Acme Corp",
			Slug:             "acme-corp",
			DisplayName:      "Acme Corporation",
			Domain:           &domain,
			Status:           "active",
			Type:             TenantTypeCustomer,
			Plan:             "enterprise",
			BillingExempt:    false,
			Settings:         map[string]interface{}{"mfa_required": true},
			Metadata:         map[string]interface{}{"crm_id": "CRM-001"},
			BillingEmail:     &billingEmail,
			StripeCustomerID: &stripeID,
			MaxUsers:         500,
			MaxStorage:       100 * 1024 * 1024 * 1024,
			TrialEndsAt:      &trialEnd,
			CreatedAt:        now,
			UpdatedAt:        now,
			SuspendedAt:      &suspendedAt,
			CancelledAt:      &cancelledAt,
		}

		require.NotNil(t, tenant)
		assert.Equal(t, id, tenant.ID)
		assert.Equal(t, "Acme Corp", tenant.Name)
		assert.Equal(t, "acme-corp", tenant.Slug)
		assert.Equal(t, "Acme Corporation", tenant.DisplayName)
		assert.Equal(t, &domain, tenant.Domain)
		assert.Equal(t, "active", tenant.Status)
		assert.Equal(t, TenantTypeCustomer, tenant.Type)
		assert.Equal(t, "enterprise", tenant.Plan)
		assert.False(t, tenant.BillingExempt)
		assert.Equal(t, map[string]interface{}{"mfa_required": true}, tenant.Settings)
		assert.Equal(t, map[string]interface{}{"crm_id": "CRM-001"}, tenant.Metadata)
		assert.Equal(t, &billingEmail, tenant.BillingEmail)
		assert.Equal(t, &stripeID, tenant.StripeCustomerID)
		assert.Equal(t, 500, tenant.MaxUsers)
		assert.Equal(t, int64(100*1024*1024*1024), tenant.MaxStorage)
		assert.Equal(t, &trialEnd, tenant.TrialEndsAt)
		assert.Equal(t, now, tenant.CreatedAt)
		assert.Equal(t, now, tenant.UpdatedAt)
		assert.Equal(t, &suspendedAt, tenant.SuspendedAt)
		assert.Equal(t, &cancelledAt, tenant.CancelledAt)
	})

	t.Run("should handle nil optional pointer fields", func(t *testing.T) {
		tenant := &Tenant{
			ID:     uuid.New(),
			Name:   "Minimal Tenant",
			Slug:   "minimal",
			Type:   TenantTypeInternal,
			Status: "active",
		}

		assert.Nil(t, tenant.Domain)
		assert.Nil(t, tenant.BillingEmail)
		assert.Nil(t, tenant.StripeCustomerID)
		assert.Nil(t, tenant.TrialEndsAt)
		assert.Nil(t, tenant.SuspendedAt)
		assert.Nil(t, tenant.CancelledAt)
		assert.Nil(t, tenant.Settings)
		assert.Nil(t, tenant.Metadata)
	})
}

// ==================== Unlimited resource sentinel cross-checks ====================

func TestTenant_UnlimitedSentinels(t *testing.T) {
	t.Run("unlimited users sentinel value is -1", func(t *testing.T) {
		tenant := &Tenant{MaxUsers: -1}
		assert.True(t, tenant.HasUnlimitedUsers())

		// Any value other than -1 must NOT be treated as unlimited.
		tenant.MaxUsers = 0
		assert.False(t, tenant.HasUnlimitedUsers())
	})

	t.Run("unlimited storage sentinel value is -1", func(t *testing.T) {
		tenant := &Tenant{MaxStorage: -1}
		assert.True(t, tenant.HasUnlimitedStorage())

		tenant.MaxStorage = 0
		assert.False(t, tenant.HasUnlimitedStorage())
	})

	t.Run("tenant can have both unlimited users and unlimited storage simultaneously", func(t *testing.T) {
		tenant := &Tenant{MaxUsers: -1, MaxStorage: -1}
		assert.True(t, tenant.HasUnlimitedUsers())
		assert.True(t, tenant.HasUnlimitedStorage())
	})
}

// ==================== IsBillingRequired non-customer type exhaustive check ====================

func TestTenant_IsBillingRequired_NonCustomerTypes(t *testing.T) {
	nonCustomerTypes := []TenantType{
		TenantTypeInternal,
		TenantTypeTrial,
		TenantTypePartner,
		TenantTypeDemo,
	}

	for _, tt := range nonCustomerTypes {
		tt := tt // capture range variable
		t.Run(string(tt)+" tenant without billing_exempt is never billing required", func(t *testing.T) {
			tenant := &Tenant{Type: tt, BillingExempt: false}
			assert.False(t, tenant.IsBillingRequired(),
				"type %q should never require billing regardless of BillingExempt", tt)
		})
	}
}
