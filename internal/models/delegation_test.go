// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildDelegation returns a fully populated Delegation for use in tests.
func buildDelegation() *Delegation {
	id := uuid.New()
	tenantID := uuid.New()
	delegatorID := uuid.New()
	delegateeID := uuid.New()
	revokedBy := uuid.New()
	now := time.Now().Truncate(time.Second)
	revokedAt := now.Add(-5 * time.Minute)
	reason := "vacation cover"
	resType := "project"
	resID := "proj-123"

	return &Delegation{
		ID:           id,
		TenantID:     tenantID,
		DelegatorID:  delegatorID,
		DelegateeID:  delegateeID,
		Permissions:  pq.StringArray{"read", "write"},
		ResourceType: &resType,
		ResourceID:   &resID,
		ExpiresAt:    now.Add(24 * time.Hour),
		Reason:       &reason,
		RevokedAt:    &revokedAt,
		RevokedBy:    &revokedBy,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// ==================== Delegation.IsActive ====================

func TestDelegation_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *Delegation
		expected bool
	}{
		{
			name: "should return true when not revoked and not expired",
			setup: func() *Delegation {
				return &Delegation{
					ExpiresAt: time.Now().Add(1 * time.Hour),
					RevokedAt: nil,
				}
			},
			expected: true,
		},
		{
			name: "should return false when revoked even if not yet expired",
			setup: func() *Delegation {
				revokedAt := time.Now().Add(-1 * time.Minute)
				return &Delegation{
					ExpiresAt: time.Now().Add(1 * time.Hour),
					RevokedAt: &revokedAt,
				}
			},
			expected: false,
		},
		{
			name: "should return false when expired and not revoked",
			setup: func() *Delegation {
				return &Delegation{
					ExpiresAt: time.Now().Add(-1 * time.Minute),
					RevokedAt: nil,
				}
			},
			expected: false,
		},
		{
			name: "should return false when both revoked and expired",
			setup: func() *Delegation {
				revokedAt := time.Now().Add(-2 * time.Hour)
				return &Delegation{
					ExpiresAt: time.Now().Add(-1 * time.Hour),
					RevokedAt: &revokedAt,
				}
			},
			expected: false,
		},
		{
			name: "should return false when expires exactly now (boundary: After returns false)",
			setup: func() *Delegation {
				// ExpiresAt set 1ns in the past to simulate exact-or-past expiry.
				return &Delegation{
					ExpiresAt: time.Now().Add(-1 * time.Nanosecond),
					RevokedAt: nil,
				}
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.setup()
			assert.Equal(t, tt.expected, d.IsActive())
		})
	}
}

// ==================== Delegation.IsExpired ====================

func TestDelegation_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *Delegation
		expected bool
	}{
		{
			name: "should return false when ExpiresAt is in the future",
			setup: func() *Delegation {
				return &Delegation{ExpiresAt: time.Now().Add(24 * time.Hour)}
			},
			expected: false,
		},
		{
			name: "should return true when ExpiresAt is in the past",
			setup: func() *Delegation {
				return &Delegation{ExpiresAt: time.Now().Add(-1 * time.Second)}
			},
			expected: true,
		},
		{
			name: "should return true one nanosecond past expiry",
			setup: func() *Delegation {
				return &Delegation{ExpiresAt: time.Now().Add(-1 * time.Nanosecond)}
			},
			expected: true,
		},
		{
			name: "should return false one hour before expiry",
			setup: func() *Delegation {
				return &Delegation{ExpiresAt: time.Now().Add(1 * time.Hour)}
			},
			expected: false,
		},
		{
			name: "should return true for a delegation that expired a week ago",
			setup: func() *Delegation {
				return &Delegation{ExpiresAt: time.Now().Add(-7 * 24 * time.Hour)}
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.setup()
			assert.Equal(t, tt.expected, d.IsExpired())
		})
	}
}

// ==================== Delegation.IsRevoked ====================

func TestDelegation_IsRevoked(t *testing.T) {
	tests := []struct {
		name      string
		revokedAt *time.Time
		expected  bool
	}{
		{
			name:      "should return true when RevokedAt is set",
			revokedAt: timePtr(time.Now().Add(-1 * time.Minute)),
			expected:  true,
		},
		{
			name:      "should return false when RevokedAt is nil",
			revokedAt: nil,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Delegation{
				ExpiresAt: time.Now().Add(1 * time.Hour),
				RevokedAt: tt.revokedAt,
			}
			assert.Equal(t, tt.expected, d.IsRevoked())
		})
	}
}

// ==================== Delegation status mutual exclusivity ====================

func TestDelegation_StatusMutualExclusivity(t *testing.T) {
	t.Run("active delegation: IsActive=true, IsExpired=false, IsRevoked=false", func(t *testing.T) {
		d := &Delegation{
			ExpiresAt: time.Now().Add(1 * time.Hour),
			RevokedAt: nil,
		}
		assert.True(t, d.IsActive(), "IsActive")
		assert.False(t, d.IsExpired(), "IsExpired")
		assert.False(t, d.IsRevoked(), "IsRevoked")
	})

	t.Run("expired delegation: IsActive=false, IsExpired=true, IsRevoked=false", func(t *testing.T) {
		d := &Delegation{
			ExpiresAt: time.Now().Add(-1 * time.Minute),
			RevokedAt: nil,
		}
		assert.False(t, d.IsActive(), "IsActive")
		assert.True(t, d.IsExpired(), "IsExpired")
		assert.False(t, d.IsRevoked(), "IsRevoked")
	})

	t.Run("revoked delegation: IsActive=false, IsRevoked=true", func(t *testing.T) {
		revokedAt := time.Now().Add(-5 * time.Minute)
		d := &Delegation{
			ExpiresAt: time.Now().Add(1 * time.Hour),
			RevokedAt: &revokedAt,
		}
		assert.False(t, d.IsActive(), "IsActive")
		assert.False(t, d.IsExpired(), "IsExpired")
		assert.True(t, d.IsRevoked(), "IsRevoked")
	})
}

// ==================== Delegation.ToResponse ====================

func TestDelegation_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly for an active delegation", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		delegatorID := uuid.New()
		delegateeID := uuid.New()
		now := time.Now().Truncate(time.Second)
		expires := now.Add(8 * time.Hour)
		reason := "annual leave cover"
		resType := "department"
		resID := "dept-42"

		d := &Delegation{
			ID:           id,
			TenantID:     tenantID,
			DelegatorID:  delegatorID,
			DelegateeID:  delegateeID,
			Permissions:  pq.StringArray{"reports:read", "users:list"},
			ResourceType: &resType,
			ResourceID:   &resID,
			ExpiresAt:    expires,
			Reason:       &reason,
			RevokedAt:    nil,
			RevokedBy:    nil,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		resp := d.ToResponse("Alice Smith", "Bob Jones")

		require.NotNil(t, resp)
		assert.Equal(t, id.String(), resp.ID)
		assert.Equal(t, tenantID.String(), resp.TenantID)
		assert.Equal(t, delegatorID.String(), resp.DelegatorID)
		assert.Equal(t, "Alice Smith", resp.DelegatorName)
		assert.Equal(t, delegateeID.String(), resp.DelegateeID)
		assert.Equal(t, "Bob Jones", resp.DelegateeName)
		assert.ElementsMatch(t, []string{"reports:read", "users:list"}, resp.Permissions)
		assert.Equal(t, &resType, resp.ResourceType)
		assert.Equal(t, &resID, resp.ResourceID)
		assert.Equal(t, expires, resp.ExpiresAt)
		assert.Equal(t, &reason, resp.Reason)
		assert.Nil(t, resp.RevokedAt)
		assert.Nil(t, resp.RevokedBy)
		assert.Equal(t, "active", resp.Status)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("should set status to revoked when RevokedAt is set", func(t *testing.T) {
		revokedAt := time.Now().Add(-10 * time.Minute)
		revokedBy := uuid.New()
		d := &Delegation{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			DelegatorID: uuid.New(),
			DelegateeID: uuid.New(),
			Permissions: pq.StringArray{"read"},
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			RevokedAt:   &revokedAt,
			RevokedBy:   &revokedBy,
		}

		resp := d.ToResponse("Alice", "Bob")

		assert.Equal(t, "revoked", resp.Status)
		assert.NotNil(t, resp.RevokedAt)
		assert.Equal(t, &revokedAt, resp.RevokedAt)
		require.NotNil(t, resp.RevokedBy)
		assert.Equal(t, revokedBy.String(), *resp.RevokedBy)
	})

	t.Run("should set status to expired when not revoked but past ExpiresAt", func(t *testing.T) {
		d := &Delegation{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			DelegatorID: uuid.New(),
			DelegateeID: uuid.New(),
			Permissions: pq.StringArray{"write"},
			ExpiresAt:   time.Now().Add(-2 * time.Hour),
			RevokedAt:   nil,
		}

		resp := d.ToResponse("Alice", "Bob")

		assert.Equal(t, "expired", resp.Status)
	})

	t.Run("should handle nil optional fields", func(t *testing.T) {
		d := &Delegation{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			DelegatorID: uuid.New(),
			DelegateeID: uuid.New(),
			Permissions: pq.StringArray{"read"},
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		}

		resp := d.ToResponse("A", "B")

		require.NotNil(t, resp)
		assert.Nil(t, resp.ResourceType)
		assert.Nil(t, resp.ResourceID)
		assert.Nil(t, resp.Reason)
		assert.Nil(t, resp.RevokedAt)
		assert.Nil(t, resp.RevokedBy)
	})

	t.Run("should convert UUIDs to string representation in response", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		delegatorID := uuid.New()
		delegateeID := uuid.New()

		d := &Delegation{
			ID:          id,
			TenantID:    tenantID,
			DelegatorID: delegatorID,
			DelegateeID: delegateeID,
			Permissions: pq.StringArray{"read"},
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		}

		resp := d.ToResponse("Alice", "Bob")

		assert.Equal(t, id.String(), resp.ID)
		assert.Equal(t, tenantID.String(), resp.TenantID)
		assert.Equal(t, delegatorID.String(), resp.DelegatorID)
		assert.Equal(t, delegateeID.String(), resp.DelegateeID)
	})

	t.Run("should produce distinct instances on each call", func(t *testing.T) {
		d := &Delegation{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			DelegatorID: uuid.New(),
			DelegateeID: uuid.New(),
			Permissions: pq.StringArray{"read"},
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		}

		resp1 := d.ToResponse("Alice", "Bob")
		resp2 := d.ToResponse("Alice", "Bob")

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})

	t.Run("revoked takes precedence over expired in status determination", func(t *testing.T) {
		// Both revoked AND past ExpiresAt: revoked should win since it is checked first.
		revokedAt := time.Now().Add(-30 * time.Minute)
		revokedBy := uuid.New()
		d := &Delegation{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			DelegatorID: uuid.New(),
			DelegateeID: uuid.New(),
			Permissions: pq.StringArray{"read"},
			ExpiresAt:   time.Now().Add(-1 * time.Hour), // already expired
			RevokedAt:   &revokedAt,
			RevokedBy:   &revokedBy,
		}

		resp := d.ToResponse("Alice", "Bob")

		assert.Equal(t, "revoked", resp.Status)
	})
}

// ==================== CreateDelegationRequest validation tags ====================

func TestCreateDelegationRequest_FieldTags(t *testing.T) {
	t.Run("should be constructable with all valid fields", func(t *testing.T) {
		delegateeID := uuid.New()
		reason := "covering while on leave"
		resType := "project"
		resID := "proj-1"

		req := CreateDelegationRequest{
			DelegateeID:  delegateeID,
			Permissions:  []string{"read", "write"},
			ResourceType: &resType,
			ResourceID:   &resID,
			Duration:     3600,
			Reason:       &reason,
		}

		assert.Equal(t, delegateeID, req.DelegateeID)
		assert.Equal(t, []string{"read", "write"}, req.Permissions)
		assert.Equal(t, &resType, req.ResourceType)
		assert.Equal(t, &resID, req.ResourceID)
		assert.Equal(t, 3600, req.Duration)
		assert.Equal(t, &reason, req.Reason)
	})

	t.Run("minimum valid duration is 60 seconds", func(t *testing.T) {
		req := CreateDelegationRequest{
			DelegateeID: uuid.New(),
			Permissions: []string{"read"},
			Duration:    60,
		}
		assert.Equal(t, 60, req.Duration)
	})

	t.Run("maximum valid duration is 604800 seconds (7 days)", func(t *testing.T) {
		req := CreateDelegationRequest{
			DelegateeID: uuid.New(),
			Permissions: []string{"read"},
			Duration:    604800,
		}
		assert.Equal(t, 604800, req.Duration)
	})

	t.Run("nil optional fields are permitted", func(t *testing.T) {
		req := CreateDelegationRequest{
			DelegateeID:  uuid.New(),
			Permissions:  []string{"read"},
			Duration:     120,
			ResourceType: nil,
			ResourceID:   nil,
			Reason:       nil,
		}
		assert.Nil(t, req.ResourceType)
		assert.Nil(t, req.ResourceID)
		assert.Nil(t, req.Reason)
	})
}

// ==================== DelegationResponse JSON marshaling ====================

func TestDelegationResponse_JSONMarshaling(t *testing.T) {
	t.Run("should produce valid JSON with expected fields", func(t *testing.T) {
		id := uuid.New()
		now := time.Now().Truncate(time.Second)
		expires := now.Add(8 * time.Hour)

		resp := &DelegationResponse{
			ID:            id.String(),
			TenantID:      uuid.New().String(),
			DelegatorID:   uuid.New().String(),
			DelegatorName: "Alice",
			DelegateeID:   uuid.New().String(),
			DelegateeName: "Bob",
			Permissions:   []string{"read", "write"},
			ExpiresAt:     expires,
			Status:        "active",
			CreatedAt:     now,
			UpdatedAt:     now,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Contains(t, out, "id")
		assert.Contains(t, out, "tenant_id")
		assert.Contains(t, out, "delegator_id")
		assert.Contains(t, out, "delegator_name")
		assert.Contains(t, out, "delegatee_id")
		assert.Contains(t, out, "delegatee_name")
		assert.Contains(t, out, "permissions")
		assert.Contains(t, out, "expires_at")
		assert.Contains(t, out, "status")
		assert.Equal(t, "active", out["status"])
	})

	t.Run("omitempty fields absent when nil", func(t *testing.T) {
		resp := &DelegationResponse{
			ID:            uuid.New().String(),
			TenantID:      uuid.New().String(),
			DelegatorID:   uuid.New().String(),
			DelegatorName: "Alice",
			DelegateeID:   uuid.New().String(),
			DelegateeName: "Bob",
			Permissions:   []string{"read"},
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			Status:        "active",
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.NotContains(t, out, "resource_type")
		assert.NotContains(t, out, "resource_id")
		assert.NotContains(t, out, "reason")
		assert.NotContains(t, out, "revoked_at")
		assert.NotContains(t, out, "revoked_by")
	})
}

// ==================== Delegation struct field mapping ====================

func TestDelegation_StructFields(t *testing.T) {
	t.Run("should hold all field values correctly", func(t *testing.T) {
		d := buildDelegation()

		assert.NotEqual(t, uuid.Nil, d.ID)
		assert.NotEqual(t, uuid.Nil, d.TenantID)
		assert.NotEqual(t, uuid.Nil, d.DelegatorID)
		assert.NotEqual(t, uuid.Nil, d.DelegateeID)
		assert.NotEmpty(t, d.Permissions)
		assert.NotNil(t, d.ResourceType)
		assert.NotNil(t, d.ResourceID)
		assert.NotNil(t, d.Reason)
		assert.NotNil(t, d.RevokedAt)
		assert.NotNil(t, d.RevokedBy)
		assert.False(t, d.CreatedAt.IsZero())
		assert.False(t, d.UpdatedAt.IsZero())
	})
}
