// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== PolicyEffect constants ====================

func TestPolicyEffectConstants(t *testing.T) {
	assert.Equal(t, PolicyEffect("allow"), PolicyEffectAllow)
	assert.Equal(t, PolicyEffect("deny"), PolicyEffectDeny)
}

func TestPolicyEffectValues_AreDistinct(t *testing.T) {
	assert.NotEqual(t, PolicyEffectAllow, PolicyEffectDeny,
		"allow and deny effects must be distinct")
}

// ==================== Policy struct ====================

func buildPolicy() *Policy {
	id := uuid.New()
	tenantID := uuid.New()
	createdBy := uuid.New()
	updatedBy := uuid.New()
	now := time.Now().Truncate(time.Second)
	conditions := json.RawMessage(`{"subject":{"role":"admin"},"action":["read","write"]}`)
	regoCode := `package authz\ndefault allow = false`

	return &Policy{
		ID:          id,
		TenantID:    &tenantID,
		Name:        "Admin Read-Write Policy",
		Description: "Grants admins full read/write access",
		Effect:      PolicyEffectAllow,
		Priority:    100,
		Conditions:  conditions,
		RegoCode:    regoCode,
		IsGlobal:    false,
		IsActive:    true,
		IsSystem:    false,
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   &createdBy,
		UpdatedBy:   &updatedBy,
	}
}

func TestPolicy_StructFields(t *testing.T) {
	t.Run("should carry all fields correctly", func(t *testing.T) {
		p := buildPolicy()

		assert.NotEqual(t, uuid.Nil, p.ID)
		require.NotNil(t, p.TenantID)
		assert.Equal(t, "Admin Read-Write Policy", p.Name)
		assert.Equal(t, "Grants admins full read/write access", p.Description)
		assert.Equal(t, PolicyEffectAllow, p.Effect)
		assert.Equal(t, 100, p.Priority)
		assert.NotNil(t, p.Conditions)
		assert.NotEmpty(t, p.RegoCode)
		assert.False(t, p.IsGlobal)
		assert.True(t, p.IsActive)
		assert.False(t, p.IsSystem)
		require.NotNil(t, p.CreatedBy)
		require.NotNil(t, p.UpdatedBy)
	})

	t.Run("should allow nil TenantID for global policies", func(t *testing.T) {
		p := &Policy{
			ID:       uuid.New(),
			Name:     "Global Deny Policy",
			Effect:   PolicyEffectDeny,
			IsGlobal: true,
			IsActive: true,
			IsSystem: true,
		}

		assert.Nil(t, p.TenantID)
		assert.True(t, p.IsGlobal)
		assert.True(t, p.IsSystem)
	})

	t.Run("should allow nil Conditions (rego-only policy)", func(t *testing.T) {
		p := &Policy{
			ID:       uuid.New(),
			Name:     "Custom Rego Policy",
			Effect:   PolicyEffectAllow,
			RegoCode: "package authz\ndefault allow = true",
			IsActive: true,
		}

		assert.Nil(t, p.Conditions)
		assert.NotEmpty(t, p.RegoCode)
	})

	t.Run("should allow nil CreatedBy and UpdatedBy", func(t *testing.T) {
		p := &Policy{
			ID:       uuid.New(),
			Name:     "System Policy",
			Effect:   PolicyEffectDeny,
			IsSystem: true,
			IsActive: true,
		}

		assert.Nil(t, p.CreatedBy)
		assert.Nil(t, p.UpdatedBy)
	})
}

// ==================== Policy.ToResponse ====================

func TestPolicy_ToResponse(t *testing.T) {
	t.Run("should return the same policy pointer (identity)", func(t *testing.T) {
		p := buildPolicy()

		resp := p.ToResponse()

		require.NotNil(t, resp)
		// ToResponse returns p itself for Policy (pass-through)
		assert.Equal(t, p, resp)
	})

	t.Run("should carry Effect correctly in response", func(t *testing.T) {
		tests := []struct {
			effect PolicyEffect
		}{
			{effect: PolicyEffectAllow},
			{effect: PolicyEffectDeny},
		}

		for _, tt := range tests {
			t.Run(string(tt.effect), func(t *testing.T) {
				p := &Policy{
					ID:       uuid.New(),
					Name:     "Test",
					Effect:   tt.effect,
					IsActive: true,
				}

				resp := p.ToResponse()
				assert.Equal(t, tt.effect, resp.Effect)
			})
		}
	})
}

// ==================== PolicyCondition struct ====================

func TestPolicyCondition_StructFields(t *testing.T) {
	t.Run("should carry all condition fields", func(t *testing.T) {
		cond := PolicyCondition{
			Subject: map[string]interface{}{
				"role":       "admin",
				"department": "engineering",
			},
			Resource: map[string]interface{}{
				"type":  "document",
				"owner": "alice",
			},
			Action: []string{"read", "write", "delete"},
			Context: map[string]interface{}{
				"ip_range":    "10.0.0.0/8",
				"time_of_day": "business_hours",
			},
		}

		assert.Equal(t, "admin", cond.Subject["role"])
		assert.Equal(t, "document", cond.Resource["type"])
		assert.Equal(t, []string{"read", "write", "delete"}, cond.Action)
		assert.Equal(t, "10.0.0.0/8", cond.Context["ip_range"])
	})

	t.Run("should allow nil/empty fields (partial condition)", func(t *testing.T) {
		cond := PolicyCondition{
			Action: []string{"read"},
		}

		assert.Nil(t, cond.Subject)
		assert.Nil(t, cond.Resource)
		assert.Nil(t, cond.Context)
		assert.Equal(t, []string{"read"}, cond.Action)
	})

	t.Run("should marshal to and from JSON correctly", func(t *testing.T) {
		cond := PolicyCondition{
			Subject:  map[string]interface{}{"role": "user"},
			Action:   []string{"read"},
			Resource: map[string]interface{}{"type": "report"},
		}

		data, err := json.Marshal(cond)
		require.NoError(t, err)

		var decoded PolicyCondition
		require.NoError(t, json.Unmarshal(data, &decoded))

		assert.Equal(t, "user", decoded.Subject["role"])
		assert.Equal(t, []string{"read"}, decoded.Action)
		assert.Equal(t, "report", decoded.Resource["type"])
	})
}

// ==================== PolicyAudit struct ====================

func TestPolicyAudit_StructFields(t *testing.T) {
	t.Run("should carry all audit fields", func(t *testing.T) {
		id := uuid.New()
		policyID := uuid.New()
		performedBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		oldValue := json.RawMessage(`{"is_active":false}`)
		newValue := json.RawMessage(`{"is_active":true}`)

		audit := PolicyAudit{
			ID:          id,
			PolicyID:    policyID,
			Action:      "activate",
			OldValue:    oldValue,
			NewValue:    newValue,
			PerformedBy: &performedBy,
			PerformedAt: now,
		}

		assert.Equal(t, id, audit.ID)
		assert.Equal(t, policyID, audit.PolicyID)
		assert.Equal(t, "activate", audit.Action)
		assert.Equal(t, oldValue, audit.OldValue)
		assert.Equal(t, newValue, audit.NewValue)
		require.NotNil(t, audit.PerformedBy)
		assert.Equal(t, performedBy, *audit.PerformedBy)
		assert.Equal(t, now, audit.PerformedAt)
	})

	t.Run("should allow nil PerformedBy", func(t *testing.T) {
		audit := PolicyAudit{
			ID:          uuid.New(),
			PolicyID:    uuid.New(),
			Action:      "create",
			PerformedAt: time.Now(),
		}

		assert.Nil(t, audit.PerformedBy)
	})

	t.Run("should support all audit action values", func(t *testing.T) {
		actions := []string{"create", "update", "delete", "activate", "deactivate"}

		for _, action := range actions {
			action := action
			t.Run(action, func(t *testing.T) {
				audit := PolicyAudit{
					ID:          uuid.New(),
					PolicyID:    uuid.New(),
					Action:      action,
					PerformedAt: time.Now(),
				}
				assert.Equal(t, action, audit.Action)
			})
		}
	})
}

// ==================== CreatePolicyRequest ====================

func TestCreatePolicyRequest_StructFields(t *testing.T) {
	t.Run("should carry all creation fields", func(t *testing.T) {
		conditions := json.RawMessage(`{"subject":{"role":"manager"}}`)

		req := CreatePolicyRequest{
			Name:        "Manager Access Policy",
			Description: "Allows managers to read all resources",
			Effect:      PolicyEffectAllow,
			Priority:    50,
			Conditions:  conditions,
			RegoCode:    "",
			IsGlobal:    false,
			IsActive:    true,
		}

		assert.Equal(t, "Manager Access Policy", req.Name)
		assert.Equal(t, "Allows managers to read all resources", req.Description)
		assert.Equal(t, PolicyEffectAllow, req.Effect)
		assert.Equal(t, 50, req.Priority)
		assert.Equal(t, conditions, req.Conditions)
		assert.False(t, req.IsGlobal)
		assert.True(t, req.IsActive)
	})

	t.Run("should allow deny effect", func(t *testing.T) {
		req := CreatePolicyRequest{
			Name:   "Deny External Access",
			Effect: PolicyEffectDeny,
		}

		assert.Equal(t, PolicyEffectDeny, req.Effect)
	})

	t.Run("should allow nil Conditions (Rego-only policy)", func(t *testing.T) {
		req := CreatePolicyRequest{
			Name:     "Rego Policy",
			Effect:   PolicyEffectAllow,
			RegoCode: "package authz\ndefault allow = true",
		}

		assert.Nil(t, req.Conditions)
		assert.NotEmpty(t, req.RegoCode)
	})

	t.Run("should allow zero priority", func(t *testing.T) {
		req := CreatePolicyRequest{
			Name:   "Low Priority Policy",
			Effect: PolicyEffectAllow,
		}

		assert.Equal(t, 0, req.Priority)
	})
}

// ==================== UpdatePolicyRequest ====================

func TestUpdatePolicyRequest_StructFields(t *testing.T) {
	t.Run("should carry optional update fields", func(t *testing.T) {
		name := "Updated Policy Name"
		desc := testUpdatedDesc
		effect := PolicyEffectDeny
		priority := 200
		rego := "package authz\ndefault allow = false"
		active := false
		conditions := json.RawMessage(`{"resource":{"type":"confidential"}}`)

		req := UpdatePolicyRequest{
			Name:        &name,
			Description: &desc,
			Effect:      &effect,
			Priority:    &priority,
			Conditions:  &conditions,
			RegoCode:    &rego,
			IsActive:    &active,
		}

		require.NotNil(t, req.Name)
		assert.Equal(t, "Updated Policy Name", *req.Name)
		require.NotNil(t, req.Description)
		assert.Equal(t, testUpdatedDesc, *req.Description)
		require.NotNil(t, req.Effect)
		assert.Equal(t, PolicyEffectDeny, *req.Effect)
		require.NotNil(t, req.Priority)
		assert.Equal(t, 200, *req.Priority)
		require.NotNil(t, req.Conditions)
		require.NotNil(t, req.RegoCode)
		assert.Equal(t, rego, *req.RegoCode)
		require.NotNil(t, req.IsActive)
		assert.False(t, *req.IsActive)
	})

	t.Run("should allow all nil for minimal patch", func(t *testing.T) {
		req := UpdatePolicyRequest{}

		assert.Nil(t, req.Name)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.Effect)
		assert.Nil(t, req.Priority)
		assert.Nil(t, req.Conditions)
		assert.Nil(t, req.RegoCode)
		assert.Nil(t, req.IsActive)
	})
}

// ==================== PolicyListResponse ====================

func TestPolicyListResponse_StructFields(t *testing.T) {
	t.Run("should carry list and pagination fields", func(t *testing.T) {
		policies := []Policy{
			{ID: uuid.New(), Name: "Policy A", Effect: PolicyEffectAllow, IsActive: true},
			{ID: uuid.New(), Name: "Policy B", Effect: PolicyEffectDeny, IsActive: false},
		}

		resp := PolicyListResponse{
			Policies:   policies,
			Total:      2,
			Page:       1,
			PageSize:   20,
			TotalPages: 1,
		}

		assert.Len(t, resp.Policies, 2)
		assert.Equal(t, int64(2), resp.Total)
		assert.Equal(t, 1, resp.Page)
		assert.Equal(t, 20, resp.PageSize)
		assert.Equal(t, 1, resp.TotalPages)
		assert.Equal(t, "Policy A", resp.Policies[0].Name)
		assert.Equal(t, "Policy B", resp.Policies[1].Name)
	})

	t.Run("should allow empty policy list", func(t *testing.T) {
		resp := PolicyListResponse{
			Policies:   []Policy{},
			Total:      0,
			Page:       1,
			PageSize:   20,
			TotalPages: 0,
		}

		assert.Empty(t, resp.Policies)
		assert.Equal(t, int64(0), resp.Total)
	})
}

// ==================== PolicyTestRequest ====================

func TestPolicyTestRequest_StructFields(t *testing.T) {
	t.Run("should carry user, resource, action and context", func(t *testing.T) {
		req := PolicyTestRequest{
			User: map[string]interface{}{
				"id":         "user-123",
				"role":       "manager",
				"department": "finance",
			},
			Resource: map[string]interface{}{
				"type": "invoice",
				"id":   "inv-456",
			},
			Action: "approve",
			Context: map[string]interface{}{
				"ip":          "10.0.0.5",
				"time_of_day": "09:30",
			},
		}

		assert.Equal(t, "user-123", req.User["id"])
		assert.Equal(t, "manager", req.User["role"])
		assert.Equal(t, "invoice", req.Resource["type"])
		assert.Equal(t, "approve", req.Action)
		assert.Equal(t, "10.0.0.5", req.Context["ip"])
	})

	t.Run("should allow nil Context (optional)", func(t *testing.T) {
		req := PolicyTestRequest{
			User:     map[string]interface{}{"role": "user"},
			Resource: map[string]interface{}{"type": "report"},
			Action:   "read",
		}

		assert.Nil(t, req.Context)
	})
}

// ==================== PolicyTestResponse ====================

func TestPolicyTestResponse_StructFields(t *testing.T) {
	t.Run("should carry allowed, matched rules and reasons when permitted", func(t *testing.T) {
		resp := PolicyTestResponse{
			Allowed:      true,
			MatchedRules: []string{"admin-read-policy", "finance-approve-policy"},
			Reasons:      []string{"User has admin role", "User is in finance department"},
		}

		assert.True(t, resp.Allowed)
		assert.Equal(t, []string{"admin-read-policy", "finance-approve-policy"}, resp.MatchedRules)
		assert.Equal(t, []string{"User has admin role", "User is in finance department"}, resp.Reasons)
	})

	t.Run("should carry not-allowed response with empty matched rules", func(t *testing.T) {
		resp := PolicyTestResponse{
			Allowed:      false,
			MatchedRules: nil,
			Reasons:      []string{"No applicable policy found"},
		}

		assert.False(t, resp.Allowed)
		assert.Nil(t, resp.MatchedRules)
		assert.Equal(t, []string{"No applicable policy found"}, resp.Reasons)
	})

	t.Run("should allow nil MatchedRules and Reasons", func(t *testing.T) {
		resp := PolicyTestResponse{
			Allowed: false,
		}

		assert.False(t, resp.Allowed)
		assert.Nil(t, resp.MatchedRules)
		assert.Nil(t, resp.Reasons)
	})
}

// ==================== Policy priority ordering ====================

func TestPolicy_PriorityOrdering(t *testing.T) {
	tests := []struct {
		name     string
		priority int
	}{
		{name: "zero priority", priority: 0},
		{name: "low priority", priority: 10},
		{name: "medium priority", priority: 50},
		{name: "high priority", priority: 100},
		{name: "maximum priority", priority: 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{
				ID:       uuid.New(),
				Name:     "Test",
				Effect:   PolicyEffectAllow,
				Priority: tt.priority,
				IsActive: true,
			}

			assert.Equal(t, tt.priority, p.Priority)
		})
	}
}

// ==================== Policy global vs tenant-scoped ====================

func TestPolicy_GlobalVsTenantScoped(t *testing.T) {
	t.Run("global policy has nil TenantID and IsGlobal=true", func(t *testing.T) {
		p := &Policy{
			ID:       uuid.New(),
			Name:     "Global Policy",
			Effect:   PolicyEffectAllow,
			IsGlobal: true,
			IsSystem: true,
			IsActive: true,
		}

		assert.Nil(t, p.TenantID)
		assert.True(t, p.IsGlobal)
	})

	t.Run("tenant-scoped policy has non-nil TenantID and IsGlobal=false", func(t *testing.T) {
		tenantID := uuid.New()
		p := &Policy{
			ID:       uuid.New(),
			TenantID: &tenantID,
			Name:     "Tenant Policy",
			Effect:   PolicyEffectAllow,
			IsGlobal: false,
			IsActive: true,
		}

		require.NotNil(t, p.TenantID)
		assert.Equal(t, tenantID, *p.TenantID)
		assert.False(t, p.IsGlobal)
	})
}
