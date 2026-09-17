// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== ConsentCategory constants ====================

func TestConsentCategoryConstants(t *testing.T) {
	assert.Equal(t, ConsentCategory("required"), ConsentCategoryRequired)
	assert.Equal(t, ConsentCategory("functional"), ConsentCategoryFunctional)
	assert.Equal(t, ConsentCategory("analytics"), ConsentCategoryAnalytics)
	assert.Equal(t, ConsentCategory("marketing"), ConsentCategoryMarketing)
	assert.Equal(t, ConsentCategory("optional"), ConsentCategoryOptional)
}

func TestConsentCategoryConstants_AreDistinct(t *testing.T) {
	categories := []ConsentCategory{
		ConsentCategoryRequired,
		ConsentCategoryFunctional,
		ConsentCategoryAnalytics,
		ConsentCategoryMarketing,
		ConsentCategoryOptional,
	}

	seen := make(map[ConsentCategory]bool)
	for _, c := range categories {
		assert.False(t, seen[c], "duplicate category constant value: %s", c)
		seen[c] = true
	}
}

// ==================== LegalBasis constants ====================

func TestLegalBasisConstants(t *testing.T) {
	assert.Equal(t, LegalBasis("consent"), LegalBasisConsent)
	assert.Equal(t, LegalBasis("contract"), LegalBasisContract)
	assert.Equal(t, LegalBasis("legal_obligation"), LegalBasisLegalObligation)
	assert.Equal(t, LegalBasis("vital_interests"), LegalBasisVitalInterests)
	assert.Equal(t, LegalBasis("public_task"), LegalBasisPublicTask)
	assert.Equal(t, LegalBasis("legitimate_interests"), LegalBasisLegitimateInterests)
}

func TestLegalBasisConstants_AreDistinct(t *testing.T) {
	bases := []LegalBasis{
		LegalBasisConsent,
		LegalBasisContract,
		LegalBasisLegalObligation,
		LegalBasisVitalInterests,
		LegalBasisPublicTask,
		LegalBasisLegitimateInterests,
	}

	seen := make(map[LegalBasis]bool)
	for _, b := range bases {
		assert.False(t, seen[b], "duplicate legal basis constant value: %s", b)
		seen[b] = true
	}
}

// ==================== ConsentType.ToResponse ====================

func buildConsentType() *ConsentType {
	id := uuid.New()
	tenantID := uuid.New()
	now := time.Now().Truncate(time.Second)
	desc := "Tracking user behaviour for improving the service"
	legalBasis := string(LegalBasisLegitimateInterests)
	retention := 365
	policyURL := "https://example.com/privacy-policy"

	return &ConsentType{
		ID:                id,
		TenantID:          tenantID,
		Name:              "analytics_tracking",
		DisplayName:       "Analytics Tracking",
		Description:       &desc,
		Category:          string(ConsentCategoryAnalytics),
		IsRequired:        false,
		IsActive:          true,
		Version:           2,
		LegalBasis:        &legalBasis,
		DataRetentionDays: &retention,
		ExternalPolicyURL: &policyURL,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func TestConsentType_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		ct := buildConsentType()

		resp := ct.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, ct.ID.String(), resp.ID)
		assert.Equal(t, "analytics_tracking", resp.Name)
		assert.Equal(t, "Analytics Tracking", resp.DisplayName)
		assert.Equal(t, "Tracking user behaviour for improving the service", resp.Description)
		assert.Equal(t, string(ConsentCategoryAnalytics), resp.Category)
		assert.False(t, resp.IsRequired)
		assert.Equal(t, 2, resp.Version)
		assert.Equal(t, string(LegalBasisLegitimateInterests), resp.LegalBasis)
		assert.Equal(t, "https://example.com/privacy-policy", resp.ExternalPolicyURL)
	})

	t.Run("should handle nil optional pointer fields with empty strings", func(t *testing.T) {
		ct := &ConsentType{
			ID:                uuid.New(),
			TenantID:          uuid.New(),
			Name:              "required_terms",
			DisplayName:       "Terms of Service",
			Description:       nil,
			Category:          string(ConsentCategoryRequired),
			IsRequired:        true,
			IsActive:          true,
			Version:           1,
			LegalBasis:        nil,
			ExternalPolicyURL: nil,
		}

		resp := ct.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, "", resp.Description, "nil Description should map to empty string")
		assert.Equal(t, "", resp.LegalBasis, "nil LegalBasis should map to empty string")
		assert.Equal(t, "", resp.ExternalPolicyURL, "nil ExternalPolicyURL should map to empty string")
		assert.True(t, resp.IsRequired)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		ct := buildConsentType()

		resp1 := ct.ToResponse()
		resp2 := ct.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})

	t.Run("ID should be formatted as UUID string", func(t *testing.T) {
		id := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
		ct := &ConsentType{
			ID:          id,
			TenantID:    uuid.New(),
			Name:        "marketing",
			DisplayName: "Marketing",
			Category:    string(ConsentCategoryMarketing),
			Version:     1,
		}

		resp := ct.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", resp.ID)
	})

	t.Run("required consent type with functional category", func(t *testing.T) {
		ct := &ConsentType{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			Name:        "session_management",
			DisplayName: "Session Management",
			Category:    string(ConsentCategoryFunctional),
			IsRequired:  true,
			IsActive:    true,
			Version:     1,
		}

		resp := ct.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, string(ConsentCategoryFunctional), resp.Category)
		assert.True(t, resp.IsRequired)
	})
}

// ==================== UserConsentWithType.ToResponse ====================

func buildUserConsentWithType() *UserConsentWithType {
	now := time.Now().Truncate(time.Second)
	grantedAt := now.Add(-24 * time.Hour)
	ip := testIPAddr192_168_1_1
	ua := testUserAgentMozilla
	legalBasis := string(LegalBasisConsent)

	return &UserConsentWithType{
		UserConsent: UserConsent{
			ID:             uuid.New(),
			UserID:         uuid.New(),
			ConsentTypeID:  uuid.New(),
			Granted:        true,
			ConsentVersion: 3,
			GrantedAt:      &grantedAt,
			RevokedAt:      nil,
			IPAddress:      &ip,
			UserAgent:      &ua,
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		ConsentType: ConsentType{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			Name:        "analytics",
			DisplayName: "Analytics",
			Category:    string(ConsentCategoryAnalytics),
			IsRequired:  false,
			IsActive:    true,
			Version:     3,
			LegalBasis:  &legalBasis,
		},
	}
}

func TestUserConsentWithType_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		c := buildUserConsentWithType()

		resp := c.ToResponse()

		require.NotNil(t, resp)
		assert.True(t, resp.Granted)
		assert.Equal(t, 3, resp.Version)
		require.NotNil(t, resp.GrantedAt)
		assert.Equal(t, c.GrantedAt, resp.GrantedAt)
		assert.Nil(t, resp.RevokedAt)

		// Embedded ConsentType response
		assert.Equal(t, c.ConsentType.ID.String(), resp.ConsentType.ID)
		assert.Equal(t, "analytics", resp.ConsentType.Name)
		assert.Equal(t, "Analytics", resp.ConsentType.DisplayName)
		assert.Equal(t, string(ConsentCategoryAnalytics), resp.ConsentType.Category)
		assert.False(t, resp.ConsentType.IsRequired)
		assert.Equal(t, 3, resp.ConsentType.Version)
		assert.Equal(t, string(LegalBasisConsent), resp.ConsentType.LegalBasis)
	})

	t.Run("should carry RevokedAt when consent is revoked", func(t *testing.T) {
		now := time.Now()
		revoked := now.Add(-1 * time.Hour)

		c := &UserConsentWithType{
			UserConsent: UserConsent{
				ID:             uuid.New(),
				UserID:         uuid.New(),
				ConsentTypeID:  uuid.New(),
				Granted:        false,
				ConsentVersion: 1,
				GrantedAt:      nil,
				RevokedAt:      &revoked,
			},
			ConsentType: ConsentType{
				ID:          uuid.New(),
				TenantID:    uuid.New(),
				Name:        "marketing",
				DisplayName: "Marketing",
				Category:    string(ConsentCategoryMarketing),
				Version:     1,
			},
		}

		resp := c.ToResponse()

		require.NotNil(t, resp)
		assert.False(t, resp.Granted)
		assert.Nil(t, resp.GrantedAt)
		require.NotNil(t, resp.RevokedAt)
		assert.Equal(t, &revoked, resp.RevokedAt)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		c := buildUserConsentWithType()

		resp1 := c.ToResponse()
		resp2 := c.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== ConsentHistoryWithType.ToResponse ====================

func buildConsentHistoryWithType() *ConsentHistoryWithType {
	now := time.Now().Truncate(time.Second)
	ip := testIPAddrTen
	ua := "TestBrowser/1.0"

	return &ConsentHistoryWithType{
		ConsentHistory: ConsentHistory{
			ID:             uuid.New(),
			UserID:         uuid.New(),
			ConsentTypeID:  uuid.New(),
			Action:         "granted",
			ConsentVersion: 2,
			IPAddress:      &ip,
			UserAgent:      &ua,
			CreatedAt:      now,
		},
		ConsentType: ConsentType{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			Name:        "functional_cookies",
			DisplayName: "Functional Cookies",
			Category:    string(ConsentCategoryFunctional),
			IsRequired:  false,
			IsActive:    true,
			Version:     2,
		},
	}
}

func TestConsentHistoryWithType_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		h := buildConsentHistoryWithType()

		resp := h.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, h.ID.String(), resp.ID)
		assert.Equal(t, "granted", resp.Action)
		assert.Equal(t, 2, resp.ConsentVersion)
		assert.Equal(t, testIPAddrTen, resp.IPAddress)
		assert.Equal(t, h.CreatedAt, resp.Timestamp)

		// Embedded ConsentType response
		assert.Equal(t, h.ConsentType.ID.String(), resp.ConsentType.ID)
		assert.Equal(t, "functional_cookies", resp.ConsentType.Name)
		assert.Equal(t, "Functional Cookies", resp.ConsentType.DisplayName)
		assert.Equal(t, string(ConsentCategoryFunctional), resp.ConsentType.Category)
	})

	t.Run("should use empty string for IPAddress when nil", func(t *testing.T) {
		h := &ConsentHistoryWithType{
			ConsentHistory: ConsentHistory{
				ID:             uuid.New(),
				UserID:         uuid.New(),
				ConsentTypeID:  uuid.New(),
				Action:         "revoked",
				ConsentVersion: 1,
				IPAddress:      nil,
				CreatedAt:      time.Now(),
			},
			ConsentType: ConsentType{
				ID:          uuid.New(),
				TenantID:    uuid.New(),
				Name:        "analytics",
				DisplayName: "Analytics",
				Category:    string(ConsentCategoryAnalytics),
				Version:     1,
			},
		}

		resp := h.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, "", resp.IPAddress, "nil IPAddress should map to empty string")
		assert.Equal(t, "revoked", resp.Action)
	})

	t.Run("Timestamp should equal ConsentHistory.CreatedAt", func(t *testing.T) {
		createdAt := time.Date(2025, 6, 15, 12, 30, 0, 0, time.UTC)
		h := &ConsentHistoryWithType{
			ConsentHistory: ConsentHistory{
				ID:             uuid.New(),
				UserID:         uuid.New(),
				ConsentTypeID:  uuid.New(),
				Action:         "granted",
				ConsentVersion: 1,
				CreatedAt:      createdAt,
			},
			ConsentType: ConsentType{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Name:     "consent_type",
				Category: string(ConsentCategoryOptional),
				Version:  1,
			},
		}

		resp := h.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, createdAt, resp.Timestamp)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		h := buildConsentHistoryWithType()

		resp1 := h.ToResponse()
		resp2 := h.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== UpdateConsentRequest ====================

func TestUpdateConsentRequest_Fields(t *testing.T) {
	tests := []struct {
		name    string
		granted bool
	}{
		{
			name:    "should hold granted=true",
			granted: true,
		},
		{
			name:    "should hold granted=false",
			granted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := UpdateConsentRequest{Granted: tt.granted}
			assert.Equal(t, tt.granted, req.Granted)
		})
	}
}

// ==================== BulkConsentRequest ====================

func TestBulkConsentRequest_Fields(t *testing.T) {
	t.Run("should hold multiple consent entries", func(t *testing.T) {
		id1 := uuid.New().String()
		id2 := uuid.New().String()

		req := BulkConsentRequest{
			Consents: []struct {
				ConsentTypeID string `json:"consent_type_id"`
				Granted       bool   `json:"granted"`
			}{
				{ConsentTypeID: id1, Granted: true},
				{ConsentTypeID: id2, Granted: false},
			},
		}

		require.Len(t, req.Consents, 2)
		assert.Equal(t, id1, req.Consents[0].ConsentTypeID)
		assert.True(t, req.Consents[0].Granted)
		assert.Equal(t, id2, req.Consents[1].ConsentTypeID)
		assert.False(t, req.Consents[1].Granted)
	})

	t.Run("zero value should have empty consents slice", func(t *testing.T) {
		req := BulkConsentRequest{}
		assert.Empty(t, req.Consents)
	})

	t.Run("should handle an empty consents list", func(t *testing.T) {
		req := BulkConsentRequest{
			Consents: []struct {
				ConsentTypeID string `json:"consent_type_id"`
				Granted       bool   `json:"granted"`
			}{},
		}
		assert.Len(t, req.Consents, 0)
	})
}
