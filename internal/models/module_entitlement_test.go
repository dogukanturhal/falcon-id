// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestModuleEntitlementStatus_IsValid(t *testing.T) {
	valid := []ModuleEntitlementStatus{
		ModuleEntitlementStatusActive,
		ModuleEntitlementStatusTrialing,
		ModuleEntitlementStatusGrace,
		ModuleEntitlementStatusExpired,
	}
	for _, s := range valid {
		assert.True(t, s.IsValid(), "expected %q to be valid", s)
	}

	invalid := []ModuleEntitlementStatus{"", "ACTIVE", "cancelled", "unknown"}
	for _, s := range invalid {
		assert.False(t, s.IsValid(), "expected %q to be invalid", s)
	}
}

func TestModuleEntitlementStatus_IsGranting(t *testing.T) {
	granting := []ModuleEntitlementStatus{
		ModuleEntitlementStatusActive,
		ModuleEntitlementStatusTrialing,
		ModuleEntitlementStatusGrace,
	}
	for _, s := range granting {
		assert.True(t, s.IsGranting(), "expected %q to grant access", s)
	}

	nonGranting := []ModuleEntitlementStatus{ModuleEntitlementStatusExpired, "", "bogus"}
	for _, s := range nonGranting {
		assert.False(t, s.IsGranting(), "expected %q to NOT grant access -- fail-closed default", s)
	}
}

func TestModuleEntitlement_TrialEligible(t *testing.T) {
	tests := []struct {
		name           string
		everTrialed    bool
		everSubscribed bool
		want           bool
	}{
		{"never trialed, never subscribed -> eligible", false, false, true},
		{"trialed before -> not eligible", true, false, false},
		{"subscribed before -> not eligible (even without trial)", false, true, false},
		{"both -> not eligible", true, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := ModuleEntitlement{EverTrialed: tt.everTrialed, EverSubscribed: tt.everSubscribed}
			assert.Equal(t, tt.want, m.TrialEligible())
		})
	}
}

func TestModuleEntitlement_TrialReason(t *testing.T) {
	end := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		m      ModuleEntitlement
		reason string
	}{
		{"never touched (expired placeholder)", ModuleEntitlement{ModuleCode: "crm", Status: ModuleEntitlementStatusExpired}, TrialReasonEligible},
		{"bundle is never trialable", ModuleEntitlement{ModuleCode: "bundle-pro", Status: ModuleEntitlementStatusExpired}, TrialReasonBundleNotTrialable},
		{"bundle prefix is case-insensitive", ModuleEntitlement{ModuleCode: "Bundle-Pro"}, TrialReasonBundleNotTrialable},
		{"trial running", ModuleEntitlement{ModuleCode: "crm", Status: ModuleEntitlementStatusTrialing, EverTrialed: true}, TrialReasonTrialActive},
		{"grace", ModuleEntitlement{ModuleCode: "crm", Status: ModuleEntitlementStatusGrace, EverTrialed: true}, TrialReasonInGrace},
		{"paid", ModuleEntitlement{ModuleCode: "crm", Status: ModuleEntitlementStatusActive, EverSubscribed: true}, TrialReasonAlreadySubscribed},
		{"active without history flag still not eligible", ModuleEntitlement{ModuleCode: "crm", Status: ModuleEntitlementStatusActive}, TrialReasonAlreadySubscribed},
		{"lapsed paid", ModuleEntitlement{ModuleCode: "crm", Status: ModuleEntitlementStatusExpired, EverSubscribed: true, EverTrialed: true}, TrialReasonAlreadySubscribed},
		{"trial used up", ModuleEntitlement{ModuleCode: "crm", Status: ModuleEntitlementStatusExpired, EverTrialed: true}, TrialReasonAlreadyTrialed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.reason, tt.m.TrialReason())
		})
	}

	trialing := ModuleEntitlement{Status: ModuleEntitlementStatusTrialing, ExpiresAt: &end}
	assert.Equal(t, &end, trialing.TrialEndsAt())
	assert.Nil(t, trialing.GraceEndsAt())
	grace := ModuleEntitlement{Status: ModuleEntitlementStatusGrace, ExpiresAt: &end}
	assert.Equal(t, &end, grace.GraceEndsAt())
	assert.Nil(t, grace.TrialEndsAt())
	active := ModuleEntitlement{Status: ModuleEntitlementStatusActive, ExpiresAt: &end}
	assert.Nil(t, active.TrialEndsAt())
	assert.Nil(t, active.GraceEndsAt())
}

func TestModuleEntitlement_ComplimentaryTrialReason(t *testing.T) {
	source := "operator-comp"
	for _, status := range []ModuleEntitlementStatus{ModuleEntitlementStatusActive, ModuleEntitlementStatusGrace} {
		m := ModuleEntitlement{ModuleCode: "crm", Status: status, Source: &source, EverSubscribed: true, EverTrialed: true}
		assert.Equal(t, TrialReasonComplimentary, m.TrialReason())
		assert.False(t, m.TrialEligible())
	}
	// Once the complimentary access has expired, paid/trial history still
	// protects the trial gate; source does not erase that history.
	m := ModuleEntitlement{ModuleCode: "crm", Status: ModuleEntitlementStatusExpired, Source: &source, EverSubscribed: true}
	assert.Equal(t, TrialReasonAlreadySubscribed, m.TrialReason())
	ended := time.Now().Add(-time.Hour)
	m = ModuleEntitlement{ModuleCode: "crm", Status: ModuleEntitlementStatusActive, Source: &source, ExpiresAt: &ended}
	assert.Equal(t, TrialReasonEligible, m.TrialReason(), "a lapsed comp grant is not paid history")
}
