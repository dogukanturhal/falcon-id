// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// defaultMFAByLevel governs the tier-1 baseline that forces MFA at
// medium/high/critical even when a tenant hasn't configured a risk policy.
// Test the matrix directly — the function is pure and the wider
// AssessLoginRisk path is integration-tested elsewhere.
func TestDefaultMFAByLevel(t *testing.T) {
	cases := []struct {
		name       string
		level      models.RiskLevel
		thresholds *models.RiskThreshold
		want       bool
	}{
		// Nil thresholds: tier-1 defaults (medium=true, high=true) apply.
		{"low/nil thresholds → no MFA", models.RiskLevelLow, nil, false},
		{"medium/nil thresholds → MFA", models.RiskLevelMedium, nil, true},
		{"high/nil thresholds → MFA", models.RiskLevelHigh, nil, true},
		{"critical/nil thresholds → MFA", models.RiskLevelCritical, nil, true},

		// Both toggles on (matches migration default for fresh rows).
		{
			"medium/both on → MFA",
			models.RiskLevelMedium,
			&models.RiskThreshold{DefaultMFAAtMedium: true, DefaultMFAAtHigh: true},
			true,
		},
		{
			"high/both on → MFA",
			models.RiskLevelHigh,
			&models.RiskThreshold{DefaultMFAAtMedium: true, DefaultMFAAtHigh: true},
			true,
		},

		// Per-level escape hatches.
		{
			"medium/medium-off → no MFA",
			models.RiskLevelMedium,
			&models.RiskThreshold{DefaultMFAAtMedium: false, DefaultMFAAtHigh: true},
			false,
		},
		{
			"high/high-off → no MFA (medium toggle does NOT cover high)",
			models.RiskLevelHigh,
			&models.RiskThreshold{DefaultMFAAtMedium: true, DefaultMFAAtHigh: false},
			false,
		},
		{
			"critical/high-off → no MFA (critical follows high toggle)",
			models.RiskLevelCritical,
			&models.RiskThreshold{DefaultMFAAtMedium: true, DefaultMFAAtHigh: false},
			false,
		},

		// Both off — opt out entirely.
		{
			"medium/both off → no MFA",
			models.RiskLevelMedium,
			&models.RiskThreshold{DefaultMFAAtMedium: false, DefaultMFAAtHigh: false},
			false,
		},
		{
			"high/both off → no MFA",
			models.RiskLevelHigh,
			&models.RiskThreshold{DefaultMFAAtMedium: false, DefaultMFAAtHigh: false},
			false,
		},

		// Low never triggers default-MFA regardless of toggles.
		{
			"low/both on → no MFA",
			models.RiskLevelLow,
			&models.RiskThreshold{DefaultMFAAtMedium: true, DefaultMFAAtHigh: true},
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := defaultMFAByLevel(tc.level, tc.thresholds)
			assert.Equal(t, tc.want, got)
		})
	}
}
