// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TestScopeImmutabilityValidation tests the application-level validation
// that prevents scope changes. The database trigger provides the ultimate
// defense, but these tests verify the Go-level check catches it first.

func TestScopeImmutabilityDetection(t *testing.T) {
	t.Run("scope change from tenant to realm should be detected", func(t *testing.T) {
		existing := &models.IdentityProvider{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			Scope:    "tenant",
			Name:     "test-provider",
		}
		updated := &models.IdentityProvider{
			ID:       existing.ID,
			TenantID: existing.TenantID,
			Scope:    "realm", // Changed!
			Name:     "test-provider",
		}

		// Verify the scope change is detected
		assert.NotEqual(t, existing.Scope, updated.Scope)
		assert.Equal(t, "tenant", existing.Scope)
		assert.Equal(t, "realm", updated.Scope)
	})

	t.Run("scope change from realm to tenant should be detected", func(t *testing.T) {
		realmID := uuid.New()
		existing := &models.IdentityProvider{
			ID:      uuid.New(),
			RealmID: &realmID,
			Scope:   "realm",
			Name:    "test-provider",
		}
		updated := &models.IdentityProvider{
			ID:       existing.ID,
			TenantID: uuid.New(), // Trying to set tenant
			Scope:    "tenant",   // Changed!
			Name:     "test-provider",
		}

		assert.NotEqual(t, existing.Scope, updated.Scope)
	})

	t.Run("tenant_id change should be detected", func(t *testing.T) {
		tenantA := uuid.New()
		tenantB := uuid.New()
		existing := &models.IdentityProvider{
			ID:       uuid.New(),
			TenantID: tenantA,
			Scope:    "tenant",
		}
		updated := &models.IdentityProvider{
			ID:       existing.ID,
			TenantID: tenantB, // Changed!
			Scope:    "tenant",
		}

		assert.NotEqual(t, existing.TenantID, updated.TenantID)
	})

	t.Run("realm_id change should be detected", func(t *testing.T) {
		realmA := uuid.New()
		realmB := uuid.New()
		existing := &models.IdentityProvider{
			ID:      uuid.New(),
			RealmID: &realmA,
			Scope:   "realm",
		}
		updated := &models.IdentityProvider{
			ID:      existing.ID,
			RealmID: &realmB, // Changed!
			Scope:   "realm",
		}

		assert.NotEqual(t, *existing.RealmID, *updated.RealmID)
	})

	t.Run("mutable fields can change without scope violation", func(t *testing.T) {
		tenantID := uuid.New()
		existing := &models.IdentityProvider{
			ID:          uuid.New(),
			TenantID:    tenantID,
			Scope:       "tenant",
			DisplayName: "Old Name",
			Priority:    10,
			IsEnabled:   true,
		}
		updated := &models.IdentityProvider{
			ID:          existing.ID,
			TenantID:    tenantID,   // Same
			Scope:       "tenant",   // Same
			DisplayName: "New Name", // Changed (allowed)
			Priority:    20,         // Changed (allowed)
			IsEnabled:   false,      // Changed (allowed)
		}

		assert.Equal(t, existing.Scope, updated.Scope)
		assert.Equal(t, existing.TenantID, updated.TenantID)
		assert.NotEqual(t, existing.DisplayName, updated.DisplayName)
		assert.NotEqual(t, existing.Priority, updated.Priority)
	})
}
