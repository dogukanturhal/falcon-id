// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

type fakeEntitlementInstances struct{ list []models.ProductInstance }

func (f fakeEntitlementInstances) ListByTenantAll(context.Context, uuid.UUID) ([]models.ProductInstance, error) {
	return f.list, nil
}

type fakeEntitlementProducts struct{ byID map[uuid.UUID]*models.Product }

func (f fakeEntitlementProducts) GetByID(_ context.Context, id uuid.UUID) (*models.Product, error) {
	return f.byID[id], nil
}

func TestDefaultModuleEntitlementChecker_SlugAlias(t *testing.T) {
	tests := []struct {
		name        string
		productSlug string
		module      string
		want        bool
	}{
		{"acmeweb row, acmeweb module", "acmeweb", "acmeweb", true},
		{"acmeweb row, acmeapp module", "acmeweb", "acmeapp", true},
		{"acmeapp row, acmeweb module", "acmeapp", "acmeweb", true},
		{"acmeapp row, acmeapp module", "acmeapp", "acmeapp", true},
		{"acmeapp row, uppercase acmeweb module", "acmeapp", "ACMEWEB", true},
		{"acmeweb row, other module", "acmeweb", "crm", false},
		{"acmeapp row, other module", "acmeapp", "crm", false},
		{"other row, acmeweb module", "crm", "acmeweb", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pid := uuid.New()
			c := NewDefaultModuleEntitlementChecker(
				fakeEntitlementInstances{list: []models.ProductInstance{
					{ID: uuid.New(), ProductID: pid, ProvisioningState: models.ProvisioningStateActive},
				}},
				fakeEntitlementProducts{byID: map[uuid.UUID]*models.Product{pid: {ID: pid, Slug: tc.productSlug}}},
			)
			got, err := c.IsTenantEntitled(context.Background(), uuid.New(), tc.module)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
