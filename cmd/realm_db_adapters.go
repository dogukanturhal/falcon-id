// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// realm_db_adapters.go wires services.RealmDBProvisioner and services.RealmService
// to the handler-layer interfaces defined in internal/handlers/realm_db_handler.go.
//
// The handler package defines its own local types (RealmDatabase, RealmDatabaseHealth)
// and interfaces (RealmDatabaseProvisioner, RealmLookup) to avoid a compile-time
// dependency on the services package. The adapters below bridge the two worlds at
// the cmd (composition root) layer, which can import both packages freely.

import (
	"context"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ---------------------------------------------------------------------------
// realmDBProvisionerAdapter
//
// Bridges services.RealmDBProvisioner to handlers.RealmDatabaseProvisioner.
// The service methods return *models.RealmDatabase whereas the handler interface
// expects the handler-local *handlers.RealmDatabase. The adapter converts
// between the two.
// ---------------------------------------------------------------------------

type realmDBProvisionerAdapter struct {
	svc *services.RealmDBProvisioner
}

// newRealmDBProvisionerAdapter wraps a RealmDBProvisioner so it satisfies the
// handlers.RealmDatabaseProvisioner interface.
func newRealmDBProvisionerAdapter(svc *services.RealmDBProvisioner) *realmDBProvisionerAdapter {
	return &realmDBProvisionerAdapter{svc: svc}
}

// ProvisionDatabase provisions a dedicated realm database and returns the
// handler-layer representation of the result.
func (a *realmDBProvisionerAdapter) ProvisionDatabase(ctx context.Context, realmID uuid.UUID, realmSlug string, preferredRegion string) (*handlers.RealmDatabase, error) {
	rd, err := a.svc.ProvisionDatabase(ctx, realmID, realmSlug, preferredRegion)
	if err != nil {
		return nil, err
	}
	if rd == nil {
		return nil, nil
	}
	return &handlers.RealmDatabase{
		ID:           rd.ID,
		RealmID:      rd.RealmID,
		DatabaseName: rd.DatabaseName,
		Host:         rd.Host,
		Port:         rd.Port,
		Status:       rd.Status,
		CreatedAt:    rd.CreatedAt,
	}, nil
}

// DecommissionDatabase deprovisions the dedicated realm database.
func (a *realmDBProvisionerAdapter) DecommissionDatabase(ctx context.Context, realmID uuid.UUID) error {
	return a.svc.DecommissionDatabase(ctx, realmID)
}

// GetDatabaseHealth returns the health of the dedicated realm database. The
// underlying service method returns a *models.RealmDatabase and we project
// only the health-relevant fields into the handler type.
func (a *realmDBProvisionerAdapter) GetDatabaseHealth(ctx context.Context, realmID uuid.UUID) (*handlers.RealmDatabaseHealth, error) {
	rd, err := a.svc.GetDatabaseHealth(ctx, realmID)
	if err != nil {
		return nil, err
	}
	if rd == nil {
		return &handlers.RealmDatabaseHealth{
			RealmID: realmID,
			Status:  "not_provisioned",
		}, nil
	}

	// Map the service-layer status to the handler/frontend vocabulary.
	// The service returns "shared_pool" when no dedicated DB exists; the
	// frontend expects "inactive" to render the "Provision" button.
	status := rd.Status
	if status == "shared_pool" {
		status = "inactive"
	}

	// models.RealmDatabase already stores HealthCheckStatus and LastHealthCheck
	// as pointer types — pass them through directly.
	return &handlers.RealmDatabaseHealth{
		RealmID:           rd.RealmID,
		Status:            status,
		Host:              rd.Host,
		DatabaseName:      rd.DatabaseName,
		PoolSize:          rd.PoolSize,
		LastHealthCheck:   rd.LastHealthCheck,
		HealthCheckStatus: rd.HealthCheckStatus,
	}, nil
}

// ---------------------------------------------------------------------------
// realmLookupAdapter
//
// Bridges services.RealmService to handlers.RealmLookup.
// handlers.RealmLookup requires a single GetSlugByID method; RealmService
// exposes GetRealm which returns a full *models.Realm. The adapter extracts
// only the slug field.
// ---------------------------------------------------------------------------

type realmLookupAdapter struct {
	svc *services.RealmService
}

// newRealmLookupAdapter wraps a RealmService so it satisfies the
// handlers.RealmLookup interface.
func newRealmLookupAdapter(svc *services.RealmService) *realmLookupAdapter {
	return &realmLookupAdapter{svc: svc}
}

// GetSlugByID resolves the slug for the given realm ID.
func (a *realmLookupAdapter) GetSlugByID(ctx context.Context, realmID uuid.UUID) (string, error) {
	realm, err := a.svc.GetByID(ctx, realmID)
	if err != nil {
		return "", err
	}
	if realm == nil {
		return "", nil
	}
	return realm.Slug, nil
}
