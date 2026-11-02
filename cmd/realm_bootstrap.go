// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// bootstrapPlatformRealm idempotently ensures the platform realm row exists
// in `realms`. The platform realm is the home of the `exampletenant`
// tenant and the platform admin user; per the RFC 9700 / OWASP Multi-Tenant
// pattern the realm is the outer security boundary and must always exist
// before users are created in it.
//
// Why this lives in the application boot path:
//
//   - Keystone manages the `realms` TABLE structure (via SchemaDefinition
//     `falcon-id-control-public-desired`). Keystone DOES NOT manage table
//     ROWS — INSERTs are operational data, not schema. The platform realm
//     is a well-known sentinel row that the application requires to start
//     functioning, so the application is the right component to ensure it.
//
//   - The cmd/admin_bootstrap.go pre-check (added in FI!137) refuses to
//     create the bootstrap admin if the platform realm row is missing.
//     Without this seed function, `dogukanturhal@example.com` cannot be
//     created on a fresh keystone-reconciled cluster, and the operator is
//     left running raw SQL INSERTs by hand against production.
//
//   - The seed runs through the application's repository layer (NOT raw
//     SQL) so any future row-shape evolution (new required column with
//     default, JSONB structure change, etc.) flows through one code path.
//
// Why repos.Realm.Create (low-level) instead of services.Realm.Create:
//
//   - services.RealmService.Create allocates a fresh UUID via uuid.New().
//     Well-known sentinel UUIDs (00000000-0000-0000-0000-000000000003)
//     cannot be threaded through the service layer without changing the
//     contract for normal operator-driven realm creation.
//
//   - The lower-level repo.Create accepts a pre-set realm.ID, which is the
//     correct signature for fixed-identity seeding.
//
// Idempotency:
//
//   - GetByID first; if the realm exists, log and return.
//   - Insert with the well-known UUID + canonical defaults that mirror
//     services.RealmService.Create's defaults (so a future operator-driven
//     migration produces equivalent rows).
//
// Failure mode:
//
//   - On error, log ERROR and return — do NOT panic. The application must
//     come up to serve health probes; a missing platform realm is operator-
//     visible via:
//     1. The bootstrapAdminUser pre-check error
//     2. A TODO follow-up Prometheus alert on `realms WHERE id = WellKnownRealmPlatform`
//        being absent for >5m
//
// This function is safe to call on every restart.
func bootstrapPlatformRealm(repos *Repositories) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	realmID := models.WellKnownRealmPlatform

	// repos.Realm is only constructed when the control-plane DB is configured
	// (cmd/repositories.go); without it there is nothing to bootstrap, and a
	// nil dereference here would contradict the "do NOT panic" contract above.
	if repos == nil || repos.Realm == nil {
		logger.Error("bootstrapPlatformRealm: realm repository unavailable (no control-plane DB); skipping",
			zap.String("realm_id", realmID.String()),
		)
		return
	}

	existing, err := repos.Realm.GetByID(ctx, realmID)
	if err != nil {
		logger.Error("bootstrapPlatformRealm: failed to check for existing realm",
			zap.String("realm_id", realmID.String()),
			zap.Error(err),
		)
		return
	}
	if existing != nil {
		logger.Info("bootstrapPlatformRealm: platform realm already exists, skipping",
			zap.String("realm_id", realmID.String()),
			zap.String("slug", existing.Slug),
			zap.String("type", string(existing.Type)),
		)
		return
	}

	// Defaults aligned with services.RealmService.Create (the canonical
	// path used by operator-driven realm creation, see internal/services/
	// realm_service.go:148). Mirroring keeps the seeded row indistinguishable
	// from one created via the admin API after bootstrap.
	settingsJSON := json.RawMessage(`{}`)
	brandingJSON := json.RawMessage(`{
		"logo_url": null,
		"favicon_url": null,
		"primary_color": "#4F46E5",
		"secondary_color": "#10B981",
		"login_background_url": null,
		"custom_css": null
	}`)
	featuresJSON := json.RawMessage(`{
		"mfa_available": true,
		"sso_available": true,
		"api_access": true,
		"custom_domain": false,
		"advanced_audit": false
	}`)

	realm := &models.Realm{
		ID:          realmID,
		Slug:        "platform",
		DisplayName: "HexxLock Platform",
		// RealmTypePlatform = "platform" — designated for HexxLock internal
		// administration per internal/models/realm.go. The historical hint
		// string in cmd/admin_bootstrap.go used "shared" — that hint pre-
		// dated this seed function and was incorrect for the platform realm.
		Type:     models.RealmTypePlatform,
		Status:   models.RealmStatusActive,
		Settings: settingsJSON,
		Branding: brandingJSON,
		Features: featuresJSON,
		// CreatedBy intentionally nil — this row is system-initiated, not
		// attributable to any human user. The `created_by` column accepts
		// NULL (see realm_repository.Create's INSERT — passes the pointer
		// straight through without coercion).
	}

	if err := repos.Realm.Create(ctx, realm); err != nil {
		// A concurrent bootstrap from a sibling pod may have inserted the
		// row between our GetByID and our Create. Treat the unique-key
		// collision as success (idempotent under pod-fleet startup races).
		if isRealmAlreadyExistsError(err) {
			logger.Info("bootstrapPlatformRealm: platform realm created concurrently by another pod, treating as success",
				zap.String("realm_id", realmID.String()),
			)
			return
		}
		logger.Error("bootstrapPlatformRealm: failed to create platform realm",
			zap.String("realm_id", realmID.String()),
			zap.Error(err),
		)
		return
	}

	logger.Info("bootstrapPlatformRealm: platform realm created",
		zap.String("realm_id", realmID.String()),
		zap.String("slug", realm.Slug),
		zap.String("type", string(realm.Type)),
	)
}

// bootstrapSharedRealm idempotently ensures the SHARED realm row exists. The
// shared realm (WellKnownRealmShared, == models.DefaultRealmID) is the
// customer-facing root of trust that holds every self-service customer as a
// logical tenant — the industry-standard "Organizations" model (Auth0
// Organizations, Keycloak Organizations): consumer/personal accounts live in
// the shared consumer tenant, and each business signup is its own SMB tenant,
// all inside this one realm. Large customers needing HARD isolation get a
// dedicated RealmTypeEnterprise realm instead — an operator/sales path, not
// self-service signup.
//
// Why this must exist before signups complete: signup_service auto-assigns
// every newly-provisioned tenant to models.DefaultRealmID, so user creation
// fails a realm_tenants FK / realm resolution if the row is absent. Same
// rationale, defaults, and idempotency as bootstrapPlatformRealm above.
func bootstrapSharedRealm(repos *Repositories) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	realmID := models.WellKnownRealmShared

	existing, err := repos.Realm.GetByID(ctx, realmID)
	if err != nil {
		logger.Error("bootstrapSharedRealm: failed to check for existing realm",
			zap.String("realm_id", realmID.String()),
			zap.Error(err),
		)
		return
	}
	if existing != nil {
		logger.Info("bootstrapSharedRealm: shared realm already exists, skipping",
			zap.String("realm_id", realmID.String()),
			zap.String("slug", existing.Slug),
			zap.String("type", string(existing.Type)),
		)
		return
	}

	settingsJSON := json.RawMessage(`{}`)
	brandingJSON := json.RawMessage(`{
		"logo_url": null,
		"favicon_url": null,
		"primary_color": "#4F46E5",
		"secondary_color": "#10B981",
		"login_background_url": null,
		"custom_css": null
	}`)
	featuresJSON := json.RawMessage(`{
		"mfa_available": true,
		"sso_available": true,
		"api_access": true,
		"custom_domain": false,
		"advanced_audit": false
	}`)

	realm := &models.Realm{
		ID:          realmID,
		Slug:        "shared",
		DisplayName: "HexxLock Shared",
		// RealmTypeShared = "shared" — multiple SMB tenants in a single realm
		// (the self-service customer home).
		Type:     models.RealmTypeShared,
		Status:   models.RealmStatusActive,
		Settings: settingsJSON,
		Branding: brandingJSON,
		Features: featuresJSON,
	}

	if err := repos.Realm.Create(ctx, realm); err != nil {
		if isRealmAlreadyExistsError(err) {
			logger.Info("bootstrapSharedRealm: shared realm created concurrently by another pod, treating as success",
				zap.String("realm_id", realmID.String()),
			)
			return
		}
		logger.Error("bootstrapSharedRealm: failed to create shared realm",
			zap.String("realm_id", realmID.String()),
			zap.Error(err),
		)
		return
	}

	logger.Info("bootstrapSharedRealm: shared realm created",
		zap.String("realm_id", realmID.String()),
		zap.String("slug", realm.Slug),
		zap.String("type", string(realm.Type)),
	)
}

// isRealmAlreadyExistsError matches the unique-violation strings that
// realm_repository.Create surfaces when realms_slug_key fires or when the
// primary-key collision propagates from pgx. Concurrent pod startup is the
// only realistic trigger for this in production. Substring match because
// the repository today returns fmt.Errorf-wrapped strings; a follow-up MR
// can introduce a typed sentinel and replace this with errors.Is.
func isRealmAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "duplicate key value violates unique constraint")
}
