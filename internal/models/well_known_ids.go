// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "github.com/google/uuid"

// Well-known sentinel UUIDs used across Falcon-ID.
//
// Naming convention:
//   - WellKnownApp*  — first-party Application Object IDs (Entra ID "App Object" pattern).
//                      These are the global application definitions, not per-tenant instances.
//   - WellKnownProduct* — product-catalogue IDs used by the subscription/provisioning layer.
//   - WellKnownTenant*  — sentinel tenant IDs with special platform meaning.
//
// All values use deterministic UUIDs (AWS-inspired) so they are safe to hard-code in
// migrations, seeds, and business logic without risk of collision with real UUIDs.

// ── Application Object IDs (00000000-0000-0000-0001-xxxxxxxxxxxx) ────────────

// WellKnownAppPlatformAdmin is the Application Object ID for the Platform Admin console.
var WellKnownAppPlatformAdmin = uuid.MustParse("00000000-0000-0000-0001-000000000001")

// WellKnownAppExampleSuite is the Application Object ID for the Example Suite product.
var WellKnownAppExampleSuite = uuid.MustParse("00000000-0000-0000-0001-000000000002")

// WellKnownAppFalconID is the Application Object ID for the Falcon-ID identity platform itself.
var WellKnownAppFalconID = uuid.MustParse("00000000-0000-0000-0001-000000000003")

// WellKnownAppAcmeWeb is the Application Object ID for AcmeWeb — the first SaaS
// product in the platform product family (marketing automation, acmeweb.example.com).
// Co-located with WellKnownProductAcmeWeb per the App/Product sentinel-co-location
// convention established by ExampleSuite.
var WellKnownAppAcmeWeb = uuid.MustParse("00000000-0000-0000-0001-000000000004")

// ── Product IDs (00000000-0000-0000-0001-xxxxxxxxxxxx) ───────────────────────

// WellKnownProductExampleSuite is the product catalogue ID for Example Suite used by the
// subscription and provisioning layer. It shares the same sentinel UUID as
// WellKnownAppExampleSuite — the application object and its product entry are
// intentionally co-located.
var WellKnownProductExampleSuite = WellKnownAppExampleSuite

// WellKnownProductAcmeWeb is the product catalogue ID for AcmeWeb. Same sentinel
// as WellKnownAppAcmeWeb — Application Object and product entry intentionally
// share a UUID. Used by Keystone seed bundles to insert the iam_products row,
// by acmeapp-bff to identify itself when querying iam_product_instances, and
// by the centralized SSO flow to gate access on iam_product_instances.product_id.
var WellKnownProductAcmeWeb = WellKnownAppAcmeWeb

// ── Realm IDs (00000000-0000-0000-0000-0000000000xx) ────────────────────────

var WellKnownRealmShared = uuid.MustParse("00000000-0000-0000-0000-000000000001")
var WellKnownRealmPlatform = uuid.MustParse("00000000-0000-0000-0000-000000000003")

// ── Tenant IDs (00000000-0000-0000-0000-xxxxxxxxxxxx) ────────────────────────

// WellKnownTenantDefaultID is the UUID of the default/fallback tenant used when no
// tenant context is present on a request (e.g. the unauthenticated login page).
var WellKnownTenantDefaultID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// DefaultRealmID points to the shared realm (customer-facing).
var DefaultRealmID = WellKnownRealmShared

// HexxlockInternalTenantID is the UUID of the exampletenant platform tenant.
// Lives in the platform realm, isolated from customer tenants.
const HexxlockInternalTenantID = "00000000-0000-0000-0000-000000000002"

// WellKnownTenantConsumer is the UUID of the HexxLock B2C consumer tenant.
// All public-facing HexxLock services (mail, docs, storage) place self-registered
// end-users into this tenant. It lives in the shared realm alongside other
// customer tenants and is the target for Home Realm Discovery's 'consumer_pool'
// policy (see migration 204).
var WellKnownTenantConsumer = uuid.MustParse("00000000-0000-0000-0000-000000000004")
