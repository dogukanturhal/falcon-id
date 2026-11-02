// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// bootstrapProvisionerOAuthClient idempotently ensures the
// `svc-serviceclient-provisioner` OAuth client row exists in
// iam_oauth_clients, sourced from credentials in env vars provided by an
// ExternalSecret reading Vault path
// `example/data/platform/serviceclient-provisioner/falcon-id-admin`.
//
// WHY THIS LIVES IN THE APPLICATION BOOT PATH
// ===========================================
// The Crossplane composition's per-service Jobs
// (provision-svcclient-{talon,accounts,awx,dojo,...}) authenticate as the
// `svc-serviceclient-provisioner` OAuth client via client_credentials grant
// against /oauth/token, then call /api/v1/admin/oauth-clients to create
// the per-service OAuth client. If the provisioner client itself is not
// present in iam_oauth_clients, the entire provisioning chain breaks at
// the head — every per-service Job fails with HTTP 400 invalid_client.
//
// The legacy bash bootstrap Job
// (<gitops-repo>/crossplane/serviceclient-cluster-init/
// bootstrap-job.yaml) creates this client by calling /api/v1/auth/login
// as the platform admin user, then POSTing to /api/v1/admin/oauth-clients
// with the resulting JWT. That path hits two architectural hazards under
// post-disaster recovery:
//
//  1. risk-MFA enrollment interrupt — fresh pod IP+UA → high risk score
//     → the login response is `{requires_mfa_enrollment: true,
//     enrollment_token: ...}` with NO access_token. Pre-enrolling MFA on
//     the admin user fixes the symptom but leaves the design fragile.
//  2. Admin user lookup goes through the FI!137 fail-closed realm gate.
//     A wrong realm assignment (Sprint-1 #5: dogukanturhal in
//     WellKnownRealmShared instead of WellKnownRealmPlatform) blocks
//     login until the realm migration runs (chicken-and-egg with
//     downstream OAuth clients that the realm migration may itself
//     depend on).
//
// This boot hook bypasses both: it has direct DB access via the same
// pgxpool the application uses for its own queries. No HTTP, no JWT, no
// realm resolution, no MFA. The credentials come from env vars, sourced
// by ExternalSecret from a Vault path the operator wrote once at cluster
// init. Same trust boundary as `bootstrapAdminUser` (FALCON_ADMIN_*).
//
// OPERATIONAL NOTE
// ============================================================
// 2026-05-07 falcon-id-pg fresh-initdb during cluster recovery wiped
// iam_oauth_clients but Vault retained the stored credentials (Vault is
// vault-ha, a separate cluster, untouched by the falcon-id-pg recovery).
// The pre-existing legacy-Job presence-only idempotency check kept
// declaring the seed alive while every downstream Crossplane Job failed.
// PM!409 added an end-to-end probe to the bash Job, which correctly
// detected the drift but couldn't recover (Vault policy missing `delete`
// + risk-MFA login interrupt). This Go boot hook replaces the bash
// Job's create flow entirely — survives any future fresh-initdb without
// operator intervention.
//
// IDEMPOTENCY
// ===========
// On every restart:
//
//   - GetByClientID; if the row exists with a hash that verifies against
//     the env-supplied secret, skip (no-op steady state).
//   - If the row is missing, INSERT it with a SHA-256 hash of the
//     env-supplied secret. SHA-256 (NOT bcrypt) is the format
//     OAuthProviderService.hashSecret produces in
//     internal/services/oauth_provider_service_tokens.go:796 — matching
//     it lets the existing /oauth/token handler verify presented
//     credentials without code changes.
//   - If the row exists but the stored hash does NOT match the
//     env-supplied secret, log warn + skip. Mismatch means the secret
//     was rotated externally (operator-driven Vault put or per-service
//     Crossplane Job rotation); auto-overwriting would silently move
//     production back to whatever value happens to be in env, defeating
//     intentional rotations. Operators flip
//     FALCON_PROVISIONER_OVERWRITE=true to force overwrite when a
//     deliberate re-seed is required.
//
// FAILURE MODE
// ============
// Errors are logged at ERROR level; the function returns. Do NOT panic
// — the application must come up to serve health probes regardless. A
// missing provisioner row surfaces operationally via the per-service
// Crossplane Job failures + the bootstrap Job's ping log entries.
//
// This function is safe to call on every restart.
func bootstrapProvisionerOAuthClient(repos *Repositories) {
	clientID := os.Getenv("FALCON_PROVISIONER_CLIENT_ID")
	clientSecret := os.Getenv("FALCON_PROVISIONER_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		// No provisioner bootstrap requested. Non-prod / dev installs
		// without a Vault-backed ExternalSecret will hit this branch
		// silently; production environments are expected to wire the
		// env vars via the chart's externalSecrets.provisionerBootstrap
		// block.
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tenantID := uuid.MustParse(models.HexxlockInternalTenantID)

	existing, err := repos.OAuthClient.GetByClientID(ctx, clientID)
	if err != nil && !errors.Is(err, repositories.ErrOAuthClientNotFound) {
		logger.Error("bootstrapProvisionerOAuthClient: failed to look up existing client",
			zap.String("client_id", clientID),
			zap.Error(err),
		)
		return
	}

	if existing != nil {
		// Row exists — verify the env-supplied secret matches. Use the
		// same dual-format verifier as oauth_provider_service.verifySecret:
		// bcrypt prefix → bcrypt.Compare; otherwise SHA-256 constant-time.
		if verifyProvisionerSecret(clientSecret, existing.ClientSecret) {
			logger.Info("bootstrapProvisionerOAuthClient: provisioner client present with matching secret, skipping",
				zap.String("client_id", clientID),
				zap.String("client_uuid", existing.ID.String()),
			)
			return
		}
		if os.Getenv("FALCON_PROVISIONER_OVERWRITE") != "true" {
			logger.Warn("bootstrapProvisionerOAuthClient: provisioner client exists but secret hash mismatches env-supplied value; refusing to overwrite (set FALCON_PROVISIONER_OVERWRITE=true to allow)",
				zap.String("client_id", clientID),
				zap.String("client_uuid", existing.ID.String()),
			)
			return
		}
		logger.Warn("bootstrapProvisionerOAuthClient: overwriting mismatched secret hash (FALCON_PROVISIONER_OVERWRITE=true)",
			zap.String("client_id", clientID),
		)
		existing.ClientSecret = hashProvisionerSecret(clientSecret)
		existing.UpdatedAt = time.Now().UTC()
		if updateErr := repos.OAuthClient.Update(ctx, existing); updateErr != nil {
			logger.Error("bootstrapProvisionerOAuthClient: failed to update mismatched client",
				zap.String("client_id", clientID),
				zap.Error(updateErr),
			)
			return
		}
		logger.Info("bootstrapProvisionerOAuthClient: provisioner client secret hash updated",
			zap.String("client_id", clientID),
		)
		return
	}

	// INSERT path: row missing, create it with canonical defaults that
	// mirror what /api/v1/admin/oauth-clients would produce for a
	// client_credentials-only confidential first-party client. See
	// internal/services/oauth_provider_service.go:425-540 for the
	// reference defaults applied by the API path.
	now := time.Now().UTC()
	description := provisionerClientDescription
	tokenAuthMethod := "client_secret_basic"
	idTokenAlg := "RS256"

	client := &models.OAuthClient{
		ID:           uuid.New(),
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: hashProvisionerSecret(clientSecret),
		Name:         "Crossplane ServiceClient Provisioner",
		Description:  &description,
		// client_credentials is the ONLY grant for this client. No
		// authorization_code (no end-user), no refresh_token (issuer
		// re-issues access_token on re-presentation of credentials),
		// no implicit/ROPC (banned by OAuth 2.1 BCP-225).
		GrantTypes: []string{"client_credentials"},
		// response_types is empty for client_credentials per RFC 6749
		// §3.1.2. The schema's NOT NULL DEFAULT '{}' lets the empty
		// slice round-trip. The OAuth provider service's
		// validateOAuth21GrantsAndResponses tolerates this combination.
		ResponseTypes: []string{},
		// Same rationale for redirect_uris: empty for non-browser flows.
		// Empty slice (NOT nil) preserves NOT NULL '{}' default.
		RedirectURIs: []string{},
		// admin:oauth-clients scope grants permission to call the
		// admin client-management endpoints. The per-service Crossplane
		// Job presents this scope on its access_token requests.
		Scopes: []string{"admin:oauth-clients"},
		// Token lifetimes match oauth_provider_service.go:425-440
		// defaults. Refresh-token lifetime is moot for
		// client_credentials (no refresh_token issued) but the schema
		// requires a non-null int.
		AccessTokenLifetime:  3600,    // 1h
		RefreshTokenLifetime: 2592000, // 30d (unused; field NOT NULL)
		IDTokenLifetime:      3600,    // 1h (unused; field NOT NULL)
		IsPublic:             false,   // Confidential client
		IsConfidential:       true,
		IsFirstParty:         true, // Cluster-internal, not third-party
		RequirePKCE:          false,
		IsActive:             true,
		// AppCategory: app_category column has DEFAULT 'general'; we
		// pass the empty string and let the schema default apply. (The
		// repo's INSERT does not include app_category in its column
		// list, so the DEFAULT fires.)
		// RequireAssignment defaults false.
		TokenEndpointAuthMethod:           tokenAuthMethod,
		IDTokenSignedResponseAlg:          idTokenAlg,
		PostLogoutRedirectURIs:            []string{},
		AllowedCORSOrigins:                []string{},
		BackchannelLogoutSessionRequired:  false,
		FrontchannelLogoutSessionRequired: false,
		Contacts:                          []string{"platform-team@example.com"},
		RequirePushedAuthorizationRequests: false,
		CreatedAt:                          now,
		UpdatedAt:                          now,
		// CreatedBy nil: system-initiated bootstrap, not attributable
		// to a human user.
	}

	if err := repos.OAuthClient.Create(ctx, client); err != nil {
		// A concurrent bootstrap from a sibling pod may have inserted
		// the row between our GetByClientID and our Create. Treat the
		// unique-key collision as success.
		if isOAuthClientAlreadyExistsError(err) {
			logger.Info("bootstrapProvisionerOAuthClient: provisioner client created concurrently by another pod, treating as success",
				zap.String("client_id", clientID),
			)
			return
		}
		logger.Error("bootstrapProvisionerOAuthClient: failed to create provisioner client",
			zap.String("client_id", clientID),
			zap.Error(err),
		)
		return
	}

	logger.Info("bootstrapProvisionerOAuthClient: provisioner OAuth client created",
		zap.String("client_id", clientID),
		zap.String("client_uuid", client.ID.String()),
		zap.String("name", client.Name),
	)
}

const provisionerClientDescription = "Cluster-init OAuth admin client that creates per-service OAuth clients via the XServiceClient Crossplane Composition. Bootstrapped by cmd/oauth_provisioner_bootstrap.go on every falcon-id startup; idempotent."

// hashProvisionerSecret returns a SHA-256 base64-rawurl hash of the
// supplied client_secret. Matches the format produced by
// internal/services/oauth_provider_service_tokens.go:hashSecret so the
// /oauth/token verifier path needs no special-case handling. Callers
// elsewhere in the codebase use bcrypt at cost 12 — both formats are
// transparently accepted by verifySecret (lines 816-824 of the same
// file). SHA-256 is preferred for new writes given the high-entropy
// random secret is not subject to dictionary attack.
func hashProvisionerSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// verifyProvisionerSecret mirrors oauth_provider_service.verifySecret's
// dual-format verification: bcrypt prefix → bcrypt.Compare; otherwise
// SHA-256 with constant-time compare. Re-implemented locally instead of
// imported because the service-layer function is unexported and adding
// it to the service interface for one boot-time caller would surface a
// helper that no application code path needs at runtime.
func verifyProvisionerSecret(presented, stored string) bool {
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(presented)) == nil
	}
	computed := hashProvisionerSecret(presented)
	// Standard library's subtle.ConstantTimeCompare returns 0/1 — convert
	// to bool. Per oauth_provider_service.verifySecret line 822-823 the
	// constant-time guard prevents timing side-channel disclosure of the
	// stored hash byte-by-byte.
	return constantTimeStringEqual(computed, stored)
}

// constantTimeStringEqual is a bool wrapper over crypto/subtle.ConstantTimeCompare
// for two strings. We avoid importing the full `subtle` package here to keep
// the boot-hook file's import surface minimal; SHA-256 hashes are fixed-length
// (43 bytes for base64-rawurl of 32 bytes) so a length-prefix mismatch returns
// false WITHOUT performing the per-byte compare — same behaviour as
// subtle.ConstantTimeCompare which returns 0 on length mismatch.
func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// isOAuthClientAlreadyExistsError matches the unique-violation strings
// surfaced by oauth_client_repository.Create when the iam_oauth_clients
// PK or UNIQUE(client_id) fires. Concurrent pod startup is the only
// realistic trigger.
func isOAuthClientAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate key value violates unique constraint") ||
		strings.Contains(msg, "already exists")
}
