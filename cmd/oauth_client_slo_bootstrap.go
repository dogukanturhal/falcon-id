// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// bootstrapOAuthClientSLOSeed idempotently enforces the canonical
// Single Logout (SLO) endpoints + NIST SP 800-63B-4 §5.2-anchored
// token lifetimes on every first-party OAuth client managed by the
// platform.
//
// WHY THIS LIVES IN THE GO BOOT HOOK
// ===================================
// The legacy seed mechanism was SQL migrations 217 (BCL URIs) +
// 219 (FCL URIs) authored alongside falcon-id !61 / talon !30 /
// frontend !17. The 2026-05-07 cluster-recovery event produced a
// `falcon-id-pg` fresh-initdb that did not re-execute those
// migrations under the new Keystone-managed schema, leaving every
// row's `backchannel_logout_uri` / `frontchannel_logout_uri` NULL.
// The OP-side BackchannelLogoutService.NotifyLogout silently
// fanned out to zero RPs for several days before being noticed
// during the 2026-05-10 audit
// (docs/audits/2026-05-10-slo-bcl-fcl-regression.md).
//
// Per the operational notes
// + operational notes, the
// canonical place for sentinel-row data — including SLO endpoints
// and token lifetimes — is the Go boot hook, NOT a SQL migration.
// Boot hooks are:
//
//   - idempotent across fresh-initdb (run on every pod restart)
//   - direct DB access (no /oauth/token, no realm gate, no MFA)
//   - testable via standard Go unit tests
//   - converged-by-design (target == desired; drift heals on next restart)
//
// PER-CLIENT MATRIX
// =================
// Each entry below is the canonical desired state for one OAuth
// client. The boot hook fetches the row by client_id, compares with
// the desired state, and patches only the fields that differ. If the
// row does not exist, the entry is SKIPPED — row creation is owned
// by either `bootstrapProvisionerOAuthClient` (svc-serviceclient-
// provisioner) or the per-service Crossplane Composition's
// provisioning Job (every other svc-*). This boot hook ENRICHES
// existing rows; it does NOT create them.
//
// The matrix matches the audit table in
// docs/audits/2026-05-10-slo-bcl-fcl-regression.md and the TTL plan
// in the same document's NIST §5.2 alignment.
//
// ABOUT BCL/FCL URIs
// ==================
// Only RPs with a SHIPPING receiver get backchannel_logout_uri and
// frontchannel_logout_uri populated. Today that's `svc-talon`
// (`talon !30` ships /auth/backchannel-logout + /auth/frontchannel-logout)
// and `svc-accounts` (`frontend !17` ships /api/auth/backchannel-logout +
// /api/auth/frontchannel-logout). Seeding URIs on RPs that have no
// receiver would cause every Sign Out fan-out to log a 4xx delivery
// error and incremennt iam_oauth_bcl_deliveries_total{status="client_error"}
// — we'd rather have zero noise than a permanent false-positive.
//
// Future RPs gain BCL/FCL URIs by being added to this matrix as soon
// as their receiver lands; the XServiceClient XRD's
// `backchannelLogoutURI` / `frontchannelLogoutURI` plumbing
// (Phase 4 in the Tier-1 SLO restoration plan) makes that one MR
// rather than one per-client.
//
// ABOUT TOKEN LIFETIMES
// =====================
// Lifetimes follow the matrix in the same docs/audits/ file:
//   - admin tier (svc-talon, svc-argocd, svc-grafana, svc-awx,
//     svc-dojo, svc-sonarqube, svc-vault, svc-gitlab, svc-harbor):
//     15min/15min/8h (NIST AAL2, bounded revocation latency).
//   - customer tier (svc-accounts): 60min/60min/30d (NIST AAL1/2).
//   - svc-integration-bus (client_credentials only, no end-user):
//     60min/60min/30d — refresh_token lifetime is unused but the
//     schema requires non-null; we keep the canonical value.
//
// FAILURE MODE
// ============
// Errors at the per-client level are logged at ERROR but do not
// short-circuit subsequent clients. The function never panics; the
// application MUST come up to serve health probes regardless. A
// missing or unconverged row surfaces operationally via the
// `iam_oauth_bcl_no_clients_total{tenant_id}` metric and the
// AlertManager rule that watches it.
func bootstrapOAuthClientSLOSeed(repos *Repositories) {
	if repos == nil || repos.OAuthClient == nil {
		logger.Warn("bootstrapOAuthClientSLOSeed: repository not wired, skipping")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// updatedBy is intentionally nil for system-initiated seed writes.
	// Schema permits NULL on iam_oauth_clients.updated_by; the audit
	// trail relies on the structured log line + Phase 6 audit-archiver
	// event, not the FK.
	for _, desired := range oauthClientSLOSeedMatrix {
		applyOAuthClientSLODesired(ctx, repos.OAuthClient, desired)
	}
}

// oauthClientSeedRepo is the minimal interface
// bootstrapOAuthClientSLOSeed needs from the OAuth client repository.
// Defined locally (rather than as a public interface in
// internal/repositories) so the seed boot hook is testable without
// pulling in the full pgxpool-backed repository — *repositories.OAuthClientRepository
// satisfies this implicitly via Go duck typing.
type oauthClientSeedRepo interface {
	GetByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error)
	Update(ctx context.Context, client *models.OAuthClient) error
}

// oauthClientSLOSeedDesired is the canonical desired state for one
// row in iam_oauth_clients managed by bootstrapOAuthClientSLOSeed.
type oauthClientSLOSeedDesired struct {
	// ClientID is the iam_oauth_clients.client_id PK lookup key.
	ClientID string

	// BackchannelLogoutURI: pointer because *string in the model.
	// nil = no BCL receiver (do not seed; intentionally NULL in DB).
	// non-nil = canonical receiver URL on a deployed first-party RP.
	BackchannelLogoutURI *string
	// BackchannelLogoutSessionRequired: ALWAYS true for first-party
	// receivers — both Talon and accounts BFF cascade per-sid (not
	// only per-sub) so they need `sid` in the logout_token.
	BackchannelLogoutSessionRequired bool

	FrontchannelLogoutURI             *string
	FrontchannelLogoutSessionRequired bool

	// AccessTokenLifetime, IDTokenLifetime, RefreshTokenLifetime in
	// seconds. Zero means "do not enforce" (preserve existing).
	AccessTokenLifetime  int
	IDTokenLifetime      int
	RefreshTokenLifetime int
}

// applyOAuthClientSLODesired fetches one row by client_id, compares
// with the desired state, and Updates only when fields differ.
// Missing rows are skipped (creation is the per-service Crossplane
// Job's responsibility).
func applyOAuthClientSLODesired(ctx context.Context, repo oauthClientSeedRepo, desired oauthClientSLOSeedDesired) {
	row, err := repo.GetByClientID(ctx, desired.ClientID)
	if err != nil {
		if errors.Is(err, repositories.ErrOAuthClientNotFound) {
			logger.Debug("bootstrapOAuthClientSLOSeed: client not present, skipping (row owned by per-service Crossplane Job)",
				zap.String("client_id", desired.ClientID),
			)
			return
		}
		logger.Error("bootstrapOAuthClientSLOSeed: failed to fetch client",
			zap.String("client_id", desired.ClientID),
			zap.Error(err),
		)
		return
	}

	changed := mergeSLODesired(row, desired)
	if !changed {
		logger.Debug("bootstrapOAuthClientSLOSeed: client already at desired state",
			zap.String("client_id", desired.ClientID),
		)
		return
	}

	row.UpdatedAt = time.Now().UTC()
	if err := repo.Update(ctx, row); err != nil {
		logger.Error("bootstrapOAuthClientSLOSeed: failed to update client",
			zap.String("client_id", desired.ClientID),
			zap.Error(err),
		)
		return
	}

	logger.Info("bootstrapOAuthClientSLOSeed: applied SLO + TTL desired state",
		zap.String("client_id", desired.ClientID),
		zap.Stringp("backchannel_logout_uri", desired.BackchannelLogoutURI),
		zap.Bool("backchannel_session_required", desired.BackchannelLogoutSessionRequired),
		zap.Stringp("frontchannel_logout_uri", desired.FrontchannelLogoutURI),
		zap.Bool("frontchannel_session_required", desired.FrontchannelLogoutSessionRequired),
		zap.Int("access_token_lifetime", desired.AccessTokenLifetime),
		zap.Int("id_token_lifetime", desired.IDTokenLifetime),
		zap.Int("refresh_token_lifetime", desired.RefreshTokenLifetime),
	)
}

// mergeSLODesired patches the OAuthClient row in-place with desired
// state, returning true iff at least one field changed.
//
// For lifetime fields, a zero in `desired` means "do not override"
// (used for client_credentials clients where the schema requires
// non-null but the value is unused). Pointer fields propagate
// directly: nil-in-desired clears the column, non-nil writes the
// new URI.
func mergeSLODesired(row *models.OAuthClient, desired oauthClientSLOSeedDesired) bool {
	changed := false

	if !equalStringPtr(row.BackchannelLogoutURI, desired.BackchannelLogoutURI) {
		row.BackchannelLogoutURI = desired.BackchannelLogoutURI
		changed = true
	}
	if row.BackchannelLogoutSessionRequired != desired.BackchannelLogoutSessionRequired {
		row.BackchannelLogoutSessionRequired = desired.BackchannelLogoutSessionRequired
		changed = true
	}
	if !equalStringPtr(row.FrontchannelLogoutURI, desired.FrontchannelLogoutURI) {
		row.FrontchannelLogoutURI = desired.FrontchannelLogoutURI
		changed = true
	}
	if row.FrontchannelLogoutSessionRequired != desired.FrontchannelLogoutSessionRequired {
		row.FrontchannelLogoutSessionRequired = desired.FrontchannelLogoutSessionRequired
		changed = true
	}

	if desired.AccessTokenLifetime != 0 && row.AccessTokenLifetime != desired.AccessTokenLifetime {
		row.AccessTokenLifetime = desired.AccessTokenLifetime
		changed = true
	}
	if desired.IDTokenLifetime != 0 && row.IDTokenLifetime != desired.IDTokenLifetime {
		row.IDTokenLifetime = desired.IDTokenLifetime
		changed = true
	}
	if desired.RefreshTokenLifetime != 0 && row.RefreshTokenLifetime != desired.RefreshTokenLifetime {
		row.RefreshTokenLifetime = desired.RefreshTokenLifetime
		changed = true
	}

	return changed
}

// equalStringPtr returns true iff two *string values are semantically
// equal (both nil, or both non-nil with equal values). Used because
// the model's *string fields would otherwise misreport "changed" on
// every restart — `reflect.DeepEqual` returns false for two distinct
// non-nil pointers regardless of pointed-to value.
func equalStringPtr(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// stringPtr is a one-call helper for embedding string literals in the
// SLO seed matrix without `s := "..."; ptr := &s` boilerplate.
func stringPtr(s string) *string {
	return &s
}

// oauthClientSLOSeedMatrix is the source of truth for SLO endpoints
// and token lifetimes on every first-party OAuth client. See the
// package-level comment on bootstrapOAuthClientSLOSeed for rationale.
//
// Lifetimes (seconds):
//
//	admin   = AccessToken=900 (15m), IDToken=900, RefreshToken=28800 (8h)
//	customer = AccessToken=3600 (1h), IDToken=3600, RefreshToken=2592000 (30d)
//	m2m     = AccessToken=3600, IDToken=3600 (unused), RefreshToken=2592000 (unused)
//
// `svc-serviceclient-provisioner` (the Crossplane provisioner client,
// dWqlfMOxNlth6wAqfUUJ3g in live prod) is intentionally absent —
// `bootstrapProvisionerOAuthClient` owns its desired state and
// applies its own m2m TTLs (cmd/oauth_provisioner_bootstrap.go:198-205).
var oauthClientSLOSeedMatrix = []oauthClientSLOSeedDesired{
	// Admin-tier IAP (Talon) — sole shipping BCL+FCL receiver for *.internal.example.com.
	// Receivers: talon !30 + feat/tier1-frontchannel-logout-receiver.
	{
		ClientID:                          "svc-talon",
		BackchannelLogoutURI:              stringPtr("https://auth.internal.example.com/auth/backchannel-logout"),
		BackchannelLogoutSessionRequired:  true,
		FrontchannelLogoutURI:             stringPtr("https://auth.internal.example.com/auth/frontchannel-logout"),
		FrontchannelLogoutSessionRequired: true,
		AccessTokenLifetime:               900,
		IDTokenLifetime:                   900,
		RefreshTokenLifetime:              28800,
	},
	// Customer-tier identity portal — accounts BFF.
	// Receivers: frontend !17 (validateBclClaims with 15 conformance tests).
	{
		ClientID:                          "svc-accounts",
		BackchannelLogoutURI:              stringPtr("https://accounts.example.com/api/auth/backchannel-logout"),
		BackchannelLogoutSessionRequired:  true,
		FrontchannelLogoutURI:             stringPtr("https://accounts.example.com/api/auth/frontchannel-logout"),
		FrontchannelLogoutSessionRequired: true,
		AccessTokenLifetime:               3600,
		IDTokenLifetime:                   3600,
		RefreshTokenLifetime:              2592000,
	},

	// Admin-tier dual-RP apps fronted by Talon. Each runs its own OIDC
	// RP against Falcon-ID for app-level RBAC; SLO at the IAP layer
	// (Talon's `talon:revoke-by-sub` Redis cascade) covers the user-
	// facing logout. None of these upstreams ship a BCL/FCL receiver
	// today; revocation is bounded by access_token TTL (15min) +
	// refresh-token revocation via /oauth/revoke (RFC 7009, Phase 5a).
	{
		ClientID:             "svc-argocd",
		AccessTokenLifetime:  900,
		IDTokenLifetime:      900,
		RefreshTokenLifetime: 28800,
	},
	{
		ClientID:             "svc-grafana",
		AccessTokenLifetime:  900,
		IDTokenLifetime:      900,
		RefreshTokenLifetime: 28800,
	},
	{
		ClientID:             "svc-awx",
		AccessTokenLifetime:  900,
		IDTokenLifetime:      900,
		RefreshTokenLifetime: 28800,
	},
	{
		ClientID:             "svc-dojo",
		AccessTokenLifetime:  900,
		IDTokenLifetime:      900,
		RefreshTokenLifetime: 28800,
	},
	{
		ClientID:             "svc-sonarqube",
		AccessTokenLifetime:  900,
		IDTokenLifetime:      900,
		RefreshTokenLifetime: 28800,
	},
	{
		ClientID:             "svc-vault",
		AccessTokenLifetime:  900,
		IDTokenLifetime:      900,
		RefreshTokenLifetime: 28800,
	},

	// Customer-tier third-party apps (NOT behind Talon) — direct
	// Traefik IngressRoute, own OIDC RP. Neither GitLab CE nor Harbor
	// ships an upstream BCL receiver natively (gitlab-org/gitlab#449119
	// still open; goharbor/harbor#12634 closed for RP-Initiated only).
	// To close the cascade gap, the platform deploys in-cluster Go
	// shims (`platform-tools/bcl-receiver`) that accept logout_token
	// POSTs and translate them into upstream admin-API calls (GitLab
	// admin block-user, Harbor admin user-disable). Receivers are
	// reachable at the cluster-internal Service DNS — no FCL because
	// the shim is a server-to-server endpoint, not an iframe.
	//
	// FCL is intentionally NOT seeded for svc-gitlab/svc-harbor: the
	// shim is a server endpoint, not an iframe target.
	{
		ClientID:                         "svc-gitlab",
		BackchannelLogoutURI:             stringPtr("http://gitlab-bcl-receiver.gitlab-bcl-receiver.svc.cluster.local:8080/backchannel-logout"),
		BackchannelLogoutSessionRequired: true,
		AccessTokenLifetime:              900,
		IDTokenLifetime:                  900,
		RefreshTokenLifetime:             28800,
	},
	{
		ClientID:                         "svc-harbor",
		BackchannelLogoutURI:             stringPtr("http://harbor-bcl-receiver.harbor-bcl-receiver.svc.cluster.local:8080/backchannel-logout"),
		BackchannelLogoutSessionRequired: true,
		AccessTokenLifetime:              900,
		IDTokenLifetime:                  900,
		RefreshTokenLifetime:             28800,
	},

	// Service-to-service M2M client_credentials. ID-token / refresh-
	// token are unused by the client_credentials grant but the schema
	// requires non-null int columns; we set the canonical defaults.
	{
		ClientID:             "svc-integration-bus",
		AccessTokenLifetime:  3600,
		IDTokenLifetime:      3600,
		RefreshTokenLifetime: 2592000,
	},
}

