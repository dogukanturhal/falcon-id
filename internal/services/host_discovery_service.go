// SPDX-License-Identifier: AGPL-3.0-or-later

// Package services — host_discovery_service.go
//
// Powers `GET /internal/v1/tenant-discovery?host=<host>`, the host→
// tenant resolution endpoint that the unified-dashboard Next.js SDK
// calls from inside the cluster to figure out which tenant a request
// belongs to when the customer access the SaaS app via a custom
// domain (e.g., crm.acme-corp.com).
//
// Design synthesized from cross-vendor research on Auth0 / Okta /
// Microsoft Entra B2C / AWS Cognito / Cloudflare Access custom-
// domain implementations:
//
//   - Host is normalized lowercase + IDNA-encoded (RFC 4343 + RFC 3492)
//     before any lookup. Defends against case-variant + Unicode-spoof
//     enumeration. Matches every reference platform.
//   - In-process LRU cache: 5-minute positive TTL, 30-second negative
//     TTL. Industry consensus from OIDC core + WorkOS / SSOJet
//     writeups; at ~10 verified hosts the whole table fits in RAM so
//     cache hit rate trends to 100%.
//   - Hard 404 on unknown host, 410 Gone on suspended, 503 on
//     pending verification (DNS propagation window). NO silent
//     default-realm fallback — host is authoritative.
//   - The branding payload in the response is the merge of tenant-
//     level branding (iam_tenant_branding) and the optional host-
//     scoped override (iam_tenant_hosts.branding_override).
package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"golang.org/x/net/idna"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// VerificationDNSPrefix is the label prefix for the TXT record the
// customer must publish to prove control of a custom domain. Reuses
// the same prefix used by the existing email-domain verification path
// (shareddomain.VerificationDNSPrefix) so customers see a consistent
// verification UX across email-domain + custom-host claim flows.
const VerificationDNSPrefix = "_hexxlock-verify"

// HostDiscoveryRepoIface is the persistence contract HostDiscoveryService
// depends on. Defined as a narrow interface here (not the concrete
// repository) so the service is testable without a real database.
//
// Tenant-default branding merge (iam_tenant_branding) is deferred —
// host-level branding_override on iam_tenant_hosts is sufficient for
// the v1 custom-domain use case; the tenant-default merge can be
// added behind this same service entry point without breaking
// callers.
type HostDiscoveryRepoIface interface {
	GetByHost(ctx context.Context, host string) (*models.TenantHost, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.TenantHost, error)
	GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.TenantHost, error)
	Create(ctx context.Context, h *models.TenantHost) error
	MarkVerified(ctx context.Context, id uuid.UUID) error
	RecordVerificationFailure(ctx context.Context, id uuid.UUID) error
	Suspend(ctx context.Context, id uuid.UUID) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// TenantSlugRepoIface is the narrow persistence contract DiscoverBySlug
// depends on (satisfied by *repositories.TenantRepository). Narrow, like
// HostDiscoveryRepoIface above, so DiscoverBySlug is testable without a
// real database.
type TenantSlugRepoIface interface {
	GetBySlug(ctx context.Context, slug string) (*models.Tenant, error)
}

// tenantStatusActive / tenantStatusTrial are the iam_tenants.status
// values DiscoverBySlug treats as "servable" (200). Every other status
// (suspended, cancelled, or anything unrecognized) maps to 410 — see
// DiscoverBySlug. Kept as unexported string constants here rather than a
// models.TenantStatus enum: iam_tenants.status has never had one (see
// models.Tenant.Status doc), and introducing one is out of scope for this
// discovery endpoint.
const (
	tenantStatusActive = "active"
	tenantStatusTrial  = "trial"
)

// HostDiscoveryService is the orchestrator: cache-front, repo-back,
// branding-merge, error-mapping. Also exposes admin methods (Claim,
// List, VerifyOne, Suspend, Delete) that share the cache so writes
// invalidate reads atomically.
type HostDiscoveryService struct {
	repo        HostDiscoveryRepoIface
	resolver    DNSResolver
	logger      *zap.Logger
	positiveTTL time.Duration
	negativeTTL time.Duration
	cacheMu     sync.RWMutex
	cache       map[string]hostCacheEntry

	// tenantRepo backs DiscoverBySlug (the slug-lookup sibling of the
	// host lookup above). nil until SetTenantRepository is called — see
	// DiscoverBySlug's ErrTenantSlugUnconfigured handling.
	tenantRepo TenantSlugRepoIface
	// slugCache is a SEPARATE map from `cache` (guarded by the same
	// cacheMu) rather than a second HostDiscoveryService-shaped struct,
	// so slug discovery shares this service's locking, construction, and
	// TTL fields instead of forking a parallel cache implementation.
	// Host cache keys are normalized hostnames (always contain a dot);
	// slug cache keys are bare tenant slugs (never contain a dot, see
	// TENANT_SLUG_REGEX) — the two key spaces cannot collide, but they
	// are kept in separate maps anyway so a host and a slug that happened
	// to share a string could never shadow each other's entry.
	slugCache map[string]slugCacheEntry
}

type hostCacheEntry struct {
	// resp is nil for negative cache entries (host not found).
	resp      *models.HostDiscoveryResponse
	notFound  bool
	expiresAt time.Time
}

type slugCacheEntry struct {
	// resp is nil for negative cache entries (slug not found). A resp
	// with a non-servable Status (see tenantStatusActive/tenantStatusTrial)
	// is cached POSITIVELY (the slug is real) but DiscoverBySlug still
	// returns ErrTenantSlugSuspended for it on every read, cached or not.
	resp      *models.TenantSlugDiscoveryResponse
	notFound  bool
	expiresAt time.Time
}

// NewHostDiscoveryService builds a HostDiscoveryService with sane
// defaults (5-minute positive cache, 30-second negative cache, default
// DNS resolver). Pass `nil` for logger to no-op; pass `nil` for
// resolver to use `net.DefaultResolver` (production default).
func NewHostDiscoveryService(repo HostDiscoveryRepoIface, resolver DNSResolver, logger *zap.Logger) *HostDiscoveryService {
	if logger == nil {
		logger = zap.NewNop()
	}
	if resolver == nil {
		resolver = &netHostDiscoveryDNSResolver{}
	}
	return &HostDiscoveryService{
		repo:        repo,
		resolver:    resolver,
		logger:      logger,
		positiveTTL: 5 * time.Minute,
		negativeTTL: 30 * time.Second,
		cache:       make(map[string]hostCacheEntry),
		slugCache:   make(map[string]slugCacheEntry),
	}
}

// SetTenantRepository injects the slug-lookup dependency backing
// DiscoverBySlug. A post-construction setter — like
// MagicLinkService.SetTenantRepository / InvitationService.SetTenantRepository
// elsewhere in this package — rather than a NewHostDiscoveryService
// parameter, since this service predates the slug-discovery requirement
// and every existing call site would otherwise need updating for a
// dependency most of them don't need.
func (s *HostDiscoveryService) SetTenantRepository(repo TenantSlugRepoIface) {
	s.tenantRepo = repo
}

// netHostDiscoveryDNSResolver wraps net.DefaultResolver. Separate type
// from the existing netDNSResolver in domain_verification_worker.go
// only to avoid name collision; behavior is identical.
type netHostDiscoveryDNSResolver struct{}

func (r *netHostDiscoveryDNSResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, host)
}

// SetTTLs allows tests / callers to override the cache TTLs.
func (s *HostDiscoveryService) SetTTLs(positive, negative time.Duration) {
	if positive > 0 {
		s.positiveTTL = positive
	}
	if negative > 0 {
		s.negativeTTL = negative
	}
}

// ErrHostNotFound is returned when the host has no row in iam_tenant_hosts.
// The handler maps this to HTTP 404.
var ErrHostNotFound = errors.New("host_discovery: not found")

// ErrHostSuspended is returned for status=suspended rows. The handler
// maps this to HTTP 410 Gone.
var ErrHostSuspended = errors.New("host_discovery: suspended")

// ErrHostClaimed is returned by RegisterVerifiedHost when the hostname
// is already registered to a DIFFERENT tenant. The handler maps this
// to HTTP 409 Conflict.
var ErrHostClaimed = errors.New("host_discovery: host claimed by another tenant")

// ErrHostPending is returned for status=pending_verification rows.
// The handler maps this to HTTP 503 Service Unavailable.
var ErrHostPending = errors.New("host_discovery: pending verification")

// NormalizeHost converts a raw Host header value into the canonical
// lookup key:
//
//  1. Strip port suffix (":443", ":80", any explicit port)
//  2. Trim whitespace + trailing dot (RFC 1034 absolute notation)
//  3. Lowercase ASCII
//  4. IDNA-encode (Unicode → xn--… punycode)
//
// Returns an error for empty / malformed values so callers can
// reject with 400 BadRequest before hitting the DB.
func NormalizeHost(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("normalize: empty host")
	}
	// Strip port. Hostnames don't legitimately contain ':'; the only
	// non-port use is IPv6 literals which we don't accept for tenant
	// hosts (custom domains are FQDNs, not IPs).
	if idx := strings.IndexByte(s, ':'); idx != -1 {
		s = s[:idx]
	}
	// Trim trailing dot from absolute DNS notation.
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("normalize: empty after trim")
	}
	// IDNA-encode (handles uppercase → lowercase as a side effect for
	// ASCII; for Unicode it applies UTS #46 + RFC 3492 punycode).
	// idna.Lookup is the lenient profile suitable for runtime input.
	encoded, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("normalize: idna: %w", err)
	}
	if len(encoded) > 253 {
		return "", fmt.Errorf("normalize: host exceeds RFC 1035 max length (253)")
	}
	return encoded, nil
}

// Discover is the public entry point. Performs normalization → cache
// check → DB lookup → branding merge → response build. Returns the
// sentinel errors ErrHostNotFound / ErrHostSuspended / ErrHostPending
// so the handler can map to HTTP status without leaking internals.
func (s *HostDiscoveryService) Discover(ctx context.Context, rawHost string) (*models.HostDiscoveryResponse, error) {
	host, err := NormalizeHost(rawHost)
	if err != nil {
		return nil, fmt.Errorf("Discover: %w", err)
	}

	// Cache check (read lock).
	s.cacheMu.RLock()
	if entry, ok := s.cache[host]; ok && time.Now().Before(entry.expiresAt) {
		s.cacheMu.RUnlock()
		if entry.notFound {
			return nil, ErrHostNotFound
		}
		return entry.resp, nil
	}
	s.cacheMu.RUnlock()

	// Cache miss — hit DB.
	row, err := s.repo.GetByHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("Discover: repo: %w", err)
	}
	if row == nil {
		s.storeNegative(host)
		return nil, ErrHostNotFound
	}

	switch row.Status {
	case models.TenantHostStatusSuspended:
		// Suspended hosts are NOT cached positively (admin may un-
		// suspend at any moment); negative-cache the lookup briefly
		// to avoid hammer-spam from a misbehaving client.
		s.storeNegative(host)
		return nil, ErrHostSuspended
	case models.TenantHostStatusPendingVerification:
		s.storeNegative(host)
		return nil, ErrHostPending
	case models.TenantHostStatusActive:
		// Fall through.
	default:
		s.logger.Warn("host_discovery: unknown status — treating as pending",
			zap.String("host", host),
			zap.String("status", string(row.Status)),
		)
		s.storeNegative(host)
		return nil, ErrHostPending
	}

	resp := &models.HostDiscoveryResponse{
		TenantID:        row.TenantID,
		Host:            row.Host,
		CanonicalURL:    row.CanonicalURL,
		Issuer:          row.CanonicalURL,
		Status:          row.Status,
		DefaultClientID: row.DefaultClientID,
		VerifiedAt:      row.VerifiedAt,
	}
	if len(row.BrandingOverride) > 0 {
		var b map[string]any
		if err := json.Unmarshal(row.BrandingOverride, &b); err == nil {
			resp.Branding = b
		}
	}

	s.storePositive(host, resp)
	return resp, nil
}

// Invalidate clears a single host from the cache. Called from admin
// write-paths (host create / verify / suspend / delete) so the next
// discovery read sees the new state immediately. Per the WorkOS
// consensus: "5-minute TTL, immediate purge on admin write."
func (s *HostDiscoveryService) Invalidate(rawHost string) {
	host, err := NormalizeHost(rawHost)
	if err != nil {
		return
	}
	s.cacheMu.Lock()
	delete(s.cache, host)
	s.cacheMu.Unlock()
}

// InvalidateAll clears the entire cache. Used by the daily re-
// verification cron after a batch update transitions multiple rows.
func (s *HostDiscoveryService) InvalidateAll() {
	s.cacheMu.Lock()
	s.cache = make(map[string]hostCacheEntry)
	s.cacheMu.Unlock()
}

// ErrTenantSlugNotFound is returned by DiscoverBySlug when no iam_tenants
// row matches the slug. The handler maps this to HTTP 404 — same
// "no silent fallback" contract as ErrHostNotFound above.
var ErrTenantSlugNotFound = errors.New("host_discovery: tenant slug not found")

// ErrTenantSlugSuspended is returned by DiscoverBySlug when the slug
// resolves to a real tenant whose status is not in the servable set
// (tenantStatusActive / tenantStatusTrial) — e.g. suspended or
// cancelled. The handler maps this to HTTP 410 Gone, mirroring
// ErrHostSuspended.
var ErrTenantSlugSuspended = errors.New("host_discovery: tenant suspended")

// ErrTenantSlugUnconfigured is returned when DiscoverBySlug is called
// before SetTenantRepository has wired a repository in. This is a
// startup wiring bug, not a genuine negative discovery result, so the
// handler maps it to HTTP 500 — it must surface as an operational
// alarm, never as an indistinguishable 404 for every slug.
var ErrTenantSlugUnconfigured = errors.New("host_discovery: tenant slug discovery not configured")

// DiscoverBySlug resolves a tenant SLUG (as opposed to Discover's HOST
// lookup) to its tenant record, for the base-domain subdomain fail-
// closed check: `<slug>.<baseDomain>` is validated for SHAPE by
// isValidTenantSlug client-side, but shape validity says nothing about
// whether `slug` is an actual tenant. This is the existence check.
//
// Deliberately queries iam_tenants (via TenantSlugRepoIface), NOT
// iam_tenant_hosts — see TenantSlugDiscoveryResponse's doc comment for
// why routing this through the host lookup would 404 real tenants that
// never went through the onboarding "choose your subdomain" step.
//
// Cache policy mirrors Discover: 5-minute positive TTL, 30-second
// negative TTL, sharing this service's slugCache map/mutex/TTL fields
// (see the HostDiscoveryService struct doc comment above).
//
// Returns sentinel errors ErrTenantSlugNotFound / ErrTenantSlugSuspended /
// ErrTenantSlugUnconfigured so the handler can map HTTP status without
// leaking internals — same convention as Discover.
func (s *HostDiscoveryService) DiscoverBySlug(ctx context.Context, rawSlug string) (*models.TenantSlugDiscoveryResponse, error) {
	slug := strings.ToLower(strings.TrimSpace(rawSlug))
	if slug == "" {
		return nil, fmt.Errorf("DiscoverBySlug: empty slug")
	}
	if s.tenantRepo == nil {
		return nil, ErrTenantSlugUnconfigured
	}

	// Cache check (read lock).
	s.cacheMu.RLock()
	if entry, ok := s.slugCache[slug]; ok && time.Now().Before(entry.expiresAt) {
		s.cacheMu.RUnlock()
		if entry.notFound {
			return nil, ErrTenantSlugNotFound
		}
		if entry.resp != nil && !slugLifecycleDiscoverable(entry.resp) {
			return nil, ErrTenantSlugSuspended
		}
		return entry.resp, nil
	}
	s.cacheMu.RUnlock()

	// Cache miss — hit DB.
	tenant, err := s.tenantRepo.GetBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.storeNegativeSlug(slug)
			return nil, ErrTenantSlugNotFound
		}
		return nil, fmt.Errorf("DiscoverBySlug: repo: %w", err)
	}
	if tenant == nil {
		s.storeNegativeSlug(slug)
		return nil, ErrTenantSlugNotFound
	}

	resp := &models.TenantSlugDiscoveryResponse{
		TenantID:           tenant.ID,
		Slug:               tenant.Slug,
		Status:             tenant.Status,
		TrialAccessExpired: tenant.Metadata["trial_access_expired"] == true,
		RecoveryOnly:       tenant.Metadata["trial_access_expired"] == true && tenant.Metadata["has_independent_entitlements"] != true,
	}

	if !slugLifecycleDiscoverable(resp) {
		// Cache POSITIVELY here (unlike suspended hosts in Discover
		// above): the slug genuinely belongs to a real, known tenant —
		// only its serving status changed. Caching the fact avoids a
		// DB hit on every request to a suspended tenant's subdomain,
		// while DiscoverBySlug still re-evaluates Status against the
		// cached response on every read (see the cache-hit branch
		// above), so an admin reactivation is visible within one TTL
		// window instead of requiring an explicit invalidation hook.
		s.storePositiveSlug(slug, resp)
		return nil, ErrTenantSlugSuspended
	}

	s.storePositiveSlug(slug, resp)
	return resp, nil
}

// Discovery is routing, never authorization. A genuine expired-trial tenant
// can still reach login/billing and independently active comp modules. Normal
// operator suspensions/deletions remain non-discoverable without this Core
// projection marker; module and tenant-status gates enforce actual access.
func slugLifecycleDiscoverable(resp *models.TenantSlugDiscoveryResponse) bool {
	if resp.Status == tenantStatusActive || resp.Status == tenantStatusTrial {
		return true
	}
	return resp.TrialAccessExpired && (resp.Status == "suspended" || resp.Status == "canceled" || resp.Status == "cancelled")
}

func (s *HostDiscoveryService) storePositiveSlug(slug string, resp *models.TenantSlugDiscoveryResponse) {
	s.cacheMu.Lock()
	s.slugCache[slug] = slugCacheEntry{resp: resp, expiresAt: time.Now().Add(s.positiveTTL)}
	s.cacheMu.Unlock()
}

func (s *HostDiscoveryService) storeNegativeSlug(slug string) {
	s.cacheMu.Lock()
	s.slugCache[slug] = slugCacheEntry{notFound: true, expiresAt: time.Now().Add(s.negativeTTL)}
	s.cacheMu.Unlock()
}

// InvalidateSlug drops any cached DiscoverBySlug result for slug —
// the write-side sibling of Invalidate above. Not currently wired to
// any caller: iam_tenants status changes (suspend/activate) happen in
// TenantService, a separate service with no reference to this cache.
// Left available for a future caller rather than left unimplemented,
// since the 30-second negative / 5-minute positive TTL already bounds
// staleness to the same window the host-discovery cache accepts today.
func (s *HostDiscoveryService) InvalidateSlug(slug string) {
	s.cacheMu.Lock()
	delete(s.slugCache, strings.ToLower(strings.TrimSpace(slug)))
	s.cacheMu.Unlock()
}

// ─── Admin write-path methods ────────────────────────────────────────────────
//
// These methods are exposed to tenant-admin handlers under
// /api/v1/admin/tenants/:tenant_id/hosts. Each write invalidates the
// cache for the affected host so subsequent discovery reads see the
// new state immediately ("5-minute TTL, immediate purge on admin
// write" — WorkOS / SSOJet consensus).

// ClaimHostRequest is the input for ClaimHost — admin asserts they
// want to register a custom hostname for a tenant. The service
// normalizes the host, generates a 64-char verification token, and
// inserts a `pending_verification` row.
type ClaimHostRequest struct {
	TenantID         uuid.UUID       `json:"-"`
	Host             string          `json:"host" binding:"required"`
	CanonicalURL     string          `json:"canonical_url" binding:"required,url"`
	DefaultClientID  *string         `json:"default_client_id,omitempty"`
	BrandingOverride json.RawMessage `json:"branding_override,omitempty"`
}

// ClaimHost registers a new tenant host in pending_verification state.
// The returned record carries the verification_token the customer
// must publish at `_hexxlock-verify.<host>` as a TXT record before
// VerifyOne will succeed.
func (s *HostDiscoveryService) ClaimHost(ctx context.Context, req *ClaimHostRequest) (*models.TenantHost, error) {
	host, err := NormalizeHost(req.Host)
	if err != nil {
		return nil, fmt.Errorf("ClaimHost: %w", err)
	}
	if req.CanonicalURL == "" {
		return nil, fmt.Errorf("ClaimHost: canonical_url required")
	}
	token, err := generateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("ClaimHost: token gen: %w", err)
	}
	h := &models.TenantHost{
		Host:               host,
		TenantID:           req.TenantID,
		CanonicalURL:       req.CanonicalURL,
		Status:             models.TenantHostStatusPendingVerification,
		VerificationToken:  token,
		VerificationMethod: models.TenantHostVerificationMethodTXT,
		DefaultClientID:    req.DefaultClientID,
		BrandingOverride:   req.BrandingOverride,
	}
	if err := s.repo.Create(ctx, h); err != nil {
		return nil, fmt.Errorf("ClaimHost: %w", err)
	}
	s.Invalidate(req.Host)
	return h, nil
}

// ListHosts returns all hosts registered to a tenant (pending +
// active + suspended). Used by the tenant-admin UI to render the
// "Custom Domains" management page.
func (s *HostDiscoveryService) ListHosts(ctx context.Context, tenantID uuid.UUID) ([]*models.TenantHost, error) {
	hosts, err := s.repo.GetByTenantID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListHosts: %w", err)
	}
	return hosts, nil
}

// GetHost looks up a single host by primary key.
func (s *HostDiscoveryService) GetHost(ctx context.Context, id uuid.UUID) (*models.TenantHost, error) {
	h, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("GetHost: %w", err)
	}
	return h, nil
}

// VerifyOne performs an immediate TXT lookup against the customer's
// DNS for the host's verification token. On match, transitions the
// row to status='active'. On miss, increments verification_failures
// and returns ErrHostVerificationPending.
func (s *HostDiscoveryService) VerifyOne(ctx context.Context, id uuid.UUID) (*models.TenantHost, error) {
	h, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("VerifyOne: %w", err)
	}
	if h == nil {
		return nil, ErrHostNotFound
	}
	if h.Status == models.TenantHostStatusActive {
		// Idempotent — already verified.
		return h, nil
	}
	lookup := fmt.Sprintf("%s.%s", VerificationDNSPrefix, h.Host)
	records, lookupErr := s.resolver.LookupTXT(ctx, lookup)
	if lookupErr != nil {
		s.logger.Debug("TXT lookup failed during VerifyOne",
			zap.String("host", h.Host),
			zap.String("lookup", lookup),
			zap.Error(lookupErr),
		)
		_ = s.repo.RecordVerificationFailure(ctx, id)
		return nil, ErrHostVerificationPending
	}
	for _, rec := range records {
		if strings.TrimSpace(rec) == h.VerificationToken {
			if err := s.repo.MarkVerified(ctx, id); err != nil {
				return nil, fmt.Errorf("VerifyOne: MarkVerified: %w", err)
			}
			s.Invalidate(h.Host)
			// Re-fetch to return current row with verified_at set.
			updated, _ := s.repo.GetByID(ctx, id)
			if updated != nil {
				return updated, nil
			}
			h.Status = models.TenantHostStatusActive
			return h, nil
		}
	}
	_ = s.repo.RecordVerificationFailure(ctx, id)
	return nil, ErrHostVerificationPending
}

// RegisterVerifiedHostRequest is the input for RegisterVerifiedHost —
// a SERVICE (not an admin) asserts a hostname has already passed
// domain-ownership verification through its own lane and must start
// resolving in tenant-discovery immediately.
type RegisterVerifiedHostRequest struct {
	TenantID        uuid.UUID `json:"tenant_id" binding:"required"`
	Host            string    `json:"host" binding:"required"`
	CanonicalURL    string    `json:"canonical_url" binding:"required,url"`
	DefaultClientID *string   `json:"default_client_id,omitempty"`
}

// RegisterVerifiedHost upserts a tenant host directly into
// status='active'.
//
// Trust model: callers reach this only through the /internal/v1
// ServiceAuth envelope — i.e. platform services. domain-management is
// the canonical caller: it has ALREADY proven domain ownership through
// its own TXT/HTTP verification (different token than the admin lane's
// `_hexxlock-verify` flow) and provisioned edge TLS, so re-running the
// admin verification here would always fail and would duplicate work.
// The admin ClaimHost→VerifyOne lane stays unchanged for hosts managed
// directly in falcon-admin.
//
// Idempotent: re-registering an existing host for the SAME tenant
// re-activates it (e.g. after suspension); a host already claimed by a
// DIFFERENT tenant returns ErrHostClaimed so a hostile tenant cannot
// steal a hostname by re-verifying it elsewhere.
func (s *HostDiscoveryService) RegisterVerifiedHost(ctx context.Context, req *RegisterVerifiedHostRequest) (*models.TenantHost, error) {
	host, err := NormalizeHost(req.Host)
	if err != nil {
		return nil, fmt.Errorf("RegisterVerifiedHost: %w", err)
	}
	if req.CanonicalURL == "" {
		return nil, fmt.Errorf("RegisterVerifiedHost: canonical_url required")
	}

	existing, err := s.repo.GetByHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("RegisterVerifiedHost: %w", err)
	}
	if existing != nil {
		if existing.TenantID != req.TenantID {
			return nil, ErrHostClaimed
		}
		if err := s.repo.MarkVerified(ctx, existing.ID); err != nil {
			return nil, fmt.Errorf("RegisterVerifiedHost: MarkVerified: %w", err)
		}
		s.Invalidate(host)
		updated, _ := s.repo.GetByID(ctx, existing.ID)
		if updated != nil {
			return updated, nil
		}
		existing.Status = models.TenantHostStatusActive
		return existing, nil
	}

	// The row schema requires a verification token even though this lane
	// never uses it — mint one so the admin re-verify cron has something
	// consistent to check against if the host is ever re-pended.
	token, err := generateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("RegisterVerifiedHost: token gen: %w", err)
	}
	h := &models.TenantHost{
		Host:               host,
		TenantID:           req.TenantID,
		CanonicalURL:       req.CanonicalURL,
		Status:             models.TenantHostStatusPendingVerification,
		VerificationToken:  token,
		VerificationMethod: models.TenantHostVerificationMethodTXT,
		DefaultClientID:    req.DefaultClientID,
	}
	if err := s.repo.Create(ctx, h); err != nil {
		return nil, fmt.Errorf("RegisterVerifiedHost: %w", err)
	}
	if err := s.repo.MarkVerified(ctx, h.ID); err != nil {
		return nil, fmt.Errorf("RegisterVerifiedHost: MarkVerified: %w", err)
	}
	s.Invalidate(host)
	created, _ := s.repo.GetByID(ctx, h.ID)
	if created != nil {
		return created, nil
	}
	h.Status = models.TenantHostStatusActive
	return h, nil
}

// SuspendHost transitions a host to status='suspended'. Idempotent —
// suspending an already-suspended host returns the current row
// without error. Invalidates the cache so discovery reads start
// returning 410 immediately.
func (s *HostDiscoveryService) SuspendHost(ctx context.Context, id uuid.UUID) error {
	h, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("SuspendHost: %w", err)
	}
	if h == nil {
		return ErrHostNotFound
	}
	if err := s.repo.Suspend(ctx, id); err != nil {
		return fmt.Errorf("SuspendHost: %w", err)
	}
	s.Invalidate(h.Host)
	return nil
}

// DeleteHost hard-deletes a host record. Cache is purged so the next
// discovery read returns 404 immediately. Operator + reason are
// captured in the audit log at the handler layer.
func (s *HostDiscoveryService) DeleteHost(ctx context.Context, id uuid.UUID) error {
	h, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("DeleteHost: %w", err)
	}
	if h == nil {
		return ErrHostNotFound
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("DeleteHost: %w", err)
	}
	s.Invalidate(h.Host)
	return nil
}

// ErrHostVerificationPending is returned by VerifyOne when the TXT
// lookup did not yield the expected token. The handler maps this to
// HTTP 409 Conflict (admin should re-check DNS configuration), in
// contrast to ErrHostPending which is the *read*-path signal for a
// row sitting in pending_verification.
var ErrHostVerificationPending = errors.New("host_discovery: verification token not found in TXT records")

// generateVerificationToken returns a 64-character hex string backed
// by 32 bytes of crypto/rand entropy. Meets the schema CHECK
// constraint `char_length(verification_token) >= 32`.
func generateVerificationToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (s *HostDiscoveryService) storePositive(host string, resp *models.HostDiscoveryResponse) {
	s.cacheMu.Lock()
	s.cache[host] = hostCacheEntry{
		resp:      resp,
		notFound:  false,
		expiresAt: time.Now().Add(s.positiveTTL),
	}
	s.cacheMu.Unlock()
}

func (s *HostDiscoveryService) storeNegative(host string) {
	s.cacheMu.Lock()
	s.cache[host] = hostCacheEntry{
		resp:      nil,
		notFound:  true,
		expiresAt: time.Now().Add(s.negativeTTL),
	}
	s.cacheMu.Unlock()
}

// SuspendByHost suspends a host by hostname — the unregister-side of
// RegisterVerifiedHost, called by domain-management when the customer
// removes their custom domain. Returns ErrHostNotFound when no row
// exists; tenant ownership is enforced so a service acting for one
// tenant cannot suspend another tenant's host.
func (s *HostDiscoveryService) SuspendByHost(ctx context.Context, tenantID uuid.UUID, rawHost string) error {
	host, err := NormalizeHost(rawHost)
	if err != nil {
		return fmt.Errorf("SuspendByHost: %w", err)
	}
	h, err := s.repo.GetByHost(ctx, host)
	if err != nil {
		return fmt.Errorf("SuspendByHost: %w", err)
	}
	if h == nil {
		return ErrHostNotFound
	}
	if h.TenantID != tenantID {
		return ErrHostClaimed
	}
	if err := s.repo.Suspend(ctx, h.ID); err != nil {
		return fmt.Errorf("SuspendByHost: %w", err)
	}
	s.Invalidate(host)
	return nil
}
