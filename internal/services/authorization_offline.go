// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	gd "github.com/dogukanturhal/hexx-pep-core/pkg/govdecision"

	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/metrics"
)

// DDIL P3.2 — governed offline authorization.
//
// Today SpiceDB is the sole authority and every check fails CLOSED at t=0 when
// SpiceDB is unreachable (see authorization_engine.go). This file promotes the
// engine's decisions to signed, time-boxed, revocation-aware records so that
// during a SpiceDB partition falcon-id serves the last-known-good decision
// within a short, adversary-aware budget — then fails closed. It never fails
// open: an absent, expired, badly-signed, or epoch-stale record all resolve to
// "not served", leaving the engine's existing fail-closed path in control.
//
// Trust model: falcon-id is a CO-LOCATED issuer — the same process both decides
// (via SpiceDB) and enforces offline. It signs each cached decision with an
// in-memory Ed25519 key generated at startup and verifies with the matching
// public key. The signature is defence-in-depth against in-process cache
// tampering; the security-load-bearing properties are the SHORT budget and the
// revocation epoch. The cache is in-memory, so a restart wipes both the cache
// and the ephemeral key together (no stale trust survives a restart). A future
// multi-PEP deployment (decisions pushed to peer enforcers) would load the
// issuer key from Vault behind the same govdecision.Signer seam — no call-site
// change. Crypto agility (Ed25519 → ML-DSA-87 under cnsa2) is likewise handled
// inside the seam.
//
// Revocation epoch: falcon-id already bumps a per-tenant role-version counter on
// every role/permission change (redis.SessionCache.IncrementRoleVersion, e.g.
// from user_service on role assignment). We stamp that version as the
// decision's epoch and hold the last-known version
// per tenant in a tenant-scoped EpochStore. A role change advances the tenant's
// known epoch above what older cached decisions carry, so EvaluateCached denies
// them EVEN OFFLINE — this is how "revoke online AND offline" is satisfied for
// authorization. The engine exposes RevokeTenantOffline so the online
// invalidation path pushes the new epoch immediately, rather than waiting for
// the next successful online re-stamp (which a partition could indefinitely
// delay).

const (
	// offlineSubjectSep joins tenant and user into the govdecision subject.
	// A control character keeps it collision-free against UUID text.
	offlineSubjectSep = "\x1f"
	// offlineTenantSep is retained inside the subject so the tenant-scoped
	// EpochStore can recover the tenant from any subject.
	offlineTenantSep = offlineSubjectSep
)

// RoleVersionProvider yields the current per-tenant role-version counter that
// falcon-id bumps on every role/permission change. It is the revocation-epoch
// source for offline authorization. *redis.SessionCache satisfies it (and is
// the live counter wired in the runtime); *redis.PermissionCache also does.
type RoleVersionProvider interface {
	GetRoleVersion(ctx context.Context, tenantID uuid.UUID) (int64, error)
}

// offlineAuthz holds the govdecision machinery wired for falcon-id. It is nil
// when DDIL_OFFLINE_AUTHZ is disabled, in which case every method is a safe
// no-op and the engine keeps its strict fail-closed behaviour.
type offlineAuthz struct {
	evaluator   *gd.CachedEvaluator
	cache       *gd.MemoryCache
	signer      gd.Signer
	budgets     gd.Budgets
	epochs      *tenantEpochStore
	roleVer     RoleVersionProvider // optional; nil ⇒ epoch fixed at 0 (budget-only revocation)
	clockLeeway time.Duration

	// now is the time source for stamping and evaluating budgets. Defaults to
	// time.Now; overridable in tests for deterministic budget-boundary checks.
	now func() time.Time

	privilegedModules map[string]struct{}
	logger            *zap.Logger
}

// newOfflineAuthz builds the offline-authz layer from config. Returns nil when
// disabled. roleVer may be nil (offline revocation then relies on the budget
// alone; a bumped epoch cannot be observed). An error is returned only if the
// issuer keypair cannot be generated, in which case the caller MUST treat
// offline authz as unavailable (strict fail-closed) rather than proceeding.
func newOfflineAuthz(cfg *config.Config, roleVer RoleVersionProvider, logger *zap.Logger) (*offlineAuthz, error) {
	if cfg == nil || !cfg.DDILOfflineAuthzEnabled {
		return nil, nil
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	signer, verifier, err := gd.GenerateEd25519()
	if err != nil {
		return nil, err
	}

	epochs := newTenantEpochStore()
	cache := gd.NewMemoryCache()
	evaluator := gd.NewCachedEvaluator(
		verifier,
		gd.WithCache(cache),
		gd.WithEpochStore(epochs),
		gd.WithLeeway(cfg.DDILOfflineAuthzClockLeeway),
	)

	standard := cfg.DDILOfflineAuthzStandardBudget
	if standard <= 0 {
		standard = 15 * time.Minute
	}
	privileged := cfg.DDILOfflineAuthzPrivilegedBudget
	if privileged <= 0 {
		privileged = 5 * time.Minute
	}

	privModules := cfg.DDILOfflineAuthzPrivilegedModules
	if len(privModules) == 0 {
		privModules = []string{"iam", "core", "admin", "platform"}
	}
	privSet := make(map[string]struct{}, len(privModules))
	for _, m := range privModules {
		if m = strings.TrimSpace(strings.ToLower(m)); m != "" {
			privSet[m] = struct{}{}
		}
	}

	logger.Info("DDIL offline authorization enabled (P3.2)",
		zap.Duration("standard_budget", standard),
		zap.Duration("privileged_budget", privileged),
		zap.Duration("clock_leeway", cfg.DDILOfflineAuthzClockLeeway),
		zap.Strings("privileged_modules", privModules),
		zap.Bool("revocation_epoch_wired", roleVer != nil),
	)

	return &offlineAuthz{
		evaluator: evaluator,
		cache:     cache,
		signer:    signer,
		budgets: gd.Budgets{
			gd.TierStandard:   standard,
			gd.TierPrivileged: privileged,
		},
		epochs:            epochs,
		roleVer:           roleVer,
		clockLeeway:       cfg.DDILOfflineAuthzClockLeeway,
		now:               time.Now,
		privilegedModules: privSet,
		logger:            logger,
	}, nil
}

// classifyTier maps a permission/resource string to its staleness tier. A
// module-level permission ("module:resource:action") is privileged when its
// module is in the configured privileged set. Anything without a recognisable
// module segment is treated as privileged (the shorter budget) — fail-closed
// bias: when in doubt, shorten the offline window.
func (o *offlineAuthz) classifyTier(resource string) gd.Tier {
	var module string
	if i := strings.IndexByte(resource, ':'); i >= 0 {
		module = resource[:i]
	} else {
		return gd.TierPrivileged
	}
	if _, ok := o.privilegedModules[strings.ToLower(module)]; ok {
		return gd.TierPrivileged
	}
	return gd.TierStandard
}

// record caches a fresh, signed decision produced by a successful online
// SpiceDB check, stamped with the current per-tenant revocation epoch. It is a
// no-op if the layer is disabled. If the current epoch cannot be determined
// (e.g. Redis unreachable), the decision is NOT cached — caching under an
// unknown epoch could either be immediately self-revoked or, worse, survive a
// later revocation it never saw. Not caching simply falls back to fail-closed.
func (o *offlineAuthz) record(ctx context.Context, tenantID, userID uuid.UUID, resource string, allowed bool) {
	if o == nil {
		return
	}

	epoch, ok := o.currentEpoch(ctx, tenantID)
	if !ok {
		o.logger.Debug("DDIL offline authz: skipping record, epoch unavailable",
			zap.String("tenant_id", tenantID.String()),
			zap.String("resource", resource),
		)
		return
	}

	tier := o.classifyTier(resource)
	now := o.now()
	validUntil, err := o.budgets.ValidUntil(tier, now)
	if err != nil {
		// Unknown tier ⇒ no budget ⇒ do not cache (fail-closed).
		o.logger.Warn("DDIL offline authz: no budget for tier, skipping record",
			zap.String("tier", string(tier)),
			zap.String("resource", resource),
		)
		return
	}

	verdict := gd.Deny
	if allowed {
		verdict = gd.Allow
	}

	d := gd.Decision{
		Subject:    offlineSubject(tenantID, userID),
		Resource:   resource,
		Verdict:    verdict,
		IssuedAt:   now,
		ValidUntil: validUntil,
		Epoch:      epoch,
		Claims: map[string]string{
			"tenant": tenantID.String(),
			"tier":   string(tier),
		},
	}

	signed, err := gd.Sign(o.signer, d)
	if err != nil {
		o.logger.Warn("DDIL offline authz: failed to sign decision, skipping record", zap.Error(err))
		return
	}
	// IngestDecision verifies the signature, caches, and advances the tenant's
	// known epoch floor to `epoch`.
	if err := o.evaluator.IngestDecision(signed); err != nil {
		o.logger.Warn("DDIL offline authz: failed to ingest decision", zap.Error(err))
		return
	}
	metrics.RecordDDILOfflineAuthz("recorded")
}

// serve returns the last-known-good decision for the request if one is valid
// (present, correctly signed, within budget, not epoch-revoked) as of now.
// The second return is false whenever nothing may be served — the caller then
// keeps its existing fail-closed behaviour. This is the ONLY offline-grant path
// and every unhappy branch resolves to false.
func (o *offlineAuthz) serve(ctx context.Context, tenantID, userID uuid.UUID, resource string) (allowed bool, served bool) {
	if o == nil {
		return false, false
	}
	req := gd.Request{
		Subject:  offlineSubject(tenantID, userID),
		Resource: resource,
		Tier:     o.classifyTier(resource),
	}
	d, ok := o.evaluator.EvaluateCached(ctx, req, o.now())
	if !ok {
		// Distinguish the fail-closed reason for observability without ever
		// changing the outcome (still not served).
		metrics.RecordDDILOfflineAuthz(o.denyReason(req))
		return false, false
	}
	if d.Verdict == gd.Allow {
		metrics.RecordDDILOfflineAuthz("served_allow")
		return true, true
	}
	metrics.RecordDDILOfflineAuthz("served_deny")
	return false, true
}

// denyReason classifies why EvaluateCached refused to serve, for metrics only.
// It never affects the decision. Order mirrors the evaluator's own gate order.
func (o *offlineAuthz) denyReason(req gd.Request) string {
	now := o.now()
	d, present := o.cache.Get(req.Subject, req.Resource)
	if !present {
		return "denied_no_cache"
	}
	if now.After(d.ValidUntil.Add(o.clockLeeway)) {
		return "denied_expired"
	}
	if d.Epoch < o.evaluator.KnownEpoch(req.Subject) {
		return "denied_revoked"
	}
	return "denied_no_cache"
}

// revokeTenant advances the tenant's known revocation epoch, immediately
// voiding every cached decision that tenant holds under an older epoch — even
// while SpiceDB is unreachable. Called from the online role/permission
// invalidation path. No-op when disabled.
func (o *offlineAuthz) revokeTenant(tenantID uuid.UUID, version uint64) {
	if o == nil {
		return
	}
	o.epochs.ObserveTenant(tenantID.String(), version)
}

// currentEpoch resolves the tenant's current role-version as an epoch. When no
// provider is wired, the epoch is fixed at 0 (offline revocation then relies on
// the budget alone). A provider error yields (0,false) so the caller skips
// caching rather than storing an entry under an unknown epoch.
func (o *offlineAuthz) currentEpoch(ctx context.Context, tenantID uuid.UUID) (uint64, bool) {
	if o.roleVer == nil {
		return 0, true
	}
	v, err := o.roleVer.GetRoleVersion(ctx, tenantID)
	if err != nil {
		return 0, false
	}
	if v < 0 {
		v = 0
	}
	return uint64(v), true
}

// offlineSubject encodes (tenant, user) into a govdecision subject that both
// uniquely keys the decision cache and lets the tenant-scoped EpochStore
// recover the tenant.
func offlineSubject(tenantID, userID uuid.UUID) string {
	return tenantID.String() + offlineSubjectSep + userID.String()
}

// tenantOfSubject recovers the tenant portion of an offlineSubject.
func tenantOfSubject(subject string) string {
	if i := strings.Index(subject, offlineTenantSep); i >= 0 {
		return subject[:i]
	}
	return subject
}

// tenantEpochStore is a concurrency-safe, monotonic govdecision.EpochStore
// keyed by TENANT rather than by individual subject. A single per-tenant
// role-version bump (redis.SessionCache.IncrementRoleVersion) must revoke
// the cached decisions of EVERY user in that tenant; a per-subject store cannot
// express that without enumerating users. By recovering the tenant from each
// subject and tracking one epoch per tenant, ObserveTenant revokes the whole
// tenant's cached decisions in O(1). Monotonic: a replayed lower epoch can
// never lower a tenant's known floor, so an old signal cannot "un-revoke".
type tenantEpochStore struct {
	mu sync.RWMutex
	m  map[string]uint64 // tenant -> highest observed epoch
}

func newTenantEpochStore() *tenantEpochStore {
	return &tenantEpochStore{m: make(map[string]uint64)}
}

// Epoch returns the known epoch for the subject's tenant (0 if none seen).
func (s *tenantEpochStore) Epoch(subject string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[tenantOfSubject(subject)]
}

// Observe records an epoch for the subject's tenant, keeping the maximum.
func (s *tenantEpochStore) Observe(subject string, epoch uint64) {
	s.observe(tenantOfSubject(subject), epoch)
}

// ObserveTenant records an epoch directly for a tenant, keeping the maximum.
// This is the revocation-push entry point used by the online invalidation path.
func (s *tenantEpochStore) ObserveTenant(tenant string, epoch uint64) {
	s.observe(tenant, epoch)
}

func (s *tenantEpochStore) observe(tenant string, epoch uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if epoch > s.m[tenant] {
		s.m[tenant] = epoch
	}
}

// Compile-time assertion that tenantEpochStore satisfies the primitive's
// EpochStore contract.
var _ gd.EpochStore = (*tenantEpochStore)(nil)
