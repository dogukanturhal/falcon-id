// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// entitlementModuleRepo abstracts iam_tenant_module_entitlements +
// iam_tenant_entitlement_flags persistence (repositories.ModuleEntitlementRepository).
type entitlementModuleRepo interface {
	UpsertModule(ctx context.Context, e *models.ModuleEntitlement) (applied bool, err error)
	UpsertFlags(ctx context.Context, f *models.TenantEntitlementFlags) (applied bool, err error)
	GetByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ModuleEntitlement, error)
	GetFlags(ctx context.Context, tenantID uuid.UUID) (*models.TenantEntitlementFlags, error)
}

// entitlementCache abstracts the Redis fresh+LKG cache
// (pkg/redis.EntitlementCacheService).
type entitlementCache interface {
	GetFresh(ctx context.Context, tenantID string, out interface{}) (bool, error)
	GetLKG(ctx context.Context, tenantID string, out interface{}) (bool, error)
	Set(ctx context.Context, tenantID string, envelope interface{}) error
	InvalidateFresh(ctx context.Context, tenantID string) error
}

// entitledModuleSyncer mirrors a tenant's module entitlement into SpiceDB's
// tenant#entitled_module relation (pkg/spicedb.Client.SyncEntitledModule).
type entitledModuleSyncer interface {
	SyncEntitledModule(ctx context.Context, tenantID uuid.UUID, moduleCode string, entitled bool, expiresAt *time.Time) error
}

// EntitlementModule is one entry in the GET /api/v1/tenant/entitlements
// envelope's `modules` array.
type EntitlementModule struct {
	Code      string  `json:"code"`
	Status    string  `json:"status"`
	ExpiresAt *string `json:"expires_at"`
	Seats     *int    `json:"seats"`
	Source    *string `json:"source"`
	TierCode  *string `json:"tier_code"`
	// ReadOnly: grace module whose writes are blocked (reads allowed).
	// Always false for any other status.
	ReadOnly bool `json:"read_only"`

	// Trial gate fields (spec 25 section 6), derived from the entitlement
	// snapshot. TrialEligible is true iff TrialReason == "eligible".
	// TrialEndsAt is set for trialing rows, GraceEndsAt for grace rows
	// (RFC3339). Additive: older cached envelopes decode these as zero values
	// and are normalised by normalizeEnvelope.
	TrialEligible bool    `json:"trial_eligible"`
	TrialReason   string  `json:"trial_reason"`
	TrialEndsAt   *string `json:"trial_ends_at,omitempty"`
	GraceEndsAt   *string `json:"grace_ends_at,omitempty"`
}

// EntitlementEnvelope is the exact response body of
// GET /api/v1/tenant/entitlements (the product roadmap §4.1):
//
//	{
//	  "stale": false, // true for LKG/fail-closed fallback
//	  "modules": [{"code","source","tier_code","read_only","status","expires_at","seats","trial_eligible",
//	               "trial_reason","trial_ends_at","grace_ends_at"}, ...],
//	  "flags": {...},
//	  "limits": {"<key>": int64, ...},   // -1 = unlimited (migration 0020)
//	  "trial_eligibility": {"<module_code>": bool, ...}
//	}
//
// This same struct is cached verbatim (fresh + LKG) by
// pkg/redis.EntitlementCacheService, so the cache layer never needs to
// know the envelope's internal shape.
type EntitlementEnvelope struct {
	// Stale distinguishes LKG/fail-closed fallback from an authoritative
	// empty snapshot. Seat-limit consumers must never lower a limit using
	// a stale envelope. Only successful source reads populate the cache.
	Stale            bool                `json:"stale"`
	Modules          []EntitlementModule `json:"modules"`
	Flags            map[string]bool     `json:"flags"`
	Limits           map[string]int64    `json:"limits"`
	TrialEligibility map[string]bool     `json:"trial_eligibility"`
}

// emptyEnvelope is the fail-closed response: no modules, no flags granted,
// and -- deliberately -- an EMPTY trial_eligibility map, not a map that
// defaults every module to eligible. When the entitlement source is
// unavailable we must not tell the UI/BFF a tenant is trial-eligible for
// anything; the UI/BFF must treat a missing key as "not eligible" and
// block trial start until a real answer is available. See
// GetEntitlements' doc comment for the full fail-closed contract.
func emptyEnvelope() EntitlementEnvelope {
	return EntitlementEnvelope{
		Stale:            true,
		Modules:          []EntitlementModule{},
		Flags:            map[string]bool{},
		Limits:           map[string]int64{},
		TrialEligibility: map[string]bool{},
	}
}

// TenantEntitlementService is the fail-closed entitlement source for
// backend/BFF/UI (the product roadmap §4.1, §2.1, §4.9). It is the single
// place both the read path (GET /api/v1/tenant/entitlements) and the two
// write paths (the example.tenant.modules.sync Kafka consumer in
// internal/entitlementsync, and PUT
// /internal/v1/tenants/{id}/module-entitlements) go through, so the
// monotonic event_version guard and the cache-invalidation-on-write are
// each implemented exactly once.
//
// # Why this never calls subscription-management synchronously
//
// The obvious alternative design for trial eligibility would be to call
// platform-commerce's GET /api/v1/internal/tenants/:tenantId/trial-history
// from this service's hot GET /api/v1/tenant/entitlements read path. This
// was deliberately rejected for two reasons:
//
//  1. It would introduce a hard synchronous cross-service dependency into
//     an endpoint whose entire design point (per the roadmap's §2.2
//     architecture diagram and §4.9 exit criterion "entitlements fail
//     closed") is to keep serving from a local, cached snapshot when
//     upstream services are degraded. A synchronous call here would mean
//     a platform-commerce outage takes down falcon-id's entitlements
//     endpoint too -- exactly the failure mode the Redis 60s+LKG cache and
//     the Kafka mirror exist to prevent.
//  2. That endpoint's trial-history is TENANT-WIDE
//     (ever_trialed/ever_subscribed per tenant), while R1's trial rule is
//     PER-MODULE (§2.1a: "self-serve trial = exactly one module... one
//     trial per tenant, ever" is stated per-module, and
//     TrialService.StartTrial gates per (tenant, module)). Calling the
//     tenant-wide endpoint would not even answer the right question
//     without further per-module projection on top.
//
// Instead, ever_trialed/ever_subscribed are carried PER MODULE as
// additional fields on the example.tenant.modules.sync snapshot event
// itself (mirrored down from subscription-management's authoritative
// trial_eligibility / tenant_subscription_items tables, through
// tenant-management), consistent with the platform's established
// one-way event-mirror pattern (subscription-management ->
// tenant-management -> falcon-id). See migration
// 0014_iam_tenant_module_entitlements.sql's header for the same rationale
// from the schema side.
type TenantEntitlementService struct {
	repo    entitlementModuleRepo
	cache   entitlementCache
	spicedb entitledModuleSyncer
	// moduleGrant, when set, is told about every granting entitlement so
	// the tenant's module roles exist and its owners hold them.
	moduleGrant moduleGrantHook
}

// moduleGrantHook materializes module access (role templates + owner grants)
// for a tenant whose entitlement to entitlementCode is granting.
type moduleGrantHook interface {
	EnsureModuleAccess(ctx context.Context, tenantID uuid.UUID, entitlementCode string) (*ModuleAccessResult, error)
}

// SetModuleGrantHook wires the module-access provisioner. Optional: nil
// leaves PutSnapshot as a pure entitlement write.
func (s *TenantEntitlementService) SetModuleGrantHook(h moduleGrantHook) {
	s.moduleGrant = h
}

// notifyModuleGrant calls the module-grant hook when the STORED row for
// (tenantID, moduleCode) is granting. Best-effort: failures are logged and
// never returned, because failing PutSnapshot would make the Kafka consumer
// abort the rest of the snapshot (and eventually DLQ it) over an IAM-side
// problem that must not corrupt entitlements. Revocation does nothing here.
func (s *TenantEntitlementService) notifyModuleGrant(ctx context.Context, tenantID uuid.UUID, moduleCode string) {
	if s.moduleGrant == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			logger.Error("entitlements: module-access hook panicked",
				zap.String("tenant_id", tenantID.String()), zap.String("module_code", moduleCode), zap.Any("panic", r))
		}
	}()
	rows, err := s.repo.GetByTenant(ctx, tenantID)
	if err != nil {
		logger.Warn("entitlements: module-access hook skipped, cannot read stored row",
			zap.String("tenant_id", tenantID.String()), zap.String("module_code", moduleCode), zap.Error(err))
		return
	}
	for i := range rows {
		if rows[i].ModuleCode != moduleCode || !rows[i].Status.IsGranting() {
			continue
		}
		hookCtx, cancel := context.WithTimeout(ctx, moduleAccessHookTimeout)
		defer cancel()
		if _, err := s.moduleGrant.EnsureModuleAccess(hookCtx, tenantID, moduleCode); err != nil {
			logger.Warn("entitlements: module-access provisioning failed",
				zap.String("tenant_id", tenantID.String()), zap.String("module_code", moduleCode), zap.Error(err))
		}
		return
	}
}

// SetSpiceDBSyncer wires the SpiceDB entitled_module mirror (spec 23 section
// 4.2). Optional: nil leaves SpiceDB untouched (SpiceDB disabled / tests).
func (s *TenantEntitlementService) SetSpiceDBSyncer(syncer entitledModuleSyncer) {
	s.spicedb = syncer
}

// syncSpiceDB makes tenant#entitled_module match the entitlement row: granting
// statuses (active/trialing/grace) touch the tuple, expired deletes it. An
// end date rides along as the entitlement_window caveat. Idempotent.
func (s *TenantEntitlementService) syncSpiceDB(ctx context.Context, e *models.ModuleEntitlement) error {
	if s.spicedb == nil {
		return nil
	}
	if err := s.spicedb.SyncEntitledModule(ctx, e.TenantID, e.ModuleCode, e.Status.IsGranting(), e.ExpiresAt); err != nil {
		return fmt.Errorf("sync entitled_module tenant=%s module=%s: %w", e.TenantID, e.ModuleCode, err)
	}
	return nil
}

// NewTenantEntitlementService creates a new service instance.
func NewTenantEntitlementService(repo entitlementModuleRepo, cache entitlementCache) *TenantEntitlementService {
	return &TenantEntitlementService{repo: repo, cache: cache}
}

// GetEntitlements returns the entitlements envelope for tenantID via the
// cache -> Postgres -> last-known-good -> fail-closed chain:
//
//  1. Fresh Redis cache (60s TTL) hit -> return it.
//  2. Cache miss -> read Postgres. On success, write BOTH the fresh and
//     LKG cache keys, then return the freshly-read envelope.
//  3. Postgres read fails (or fresh-cache read itself errors, which is
//     treated the same as a miss -- see the comment below) -> fall back
//     to the LKG cache key. If present, return it with stale=true (this is the ONLY case
//     where a caller receives data that may be more than 60s stale, and
//     it happens ONLY during an actual Postgres outage).
//  4. LKG also absent/unreadable -> FAIL CLOSED: return emptyEnvelope() (stale=true),
//     nil. This is never an error return -- fail-closed means "answer
//     with zero entitlements", not "propagate a 5xx", so a
//     mis-implemented caller can't accidentally treat a transport error
//     as "open" (e.g. by ignoring the error and defaulting to allow).
//
// A Redis error on the fresh-key GET is deliberately treated identically
// to a clean miss (fall through to Postgres) rather than being returned
// as an error: Redis being unavailable must never make entitlements LESS
// available than they'd be with no cache at all.
func (s *TenantEntitlementService) GetEntitlements(ctx context.Context, tenantID uuid.UUID) (EntitlementEnvelope, error) {
	tid := tenantID.String()

	if s.hasCache() {
		var cached EntitlementEnvelope
		if hit, err := s.cache.GetFresh(ctx, tid, &cached); err != nil {
			logger.Warn("entitlements: fresh cache read failed, falling through to Postgres",
				zap.String("tenant_id", tid), zap.Error(err))
		} else if hit {
			return normalizeEnvelope(cached), nil
		}
	}

	envelope, err := s.readFromSource(ctx, tenantID)
	if err != nil {
		logger.Warn("entitlements: Postgres read failed, falling back to last-known-good",
			zap.String("tenant_id", tid), zap.Error(err))

		if !s.hasCache() {
			// No Redis configured at all -- there is no LKG to fall
			// back to. Fail closed.
			logger.Warn("entitlements: no cache configured, failing closed",
				zap.String("tenant_id", tid))
			return emptyEnvelope(), nil
		}

		var lkg EntitlementEnvelope
		if hit, lkgErr := s.cache.GetLKG(ctx, tid, &lkg); lkgErr != nil {
			logger.Error("entitlements: last-known-good cache read failed, failing closed",
				zap.String("tenant_id", tid), zap.Error(lkgErr))
			return emptyEnvelope(), nil
		} else if hit {
			lkg.Stale = true
			return normalizeEnvelope(lkg), nil
		}

		// No LKG entry either (never seen a successful read for this
		// tenant, or it aged out after 24h of sustained outage). Fail
		// closed -- never nil-slice/nil-map the caller into a panic,
		// never "assume allowed".
		logger.Warn("entitlements: no last-known-good available, failing closed",
			zap.String("tenant_id", tid))
		return emptyEnvelope(), nil
	}

	if s.hasCache() {
		if setErr := s.cache.Set(ctx, tid, envelope); setErr != nil {
			// A cache-write failure must not fail the request that just
			// successfully read the real data from Postgres.
			logger.Warn("entitlements: cache write failed (serving Postgres result anyway)",
				zap.String("tenant_id", tid), zap.Error(setErr))
		}
	}

	return envelope, nil
}

// hasCache reports whether a real cache backend is configured. Necessary
// because a nil entitlementCache is passed as a genuinely nil interface
// (see NewTenantEntitlementService callers in cmd/services.go) rather than
// a nil pointer boxed in a non-nil interface -- so `s.cache != nil` here
// is a safe, correct nil check, not the classic "nil pointer in non-nil
// interface" trap.
func (s *TenantEntitlementService) hasCache() bool {
	return s.cache != nil
}

// readFromSource builds the envelope directly from Postgres, bypassing
// the cache entirely. Used by GetEntitlements on a cache miss/failure.
func (s *TenantEntitlementService) readFromSource(ctx context.Context, tenantID uuid.UUID) (EntitlementEnvelope, error) {
	modules, err := s.repo.GetByTenant(ctx, tenantID)
	if err != nil {
		return EntitlementEnvelope{}, fmt.Errorf("TenantEntitlementService.readFromSource modules: %w", err)
	}

	flagsRow, err := s.repo.GetFlags(ctx, tenantID)
	if err != nil {
		return EntitlementEnvelope{}, fmt.Errorf("TenantEntitlementService.readFromSource flags: %w", err)
	}

	envelope := emptyEnvelope()
	envelope.Stale = false // successful source read, even when no modules exist
	for _, m := range modules {
		var expiresAt *string
		if m.ExpiresAt != nil {
			formatted := m.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00")
			expiresAt = &formatted
		}
		reason := m.TrialReason()
		eligible := reason == models.TrialReasonEligible
		envelope.Modules = append(envelope.Modules, EntitlementModule{
			Code:          m.ModuleCode,
			Status:        string(m.Status),
			ExpiresAt:     expiresAt,
			Seats:         m.Seats,
			Source:        m.Source,
			TierCode:      m.TierCode,
			ReadOnly:      m.ReadOnly && m.Status == models.ModuleEntitlementStatusGrace,
			TrialEligible: eligible,
			TrialReason:   reason,
			TrialEndsAt:   formatEntitlementTime(m.TrialEndsAt()),
			GraceEndsAt:   formatEntitlementTime(m.GraceEndsAt()),
		})
		// trial_eligibility is keyed by every module the tenant has EVER
		// had a row for, not just currently-granting ones, so a lapsed
		// module still correctly reports itself as no-longer-eligible. It
		// mirrors modules[].trial_eligible (legacy shape, kept for callers
		// that predate the per-module fields).
		envelope.TrialEligibility[m.ModuleCode] = eligible
	}
	if flagsRow != nil && flagsRow.Flags != nil {
		envelope.Flags = flagsRow.Flags
	}
	if flagsRow != nil && flagsRow.Limits != nil {
		envelope.Limits = flagsRow.Limits
	}

	return envelope, nil
}

func formatEntitlementTime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	formatted := t.UTC().Format(time.RFC3339)
	return &formatted
}

// normalizeEnvelope upgrades an envelope cached before the per-module trial
// fields existed (fresh or last-known-good): modules without trial_reason take
// their eligibility from the legacy trial_eligibility map and report the
// generic "not_eligible" reason when that is false. It never grants
// eligibility the legacy map did not.
func normalizeEnvelope(e EntitlementEnvelope) EntitlementEnvelope {
	// Envelopes cached before migration 0020 have no "limits" key: serve
	// {} (consumers apply their own fallback), never null.
	if e.Limits == nil {
		e.Limits = map[string]int64{}
	}
	for i := range e.Modules {
		m := &e.Modules[i]
		if m.TrialReason != "" {
			continue
		}
		m.TrialEligible = e.TrialEligibility[m.Code]
		if m.TrialEligible {
			m.TrialReason = models.TrialReasonEligible
		} else {
			m.TrialReason = models.TrialReasonNotEligibleLegacyRow
		}
	}
	return e
}

// PutSnapshot idempotently applies one module's entitlement snapshot. It
// is the SOLE write path for iam_tenant_module_entitlements, shared by:
//
//   - internal/entitlementsync's example.tenant.modules.sync Kafka
//     consumer (the normal, event-driven path), and
//   - PUT /internal/v1/tenants/{id}/module-entitlements (an out-of-band
//     ops/backfill/replay path with the exact same idempotency
//     guarantees, so an operator can safely re-PUT a snapshot without
//     regressing a newer one already applied by Kafka).
//
// The monotonic event_version guard lives in the repository's UPSERT
// WHERE clause (repositories.ModuleEntitlementRepository.UpsertModule),
// not here -- this method only decides what to do with the "applied"
// bool: on true, invalidate the fresh cache key so the next read reflects
// the change immediately (well within the roadmap's "reaches the UI in
// under 5 minutes" §4.9 exit criterion; in practice, on the order of one
// cache-invalidation call).
func (s *TenantEntitlementService) PutSnapshot(ctx context.Context, e *models.ModuleEntitlement) error {
	if !e.Status.IsValid() {
		return fmt.Errorf("TenantEntitlementService.PutSnapshot: invalid status %q for tenant=%s module=%s", e.Status, e.TenantID, e.ModuleCode)
	}

	applied, err := s.repo.UpsertModule(ctx, e)
	if err != nil {
		return fmt.Errorf("TenantEntitlementService.PutSnapshot: %w", err)
	}
	if !applied {
		logger.Debug("entitlements: stale/duplicate snapshot ignored",
			zap.String("tenant_id", e.TenantID.String()),
			zap.String("module_code", e.ModuleCode),
			zap.Int64("event_version", e.EventVersion))
		s.notifyModuleGrant(ctx, e.TenantID, e.ModuleCode)
		// A redelivery after a failed SpiceDB write must still converge:
		// re-sync from the STORED row (never from the ignored snapshot), so
		// the Kafka retry heals the tuple without regressing newer state.
		return s.resyncStoredModule(ctx, e.TenantID, e.ModuleCode)
	}

	if s.hasCache() {
		if err := s.cache.InvalidateFresh(ctx, e.TenantID.String()); err != nil {
			logger.Warn("entitlements: fresh cache invalidation failed after write",
				zap.String("tenant_id", e.TenantID.String()), zap.Error(err))
		}
	}
	s.notifyModuleGrant(ctx, e.TenantID, e.ModuleCode)
	// A SpiceDB failure is returned so the Kafka consumer retries/DLQs it;
	// the DB row is already committed and the retry re-syncs it (see above).
	return s.syncSpiceDB(ctx, e)
}

// resyncStoredModule re-applies SpiceDB state from the stored row for one
// module. No-op without a syncer.
func (s *TenantEntitlementService) resyncStoredModule(ctx context.Context, tenantID uuid.UUID, moduleCode string) error {
	if s.spicedb == nil {
		return nil
	}
	rows, err := s.repo.GetByTenant(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("TenantEntitlementService.resyncStoredModule: %w", err)
	}
	for i := range rows {
		if rows[i].ModuleCode == moduleCode {
			return s.syncSpiceDB(ctx, &rows[i])
		}
	}
	return nil
}

// PutFlagsSnapshot is PutSnapshot's counterpart for the tenant-wide flags
// row. Same idempotency/invalidation contract.
func (s *TenantEntitlementService) PutFlagsSnapshot(ctx context.Context, f *models.TenantEntitlementFlags) error {
	applied, err := s.repo.UpsertFlags(ctx, f)
	if err != nil {
		return fmt.Errorf("TenantEntitlementService.PutFlagsSnapshot: %w", err)
	}
	if !applied {
		logger.Debug("entitlements: stale/duplicate flags snapshot ignored",
			zap.String("tenant_id", f.TenantID.String()), zap.Int64("event_version", f.EventVersion))
		return nil
	}

	if s.hasCache() {
		if err := s.cache.InvalidateFresh(ctx, f.TenantID.String()); err != nil {
			logger.Warn("entitlements: fresh cache invalidation failed after flags write",
				zap.String("tenant_id", f.TenantID.String()), zap.Error(err))
		}
	}
	return nil
}
