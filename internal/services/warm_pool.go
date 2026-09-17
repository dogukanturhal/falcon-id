// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// WarmPoolConfig holds per-DC pool sizing and timing parameters.
// Values are loaded from the warmpool-config ConfigMap; the struct is also
// used as the in-process representation with sane defaults.
type WarmPoolConfig struct {
	// Regions maps DC name (e.g. "istanbul", "ankara") to pool config.
	Regions map[string]RegionPoolConfig

	// CheckInterval is how often the maintenance loop evaluates pool levels.
	CheckInterval time.Duration

	// ProvisionTimeout is the maximum time to wait for a new warm cluster
	// to reach "ready" state before marking it failed.
	ProvisionTimeout time.Duration
}

// DefaultWarmPoolConfig returns production-ready defaults aligned with the
// warm-pool-config.yaml ConfigMap values.
func DefaultWarmPoolConfig() WarmPoolConfig {
	return WarmPoolConfig{
		Regions: map[string]RegionPoolConfig{
			"istanbul": {MinReady: 2, MaxReady: 5},
			"ankara":   {MinReady: 2, MaxReady: 5},
		},
		CheckInterval:    60 * time.Second,
		ProvisionTimeout: 15 * time.Minute,
	}
}

// RegionPoolConfig defines the warm-pool sizing for a single data center.
type RegionPoolConfig struct {
	// MinReady: trigger replenishment when available count drops below this.
	MinReady int
	// MaxReady: do not pre-provision beyond this count.
	MaxReady int
}

// WarmHost represents a single warm (pre-provisioned) cluster entry.
// Status lifecycle: "provisioning" → "warm" → "assigned".
type WarmHost struct {
	ID           uuid.UUID  `json:"id"`
	Region       string     `json:"region"`
	Status       string     `json:"status"` // "provisioning", "warm", "assigned"
	DBName       string     `json:"database_name,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	AssignedAt   *time.Time `json:"assigned_at,omitempty"`
	AssignedToID *uuid.UUID `json:"assigned_to_realm_id,omitempty"`
}

// WarmPoolRepository defines the data access interface for warm host records.
// The concrete implementation lives in internal/repositories.
// Separate from DatabaseHostRepository to keep concerns isolated.
type WarmPoolRepository interface {
	// ListByRegionAndStatus returns warm hosts for a DC filtered by status.
	// status values: "provisioning", "warm", "assigned"
	ListByRegionAndStatus(ctx context.Context, region, status string) ([]*WarmHost, error)

	// Create registers a new warm host entry (status = "provisioning").
	Create(ctx context.Context, host *WarmHost) error

	// UpdateStatus atomically updates the warm host status.
	// Returns an error if the host does not exist or the transition is invalid.
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error

	// AssignToRealm marks a warm host as "assigned" and records the realm.
	// This is an atomic CAS-style update: only succeeds if current status is "warm".
	AssignToRealm(ctx context.Context, id uuid.UUID, realmID uuid.UUID) error

	// CountByRegionAndStatus returns the count of hosts matching the filter.
	// Used by the maintenance loop to avoid a full list scan.
	CountByRegionAndStatus(ctx context.Context, region, status string) (int, error)
}

// WarmPoolManager maintains a pool of pre-provisioned warm PostgreSQL clusters
// per data center. It runs a background maintenance loop that:
//  1. Counts warm (unassigned) hosts per DC.
//  2. Triggers replenishment when count < MinReady.
//  3. Caps pre-provisioning at MaxReady to avoid resource waste.
//
// On the fast path, AssignWarm() atomically claims the first available warm
// host in the requested DC. The caller (ProductDBProvisioner) then applies
// tenant schema on top of the pre-migrated cluster.
type WarmPoolManager struct {
	warmRepo    WarmPoolRepository
	provisioner *RealmDBProvisioner
	config      WarmPoolConfig
	log         *zap.SugaredLogger

	// mu protects in-flight replenishment tracking to prevent duplicate jobs.
	mu       sync.Mutex
	inFlight map[string]int // region → number of in-flight replenishment jobs
	stopCh   chan struct{}
	stopped  bool
}

// NewWarmPoolManager creates a WarmPoolManager with the supplied dependencies.
// warmRepo may be nil in test environments; the manager degrades gracefully
// (Start becomes a no-op, AssignWarm always returns nil).
func NewWarmPoolManager(
	warmRepo WarmPoolRepository,
	provisioner *RealmDBProvisioner,
	config WarmPoolConfig,
	log *zap.SugaredLogger,
) *WarmPoolManager {
	if config.CheckInterval == 0 {
		config.CheckInterval = 60 * time.Second
	}
	if config.ProvisionTimeout == 0 {
		config.ProvisionTimeout = 15 * time.Minute
	}
	if len(config.Regions) == 0 {
		config.Regions = DefaultWarmPoolConfig().Regions
	}

	return &WarmPoolManager{
		warmRepo:    warmRepo,
		provisioner: provisioner,
		config:      config,
		log:         log,
		inFlight:    make(map[string]int),
		stopCh:      make(chan struct{}),
	}
}

// Start begins the warm pool maintenance loop.
// It runs until Stop() is called or ctx is cancelled.
// The loop runs in the calling goroutine; callers should invoke it via go.
func (m *WarmPoolManager) Start() {
	if m.warmRepo == nil {
		m.log.Warnw("WarmPoolManager: warmRepo is nil, maintenance loop disabled")
		return
	}

	m.log.Infow("WarmPoolManager: starting maintenance loop",
		"check_interval", m.config.CheckInterval,
		"regions", len(m.config.Regions),
	)

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	// Run an immediate check on startup so the pool is evaluated without
	// waiting for the first tick.
	m.runMaintenanceCycle(context.Background())

	for {
		select {
		case <-ticker.C:
			m.runMaintenanceCycle(context.Background())
		case <-m.stopCh:
			m.log.Infow("WarmPoolManager: maintenance loop stopped")
			return
		}
	}
}

// Stop signals the maintenance loop to exit cleanly.
// It is safe to call Stop multiple times.
func (m *WarmPoolManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.stopped {
		m.stopped = true
		close(m.stopCh)
	}
}

// AssignWarm atomically claims a warm host in the specified region.
// Returns nil if no warm host is currently available — callers must fall back
// to synchronous on-demand provisioning.
//
// The returned WarmHost has Status = "assigned". The host is registered in
// iam_database_hosts by the caller (ProductDBProvisioner) after this returns.
func (m *WarmPoolManager) AssignWarm(ctx context.Context, region string) (*WarmHost, error) {
	if m.warmRepo == nil {
		return nil, nil //nolint:nilnil // intentional: nil = no warm host available
	}

	// List available warm hosts in this DC.
	available, err := m.warmRepo.ListByRegionAndStatus(ctx, region, "warm")
	if err != nil {
		return nil, fmt.Errorf("warmpool: list warm hosts in %s: %w", region, err)
	}
	if len(available) == 0 {
		m.log.Warnw("WarmPoolManager: no warm hosts available",
			"region", region,
		)
		// Trigger emergency replenishment in the background.
		go m.replenishRegion(context.Background(), region) //nolint:gosec // goroutine must outlive request context
		return nil, nil                                    //nolint:nilnil
	}

	// Claim the oldest warm host (FIFO assignment for predictable rotation).
	candidate := available[0]
	if err := m.warmRepo.AssignToRealm(ctx, candidate.ID, uuid.Nil); err != nil {
		// Concurrent assignment race — retry once with the next candidate.
		if len(available) > 1 {
			candidate = available[1]
			if err2 := m.warmRepo.AssignToRealm(ctx, candidate.ID, uuid.Nil); err2 != nil {
				return nil, fmt.Errorf("warmpool: failed to assign warm host (two attempts): %w", err2)
			}
		} else {
			return nil, fmt.Errorf("warmpool: assignment race on only available host: %w", err)
		}
	}

	now := time.Now().UTC()
	candidate.Status = "assigned"
	candidate.AssignedAt = &now

	m.log.Infow("WarmPoolManager: warm host assigned",
		"host_id", candidate.ID,
		"region", region,
		"db_name", candidate.DBName,
	)

	// Trigger replenishment check asynchronously — do not block the assignment.
	go m.replenishIfNeeded(context.Background(), region) //nolint:gosec // goroutine must outlive request context

	return candidate, nil
}

// GetStatus returns the current warm pool state grouped by region.
// Used by the /api/v1/platform/warmpool handler.
func (m *WarmPoolManager) GetStatus(ctx context.Context) (map[string][]WarmHost, error) {
	if m.warmRepo == nil {
		// Return empty status when repo is not configured (dev/test mode).
		result := make(map[string][]WarmHost, len(m.config.Regions))
		for region := range m.config.Regions {
			result[region] = []WarmHost{}
		}
		return result, nil
	}

	result := make(map[string][]WarmHost, len(m.config.Regions))
	for region := range m.config.Regions {
		// Fetch all statuses for this DC.
		warm, err := m.warmRepo.ListByRegionAndStatus(ctx, region, "warm")
		if err != nil {
			return nil, fmt.Errorf("warmpool: list warm in %s: %w", region, err)
		}
		provisioning, err := m.warmRepo.ListByRegionAndStatus(ctx, region, "provisioning")
		if err != nil {
			return nil, fmt.Errorf("warmpool: list provisioning in %s: %w", region, err)
		}
		assigned, err := m.warmRepo.ListByRegionAndStatus(ctx, region, "assigned")
		if err != nil {
			return nil, fmt.Errorf("warmpool: list assigned in %s: %w", region, err)
		}

		all := make([]WarmHost, 0, len(warm)+len(provisioning)+len(assigned))
		for _, h := range warm {
			all = append(all, *h)
		}
		for _, h := range provisioning {
			all = append(all, *h)
		}
		for _, h := range assigned {
			all = append(all, *h)
		}
		result[region] = all
	}

	return result, nil
}

// runMaintenanceCycle checks all configured regions and triggers replenishment
// where needed. Called by the ticker loop and on startup.
func (m *WarmPoolManager) runMaintenanceCycle(ctx context.Context) {
	for region, cfg := range m.config.Regions {
		count, err := m.warmRepo.CountByRegionAndStatus(ctx, region, "warm")
		if err != nil {
			m.log.Errorw("WarmPoolManager: failed to count warm hosts",
				"region", region,
				"err", err,
			)
			continue
		}

		m.log.Debugw("WarmPoolManager: pool check",
			"region", region,
			"warm_count", count,
			"min_ready", cfg.MinReady,
			"max_ready", cfg.MaxReady,
		)

		if count < cfg.MinReady {
			needed := cfg.MinReady - count
			m.log.Infow("WarmPoolManager: pool below min_ready, replenishing",
				"region", region,
				"warm_count", count,
				"min_ready", cfg.MinReady,
				"needed", needed,
			)
			for i := 0; i < needed; i++ {
				go m.replenishRegion(ctx, region)
			}
		}
	}
}

// replenishIfNeeded is the post-assignment check — triggered after each
// assignment to keep the pool topped up.
func (m *WarmPoolManager) replenishIfNeeded(ctx context.Context, region string) {
	cfg, ok := m.config.Regions[region]
	if !ok {
		return
	}

	count, err := m.warmRepo.CountByRegionAndStatus(ctx, region, "warm")
	if err != nil {
		m.log.Errorw("WarmPoolManager: count failed in post-assignment check",
			"region", region,
			"err", err,
		)
		return
	}

	if count < cfg.MinReady {
		m.replenishRegion(ctx, region)
	}
}

// replenishRegion provisions a single new warm cluster in the specified DC.
// It respects MaxReady: if the pool is already full, it does nothing.
// In-flight tracking prevents duplicate concurrent replenishments.
func (m *WarmPoolManager) replenishRegion(ctx context.Context, region string) {
	cfg, ok := m.config.Regions[region]
	if !ok {
		m.log.Errorw("WarmPoolManager: unknown region in replenishment", "region", region)
		return
	}

	// Check in-flight count to avoid over-provisioning.
	m.mu.Lock()
	inFlight := m.inFlight[region]
	m.mu.Unlock()

	totalCount, err := m.warmRepo.CountByRegionAndStatus(ctx, region, "warm")
	if err != nil {
		m.log.Errorw("WarmPoolManager: count failed before replenishment",
			"region", region,
			"err", err,
		)
		return
	}
	provisioningCount, err := m.warmRepo.CountByRegionAndStatus(ctx, region, "provisioning")
	if err != nil {
		m.log.Errorw("WarmPoolManager: provisioning count failed",
			"region", region,
			"err", err,
		)
		return
	}

	effective := totalCount + provisioningCount + inFlight
	if effective >= cfg.MaxReady {
		m.log.Debugw("WarmPoolManager: pool at or above max_ready, skipping replenishment",
			"region", region,
			"effective_count", effective,
			"max_ready", cfg.MaxReady,
		)
		return
	}

	// Increment in-flight counter.
	m.mu.Lock()
	m.inFlight[region]++
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.inFlight[region]--
		m.mu.Unlock()
	}()

	warmID := uuid.New()
	now := time.Now().UTC()

	// Register the warm host in "provisioning" state immediately so that
	// concurrent replenishment loops see it before the CNPG cluster is ready.
	host := &WarmHost{
		ID:        warmID,
		Region:    region,
		Status:    "provisioning",
		DBName:    fmt.Sprintf("hexxlock_warm_%s_%s", region, warmID.String()[:8]),
		CreatedAt: now,
	}
	if err := m.warmRepo.Create(ctx, host); err != nil {
		m.log.Errorw("WarmPoolManager: failed to create warm host record",
			"region", region,
			"warm_id", warmID,
			"err", err,
		)
		return
	}

	m.log.Infow("WarmPoolManager: replenishment started",
		"region", region,
		"warm_id", warmID,
		"db_name", host.DBName,
	)

	// Provision the actual PostgreSQL database using RealmDBProvisioner.
	// We use a timeout context to bound provisioning time.
	provCtx, cancel := context.WithTimeout(ctx, m.config.ProvisionTimeout)
	defer cancel()

	if m.provisioner != nil {
		// ProvisionDatabase creates the database on a selected host.
		// For warm pool, we use the region as the preferred region.
		// realmID is uuid.Nil until a real tenant is assigned.
		if _, err := m.provisioner.ProvisionDatabase(provCtx, uuid.Nil, host.DBName, region); err != nil {
			m.log.Errorw("WarmPoolManager: replenishment provisioning failed",
				"region", region,
				"warm_id", warmID,
				"db_name", host.DBName,
				"err", err,
			)
			// Mark as failed — the next maintenance cycle will retry.
			if updateErr := m.warmRepo.UpdateStatus(ctx, warmID, "failed"); updateErr != nil {
				m.log.Errorw("WarmPoolManager: failed to mark host as failed",
					"warm_id", warmID,
					"err", updateErr,
				)
			}
			return
		}
	}

	// Mark the warm host as ready.
	if err := m.warmRepo.UpdateStatus(ctx, warmID, "warm"); err != nil {
		m.log.Errorw("WarmPoolManager: failed to mark host as warm",
			"warm_id", warmID,
			"err", err,
		)
		return
	}

	m.log.Infow("WarmPoolManager: warm host ready",
		"region", region,
		"warm_id", warmID,
		"db_name", host.DBName,
	)
}
