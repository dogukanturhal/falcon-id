// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// shard_balancer.go implements ShardBalancer, a background worker that
// monitors host load and rebalances realm databases across PostgreSQL hosts
// when any host exceeds a configurable capacity threshold.
//
// Algorithm (per tick):
//  1. List all active hosts and compute load = current_databases / max_databases.
//  2. For each overloaded host (load > threshold, default 80%):
//     a. Find the least-loaded host in the same data_residency_zone.
//     b. If that host has < 50% capacity, select the smallest/newest realm on
//        the overloaded host and call migrator.MigrateRealmDatabase.
//  3. If no host exceeds the threshold, log at debug level and skip.
//
// Dry-run mode (SHARD_BALANCER_DRY_RUN=true) logs what would happen without
// actually triggering migrations. Useful for capacity planning and safe rollout.

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// shardBalancerRealmDBRepo is the narrow interface ShardBalancer requires from
// the realm database repository. It only needs the ability to find the
// candidate realm to migrate off an overloaded host.
type shardBalancerRealmDBRepo interface {
	// GetOldestByHostID returns the oldest active realm database on the given
	// host — a proxy for "smallest" in terms of tenant age and data volume.
	// Returns (nil, nil) when no active database exists on the host.
	GetOldestByHostID(ctx context.Context, hostID uuid.UUID) (*models.RealmDatabase, error)
}

// shardBalancerHostRepo combines the capacity-tracking operations from
// DatabaseHostRepository with the full listing capability needed to survey
// all hosts on each balancer tick.
type shardBalancerHostRepo interface {
	DatabaseHostRepository
	List(ctx context.Context) ([]models.RealmDatabaseHost, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.RealmDatabaseHost, error)
}

const (
	defaultBalancerInterval  = 5 * time.Minute
	defaultOverloadThreshold = 0.80 // trigger rebalance when host > 80% full
	defaultUnderloadTarget   = 0.50 // only migrate to hosts with < 50% load
)

// BalanceEvent records a single rebalance operation (actual or dry-run).
type BalanceEvent struct {
	RealmID         uuid.UUID `json:"realm_id"`
	SourceHostID    uuid.UUID `json:"source_host_id"`
	SourceHostAlias string    `json:"source_host_alias"`
	TargetHostID    uuid.UUID `json:"target_host_id"`
	TargetHostAlias string    `json:"target_host_alias"`
	Zone            string    `json:"zone"`
	DryRun          bool      `json:"dry_run"`
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     time.Time `json:"completed_at,omitempty"`
	Error           string    `json:"error,omitempty"`
	Status          string    `json:"status"` // "completed" | awxJobStatusFailed | "would_migrate"
}

// HostLoadSnapshot captures the load state of a single host at a point in time.
type HostLoadSnapshot struct {
	HostID    uuid.UUID `json:"host_id"`
	HostAlias string    `json:"host_alias"`
	Region    string    `json:"region,omitempty"`
	Zone      string    `json:"zone,omitempty"`
	Current   int       `json:"current_databases"`
	Max       int       `json:"max_databases"`
	LoadPct   float64   `json:"load_pct"` // 0–1
	IsActive  bool      `json:"is_active"`
}

// ShardBalanceStatus is the response payload for GET /api/v1/platform/shard-balance.
type ShardBalanceStatus struct {
	Hosts         []HostLoadSnapshot `json:"hosts"`
	RecentEvents  []BalanceEvent     `json:"recent_events"`
	DryRunMode    bool               `json:"dry_run_mode"`
	Threshold     float64            `json:"threshold"`
	LastCheckedAt time.Time          `json:"last_checked_at"`
}

// ShardBalancer periodically checks host load and migrates realm databases
// from overloaded hosts to under-loaded ones within the same residency zone.
type ShardBalancer struct {
	hostRepo    shardBalancerHostRepo
	realmDBRepo shardBalancerRealmDBRepo
	migrator    *RealmDBMigrator
	placement   *PlacementEngine
	interval    time.Duration
	threshold   float64 // load fraction that triggers a rebalance (default 0.80)
	log         *zap.SugaredLogger
	dryRun      bool

	mu            sync.Mutex
	recentEvents  []BalanceEvent // ring buffer of last 50 events
	lastCheckedAt time.Time

	stopCh chan struct{}
}

// NewShardBalancer constructs a ShardBalancer. The env var
// SHARD_BALANCER_DRY_RUN=true activates dry-run mode at construction time so
// it cannot be changed at runtime (avoids accidental live migrations in prod).
func NewShardBalancer(
	hostRepo shardBalancerHostRepo,
	realmDBRepo shardBalancerRealmDBRepo,
	migrator *RealmDBMigrator,
	placement *PlacementEngine,
	log *zap.SugaredLogger,
) *ShardBalancer {
	dryRun := os.Getenv("SHARD_BALANCER_DRY_RUN") == "true"
	if dryRun {
		log.Infow("ShardBalancer: dry-run mode enabled (SHARD_BALANCER_DRY_RUN=true) — no migrations will be triggered")
	}
	return &ShardBalancer{
		hostRepo:    hostRepo,
		realmDBRepo: realmDBRepo,
		migrator:    migrator,
		placement:   placement,
		interval:    defaultBalancerInterval,
		threshold:   defaultOverloadThreshold,
		log:         log,
		dryRun:      dryRun,
		stopCh:      make(chan struct{}),
	}
}

// Start begins the background balancer loop. Call in a goroutine:
//
//	go balancer.Start(ctx)
func (b *ShardBalancer) Start(ctx context.Context) {
	b.log.Infow("ShardBalancer: starting",
		"interval", b.interval,
		"threshold", fmt.Sprintf("%.0f%%", b.threshold*100),
		"dry_run", b.dryRun,
	)

	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()

	// Run one pass immediately so the first balance check is not delayed by
	// a full interval when the service starts.
	b.runBalance(ctx)

	for {
		select {
		case <-ticker.C:
			b.runBalance(ctx)
		case <-b.stopCh:
			b.log.Infow("ShardBalancer: stopped")
			return
		case <-ctx.Done():
			b.log.Infow("ShardBalancer: context cancelled, stopping")
			return
		}
	}
}

// Stop signals the balancer goroutine to exit after the current tick.
// Safe to call multiple times.
func (b *ShardBalancer) Stop() {
	select {
	case <-b.stopCh:
		// Already closed.
	default:
		close(b.stopCh)
	}
}

// Status returns a snapshot of all host loads and recent rebalance events.
// This is the backing data for GET /api/v1/platform/shard-balance.
func (b *ShardBalancer) Status(ctx context.Context) (*ShardBalanceStatus, error) {
	hosts, err := b.hostRepo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("ShardBalancer.Status: list hosts: %w", err)
	}

	snapshots := make([]HostLoadSnapshot, 0, len(hosts))
	for _, h := range hosts {
		region := ""
		if h.Region != nil {
			region = *h.Region
		}
		zone := h.DataResidencyZone
		load := 0.0
		if h.MaxDatabases > 0 {
			load = float64(h.CurrentDatabases) / float64(h.MaxDatabases)
		}
		snapshots = append(snapshots, HostLoadSnapshot{
			HostID:    h.ID,
			HostAlias: h.HostAlias,
			Region:    region,
			Zone:      zone,
			Current:   h.CurrentDatabases,
			Max:       h.MaxDatabases,
			LoadPct:   load,
			IsActive:  h.IsActive,
		})
	}

	b.mu.Lock()
	events := make([]BalanceEvent, len(b.recentEvents))
	copy(events, b.recentEvents)
	lastChecked := b.lastCheckedAt
	b.mu.Unlock()

	return &ShardBalanceStatus{
		Hosts:         snapshots,
		RecentEvents:  events,
		DryRunMode:    b.dryRun,
		Threshold:     b.threshold,
		LastCheckedAt: lastChecked,
	}, nil
}

// ---------------------------------------------------------------------------
// Internal balancer loop
// ---------------------------------------------------------------------------

// runBalance is a single balancer tick: list hosts, find overloaded ones,
// select a target, and migrate one realm per overloaded host.
func (b *ShardBalancer) runBalance(ctx context.Context) {
	b.mu.Lock()
	b.lastCheckedAt = time.Now().UTC()
	b.mu.Unlock()

	hosts, err := b.hostRepo.List(ctx)
	if err != nil {
		b.log.Errorw("ShardBalancer: failed to list hosts", "err", err)
		return
	}
	if len(hosts) == 0 {
		b.log.Debugw("ShardBalancer: no hosts registered, skipping tick")
		return
	}

	overloaded := b.overloadedHosts(hosts)
	if len(overloaded) == 0 {
		b.log.Debugw("ShardBalancer: all hosts within threshold, no rebalance needed",
			"host_count", len(hosts),
			"threshold", fmt.Sprintf("%.0f%%", b.threshold*100),
		)
		return
	}

	b.log.Infow("ShardBalancer: overloaded hosts detected",
		"count", len(overloaded),
		"threshold", fmt.Sprintf("%.0f%%", b.threshold*100),
	)

	for _, src := range overloaded {
		if ctx.Err() != nil {
			return
		}
		b.rebalanceHost(ctx, src, hosts)
	}
}

// overloadedHosts returns active hosts whose load fraction exceeds the threshold.
func (b *ShardBalancer) overloadedHosts(hosts []models.RealmDatabaseHost) []models.RealmDatabaseHost {
	var out []models.RealmDatabaseHost
	for _, h := range hosts {
		if !h.IsActive {
			continue
		}
		if h.MaxDatabases <= 0 {
			continue
		}
		load := float64(h.CurrentDatabases) / float64(h.MaxDatabases)
		if load > b.threshold {
			out = append(out, h)
		}
	}
	return out
}

// rebalanceHost attempts to migrate one realm from src to a suitable target
// host in the same data residency zone.
func (b *ShardBalancer) rebalanceHost(ctx context.Context, src models.RealmDatabaseHost, allHosts []models.RealmDatabaseHost) {
	srcLoad := float64(src.CurrentDatabases) / float64(src.MaxDatabases)
	b.log.Infow("ShardBalancer: processing overloaded host",
		"host_alias", src.HostAlias,
		"current", src.CurrentDatabases,
		"max", src.MaxDatabases,
		"load_pct", fmt.Sprintf("%.1f%%", srcLoad*100),
		"zone", src.DataResidencyZone,
	)

	// Find the least-loaded host in the same zone with < 50% capacity.
	target := b.findTargetHost(src, allHosts)
	if target == nil {
		b.log.Warnw("ShardBalancer: no suitable target host in zone — skipping",
			"source_host", src.HostAlias,
			"zone", src.DataResidencyZone,
		)
		return
	}

	// Find a candidate realm to migrate off the source host.
	candidate, err := b.realmDBRepo.GetOldestByHostID(ctx, src.ID)
	if err != nil {
		b.log.Errorw("ShardBalancer: failed to get candidate realm",
			"source_host", src.HostAlias,
			"err", err,
		)
		return
	}
	if candidate == nil {
		b.log.Warnw("ShardBalancer: no active realm database found on overloaded host",
			"source_host", src.HostAlias,
		)
		return
	}

	targetLoad := float64(target.CurrentDatabases) / float64(target.MaxDatabases)

	event := BalanceEvent{
		RealmID:         candidate.RealmID,
		SourceHostID:    src.ID,
		SourceHostAlias: src.HostAlias,
		TargetHostID:    target.ID,
		TargetHostAlias: target.HostAlias,
		Zone:            src.DataResidencyZone,
		DryRun:          b.dryRun,
		StartedAt:       time.Now().UTC(),
	}

	if b.dryRun {
		event.Status = "would_migrate"
		event.CompletedAt = time.Now().UTC()
		b.recordEvent(event)

		b.log.Infow("ShardBalancer (DRY RUN): would migrate realm",
			"realm_id", candidate.RealmID,
			"source_host", src.HostAlias,
			"source_load", fmt.Sprintf("%.1f%%", srcLoad*100),
			"target_host", target.HostAlias,
			"target_load", fmt.Sprintf("%.1f%%", targetLoad*100),
			"zone", src.DataResidencyZone,
		)
		return
	}

	b.log.Infow("ShardBalancer: migrating realm",
		"realm_id", candidate.RealmID,
		"source_host", src.HostAlias,
		"source_load", fmt.Sprintf("%.1f%%", srcLoad*100),
		"target_host", target.HostAlias,
		"target_load", fmt.Sprintf("%.1f%%", targetLoad*100),
		"zone", src.DataResidencyZone,
	)

	migReq := MigrationRequest{
		RealmID:                  candidate.RealmID,
		TargetHostID:             &target.ID,
		DropSourceAfterMigration: false, // conservative: keep source intact
	}

	status, err := b.migrator.MigrateRealmDatabase(ctx, migReq)
	event.CompletedAt = time.Now().UTC()

	if err != nil {
		event.Status = awxJobStatusFailed
		event.Error = err.Error()
		b.recordEvent(event)

		b.log.Errorw("ShardBalancer: migration failed",
			"realm_id", candidate.RealmID,
			"source_host", src.HostAlias,
			"target_host", target.HostAlias,
			"err", err,
		)
		return
	}

	event.Status = DeletionOverallCompleted
	b.recordEvent(event)

	b.log.Infow("ShardBalancer: migration completed",
		"realm_id", candidate.RealmID,
		"source_host", src.HostAlias,
		"target_host", target.HostAlias,
		"tables", status.TablesCount,
		"rows", status.TotalRows,
		"elapsed", event.CompletedAt.Sub(event.StartedAt),
	)
}

// findTargetHost returns the least-loaded host in the same zone as src that
// has < 50% capacity. Returns nil when no such host exists.
func (b *ShardBalancer) findTargetHost(src models.RealmDatabaseHost, allHosts []models.RealmDatabaseHost) *models.RealmDatabaseHost {
	var best *models.RealmDatabaseHost
	var bestLoad float64

	for i := range allHosts {
		h := &allHosts[i]
		if !h.IsActive || h.HealthStatus != fleetStatusHealthy {
			continue
		}
		if h.ID == src.ID {
			continue // skip the overloaded source
		}
		if h.DataResidencyZone != src.DataResidencyZone {
			continue // must be in the same zone
		}
		if h.MaxDatabases <= 0 {
			continue
		}
		load := float64(h.CurrentDatabases) / float64(h.MaxDatabases)
		if load >= defaultUnderloadTarget {
			continue // only migrate to hosts with < 50% load
		}
		if best == nil || load < bestLoad {
			best = h
			bestLoad = load
		}
	}
	return best
}

// recordEvent appends an event to the in-memory ring buffer (max 50 entries).
func (b *ShardBalancer) recordEvent(ev BalanceEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.recentEvents = append(b.recentEvents, ev)
	if len(b.recentEvents) > 50 {
		b.recentEvents = b.recentEvents[len(b.recentEvents)-50:]
	}
}
