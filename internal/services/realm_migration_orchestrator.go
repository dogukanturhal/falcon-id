// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ErrNoPendingMigrations is returned by MigratorRunner when the target database
// is already fully up to date. The orchestrator uses this sentinel to mark a
// realm as Skipped rather than Failed.
var ErrNoPendingMigrations = errors.New("no pending migrations")

// RealmMigrationStatus describes the outcome of migrating a single realm database.
type RealmMigrationStatus string

const (
	// RealmMigrationPending is an exported identifier.
	RealmMigrationPending RealmMigrationStatus = "pending"
	// RealmMigrationRunning is an exported identifier.
	RealmMigrationRunning RealmMigrationStatus = "running"
	// RealmMigrationSucceeded is an exported identifier.
	RealmMigrationSucceeded RealmMigrationStatus = "succeeded"
	// RealmMigrationFailed is an exported identifier.
	RealmMigrationFailed RealmMigrationStatus = "failed"
	// RealmMigrationSkipped is an exported identifier.
	RealmMigrationSkipped RealmMigrationStatus = "skipped"
)

// RealmMigrationProgress is emitted for every realm as its status changes.
type RealmMigrationProgress struct {
	RealmID      uuid.UUID            `json:"realm_id"`
	RealmSlug    string               `json:"realm_slug"`
	Status       RealmMigrationStatus `json:"status"`
	ErrorMessage string               `json:"error_message,omitempty"`
	MigratedAt   *time.Time           `json:"migrated_at,omitempty"`
}

// OrchestratorResult summarises a completed RunAll call.
type OrchestratorResult struct {
	TotalRealms   int                      `json:"total_realms"`
	Succeeded     int                      `json:"succeeded"`
	Failed        int                      `json:"failed"`
	Skipped       int                      `json:"skipped"`
	RealmResults  []RealmMigrationProgress `json:"realm_results"`
	CircuitBroken bool                     `json:"circuit_broken"`
}

// OrchestratorConfig controls the behaviour of a RunAll call.
type OrchestratorConfig struct {
	// SandboxRealmID, when set, identifies the canary realm. It is migrated
	// first; if it fails, the entire run is aborted.
	SandboxRealmID *uuid.UUID

	// MaxConcurrent caps the number of realm migrations running in parallel.
	// Defaults to 3 when zero.
	MaxConcurrent int

	// CircuitBreakerLimit is the number of consecutive failures that causes the
	// orchestrator to stop processing remaining realms. Defaults to 3 when zero.
	CircuitBreakerLimit int
}

// RealmDatabaseLister lists all active realm database configurations.
// Implemented by *repositories.RealmDatabaseRepository.
type RealmDatabaseLister interface {
	ListActive(ctx context.Context) ([]models.RealmDatabase, error)
}

// PoolOpener opens a pgxpool.Pool for the given connection string.
// In production this wraps database.NewPostgresDB; in tests it is mocked.
type PoolOpener interface {
	OpenPool(ctx context.Context, connectionString string) (*pgxpool.Pool, error)
}

// MigratorRunner executes schema migrations against a database pool.
// Returning ErrNoPendingMigrations signals that the database is already current.
type MigratorRunner interface {
	RunMigrations(ctx context.Context, pool *pgxpool.Pool) error
}

// RealmMigrationOrchestrator coordinates schema migrations across all dedicated
// realm databases using a canary rollout and a consecutive-failure circuit breaker.
type RealmMigrationOrchestrator struct {
	realmDBRepo    RealmDatabaseLister
	poolOpener     PoolOpener
	migratorRunner MigratorRunner
	logger         *zap.Logger
}

// NewRealmMigrationOrchestrator constructs a RealmMigrationOrchestrator.
func NewRealmMigrationOrchestrator(
	realmDBRepo RealmDatabaseLister,
	poolOpener PoolOpener,
	migratorRunner MigratorRunner,
	logger *zap.Logger,
) *RealmMigrationOrchestrator {
	return &RealmMigrationOrchestrator{
		realmDBRepo:    realmDBRepo,
		poolOpener:     poolOpener,
		migratorRunner: migratorRunner,
		logger:         logger,
	}
}

// RunAll applies pending migrations to every active realm database.
//
// Canary phase: if cfg.SandboxRealmID is set, that realm is migrated first in
// isolation. A failure in the canary aborts the run immediately and returns a
// result with CircuitBroken: false (the circuit was not tripped by consecutive
// failures; the canary itself is the guard).
//
// Main phase: remaining realms are processed with bounded concurrency
// (cfg.MaxConcurrent, default 3). A consecutive-failure counter is incremented
// atomically on each failure and reset to zero on each success. Once the counter
// reaches cfg.CircuitBreakerLimit (default 3) the orchestrator stops scheduling
// new migrations and sets CircuitBroken: true in the result.
//
// progressFn is called for every realm as its status transitions. It may be nil.
func (o *RealmMigrationOrchestrator) RunAll(
	ctx context.Context,
	cfg OrchestratorConfig,
	progressFn func(RealmMigrationProgress),
) (*OrchestratorResult, error) {
	// Apply defaults.
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 3
	}
	if cfg.CircuitBreakerLimit <= 0 {
		cfg.CircuitBreakerLimit = 3
	}

	notify := func(p RealmMigrationProgress) {
		if progressFn != nil {
			progressFn(p)
		}
	}

	// Fetch all active realm databases.
	allRealms, err := o.realmDBRepo.ListActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("RealmMigrationOrchestrator.RunAll: list active realms: %w", err)
	}

	result := &OrchestratorResult{
		TotalRealms:  len(allRealms),
		RealmResults: make([]RealmMigrationProgress, 0, len(allRealms)),
	}

	if len(allRealms) == 0 {
		return result, nil
	}

	// Separate the canary realm (if configured) from the rest.
	var canary *models.RealmDatabase
	remaining := make([]models.RealmDatabase, 0, len(allRealms))

	for i := range allRealms {
		rd := allRealms[i]
		if cfg.SandboxRealmID != nil && rd.RealmID == *cfg.SandboxRealmID {
			rdCopy := rd
			canary = &rdCopy
		} else {
			remaining = append(remaining, rd)
		}
	}

	// -------------------------------------------------------------------------
	// Canary phase
	// -------------------------------------------------------------------------
	if canary != nil {
		o.logger.Info("Canary migration starting",
			zap.String("realm_id", canary.RealmID.String()),
			zap.String("realm_slug", canary.ConnectionName),
		)

		notify(RealmMigrationProgress{
			RealmID:   canary.RealmID,
			RealmSlug: canary.ConnectionName,
			Status:    RealmMigrationRunning,
		})

		prog := o.migrateOne(ctx, *canary)
		result.RealmResults = append(result.RealmResults, prog)

		switch prog.Status {
		case RealmMigrationSucceeded:
			result.Succeeded++
		case RealmMigrationSkipped:
			result.Skipped++
		case RealmMigrationFailed:
			result.Failed++
			notify(prog)

			o.logger.Error("Canary migration failed — aborting run",
				zap.String("realm_id", canary.RealmID.String()),
				zap.String("error", prog.ErrorMessage),
			)
			// Fill remaining realms as pending (not yet attempted).
			for _, rd := range remaining {
				p := RealmMigrationProgress{
					RealmID:   rd.RealmID,
					RealmSlug: rd.ConnectionName,
					Status:    RealmMigrationPending,
				}
				result.RealmResults = append(result.RealmResults, p)
				notify(p)
			}
			return result, nil
		}

		notify(prog)
	}

	// -------------------------------------------------------------------------
	// Main phase — bounded concurrency with circuit breaker
	// -------------------------------------------------------------------------

	var (
		consecutiveFails atomic.Int32
		circuitBroken    atomic.Bool
		mu               sync.Mutex // protects result.RealmResults and counters
		wg               sync.WaitGroup
		sem              = make(chan struct{}, cfg.MaxConcurrent)
	)

	for i := range remaining {
		rd := remaining[i]

		// Check circuit before scheduling.
		if circuitBroken.Load() {
			p := RealmMigrationProgress{
				RealmID:   rd.RealmID,
				RealmSlug: rd.ConnectionName,
				Status:    RealmMigrationPending,
			}
			mu.Lock()
			result.RealmResults = append(result.RealmResults, p)
			mu.Unlock()
			notify(p)
			continue
		}

		// Notify that this realm is queued.
		notify(RealmMigrationProgress{
			RealmID:   rd.RealmID,
			RealmSlug: rd.ConnectionName,
			Status:    RealmMigrationPending,
		})

		// Acquire semaphore slot.
		sem <- struct{}{}

		// Re-check circuit after acquiring slot — another goroutine may have tripped it.
		if circuitBroken.Load() {
			<-sem
			p := RealmMigrationProgress{
				RealmID:   rd.RealmID,
				RealmSlug: rd.ConnectionName,
				Status:    RealmMigrationPending,
			}
			mu.Lock()
			result.RealmResults = append(result.RealmResults, p)
			mu.Unlock()
			notify(p)
			continue
		}

		wg.Add(1)
		go func(realm models.RealmDatabase) {
			defer wg.Done()
			defer func() { <-sem }()

			notify(RealmMigrationProgress{
				RealmID:   realm.RealmID,
				RealmSlug: realm.ConnectionName,
				Status:    RealmMigrationRunning,
			})

			prog := o.migrateOne(ctx, realm)

			mu.Lock()
			result.RealmResults = append(result.RealmResults, prog)
			switch prog.Status {
			case RealmMigrationSucceeded:
				result.Succeeded++
				consecutiveFails.Store(0)
			case RealmMigrationSkipped:
				result.Skipped++
				consecutiveFails.Store(0)
			case RealmMigrationFailed:
				result.Failed++
				n := consecutiveFails.Add(1)
				if int(n) >= cfg.CircuitBreakerLimit {
					circuitBroken.Store(true)
					result.CircuitBroken = true
					o.logger.Error("Circuit breaker tripped — stopping remaining realm migrations",
						zap.Int32("consecutive_failures", n),
					)
				}
			}
			mu.Unlock()

			notify(prog)
		}(rd)
	}

	wg.Wait()
	return result, nil
}

// migrateOne runs migrations for a single realm database.
// It opens a connection pool, delegates to MigratorRunner, and returns a
// RealmMigrationProgress reflecting the outcome.
func (o *RealmMigrationOrchestrator) migrateOne(ctx context.Context, rd models.RealmDatabase) RealmMigrationProgress {
	connStr := buildConnectionString(rd)

	pool, err := o.poolOpener.OpenPool(ctx, connStr)
	if err != nil {
		o.logger.Error("Failed to open pool for realm database",
			zap.String("realm_id", rd.RealmID.String()),
			zap.Error(err),
		)
		return RealmMigrationProgress{
			RealmID:      rd.RealmID,
			RealmSlug:    rd.ConnectionName,
			Status:       RealmMigrationFailed,
			ErrorMessage: fmt.Sprintf("open pool: %s", err.Error()),
		}
	}

	// Pools opened here are owned exclusively by this call; close them when done.
	// Guard against a nil pool (can occur in tests that mock OpenPool).
	if pool != nil {
		defer pool.Close()
	}

	if err := o.migratorRunner.RunMigrations(ctx, pool); err != nil {
		if errors.Is(err, ErrNoPendingMigrations) {
			o.logger.Info("Realm database already up to date — skipping",
				zap.String("realm_id", rd.RealmID.String()),
			)
			return RealmMigrationProgress{
				RealmID:   rd.RealmID,
				RealmSlug: rd.ConnectionName,
				Status:    RealmMigrationSkipped,
			}
		}

		o.logger.Error("Migration failed for realm database",
			zap.String("realm_id", rd.RealmID.String()),
			zap.Error(err),
		)
		return RealmMigrationProgress{
			RealmID:      rd.RealmID,
			RealmSlug:    rd.ConnectionName,
			Status:       RealmMigrationFailed,
			ErrorMessage: err.Error(),
		}
	}

	now := time.Now().UTC()
	o.logger.Info("Realm database migrated successfully",
		zap.String("realm_id", rd.RealmID.String()),
	)
	return RealmMigrationProgress{
		RealmID:    rd.RealmID,
		RealmSlug:  rd.ConnectionName,
		Status:     RealmMigrationSucceeded,
		MigratedAt: &now,
	}
}

// buildConnectionString constructs a DSN from a RealmDatabase record.
func buildConnectionString(rd models.RealmDatabase) string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		rd.Username,
		rd.PasswordEncrypted, // caller is responsible for decryption before passing in
		rd.Host,
		rd.Port,
		rd.DatabaseName,
		rd.SSLMode,
	)
}
