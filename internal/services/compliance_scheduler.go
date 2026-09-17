// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// advisoryLockComplianceScheduler is the PostgreSQL advisory lock key used for
// compliance scheduler leader election in multi-replica deployments.
// Must be unique across all advisory locks in the service.
const advisoryLockComplianceScheduler int64 = 857491005

// scheduledPolicy is a lightweight projection of policy + control data used by
// the scheduler to avoid re-querying the control for every evaluation tick.
type scheduledPolicy struct {
	policyID  uuid.UUID
	tenantID  uuid.UUID
	controlID uuid.UUID
	schedule  string
}

// ComplianceScheduler drives the continuous evaluation loop. It queries the
// database for policies whose next_run_at has elapsed and evaluates them via
// the CompliancePolicyEngine.
//
// In multi-replica Kubernetes deployments the scheduler acquires a PostgreSQL
// advisory lock before each sweep so that only one replica processes scheduled
// evaluations at a time. The lock is automatically released at the end of each
// sweep tick, allowing another replica to take over on the next interval should
// the lock-holder restart.
type ComplianceScheduler struct {
	engine   *CompliancePolicyEngine
	db       *pgxpool.Pool
	interval time.Duration

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewComplianceScheduler creates a ComplianceScheduler. Pass interval = 0 to
// use the default of 1 minute.
func NewComplianceScheduler(engine *CompliancePolicyEngine, db *pgxpool.Pool, interval time.Duration) *ComplianceScheduler {
	if interval <= 0 {
		interval = 1 * time.Minute
	}
	return &ComplianceScheduler{
		engine:   engine,
		db:       db,
		interval: interval,
	}
}

// Start launches the background evaluation loop. It is non-blocking; the goroutine
// stops when the returned context is cancelled or Stop is called.
func (s *ComplianceScheduler) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		logger.Log.Info("Compliance scheduler started",
			zap.Duration("interval", s.interval),
		)

		// Run once immediately on startup so policies are not delayed by a full
		// interval when the service restarts.
		s.runScheduledEvaluations(ctx)

		for {
			select {
			case <-ctx.Done():
				logger.Log.Info("Compliance scheduler stopped")
				return
			case <-ticker.C:
				s.runScheduledEvaluations(ctx)
			}
		}
	}()
}

// Stop gracefully shuts down the scheduler, waiting for the current sweep to
// complete before returning.
func (s *ComplianceScheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

// runScheduledEvaluations is the main sweep body.
//
//  1. Acquires a PostgreSQL advisory lock (leader election).
//  2. Queries policies whose next_run_at has elapsed.
//  3. Loads each control and evaluates it.
//  4. Updates last_run_at and next_run_at.
func (s *ComplianceScheduler) runScheduledEvaluations(ctx context.Context) {
	if s.db == nil {
		return
	}

	// Acquire a connection and hold the advisory lock for the duration of this sweep.
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		logger.Log.Error("ComplianceScheduler: failed to acquire connection", zap.Error(err))
		return
	}
	defer conn.Release()

	var acquired bool
	if err := conn.QueryRow(ctx,
		"SELECT pg_try_advisory_lock($1)", advisoryLockComplianceScheduler,
	).Scan(&acquired); err != nil {
		logger.Log.Error("ComplianceScheduler: advisory lock query failed", zap.Error(err))
		return
	}
	if !acquired {
		logger.Log.Debug("ComplianceScheduler: another replica holds the lock — skipping this tick")
		return
	}
	defer func() {
		if _, unlockErr := conn.Exec(ctx,
			"SELECT pg_advisory_unlock($1)", advisoryLockComplianceScheduler,
		); unlockErr != nil {
			logger.Log.Warn("ComplianceScheduler: advisory unlock failed", zap.Error(unlockErr))
		}
	}()

	policies, err := s.queryDuePolices(ctx)
	if err != nil {
		logger.Log.Error("ComplianceScheduler: failed to query due policies", zap.Error(err))
		return
	}

	if len(policies) == 0 {
		logger.Log.Debug("ComplianceScheduler: no policies due for evaluation")
		return
	}

	logger.Log.Info("ComplianceScheduler: evaluating due policies", zap.Int("count", len(policies)))

	for i := range policies {
		if ctx.Err() != nil {
			return
		}
		s.evaluatePolicy(ctx, &policies[i])
	}
}

// queryDuePolices returns all enabled policies whose next_run_at <= now().
func (s *ComplianceScheduler) queryDuePolices(ctx context.Context) ([]scheduledPolicy, error) {
	query := `
		SELECT p.id, p.tenant_id, p.control_id, p.schedule
		FROM iam_compliance_policies p
		JOIN iam_compliance_controls c ON c.id = p.control_id
		WHERE p.enabled = true
		  AND c.enabled = true
		  AND (p.next_run_at IS NULL OR p.next_run_at <= now())
		ORDER BY p.next_run_at ASC NULLS FIRST`

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ComplianceScheduler.queryDuePolices: %w", err)
	}
	defer rows.Close()

	var policies []scheduledPolicy
	for rows.Next() {
		var p scheduledPolicy
		if err := rows.Scan(&p.policyID, &p.tenantID, &p.controlID, &p.schedule); err != nil {
			logger.Log.Warn("ComplianceScheduler.queryDuePolices: scan error", zap.Error(err))
			continue
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ComplianceScheduler.queryDuePolices: rows: %w", err)
	}
	return policies, nil
}

// evaluatePolicy loads the control definition, runs EvaluateControl, and
// advances the policy's scheduling timestamps.
func (s *ComplianceScheduler) evaluatePolicy(ctx context.Context, p *scheduledPolicy) {
	control, err := s.engine.GetControlByID(ctx, p.controlID)
	if err != nil {
		logger.Log.Error("ComplianceScheduler.evaluatePolicy: failed to load control",
			zap.String("policy_id", p.policyID.String()),
			zap.String("control_id", p.controlID.String()),
			zap.Error(err),
		)
		s.advanceSchedule(ctx, p.policyID, p.schedule)
		return
	}

	_, err = s.engine.EvaluateControl(ctx, p.policyID, p.tenantID, control)
	if err != nil {
		logger.Log.Error("ComplianceScheduler.evaluatePolicy: evaluation failed",
			zap.String("policy_id", p.policyID.String()),
			zap.String("control", control.ControlID),
			zap.Error(err),
		)
	}

	// Always advance the schedule even when evaluation errored, to prevent the
	// policy from being retried every second.
	s.advanceSchedule(ctx, p.policyID, p.schedule)
}

// advanceSchedule updates last_run_at and next_run_at on the policy row.
func (s *ComplianceScheduler) advanceSchedule(ctx context.Context, policyID uuid.UUID, schedule string) {
	next := nextRunTime(schedule)
	_, err := s.db.Exec(ctx,
		`UPDATE iam_compliance_policies
		 SET last_run_at = now(), next_run_at = $2, updated_at = now()
		 WHERE id = $1`,
		policyID, next,
	)
	if err != nil {
		logger.Log.Error("ComplianceScheduler.advanceSchedule: failed to update timestamps",
			zap.String("policy_id", policyID.String()),
			zap.Error(err),
		)
	}
}
