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

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/metrics"
)

// advisoryLockSoDReevaluator is the PostgreSQL advisory lock key for leader
// election among SoDReevaluator replicas (distinct from the other constants
// 857491001/2/5/6 in this repo).
const advisoryLockSoDReevaluator int64 = 857491007

// SoDReevaluationInterval is how often the full pass runs (spec 23 section
// 5.2: continuous re-evaluation, daily).
const SoDReevaluationInterval = 24 * time.Hour

// sodReevalInitialDelay postpones the first pass after boot so it does not
// compete with startup work.
const sodReevalInitialDelay = 2 * time.Minute

// sodReevalRepo is the persistence the re-evaluator needs
// (repositories.SoDRepository).
type sodReevalRepo interface {
	ListActiveRulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.SoDRule, error)
	ReportViolation(ctx context.Context, v *models.SoDViolation) (newlyOpen bool, err error)
	ResolveViolationsNotIn(ctx context.Context, tenantID, userID uuid.UUID, keepRuleIDs []uuid.UUID) (int, error)
	ListTenantsForSoDReevaluation(ctx context.Context) ([]uuid.UUID, error)
	ListUsersForSoDReevaluation(ctx context.Context, tenantID uuid.UUID) (map[uuid.UUID][]uuid.UUID, error)
	CountOpenViolations(ctx context.Context) (int, error)
}

// sodReevalAudit is the slice of AuditService the job uses.
type sodReevalAudit interface {
	LogUserAction(ctx context.Context, tenantID uuid.UUID, actorID, targetUserID *uuid.UUID, action string, success bool, details map[string]interface{})
}

// SoDAuditEventViolationDetected is the audit action written when the job
// opens a violation.
const SoDAuditEventViolationDetected = "auth.sod.violation_detected"

// SoDReevaluator re-checks SoD rules against every active role assignment
// (spec 23 section 5.2 "continuous re-evaluation"): daily for all tenants and
// on demand for one tenant when its rule set changes. WARN mode only: it
// records violations, resolves ones that no longer hold, emits a metric and
// an audit event per newly opened violation, and never revokes a role.
//
// Multi-replica safety: the daily pass takes a session-level PostgreSQL
// advisory lock (same pattern as MeteringAggregator); replicas that do not
// get it skip the tick. Every write is an idempotent upsert, so a concurrent
// on-demand pass cannot corrupt state.
type SoDReevaluator struct {
	repo        sodReevalRepo
	permissions sodPermissionRepo
	audit       sodReevalAudit
	db          *pgxpool.Pool
	interval    time.Duration

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewSoDReevaluator builds the job. db may be nil (no leader lock, e.g.
// single-replica tests); audit may be nil (no audit rows, log only).
func NewSoDReevaluator(repo sodReevalRepo, permissions sodPermissionRepo, audit sodReevalAudit, db *pgxpool.Pool) *SoDReevaluator {
	return &SoDReevaluator{repo: repo, permissions: permissions, audit: audit, db: db, interval: SoDReevaluationInterval}
}

// Start runs the daily loop until ctx is cancelled or Stop is called.
func (r *SoDReevaluator) Start(ctx context.Context) {
	ctx, r.cancel = context.WithCancel(ctx)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		timer := time.NewTimer(sodReevalInitialDelay)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if err := r.RunDaily(ctx); err != nil {
					logger.Error("SoD re-evaluation daily pass failed", zap.Error(err))
				}
				timer.Reset(r.interval)
			}
		}
	}()
}

// Stop stops the loop and waits for an in-flight pass.
func (r *SoDReevaluator) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
}

// RunDaily evaluates every tenant under the leader lock. Returns nil when
// another replica is the leader.
func (r *SoDReevaluator) RunDaily(ctx context.Context) error {
	if r.db != nil {
		conn, err := r.db.Acquire(ctx)
		if err != nil {
			metrics.SoDReevaluationRuns.WithLabelValues("daily", "error").Inc()
			return fmt.Errorf("SoDReevaluator: acquire connection for advisory lock: %w", err)
		}
		defer conn.Release()
		var acquired bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", advisoryLockSoDReevaluator).Scan(&acquired); err != nil {
			metrics.SoDReevaluationRuns.WithLabelValues("daily", "error").Inc()
			return fmt.Errorf("SoDReevaluator: advisory lock: %w", err)
		}
		if !acquired {
			metrics.SoDReevaluationRuns.WithLabelValues("daily", "skipped").Inc()
			logger.Debug("SoDReevaluator: another replica holds the lock, skipping pass")
			return nil
		}
		defer func() {
			// Unlock with a fresh context: ctx may already be cancelled.
			unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", advisoryLockSoDReevaluator)
		}()
	}

	tenants, err := r.repo.ListTenantsForSoDReevaluation(ctx)
	if err != nil {
		metrics.SoDReevaluationRuns.WithLabelValues("daily", "error").Inc()
		return fmt.Errorf("SoDReevaluator: list tenants: %w", err)
	}
	var firstErr error
	for _, tenantID := range tenants {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := r.reevaluateTenant(ctx, tenantID); err != nil {
			logger.Error("SoD re-evaluation failed for tenant", zap.String("tenant_id", tenantID.String()), zap.Error(err))
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if n, err := r.repo.CountOpenViolations(ctx); err == nil {
		metrics.SoDViolationsOpen.Set(float64(n))
	}
	if firstErr != nil {
		metrics.SoDReevaluationRuns.WithLabelValues("daily", "error").Inc()
		return firstErr
	}
	metrics.SoDReevaluationRuns.WithLabelValues("daily", "ok").Inc()
	return nil
}

// ReevaluateTenant re-checks one tenant (rule-change trigger).
func (r *SoDReevaluator) ReevaluateTenant(ctx context.Context, tenantID uuid.UUID) error {
	if err := r.reevaluateTenant(ctx, tenantID); err != nil {
		metrics.SoDReevaluationRuns.WithLabelValues("rule_change", "error").Inc()
		return err
	}
	metrics.SoDReevaluationRuns.WithLabelValues("rule_change", "ok").Inc()
	return nil
}

// ReevaluateTenantAsync fires ReevaluateTenant in the background with its own
// bounded context; it is the SoDService rule-change hook. Failures are logged
// (the daily pass converges anyway).
func (r *SoDReevaluator) ReevaluateTenantAsync(tenantID uuid.UUID) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := r.ReevaluateTenant(ctx, tenantID); err != nil {
			logger.Warn("SoD rule-change re-evaluation failed (daily pass will retry)",
				zap.String("tenant_id", tenantID.String()), zap.Error(err))
		}
	}()
}

func (r *SoDReevaluator) reevaluateTenant(ctx context.Context, tenantID uuid.UUID) error {
	rules, err := r.repo.ListActiveRulesForTenant(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}
	users, err := r.repo.ListUsersForSoDReevaluation(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	var firstErr error
	for userID, roleIDs := range users {
		if err := r.reevaluateUser(ctx, tenantID, userID, roleIDs, rules); err != nil {
			logger.Warn("SoD re-evaluation failed for user",
				zap.String("tenant_id", tenantID.String()), zap.String("user_id", userID.String()), zap.Error(err))
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (r *SoDReevaluator) reevaluateUser(ctx context.Context, tenantID, userID uuid.UUID, roleIDs []uuid.UUID, rules []models.SoDRule) error {
	held := map[string]bool{}
	if len(rules) > 0 && len(roleIDs) > 0 {
		names, err := r.permissions.GetUserPermissionNames(ctx, userID, tenantID)
		if err != nil {
			return fmt.Errorf("user permissions: %w", err)
		}
		for _, n := range names {
			held[n] = true
		}
	}

	keep := make([]uuid.UUID, 0)
	for _, rule := range rules {
		if !held[rule.PermissionA] || !held[rule.PermissionB] {
			continue
		}
		v := &models.SoDViolation{
			TenantID: tenantID, UserID: userID, RuleID: rule.ID,
			PermissionA: rule.PermissionA, PermissionB: rule.PermissionB,
			Mode: rule.Mode, RoleIDs: roleIDs,
		}
		newlyOpen, err := r.repo.ReportViolation(ctx, v)
		if err != nil {
			return err
		}
		keep = append(keep, rule.ID)
		if newlyOpen {
			r.recordDetected(ctx, v)
		}
	}

	resolved, err := r.repo.ResolveViolationsNotIn(ctx, tenantID, userID, keep)
	if err != nil {
		return err
	}
	if resolved > 0 {
		metrics.SoDViolationsResolved.Add(float64(resolved))
	}
	return nil
}

func (r *SoDReevaluator) recordDetected(ctx context.Context, v *models.SoDViolation) {
	metrics.SoDViolationsDetected.WithLabelValues(string(v.Mode)).Inc()
	// Warn mode: log + audit, never block or revoke (R1 policy).
	logger.SecurityAudit.Warn("SoD violation detected by continuous re-evaluation (warn mode)",
		zap.String("event", SoDAuditEventViolationDetected),
		zap.String("tenant_id", v.TenantID.String()),
		zap.String("user_id", v.UserID.String()),
		zap.String("rule_id", v.RuleID.String()),
		zap.String("permission_a", v.PermissionA),
		zap.String("permission_b", v.PermissionB),
		zap.String("mode", string(v.Mode)),
	)
	if r.audit != nil {
		userID := v.UserID
		r.audit.LogUserAction(ctx, v.TenantID, nil, &userID, SoDAuditEventViolationDetected, true, map[string]interface{}{
			"rule_id":      v.RuleID.String(),
			"permission_a": v.PermissionA,
			"permission_b": v.PermissionB,
			"mode":         string(v.Mode),
			"source":       "continuous_reevaluation",
		})
	}
}
