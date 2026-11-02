// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	employeeExpiryDefaultInterval = 15 * time.Minute
	employeeExpiryBatch           = 200
)

// EmployeeAccessExpiryWorker deactivates employee-class (ESS) seats whose access_expires_at has passed (R-HR WP-21). It
// iterates tenants and lists expired seats PER TENANT: iam_user_memberships has FORCE RLS, so a cross-tenant query would
// silently return no rows.
type EmployeeAccessExpiryWorker struct {
	db          *pgxpool.Pool
	memberships *repositories.UserMembershipRepository
	access      *EmployeeAccessService
	interval    time.Duration

	stopChan chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewEmployeeAccessExpiryWorker constructs the worker; interval <= 0 means every 15 minutes.
func NewEmployeeAccessExpiryWorker(db *pgxpool.Pool, memberships *repositories.UserMembershipRepository, access *EmployeeAccessService, interval time.Duration) *EmployeeAccessExpiryWorker {
	if interval <= 0 {
		interval = employeeExpiryDefaultInterval
	}
	return &EmployeeAccessExpiryWorker{db: db, memberships: memberships, access: access, interval: interval, stopChan: make(chan struct{})}
}

// Start launches the loop and returns immediately.
func (w *EmployeeAccessExpiryWorker) Start(ctx context.Context) {
	if w.db == nil || w.memberships == nil || w.access == nil {
		logger.Warn("Employee access expiry worker not started: missing dependencies")
		return
	}
	logger.Info("Starting employee access expiry worker", zap.Duration("interval", w.interval))
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if n, err := w.RunOnce(ctx); err != nil {
					logger.Warn("Employee access expiry pass failed", zap.Error(err))
				} else if n > 0 {
					logger.Info("Employee access expiry pass deactivated seats", zap.Int("deactivated", n))
				}
			case <-w.stopChan:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop signals the loop and waits for it. Safe to call more than once.
func (w *EmployeeAccessExpiryWorker) Stop() {
	w.stopOnce.Do(func() { close(w.stopChan) })
	w.wg.Wait()
}

// RunOnce makes one pass over every non-deleted tenant and returns how many seats it deactivated.
func (w *EmployeeAccessExpiryWorker) RunOnce(ctx context.Context) (int, error) {
	rows, err := w.db.Query(ctx, `SELECT id FROM iam_tenants WHERE status != 'deleted' ORDER BY id`)
	if err != nil {
		return 0, err
	}
	var tenants []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		tenants = append(tenants, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	deactivated := 0
	for _, tenantID := range tenants {
		users, err := w.memberships.ListExpiredEmployee(ctx, tenantID, employeeExpiryBatch)
		if err != nil {
			logger.Warn("Employee access expiry: list failed", zap.String("tenant_id", tenantID.String()), zap.Error(err))
			continue
		}
		for _, userID := range users {
			if err := w.access.Deactivate(ctx, tenantID, userID); err != nil {
				logger.Warn("Employee access expiry: deactivate failed (retried next pass)",
					zap.String("tenant_id", tenantID.String()), zap.String("user_id", userID.String()), zap.Error(err))
				continue
			}
			deactivated++
		}
	}
	return deactivated, nil
}
