// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RotationScheduler runs periodic key rotation checks.
type RotationScheduler struct {
	km       *KeyManager
	interval time.Duration
	logger   *zap.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRotationScheduler creates a new scheduler that checks for key rotation needs.
// interval is how often to check; the actual rotation happens when the active key
// is within 7 days of expiry.
func NewRotationScheduler(km *KeyManager, interval time.Duration, logger *zap.Logger) *RotationScheduler {
	return &RotationScheduler{
		km:       km,
		interval: interval,
		logger:   logger,
	}
}

// Start begins the rotation scheduler in a background goroutine.
func (rs *RotationScheduler) Start(ctx context.Context) {
	ctx, rs.cancel = context.WithCancel(ctx)

	rs.wg.Add(1)
	go func() {
		defer rs.wg.Done()
		rs.run(ctx)
	}()

	rs.logger.Info("Key rotation scheduler started",
		zap.Duration("check_interval", rs.interval),
	)
}

// Stop gracefully stops the rotation scheduler.
func (rs *RotationScheduler) Stop() {
	if rs.cancel != nil {
		rs.cancel()
	}
	rs.wg.Wait()
	rs.logger.Info("Key rotation scheduler stopped")
}

func (rs *RotationScheduler) run(ctx context.Context) {
	ticker := time.NewTicker(rs.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rs.checkAndRotate(ctx)
		}
	}
}

func (rs *RotationScheduler) checkAndRotate(ctx context.Context) {
	rs.km.mu.RLock()
	activeKey := rs.km.activeKey
	rs.km.mu.RUnlock()

	if activeKey == nil {
		rs.logger.Warn("No active signing key found during rotation check")
		return
	}

	// Rotate if the active key expires within 7 days
	rotationThreshold := 7 * 24 * time.Hour
	if time.Until(activeKey.ExpiresAt) <= rotationThreshold {
		rs.logger.Info("Active signing key approaching expiry, initiating rotation",
			zap.String("kid", activeKey.KeyID),
			zap.Time("expires_at", activeKey.ExpiresAt),
			zap.Duration("time_until_expiry", time.Until(activeKey.ExpiresAt)),
		)

		if err := rs.km.Rotate(ctx); err != nil {
			rs.logger.Error("Failed to rotate signing key", zap.Error(err))
			return
		}

		rs.logger.Info("Key rotation completed successfully")
	}
}
