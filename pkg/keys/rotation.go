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
// is within 7 days of expiry. The new key is published as pending and activated after
// the publish delay, so interval also bounds activation lateness.
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

// tickTimeout bounds each maintain/reload tick so a stuck DB call cannot wedge the loop.
const tickTimeout = 30 * time.Second

func (rs *RotationScheduler) run(ctx context.Context) {
	ticker := time.NewTicker(rs.interval)
	defer ticker.Stop()

	// Periodic reload keeps every replica's key set (and active key) converged.
	var reloadC <-chan time.Time
	if rs.km.store != nil {
		reloadTicker := time.NewTicker(rs.km.opts.WithDefaults().ReloadInterval)
		defer reloadTicker.Stop()
		reloadC = reloadTicker.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rs.checkAndRotate(ctx)
		case <-reloadC:
			rctx, cancel := context.WithTimeout(ctx, tickTimeout)
			err := rs.km.Reload(rctx)
			cancel()
			if err != nil {
				rs.logger.Warn("Periodic signing key reload failed", zap.Error(err))
			}
		}
	}
}

// checkAndRotate runs one lifecycle step. Every replica calls it; the advisory lock
// inside KeyManager.Maintain elects a single rotator and the expiry/pending state is
// re-checked under that lock, so concurrent replicas never rotate twice.
func (rs *RotationScheduler) checkAndRotate(ctx context.Context) {
	tctx, cancel := context.WithTimeout(ctx, tickTimeout)
	defer cancel()
	if err := rs.km.Maintain(tctx); err != nil {
		rs.logger.Error("Signing key lifecycle step failed", zap.Error(err))
	}
}
