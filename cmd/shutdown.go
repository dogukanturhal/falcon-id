// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

const (
	defaultShutdownDrainDelay = 10 * time.Second
	defaultShutdownTimeout    = 25 * time.Second
)

// draining flips to true on SIGTERM/SIGINT. /health/ready returns 503 while
// it is set so the Service and gateway stop routing new requests here while
// the pod keeps serving in-flight and late-arriving ones. Liveness is not
// affected.
var draining atomic.Bool

// durationFromEnv parses a Go duration env var, falling back to def when
// unset, malformed or negative.
func durationFromEnv(key string, def time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		logger.Warn("invalid duration env, using default",
			zap.String("key", key), zap.String("value", raw), zap.Duration("default", def))
		return def
	}
	return d
}

// gracefulShutdown runs the ordered shutdown: mark draining, keep serving for
// drainDelay, shut the HTTP server down (bounded by timeout), then stop
// background tasks, then flush tracing. sleep is injectable for tests.
func gracefulShutdown(
	drainDelay, timeout time.Duration,
	sleep func(time.Duration),
	shutdownHTTP func(context.Context) error,
	stopBackground func(),
	flush func(context.Context),
) {
	draining.Store(true)
	logger.Info("Shutdown: draining, readiness now failing", zap.Duration("drain_delay", drainDelay))
	sleep(drainDelay)

	logger.Info("Shutdown: stopping HTTP server", zap.Duration("timeout", timeout))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := shutdownHTTP(ctx); err != nil {
		logger.Error("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Shutdown: stopping background tasks")
	stopBackground()

	logger.Info("Shutdown: flushing tracing")
	flush(ctx)
}
