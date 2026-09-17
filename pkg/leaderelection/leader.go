// SPDX-License-Identifier: AGPL-3.0-or-later

// Package leaderelection provides a pluggable distributed leader election
// abstraction for singleton background tasks. It decouples the calling code
// from the underlying coordination mechanism, allowing the backend to be
// swapped (e.g., from PostgreSQL advisory locks to Kubernetes Lease objects)
// without changing service logic.
//
// All implementations are safe for concurrent use from multiple goroutines.
package leaderelection

import (
	"context"
	"time"
)

// LeaderElector provides distributed leader election for singleton background tasks.
// Implementations must be safe for concurrent use from multiple goroutines.
type LeaderElector interface {
	// TryAcquire attempts to acquire leadership without blocking.
	// Returns (true, nil) if this instance is now the leader.
	// Returns (false, nil) if another instance holds leadership.
	// Returns (false, err) if the acquisition attempt itself failed.
	TryAcquire(ctx context.Context) (bool, error)

	// Release relinquishes leadership held by this instance.
	// It is safe to call Release when not the leader; the call is a no-op.
	Release(ctx context.Context) error

	// IsLeader reports whether this instance currently holds leadership.
	// The result reflects the last TryAcquire or Release outcome; it does
	// not perform an additional round-trip to the coordination backend.
	IsLeader() bool

	// RunAsLeader executes fn only if this instance can acquire leadership.
	// Leadership is released when fn returns. If this instance does not
	// acquire leadership, fn is not called and nil is returned.
	RunAsLeader(ctx context.Context, fn func(ctx context.Context)) error
}

// Config holds configuration for creating a LeaderElector via New.
type Config struct {
	// Method selects the leader election backend.
	// Supported values: "advisory_lock" (default), "k8s_lease".
	Method string

	// LockName is a human-readable unique identifier for this lock.
	// Used as the resource name in lease-based backends and for logging.
	LockName string

	// LockID is the numeric advisory lock ID used by the advisory_lock backend.
	// Choose a stable constant unique across your application. The two
	// existing constants in falcon-id are 857491001 (provisioning reconciler)
	// and 857491002 (schema migrator).
	LockID int64

	// RenewInterval controls how often a lease-based backend renews its hold.
	// Ignored by the advisory_lock backend. Defaults to LeaseDuration / 3.
	RenewInterval time.Duration

	// LeaseDuration is how long a lease lasts before it is considered expired
	// by the coordination backend. Ignored by the advisory_lock backend.
	LeaseDuration time.Duration
}
