// SPDX-License-Identifier: AGPL-3.0-or-later

package leaderelection

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// New creates a LeaderElector from the provided configuration.
//
// Method resolution:
//
//	"" or "advisory_lock" — PostgreSQL advisory lock backend (requires pool).
//	"k8s_lease"           — Kubernetes Lease backend (pool is ignored).
//
// An error is returned when:
//   - The method is "advisory_lock" (or empty) and pool is nil.
//   - The method string is not recognised.
func New(cfg Config, pool *pgxpool.Pool) (LeaderElector, error) {
	switch cfg.Method {
	case "", "advisory_lock":
		if pool == nil {
			return nil, fmt.Errorf(
				"leaderelection: pgxpool.Pool is required for advisory_lock leader election (lock=%q)",
				cfg.LockName,
			)
		}
		return NewAdvisoryLockElector(pool, cfg.LockID), nil

	case "k8s_lease":
		// Namespace and identity come from the pod environment
		// (POD_NAMESPACE / service-account file, POD_NAME / hostname).
		return NewK8sLeaseElector(cfg.LockName, "").WithOptions(K8sLeaseOptions{
			LeaseDuration: cfg.LeaseDuration,
			RetryPeriod:   cfg.RenewInterval,
		}), nil

	default:
		return nil, fmt.Errorf("leaderelection: unknown method %q (supported: advisory_lock, k8s_lease)", cfg.Method)
	}
}
