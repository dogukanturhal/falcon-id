// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// HostHealthWorker periodically probes every registered database host and
// updates its health_status in the iam_realm_database_hosts table.
//
// The worker is started with Start(ctx) in a background goroutine and is
// stopped by either cancelling the context or calling Stop().
type HostHealthWorker struct {
	hostRepo   *repositories.DatabaseHostRepository
	encryption *crypto.EncryptionService // optional; nil = use raw DSN (dev mode)
	interval   time.Duration             // how often to probe all hosts
	timeout    time.Duration             // per-host probe deadline
	log        *zap.SugaredLogger
	stopCh     chan struct{}
}

const (
	defaultHealthInterval = 30 * time.Second
	defaultHealthTimeout  = 5 * time.Second
)

// NewHostHealthWorker creates a HostHealthWorker with default intervals (30s
// check cycle, 5s per-host timeout). Call SetEncryptionService to enable
// decryption of encrypted DSNs stored in the database.
func NewHostHealthWorker(
	hostRepo *repositories.DatabaseHostRepository,
	log *zap.SugaredLogger,
) *HostHealthWorker {
	return &HostHealthWorker{
		hostRepo: hostRepo,
		interval: defaultHealthInterval,
		timeout:  defaultHealthTimeout,
		log:      log,
		stopCh:   make(chan struct{}),
	}
}

// SetEncryptionService wires an optional EncryptionService so that connection
// strings stored with the "enc:v1:" prefix are decrypted before probing.
// When not set the worker uses the raw connection string (suitable for dev
// seeds that store plaintext DSNs).
func (w *HostHealthWorker) SetEncryptionService(enc *crypto.EncryptionService) {
	w.encryption = enc
}

// Start begins the background health-check loop. It should be called in a
// separate goroutine:
//
//	go worker.Start(ctx)
//
// The loop fires an initial probe immediately so host health is known at
// startup without waiting for the first interval to elapse.
func (w *HostHealthWorker) Start(ctx context.Context) {
	w.log.Infow("HostHealthWorker: starting",
		"interval", w.interval,
		"per_host_timeout", w.timeout,
	)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Probe once immediately so health is populated at startup.
	w.runProbes(ctx)

	for {
		select {
		case <-ticker.C:
			w.runProbes(ctx)
		case <-w.stopCh:
			w.log.Infow("HostHealthWorker: stopped")
			return
		case <-ctx.Done():
			w.log.Infow("HostHealthWorker: context cancelled, stopping")
			return
		}
	}
}

// Stop signals the worker to cease after the current probe round completes.
// It is safe to call Stop multiple times.
func (w *HostHealthWorker) Stop() {
	select {
	case <-w.stopCh:
		// Already closed — nothing to do.
	default:
		close(w.stopCh)
	}
}

// runProbes lists all hosts and probes each one, updating health_status in the
// database. Individual probe failures are logged but do not abort the round.
func (w *HostHealthWorker) runProbes(ctx context.Context) {
	hosts, err := w.hostRepo.List(ctx)
	if err != nil {
		w.log.Errorw("HostHealthWorker: failed to list hosts", "err", err)
		return
	}
	if len(hosts) == 0 {
		return
	}

	w.log.Debugw("HostHealthWorker: probing hosts", "count", len(hosts))

	for _, h := range hosts {
		// Each probe gets its own deadline.
		probeCtx, cancel := context.WithTimeout(ctx, w.timeout)
		healthy, reason := w.probeHost(probeCtx, h.ConnectionStringEnc)
		cancel()

		newStatus := fleetStatusHealthy
		if !healthy {
			newStatus = "unhealthy"
		}

		if err := w.hostRepo.UpdateHealthStatus(ctx, h.ID, newStatus); err != nil {
			w.log.Warnw("HostHealthWorker: failed to update health status",
				"host_id", h.ID,
				"host_alias", h.HostAlias,
				"err", err,
			)
			continue
		}

		if healthy {
			w.log.Debugw("HostHealthWorker: host healthy",
				"host_alias", h.HostAlias,
				"host_id", h.ID,
			)
		} else {
			w.log.Warnw("HostHealthWorker: host unhealthy",
				"host_alias", h.HostAlias,
				"host_id", h.ID,
				"reason", reason,
			)
		}
	}
}

// probeHost opens a single-connection pgxpool to the host, executes SELECT 1,
// and returns (true, "") on success or (false, errorMessage) on failure.
//
// DSN decryption:
//   - When an EncryptionService is wired and the stored value has the "enc:v1:"
//     prefix, the ciphertext is decrypted before connecting.
//   - When no EncryptionService is set, or the value has no encrypted prefix,
//     the raw string is used as-is (suitable for dev plaintext seeds).
func (w *HostHealthWorker) probeHost(ctx context.Context, connStringEnc string) (ok bool, reason string) {
	dsn := connStringEnc

	if crypto.IsEncrypted(connStringEnc) {
		if w.encryption != nil {
			decrypted, err := w.encryption.Decrypt(connStringEnc)
			if err != nil {
				return false, fmt.Sprintf("decrypt DSN: %v", err)
			}
			dsn = decrypted
		}
		// When no encryption service is wired but the DSN looks encrypted,
		// attempt to use the raw value; pgxpool.ParseConfig will fail and we record unhealthy.
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return false, fmt.Sprintf("parse DSN: %v", err)
	}

	// Minimal pool: one connection, connect timeout honours the per-host deadline.
	cfg.MaxConns = 1
	cfg.ConnConfig.ConnectTimeout = w.timeout

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return false, fmt.Sprintf("open pool: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, "SELECT 1"); err != nil {
		return false, fmt.Sprintf("SELECT 1: %v", err)
	}

	return true, ""
}
