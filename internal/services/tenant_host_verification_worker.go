// SPDX-License-Identifier: AGPL-3.0-or-later

// Package services — tenant_host_verification_worker.go
//
// Daily re-verification loop for iam_tenant_hosts. Reads rows in
// `active` or `pending_verification` state ordered by last_verified_at
// ASC NULLS FIRST, does a TXT lookup against the customer's DNS, and
// either marks the host verified (+ resets verification_failures to 0)
// or increments the failures counter. Hosts whose failures cross a
// configurable threshold are auto-suspended.
//
// Mirrors the existing DomainVerificationWorker (email-domain
// equivalent) but operates on iam_tenant_hosts. Lives in the same
// package so it can share the DNSResolver interface.
//
// Suspend policy (cross-vendor research consensus):
//   Auth0      — domain stops working when DNS proof lapses (no
//                grace period documented).
//   Okta       — disables verification at the cert layer once LE
//                renewal fails enough times.
//   Cognito    — auto-removes the custom domain alias if parent A
//                record disappears.
// We adopt the Okta-style "14 consecutive failures = suspend"
// (~14 days at daily cadence) — generous enough to ride out routine
// DNS hosting outages, strict enough to retire abandoned domains.
package services

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// tenantHostWorkerRepo is the narrow repository contract for the
// re-verification worker. Defined here so the worker is testable
// against a mock without standing up the full TenantHostRepository.
type tenantHostWorkerRepo interface {
	ListForRecheck(ctx context.Context, limit int) ([]*models.TenantHost, error)
	MarkVerified(ctx context.Context, id uuid.UUID) error
	RecordVerificationFailure(ctx context.Context, id uuid.UUID) error
	Suspend(ctx context.Context, id uuid.UUID) error
}

// TenantHostVerificationWorker periodically re-checks every active +
// pending host's TXT proof.
type TenantHostVerificationWorker struct {
	repo            tenantHostWorkerRepo
	resolver        DNSResolver
	logger          *zap.Logger
	interval        time.Duration
	batchSize       int
	suspendAfter    int
	cacheInvalidate func(host string)

	mu      sync.Mutex
	running bool
}

// NewTenantHostVerificationWorker builds a worker with the supplied
// dependencies. `cacheInvalidate` lets the worker punch through the
// HostDiscoveryService cache for state transitions; pass a no-op for
// standalone tests.
func NewTenantHostVerificationWorker(
	repo tenantHostWorkerRepo,
	resolver DNSResolver,
	cacheInvalidate func(host string),
	logger *zap.Logger,
) *TenantHostVerificationWorker {
	if logger == nil {
		logger = zap.NewNop()
	}
	if resolver == nil {
		resolver = &netHostDiscoveryDNSResolver{}
	}
	if cacheInvalidate == nil {
		cacheInvalidate = func(string) {}
	}
	return &TenantHostVerificationWorker{
		repo:            repo,
		resolver:        resolver,
		cacheInvalidate: cacheInvalidate,
		logger:          logger,
		interval:        24 * time.Hour,
		batchSize:       100,
		suspendAfter:    14,
	}
}

// SetInterval, SetBatchSize, SetSuspendAfter — tunables for tests +
// non-production deploys.
func (w *TenantHostVerificationWorker) SetInterval(d time.Duration)    { w.interval = d }
func (w *TenantHostVerificationWorker) SetBatchSize(n int)             { w.batchSize = n }
func (w *TenantHostVerificationWorker) SetSuspendAfter(n int)          { w.suspendAfter = n }

// Run blocks the caller, ticking every `interval`. Cancel via ctx.
// First tick fires immediately (so a newly-started pod doesn't have
// to wait 24h for the first reconciliation).
func (w *TenantHostVerificationWorker) Run(ctx context.Context) {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	w.running = true
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
	}()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// First tick immediate.
	if err := w.ReconcileOnce(ctx); err != nil {
		w.logger.Error("tenant_host_verification: initial reconcile failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.ReconcileOnce(ctx); err != nil {
				w.logger.Error("tenant_host_verification: reconcile failed", zap.Error(err))
			}
		}
	}
}

// ReconcileOnce performs a single pass: list up to batchSize rows
// due for re-check, TXT-lookup each, and transition state.
func (w *TenantHostVerificationWorker) ReconcileOnce(ctx context.Context) error {
	hosts, err := w.repo.ListForRecheck(ctx, w.batchSize)
	if err != nil {
		return fmt.Errorf("tenant_host_verification: list: %w", err)
	}
	for _, h := range hosts {
		w.checkOne(ctx, h)
	}
	return nil
}

func (w *TenantHostVerificationWorker) checkOne(ctx context.Context, h *models.TenantHost) {
	lookup := fmt.Sprintf("%s.%s", VerificationDNSPrefix, h.Host)
	records, err := w.resolver.LookupTXT(ctx, lookup)
	if err != nil {
		w.logger.Debug("tenant_host_verification: TXT lookup failed",
			zap.String("host", h.Host),
			zap.Error(err),
		)
		w.recordFailureAndMaybeSuspend(ctx, h)
		return
	}
	for _, rec := range records {
		if strings.TrimSpace(rec) == h.VerificationToken {
			if err := w.repo.MarkVerified(ctx, h.ID); err != nil {
				// MarkVerified rejects non-pending rows — that's fine
				// for already-active hosts (the row stays as-is). Log
				// + move on rather than count this as a failure.
				w.logger.Debug("tenant_host_verification: MarkVerified skipped",
					zap.String("host", h.Host),
					zap.Error(err),
				)
			}
			w.cacheInvalidate(h.Host)
			return
		}
	}
	// No matching record → failure.
	w.recordFailureAndMaybeSuspend(ctx, h)
}

func (w *TenantHostVerificationWorker) recordFailureAndMaybeSuspend(ctx context.Context, h *models.TenantHost) {
	if err := w.repo.RecordVerificationFailure(ctx, h.ID); err != nil {
		w.logger.Warn("tenant_host_verification: RecordVerificationFailure failed",
			zap.String("host", h.Host),
			zap.Error(err),
		)
		return
	}
	// Count BEFORE this increment + 1 (cheaper than re-reading).
	if h.VerificationFailures+1 >= w.suspendAfter {
		if err := w.repo.Suspend(ctx, h.ID); err != nil {
			w.logger.Error("tenant_host_verification: Suspend failed",
				zap.String("host", h.Host),
				zap.Error(err),
			)
			return
		}
		w.cacheInvalidate(h.Host)
		w.logger.Info("tenant_host_verification: host auto-suspended after consecutive failures",
			zap.String("host", h.Host),
			zap.Int("failures", h.VerificationFailures+1),
			zap.Int("threshold", w.suspendAfter),
		)
	}
}
