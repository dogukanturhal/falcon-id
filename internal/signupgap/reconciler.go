// SPDX-License-Identifier: AGPL-3.0-or-later

// Package signupgap runs periodic background jobs around abandoned
// self-service signups — the falcon-id-side half of the platform's
// signup-abandonment-recovery work (see platform-core's trialexpiry
// package for the tenant-management-side half, which this package
// deliberately mirrors: same Config/Start/Stop/run shape, same metrics
// conventions, same structured-log style).
//
// Production evidence (2026-09) showed three distinct failure shapes for
// self-service signup:
//  1. Abandoned before InitiateSignup ever verified — the email link was
//     never clicked. These rows simply expire (ExpiresAt, 24h from
//     creation) and are genuinely dead: nothing to recover, nothing to
//     notify (we never confirmed the address is real / wanted by anyone).
//  2. Verified but never completed CompleteSignup — the person came back
//     to a live tab or bookmark, or gave up partway through picking a
//     password. Unlike (1), the email IS confirmed real, so this is the
//     recoverable case: Reconciler leaves these alone (see NOT completed
//     AND expired in DeleteExpired's WHERE clause — verified-but-expired
//     rows are reaped as dead once their window closes, same as
//     never-verified ones), and GapReconciler (gap_reconciler.go)
//     surfaces how many are CURRENTLY in the still-recoverable window.
//  3. Completed, but the underlying provisionTenant call was not
//     idempotent on retry, producing a second orphaned tenant-management
//     tenant for the same person (production: "atlasbadi" 938ba35f vs.
//     "atlasbadi-a1ad" cf097694). That failure shape is NOT a reconciler
//     concern — it is fixed at the source in signup_service.go
//     (InitiateSignup's verified-pending-reuse branch and
//     provisionTenant's req.TenantID resume checkpoint, both added
//     alongside this package) and has no residual cleanup component here
//     (the tenant-management-side orphan it can still leave behind is
//     tenant-management's to reap — see platform-core's orphan-tenant
//     work).
//
// Reconciler here handles ONLY the reaping half: rows in
// iam_signup_requests that are unrecoverable — never completed and past
// their expiry window. It drives the SignupRequestRepository.DeleteExpired
// method, which existed, was tested, and was correct well before this
// package — it was simply never called by anything. See
// GapReconciler for the "currently recoverable, not yet dead" detection
// half of this work.
package signupgap

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ExpiredSignupReaper is the surface of *repositories.SignupRequestRepository
// this reconciler needs. Defined as an interface so it can be exercised
// with a fake in unit tests without a real DB.
type ExpiredSignupReaper interface {
	// DeleteExpired removes every signup request that is NOT completed
	// and whose expires_at has passed, and returns how many rows were
	// deleted. This predicate can never match a completed signup — a
	// completed signup has tenant_id/user_id set and represents a real,
	// live account; the WHERE clause excludes it unconditionally,
	// regardless of how old it is. See
	// signup_request_repository_test.go's reaping-predicate tests for
	// the proof.
	DeleteExpired(ctx context.Context) (int64, error)
}

// Config knobs for the reconciler. Zero values yield sensible defaults.
type Config struct {
	// PollInterval is how often a reap cycle runs. Default 1h — signup
	// expiry is not latency-sensitive (rows only become eligible 24h
	// after creation), so this is tuned for low overhead over fast
	// reaction, same rationale as trialexpiry.Config.PollInterval.
	PollInterval time.Duration
}

func (c *Config) withDefaults() {
	if c.PollInterval <= 0 {
		c.PollInterval = time.Hour
	}
}

// Reconciler periodically drives ExpiredSignupReaper.DeleteExpired.
type Reconciler struct {
	reaper  ExpiredSignupReaper
	metrics *Metrics
	log     *zap.SugaredLogger
	cfg     Config

	stopCh chan struct{}
	doneCh chan struct{}
	once   sync.Once
}

// NewReconciler constructs a Reconciler. Caller must call Start to begin
// processing and Stop before exit to wait for the in-flight cycle to
// finish.
func NewReconciler(reaper ExpiredSignupReaper, metrics *Metrics, log *zap.SugaredLogger, cfg Config) *Reconciler {
	cfg.withDefaults()
	return &Reconciler{
		reaper:  reaper,
		metrics: metrics,
		log:     log,
		cfg:     cfg,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

// Start launches the reconciler goroutine. Returns immediately. Safe to
// call once; subsequent calls are no-ops.
func (r *Reconciler) Start(ctx context.Context) {
	r.once.Do(func() {
		go r.run(ctx)
	})
}

// Stop signals the reconciler to exit and waits for the current cycle
// (if any) to finish. Safe to call multiple times.
func (r *Reconciler) Stop() {
	select {
	case <-r.stopCh:
		// already stopped
	default:
		close(r.stopCh)
	}
	<-r.doneCh
}

func (r *Reconciler) run(ctx context.Context) {
	defer close(r.doneCh)

	// Run one cycle immediately on start so a restart after a long
	// downtime does not have to wait a full PollInterval before
	// catching up on a backlog.
	r.cycle(ctx)

	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			if r.log != nil {
				r.log.Info("signup gap reconciler stopping")
			}
			return
		case <-ctx.Done():
			if r.log != nil {
				r.log.Info("signup gap reconciler context cancelled")
			}
			return
		case <-ticker.C:
			r.cycle(ctx)
		}
	}
}

// cycle runs exactly one DeleteExpired call. Unlike trialexpiry's
// batched drain loop, there is no inner "repeat until short batch" here:
// DeleteExpired is a single bulk DELETE bounded entirely by its own WHERE
// clause (not a paginated cursor, and not a row-locking transaction that
// needs bounding to avoid a long-held lock — a stateless bulk delete has
// no such risk), so one call per cycle fully catches up the backlog every
// time regardless of size.
func (r *Reconciler) cycle(ctx context.Context) {
	select {
	case <-r.stopCh:
		return
	case <-ctx.Done():
		return
	default:
	}

	start := time.Now()
	deleted, err := r.reaper.DeleteExpired(ctx)
	duration := time.Since(start)

	if err != nil {
		if r.log != nil {
			r.log.Errorw("signup gap reconciler reap cycle failed", "error", err)
		}
		if r.metrics != nil {
			r.metrics.CyclesTotal.WithLabelValues("error").Inc()
		}
		return
	}

	if r.metrics != nil {
		r.metrics.CycleDurationSeconds.Observe(duration.Seconds())
		if deleted > 0 {
			r.metrics.SignupsReapedTotal.Add(float64(deleted))
			r.metrics.CyclesTotal.WithLabelValues("reaped").Inc()
		} else {
			r.metrics.CyclesTotal.WithLabelValues("idle").Inc()
		}
	}

	if deleted > 0 && r.log != nil {
		r.log.Infow("signup gap reconciler reaped expired signup requests", "count", deleted)
	}
}
