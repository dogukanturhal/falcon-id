// SPDX-License-Identifier: AGPL-3.0-or-later

package signupgap

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// StallDetector is the surface of *repositories.SignupRequestRepository
// this reconciler needs to count currently-recoverable, stalled signups.
type StallDetector interface {
	// CountStalledSignups returns how many signup requests are verified,
	// not completed, not yet expired, and were verified before the
	// cutoff — i.e. currently sitting in the recoverable window this
	// reconciler tracks.
	CountStalledSignups(ctx context.Context, verifiedBefore time.Time) (int, error)
}

// GapConfig knobs for GapReconciler.
type GapConfig struct {
	// PollInterval is how often the stall count is refreshed. Default
	// 15m — matches trialexpiry's GapReconciler default; this is a
	// cheap COUNT query, not a mutation, so more frequent polling is
	// safe, but there is no reason to poll faster than an operator
	// dashboard would refresh.
	PollInterval time.Duration
	// StallThreshold is how long after verification a request must sit
	// uncompleted before it counts as "stalled" rather than merely
	// mid-flow. Default 1h.
	//
	// Threshold rationale (see the accompanying report's research
	// citations for re-engagement-email timing benchmarks — a
	// send-at-1h/24h/72h cadence is the commonly cited pattern for cart-
	// /signup-abandonment recovery): 1h is deliberately short. It is
	// used here ONLY to size a metric (how many are currently stalled),
	// not to trigger any action, so erring toward counting a request
	// "stalled" a little early costs nothing — there is no send, no
	// write, no side effect tied to crossing this line.
	StallThreshold time.Duration
}

func (c *GapConfig) withDefaults() {
	if c.PollInterval <= 0 {
		c.PollInterval = 15 * time.Minute
	}
	if c.StallThreshold <= 0 {
		c.StallThreshold = time.Hour
	}
}

// GapReconciler periodically counts verified-but-not-completed signup
// requests older than GapConfig.StallThreshold and publishes the count as
// a gauge, plus a structured log line.
//
// IMPORTANT — what this deliberately does NOT do: send any email.
// falcon-id already has a SignupEmailSender capable of sending a
// transactional email (used by InitiateSignup for the verification link),
// but re-engagement email needs something that does not exist yet: a
// durable, visible record of what was sent to whom and when, so a retry
// of this reconciler (or a redeploy) does not re-send the same nudge
// indefinitely, and so an operator can audit exactly what went out. That
// record would need either a new iam_signup_requests column (e.g. a
// last_recovery_email_sent_at timestamp) or an equivalent table — a
// schema change this change deliberately does not ship (no Keystone
// MigrationBundle accompanies this package). Per the explicit instruction
// this work was done under: "if re-engagement email needs infrastructure
// that does not exist, say so and build the detection + recording half
// properly rather than faking a send" — this is that: the detection half
// (this file) is real and complete; the send half is not built, and is
// not faked.
type GapReconciler struct {
	detector StallDetector
	metrics  *GapMetrics
	log      *zap.SugaredLogger
	cfg      GapConfig

	stopCh chan struct{}
	doneCh chan struct{}
	once   sync.Once
}

// NewGapReconciler constructs a GapReconciler.
func NewGapReconciler(detector StallDetector, metrics *GapMetrics, log *zap.SugaredLogger, cfg GapConfig) *GapReconciler {
	cfg.withDefaults()
	return &GapReconciler{
		detector: detector,
		metrics:  metrics,
		log:      log,
		cfg:      cfg,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Start launches the reconciler goroutine. Safe to call once.
func (r *GapReconciler) Start(ctx context.Context) {
	r.once.Do(func() {
		go r.run(ctx)
	})
}

// Stop signals the reconciler to exit and waits for it to finish.
func (r *GapReconciler) Stop() {
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
	<-r.doneCh
}

func (r *GapReconciler) run(ctx context.Context) {
	defer close(r.doneCh)

	r.cycle(ctx)

	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			if r.log != nil {
				r.log.Info("signup stall gap reconciler stopping")
			}
			return
		case <-ctx.Done():
			if r.log != nil {
				r.log.Info("signup stall gap reconciler context cancelled")
			}
			return
		case <-ticker.C:
			r.cycle(ctx)
		}
	}
}

func (r *GapReconciler) cycle(ctx context.Context) {
	select {
	case <-r.stopCh:
		return
	case <-ctx.Done():
		return
	default:
	}

	start := time.Now()
	cutoff := time.Now().Add(-r.cfg.StallThreshold)
	count, err := r.detector.CountStalledSignups(ctx, cutoff)
	duration := time.Since(start)

	if err != nil {
		if r.log != nil {
			r.log.Errorw("signup stall gap reconciler cycle failed", "error", err)
		}
		if r.metrics != nil {
			r.metrics.CyclesTotal.WithLabelValues("error").Inc()
		}
		return
	}

	if r.metrics != nil {
		r.metrics.CycleDurationSeconds.Observe(duration.Seconds())
		r.metrics.StalledSignupsCurrent.Set(float64(count))
		r.metrics.CyclesTotal.WithLabelValues("ok").Inc()
	}

	if r.log != nil {
		r.log.Infow("signup stall gap reconciler cycle complete",
			"stalled_signup_count", count,
			"stall_threshold", r.cfg.StallThreshold.String(),
		)
	}
}
