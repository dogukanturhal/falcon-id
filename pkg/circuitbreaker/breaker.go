// SPDX-License-Identifier: AGPL-3.0-or-later

// Package circuitbreaker provides a generic, thread-safe circuit breaker
// implementation following the classic three-state pattern (Closed, Open,
// Half-Open).  It is intentionally dependency-free so that any package in the
// service can import it without introducing cycles.
package circuitbreaker

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// State represents the current state of a Breaker.
type State int

const (
	// StateClosed is the normal operating state.  All requests are allowed.
	StateClosed State = iota
	// StateOpen means the downstream is considered failing.  Requests are
	// rejected immediately without calling the wrapped function.
	StateOpen
	// StateHalfOpen is a probing state that allows a limited number of
	// requests to test whether the downstream has recovered.
	StateHalfOpen
)

// String returns a human-readable name for the state.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// Sentinel errors returned by Execute.
var (
	// ErrCircuitOpen is returned when Execute is called while the breaker is
	// in the Open state and the reset timeout has not yet elapsed.
	ErrCircuitOpen = errors.New("circuit breaker is open")

	// ErrHalfOpenFull is returned when Execute is called while the breaker is
	// in the Half-Open state and the maximum concurrent probing requests have
	// already been issued.
	ErrHalfOpenFull = errors.New("circuit breaker half-open: too many probe requests")
)

// Config holds all tunable parameters for a Breaker.
//
// Zero-value fields are replaced with safe defaults (see defaults below) so
// callers only need to set fields they care about.
type Config struct {
	// Name is an optional label used in OnStateChange callbacks and Stats.
	Name string

	// FailureThreshold is the number of consecutive failures required to
	// transition from Closed to Open.  Default: 5.
	FailureThreshold int

	// SuccessThreshold is the number of consecutive successes in the Half-Open
	// state required to transition back to Closed.  Default: 3.
	SuccessThreshold int

	// ResetTimeout is how long the breaker stays in the Open state before
	// transitioning to Half-Open to probe for recovery.  Default: 30s.
	ResetTimeout time.Duration

	// HalfOpenMaxRequests is the maximum number of concurrent requests
	// allowed through in the Half-Open state.  Default: 1.
	HalfOpenMaxRequests int

	// OnStateChange is an optional callback invoked whenever the state
	// changes.  It is called synchronously while a mutex is held, so it must
	// not block or call back into the Breaker.
	OnStateChange func(name string, from, to State)
}

func (c *Config) applyDefaults() {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = 5
	}
	if c.SuccessThreshold <= 0 {
		c.SuccessThreshold = 3
	}
	if c.ResetTimeout <= 0 {
		c.ResetTimeout = 30 * time.Second
	}
	if c.HalfOpenMaxRequests <= 0 {
		c.HalfOpenMaxRequests = 1
	}
}

// Stats is a point-in-time snapshot of Breaker counters.
type Stats struct {
	// Name mirrors Config.Name.
	Name string
	// State is the current state at the time of the snapshot.
	State State
	// Requests is the total number of times Execute has been called.
	Requests uint64
	// Successes is the total number of successful executions.
	Successes uint64
	// Failures is the total number of failed executions.
	Failures uint64
	// ConsecutiveFailures is the current run of consecutive failures.
	ConsecutiveFailures uint64
	// ConsecutiveSuccesses is the current run of consecutive successes
	// (relevant in Half-Open state).
	ConsecutiveSuccesses uint64
	// LastTransition is when the state last changed.
	LastTransition time.Time
}

// Breaker is a generic, thread-safe circuit breaker.  Use New to create one.
type Breaker struct {
	cfg Config

	// state is read/written atomically for hot-path checks; mutations that
	// need to update related timestamps or counters are also protected by mu.
	state int32 // atomic — values are State constants cast to int32

	// Counters are all atomic so Execute can read and update them without
	// acquiring mu in the common (Closed) case.
	requests             uint64 // atomic
	successes            uint64 // atomic
	failures             uint64 // atomic
	consecutiveFailures  uint32 // atomic
	consecutiveSuccesses uint32 // atomic
	halfOpenInFlight     int32  // atomic

	mu             sync.Mutex
	lastTransition time.Time
}

// New creates a Breaker with the given Config.
func New(cfg Config) *Breaker {
	cfg.applyDefaults()
	return &Breaker{
		state:          int32(StateClosed),
		cfg:            cfg,
		lastTransition: time.Now(),
	}
}

// State returns the current state of the breaker.
func (b *Breaker) State() State {
	return State(atomic.LoadInt32(&b.state))
}

// Stats returns a snapshot of the breaker's counters and state.
func (b *Breaker) Stats() Stats {
	b.mu.Lock()
	lt := b.lastTransition
	b.mu.Unlock()

	return Stats{
		Name:                 b.cfg.Name,
		State:                b.State(),
		Requests:             atomic.LoadUint64(&b.requests),
		Successes:            atomic.LoadUint64(&b.successes),
		Failures:             atomic.LoadUint64(&b.failures),
		ConsecutiveFailures:  uint64(atomic.LoadUint32(&b.consecutiveFailures)),
		ConsecutiveSuccesses: uint64(atomic.LoadUint32(&b.consecutiveSuccesses)),
		LastTransition:       lt,
	}
}

// Reset unconditionally transitions the breaker back to the Closed state and
// clears all counters.  Useful for administrative resets.
func (b *Breaker) Reset() {
	b.transitionTo(StateClosed)
}

// Execute calls fn if the breaker allows the request to proceed.
//
// If the breaker is Open and the reset timeout has not elapsed, ErrCircuitOpen
// is returned immediately without calling fn.  If the breaker is Half-Open and
// the maximum concurrent probing requests are already in-flight, ErrHalfOpenFull
// is returned.
//
// If fn returns a non-nil error the breaker records a failure; otherwise it
// records a success.  State transitions happen as a side-effect of recording.
func (b *Breaker) Execute(fn func() error) error {
	// Fast-path: gate the request based on current state.
	if err := b.allow(); err != nil {
		return err
	}

	atomic.AddUint64(&b.requests, 1)

	// In half-open state we track in-flight requests so we can cap them.
	inHalfOpen := b.State() == StateHalfOpen
	if inHalfOpen {
		atomic.AddInt32(&b.halfOpenInFlight, -1) // we already incremented in allow()
	}

	err := fn()

	if err != nil {
		b.recordFailure()
	} else {
		b.recordSuccess()
	}

	return err
}

// allow decides whether a request should be let through.
// It may transition Open -> Half-Open if the reset timeout has elapsed.
func (b *Breaker) allow() error {
	current := b.State()

	switch current {
	case StateClosed:
		return nil

	case StateOpen:
		b.mu.Lock()
		elapsed := time.Since(b.lastTransition)
		b.mu.Unlock()

		if elapsed >= b.cfg.ResetTimeout {
			// Attempt to transition.  Only one goroutine should succeed via CAS.
			if atomic.CompareAndSwapInt32(&b.state, int32(StateOpen), int32(StateHalfOpen)) {
				b.mu.Lock()
				old := b.lastTransition
				b.lastTransition = time.Now()
				b.mu.Unlock()

				if b.cfg.OnStateChange != nil {
					b.cfg.OnStateChange(b.cfg.Name, StateOpen, StateHalfOpen)
				}
				_ = old // suppress unused variable
				atomic.StoreUint32(&b.consecutiveSuccesses, 0)
				atomic.StoreUint32(&b.consecutiveFailures, 0)
				atomic.StoreInt32(&b.halfOpenInFlight, 0)
			}
			// After the CAS (successful or not), fall through to the Half-Open
			// handler to try to acquire a probe slot.
			return b.tryHalfOpen()
		}
		return ErrCircuitOpen

	case StateHalfOpen:
		return b.tryHalfOpen()

	default:
		return nil
	}
}

// tryHalfOpen attempts to acquire a probe slot in the Half-Open state.
func (b *Breaker) tryHalfOpen() error {
	inFlight := atomic.AddInt32(&b.halfOpenInFlight, 1)
	if inFlight > int32(b.cfg.HalfOpenMaxRequests) { //nolint:gosec // value is bounded by failure count config, safe conversion
		atomic.AddInt32(&b.halfOpenInFlight, -1)
		return ErrHalfOpenFull
	}
	return nil
}

// recordSuccess updates counters after a successful call.
func (b *Breaker) recordSuccess() {
	atomic.AddUint64(&b.successes, 1)
	atomic.StoreUint32(&b.consecutiveFailures, 0)

	current := b.State()
	if current == StateHalfOpen {
		atomic.AddInt32(&b.halfOpenInFlight, -1)
		count := atomic.AddUint32(&b.consecutiveSuccesses, 1)
		if int(count) >= b.cfg.SuccessThreshold {
			b.transitionTo(StateClosed)
		}
		return
	}

	// In closed state just track the run; no state transition needed.
	atomic.AddUint32(&b.consecutiveSuccesses, 1)
}

// recordFailure updates counters after a failed call.
func (b *Breaker) recordFailure() {
	atomic.AddUint64(&b.failures, 1)
	atomic.StoreUint32(&b.consecutiveSuccesses, 0)

	current := b.State()

	switch current {
	case StateClosed:
		count := atomic.AddUint32(&b.consecutiveFailures, 1)
		if int(count) >= b.cfg.FailureThreshold {
			b.transitionTo(StateOpen)
		}

	case StateHalfOpen:
		atomic.AddInt32(&b.halfOpenInFlight, -1)
		// A single failure while probing sends us back to Open.
		atomic.AddUint32(&b.consecutiveFailures, 1)
		b.transitionTo(StateOpen)
	}
}

// transitionTo moves the breaker to newState, resets relevant counters, and
// fires the OnStateChange callback.  It is safe to call even if the breaker is
// already in newState (transition is a no-op in that case).
func (b *Breaker) transitionTo(newState State) {
	b.mu.Lock()
	defer b.mu.Unlock()

	old := State(atomic.LoadInt32(&b.state))
	if old == newState {
		return
	}

	atomic.StoreInt32(&b.state, int32(newState)) //nolint:gosec // value is bounded by failure count config, safe conversion
	b.lastTransition = time.Now()

	// Reset counters on transition.
	atomic.StoreUint32(&b.consecutiveFailures, 0)
	atomic.StoreUint32(&b.consecutiveSuccesses, 0)
	atomic.StoreInt32(&b.halfOpenInFlight, 0)

	if b.cfg.OnStateChange != nil {
		b.cfg.OnStateChange(b.cfg.Name, old, newState)
	}
}
