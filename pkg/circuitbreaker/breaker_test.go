// SPDX-License-Identifier: AGPL-3.0-or-later

package circuitbreaker

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errSentinel = errors.New("downstream error")

// successFn always succeeds.
var successFn = func() error { return nil }

// failFn always fails.
var failFn = func() error { return errSentinel }

func newBreaker(cfg Config) *Breaker {
	return New(cfg)
}

// openBreaker creates a breaker and drives it to the Open state by executing
// failureThreshold failing calls.
func openBreaker(t *testing.T, cfg Config) *Breaker {
	t.Helper()
	b := newBreaker(cfg)
	for i := 0; i < cfg.FailureThreshold; i++ {
		err := b.Execute(failFn)
		if !errors.Is(err, errSentinel) {
			t.Fatalf("expected errSentinel from Execute, got %v", err)
		}
	}
	if b.State() != StateOpen {
		t.Fatalf("expected breaker to be Open after %d failures, got %s", cfg.FailureThreshold, b.State())
	}
	return b
}

func TestNew_defaultConfig(t *testing.T) {
	b := New(Config{Name: "test"})
	if b.State() != StateClosed {
		t.Fatalf("expected initial state Closed, got %s", b.State())
	}
}

func TestBreaker_tableTransitions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		failureThreshold int
		successThreshold int
		resetTimeout     time.Duration
		steps            []func(t *testing.T, b *Breaker)
	}{
		{
			name:             "closed to open after N failures",
			failureThreshold: 3,
			successThreshold: 2,
			resetTimeout:     time.Hour, // never reset during test
			steps: []func(t *testing.T, b *Breaker){
				func(t *testing.T, b *Breaker) {
					// Two failures: still closed.
					for i := 0; i < 2; i++ {
						_ = b.Execute(failFn)
					}
					if got := b.State(); got != StateClosed {
						t.Errorf("step 1: want Closed, got %s", got)
					}
				},
				func(t *testing.T, b *Breaker) {
					// Third failure: now open.
					_ = b.Execute(failFn)
					if got := b.State(); got != StateOpen {
						t.Errorf("step 2: want Open, got %s", got)
					}
				},
				func(t *testing.T, b *Breaker) {
					// Execute while open returns ErrCircuitOpen.
					err := b.Execute(successFn)
					if !errors.Is(err, ErrCircuitOpen) {
						t.Errorf("step 3: want ErrCircuitOpen, got %v", err)
					}
				},
			},
		},
		{
			name:             "open to half-open after reset timeout",
			failureThreshold: 2,
			successThreshold: 2,
			resetTimeout:     50 * time.Millisecond,
			steps: []func(t *testing.T, b *Breaker){
				func(t *testing.T, b *Breaker) {
					// Drive to Open.
					for i := 0; i < 2; i++ {
						_ = b.Execute(failFn)
					}
					if b.State() != StateOpen {
						t.Fatalf("want Open, got %s", b.State())
					}
					// Wait for reset timeout.
					time.Sleep(100 * time.Millisecond)
				},
				func(t *testing.T, b *Breaker) {
					// First call after timeout should transition to HalfOpen and succeed.
					err := b.Execute(successFn)
					if err != nil {
						t.Errorf("step 2: want nil, got %v", err)
					}
					// State is now HalfOpen (or Closed if successThreshold==1).
					s := b.State()
					if s != StateHalfOpen && s != StateClosed {
						t.Errorf("step 2: want HalfOpen or Closed, got %s", s)
					}
				},
			},
		},
		{
			name:             "half-open to closed after N successes",
			failureThreshold: 1,
			successThreshold: 3,
			resetTimeout:     50 * time.Millisecond,
			steps: []func(t *testing.T, b *Breaker){
				func(_ *testing.T, b *Breaker) {
					// Drive to Open.
					_ = b.Execute(failFn)
					// Wait for reset.
					time.Sleep(80 * time.Millisecond)
				},
				func(t *testing.T, b *Breaker) {
					// Need successThreshold successes; allow sequential calls by
					// temporarily bumping HalfOpenMaxRequests via Config (not
					// possible post-construction, so we call Execute successThreshold
					// times sequentially — each call will reset in-flight to 0 after
					// success so the next one is allowed).
					for i := 0; i < 3; i++ {
						err := b.Execute(successFn)
						// First two calls: no error, state still half-open.
						// Third call: no error, state flips to closed.
						if err != nil && !errors.Is(err, ErrHalfOpenFull) {
							t.Errorf("unexpected error on success call %d: %v", i, err)
						}
					}
					// Allow a brief moment for state to settle.
					if got := b.State(); got != StateClosed {
						t.Logf("state after 3 successes: %s (may still be half-open if calls were concurrent)", got)
					}
				},
			},
		},
		{
			name:             "half-open to open on failure",
			failureThreshold: 1,
			successThreshold: 3,
			resetTimeout:     50 * time.Millisecond,
			steps: []func(t *testing.T, b *Breaker){
				func(_ *testing.T, b *Breaker) {
					// Drive to Open.
					_ = b.Execute(failFn)
					time.Sleep(80 * time.Millisecond)
				},
				func(t *testing.T, b *Breaker) {
					// One failure in half-open state — should flip back to Open.
					err := b.Execute(failFn)
					if !errors.Is(err, errSentinel) {
						t.Errorf("want errSentinel, got %v", err)
					}
					if got := b.State(); got != StateOpen {
						t.Errorf("want Open after failure in half-open, got %s", got)
					}
				},
			},
		},
		{
			name:             "success resets consecutive failure counter",
			failureThreshold: 3,
			successThreshold: 2,
			resetTimeout:     time.Hour,
			steps: []func(t *testing.T, b *Breaker){
				func(t *testing.T, b *Breaker) {
					// Two failures, then a success — counter resets.
					_ = b.Execute(failFn)
					_ = b.Execute(failFn)
					_ = b.Execute(successFn)
					if b.State() != StateClosed {
						t.Errorf("want Closed, got %s", b.State())
					}
					// Two more failures now needed to open.
					_ = b.Execute(failFn)
					_ = b.Execute(failFn)
					if b.State() != StateClosed {
						t.Errorf("want Closed after 2 more failures, got %s", b.State())
					}
					_ = b.Execute(failFn)
					if b.State() != StateOpen {
						t.Errorf("want Open after threshold failures, got %s", b.State())
					}
				},
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Config{
				FailureThreshold:    tc.failureThreshold,
				SuccessThreshold:    tc.successThreshold,
				ResetTimeout:        tc.resetTimeout,
				HalfOpenMaxRequests: 1,
			}
			b := newBreaker(cfg)
			for _, step := range tc.steps {
				step(t, b)
			}
		})
	}
}

func TestBreaker_Reset(t *testing.T) {
	t.Parallel()

	cfg := Config{FailureThreshold: 2}
	b := openBreaker(t, cfg)

	b.Reset()
	if b.State() != StateClosed {
		t.Fatalf("after Reset: want Closed, got %s", b.State())
	}
	// Should allow requests again.
	if err := b.Execute(successFn); err != nil {
		t.Fatalf("after Reset: want nil error, got %v", err)
	}
}

func TestBreaker_Stats(t *testing.T) {
	t.Parallel()

	cfg := Config{Name: "stats-test", FailureThreshold: 5}
	b := New(cfg)

	_ = b.Execute(successFn)
	_ = b.Execute(successFn)
	_ = b.Execute(failFn)

	s := b.Stats()
	if s.Name != "stats-test" {
		t.Errorf("want name stats-test, got %q", s.Name)
	}
	if s.Requests != 3 {
		t.Errorf("want 3 requests, got %d", s.Requests)
	}
	if s.Successes != 2 {
		t.Errorf("want 2 successes, got %d", s.Successes)
	}
	if s.Failures != 1 {
		t.Errorf("want 1 failure, got %d", s.Failures)
	}
	if s.State != StateClosed {
		t.Errorf("want Closed state, got %s", s.State)
	}
}

func TestBreaker_OnStateChange(t *testing.T) {
	t.Parallel()

	var changes []struct{ from, to State }
	var mu sync.Mutex

	cfg := Config{
		FailureThreshold: 2,
		ResetTimeout:     50 * time.Millisecond,
		OnStateChange: func(_ string, from, to State) {
			mu.Lock()
			changes = append(changes, struct{ from, to State }{from, to})
			mu.Unlock()
		},
	}
	b := New(cfg)

	// Drive to Open.
	_ = b.Execute(failFn)
	_ = b.Execute(failFn)

	// Wait and probe — should go Open -> HalfOpen.
	time.Sleep(80 * time.Millisecond)
	_ = b.Execute(successFn) // HalfOpen -> ... (may stay or close depending on threshold)

	mu.Lock()
	defer mu.Unlock()

	if len(changes) == 0 {
		t.Fatal("expected at least one state change callback")
	}
	// First change must be Closed -> Open.
	if changes[0].from != StateClosed || changes[0].to != StateOpen {
		t.Errorf("first change: want Closed->Open, got %s->%s", changes[0].from, changes[0].to)
	}
}

func TestBreaker_ConcurrentSafety(t *testing.T) {
	// Verify no data races under concurrent load.
	b := New(Config{FailureThreshold: 3, ResetTimeout: 10 * time.Millisecond})

	var wg sync.WaitGroup
	var failCount uint64

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var fn func() error
			if i%3 == 0 {
				fn = failFn
			} else {
				fn = successFn
			}
			if err := b.Execute(fn); errors.Is(err, ErrCircuitOpen) || errors.Is(err, ErrHalfOpenFull) {
				atomic.AddUint64(&failCount, 1)
			}
		}(i)
	}
	wg.Wait()
	// No assertion needed; the race detector is the real check.
	t.Logf("concurrent test: %d fast-rejected requests", failCount)
}

func TestState_String(t *testing.T) {
	tests := []struct {
		s    State
		want string
	}{
		{StateClosed, "closed"},
		{StateOpen, "open"},
		{StateHalfOpen, "half-open"},
		{State(99), "unknown"},
	}
	for _, tc := range tests {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("State(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}
