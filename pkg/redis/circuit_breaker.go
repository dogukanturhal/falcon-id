// SPDX-License-Identifier: AGPL-3.0-or-later

// Package redis provides Redis-based caching and state management.
package redis

import (
	"context"
	"errors"
	"time"

	"github.com/dogukanturhal/falcon-id/pkg/circuitbreaker"
	"go.uber.org/zap"
)

// ErrCircuitOpen is returned by CircuitAwareClient methods when the underlying
// circuit breaker is in the Open state.  Callers that have a fallback path
// (e.g. fall through to a database query) should check for this error.
var ErrCircuitOpen = errors.New("redis circuit breaker is open")

// CircuitAwareClient wraps a *Client and gates every Redis operation through a
// circuitbreaker.Breaker.  When the breaker is open, the operation returns
// ErrCircuitOpen immediately without touching the network, allowing the caller's
// existing fallback logic to activate with zero latency.
//
// The embedded *Client is intentionally unexported through the wrapper: callers
// must use the methods defined on CircuitAwareClient.  If raw access is needed
// (e.g. for Pipeline), obtain the inner client through Unwrap.
type CircuitAwareClient struct {
	*Client
	breaker *circuitbreaker.Breaker
	logger  *zap.Logger
}

// NewCircuitAwareClient creates a CircuitAwareClient that decorates the given
// Client with the supplied circuit breaker configuration.
func NewCircuitAwareClient(client *Client, cfg circuitbreaker.Config) *CircuitAwareClient {
	if cfg.Name == "" {
		cfg.Name = "redis"
	}
	b := circuitbreaker.New(cfg)
	return &CircuitAwareClient{
		Client:  client,
		breaker: b,
		logger:  client.logger,
	}
}

// Unwrap returns the underlying *Client for operations not covered by this
// wrapper.  Use sparingly; calls made through the raw client bypass circuit
// breaking.
func (c *CircuitAwareClient) Unwrap() *Client {
	return c.Client
}

// BreakerState returns the current state of the circuit breaker.
func (c *CircuitAwareClient) BreakerState() circuitbreaker.State {
	return c.breaker.State()
}

// BreakerStats returns a snapshot of the circuit breaker's counters.
func (c *CircuitAwareClient) BreakerStats() circuitbreaker.Stats {
	return c.breaker.Stats()
}

// ResetBreaker forces the circuit breaker back to the Closed state.  Intended
// for administrative/operational use only.
func (c *CircuitAwareClient) ResetBreaker() {
	c.breaker.Reset()
	c.logger.Warn("Redis circuit breaker manually reset to closed state")
}

// ============================================================
// Wrapped operations
// ============================================================

// Get wraps Client.Get with circuit breaking.
func (c *CircuitAwareClient) Get(ctx context.Context, key string) (string, error) {
	var result string
	err := c.breaker.Execute(func() error {
		var e error
		result, e = c.Client.Get(ctx, key)
		return e
	})
	return result, mapBreakerErr(err)
}

// Set wraps Client.Set with circuit breaking.
func (c *CircuitAwareClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return mapBreakerErr(c.breaker.Execute(func() error {
		return c.Client.Set(ctx, key, value, expiration)
	}))
}

// Del wraps Client.Del with circuit breaking.
func (c *CircuitAwareClient) Del(ctx context.Context, keys ...string) error {
	return mapBreakerErr(c.breaker.Execute(func() error {
		return c.Client.Del(ctx, keys...)
	}))
}

// Exists wraps Client.Exists with circuit breaking.
func (c *CircuitAwareClient) Exists(ctx context.Context, keys ...string) (int64, error) {
	var result int64
	err := c.breaker.Execute(func() error {
		var e error
		result, e = c.Client.Exists(ctx, keys...)
		return e
	})
	return result, mapBreakerErr(err)
}

// Expire wraps Client.Expire with circuit breaking.
func (c *CircuitAwareClient) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return mapBreakerErr(c.breaker.Execute(func() error {
		return c.Client.Expire(ctx, key, expiration)
	}))
}

// TTL wraps Client.TTL with circuit breaking.
func (c *CircuitAwareClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	var result time.Duration
	err := c.breaker.Execute(func() error {
		var e error
		result, e = c.Client.TTL(ctx, key)
		return e
	})
	return result, mapBreakerErr(err)
}

// Incr wraps Client.Incr with circuit breaking.
func (c *CircuitAwareClient) Incr(ctx context.Context, key string) (int64, error) {
	var result int64
	err := c.breaker.Execute(func() error {
		var e error
		result, e = c.Client.Incr(ctx, key)
		return e
	})
	return result, mapBreakerErr(err)
}

// IncrBy wraps Client.IncrBy with circuit breaking.
func (c *CircuitAwareClient) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	var result int64
	err := c.breaker.Execute(func() error {
		var e error
		result, e = c.Client.IncrBy(ctx, key, value)
		return e
	})
	return result, mapBreakerErr(err)
}

// SetNX wraps Client.SetNX with circuit breaking.
func (c *CircuitAwareClient) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	var result bool
	err := c.breaker.Execute(func() error {
		var e error
		result, e = c.Client.SetNX(ctx, key, value, expiration)
		return e
	})
	return result, mapBreakerErr(err)
}

// Health wraps Client.Health with circuit breaking.  Unlike other operations,
// a Health check failure does NOT count against the breaker's failure threshold
// because health probes are special-purpose and should not affect service
// availability decisions.  We call the underlying client directly.
func (c *CircuitAwareClient) Health(ctx context.Context) error {
	return c.Client.Health(ctx)
}

// mapBreakerErr translates circuitbreaker sentinel errors into the redis
// package's ErrCircuitOpen so that callers do not need to import the
// circuitbreaker package just to check for this condition.
func mapBreakerErr(err error) error {
	if errors.Is(err, circuitbreaker.ErrCircuitOpen) || errors.Is(err, circuitbreaker.ErrHalfOpenFull) {
		return ErrCircuitOpen
	}
	return err
}
