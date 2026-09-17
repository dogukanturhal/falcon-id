// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgxpool"
)

// QueryIntent communicates to ReadWritePool.Acquire which pool to select.
type QueryIntent int

const (
	// IntentWrite routes the query to the primary (read-write) pool.  This is
	// the default intent; Acquire returns the primary when no intent is stored
	// in the context.
	IntentWrite QueryIntent = iota

	// IntentRead routes the query to a read replica using round-robin
	// selection.  If no replicas are configured, the primary is used.
	IntentRead

	// IntentReadStrong routes the query to the primary to guarantee reading
	// the latest committed data, bypassing any replication lag.
	IntentReadStrong
)

// contextKey is the unexported key type used for context values in this package.
type contextKey int

const intentKey contextKey = iota

// WithReadIntent returns a copy of ctx with IntentRead stored inside.
// Acquire on a ReadWritePool will route to a replica when this context is used.
func WithReadIntent(ctx context.Context) context.Context {
	return context.WithValue(ctx, intentKey, IntentRead)
}

// WithWriteIntent returns a copy of ctx with IntentWrite stored inside.
// This is the default, but callers can use it to be explicit.
func WithWriteIntent(ctx context.Context) context.Context {
	return context.WithValue(ctx, intentKey, IntentWrite)
}

// WithStrongReadIntent returns a copy of ctx with IntentReadStrong stored
// inside.  Acquire will route to the primary even when replicas are present.
func WithStrongReadIntent(ctx context.Context) context.Context {
	return context.WithValue(ctx, intentKey, IntentReadStrong)
}

// queryIntentFromContext extracts the QueryIntent stored in ctx, defaulting to
// IntentWrite if none is present.
func queryIntentFromContext(ctx context.Context) QueryIntent {
	v := ctx.Value(intentKey)
	if v == nil {
		return IntentWrite
	}
	intent, ok := v.(QueryIntent)
	if !ok {
		return IntentWrite
	}
	return intent
}

// ErrNoPrimary is returned when ReadWritePool has no primary pool configured.
var ErrNoPrimary = errors.New("rwpool: no primary database pool configured")

// ReadWritePool is a thin routing layer on top of one primary and zero or more
// replica pgxpool.Pool instances.
//
//   - Writes and strong reads always go to the primary.
//   - Normal reads are distributed across replicas in a round-robin fashion.
//   - When no replicas are configured, reads are also served by the primary.
//
// ReadWritePool does NOT manage connection lifecycle; it merely selects which
// pool to use.  All pools must be fully initialised before calling Acquire.
type ReadWritePool struct {
	primary  *pgxpool.Pool
	replicas []*pgxpool.Pool
	// index is used for round-robin replica selection.
	index atomic.Uint64
}

// NewReadWritePool creates a ReadWritePool with the given primary and optional
// replica pools.
func NewReadWritePool(primary *pgxpool.Pool, replicas ...*pgxpool.Pool) *ReadWritePool {
	rp := &ReadWritePool{
		primary:  primary,
		replicas: replicas,
	}
	return rp
}

// Acquire selects and returns the appropriate pool for the query intent stored
// in ctx.  The returned pool must NOT be closed by the caller; it belongs to
// ReadWritePool.
//
// Intent resolution rules:
//
//	IntentWrite / IntentReadStrong / no intent → primary
//	IntentRead with replicas configured        → round-robin replica
//	IntentRead without replicas                → primary
func (p *ReadWritePool) Acquire(ctx context.Context) (*pgxpool.Pool, error) {
	if p.primary == nil {
		return nil, ErrNoPrimary
	}

	intent := queryIntentFromContext(ctx)

	switch intent {
	case IntentRead:
		if len(p.replicas) > 0 {
			// Round-robin selection.
			idx := p.index.Add(1) - 1
			return p.replicas[idx%uint64(len(p.replicas))], nil
		}
		// No replicas; fall through to primary.
		return p.primary, nil

	default: // IntentWrite, IntentReadStrong, or unknown
		return p.primary, nil
	}
}

// Primary returns the primary (read-write) pool directly.
func (p *ReadWritePool) Primary() *pgxpool.Pool {
	return p.primary
}

// ReplicaCount returns the number of replica pools configured.
func (p *ReadWritePool) ReplicaCount() int {
	return len(p.replicas)
}

// Close closes all managed pools (primary + replicas).  It should be called
// once during graceful shutdown.
func (p *ReadWritePool) Close() {
	if p.primary != nil {
		p.primary.Close()
	}
	for _, r := range p.replicas {
		if r != nil {
			r.Close()
		}
	}
}

// String returns a human-readable description of the pool configuration.
func (p *ReadWritePool) String() string {
	return fmt.Sprintf("ReadWritePool{primary=%v, replicas=%d}", p.primary != nil, len(p.replicas))
}
