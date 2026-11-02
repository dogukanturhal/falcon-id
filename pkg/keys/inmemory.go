// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// inMemoryStore is a process-local keyStore for tests of packages that consume a
// KeyManager (no database). Not for production use.
type inMemoryStore struct {
	mu   sync.Mutex
	rows []SigningKey
}

func (s *inMemoryStore) Load(context.Context) ([]SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []SigningKey
	for _, r := range s.rows {
		if r.Status != StatusRevoked {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ActivatedAt.After(out[j].ActivatedAt) })
	return out, nil
}

func (s *inMemoryStore) Insert(_ context.Context, sk SigningKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, sk)
	return nil
}

func (s *inMemoryStore) Promote(_ context.Context, pendingID uuid.UUID, retire []uuid.UUID, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rows {
		if s.rows[i].ID == pendingID && s.rows[i].Status == StatusPending {
			s.rows[i].Status, s.rows[i].ActivatedAt = StatusActive, now
			continue
		}
		for _, id := range retire {
			if s.rows[i].ID == id && s.rows[i].Status == StatusActive {
				t := now
				s.rows[i].Status, s.rows[i].RotatedAt = StatusRotated, &t
			}
		}
	}
	return nil
}

func (s *inMemoryStore) Revoke(_ context.Context, kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rows {
		if s.rows[i].KeyID == kid {
			s.rows[i].Status = StatusRevoked
		}
	}
	return nil
}

func (s *inMemoryStore) WithRotationLock(ctx context.Context, fn func(context.Context) error) (bool, error) {
	return true, fn(ctx)
}

// NewInMemoryKeyManager returns a KeyManager backed by an in-memory store and the
// given clock, for tests that need real rotation without a database.
func NewInMemoryKeyManager(opts Options, now func() time.Time) (*KeyManager, error) {
	km, err := newKeyManager(&inMemoryStore{}, make([]byte, 32), zap.NewNop())
	if err != nil {
		return nil, err
	}
	km.Configure(opts)
	km.now = now
	return km, nil
}
