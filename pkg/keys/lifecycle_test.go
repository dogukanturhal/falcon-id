// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// memStore is an in-memory keyStore shared by several KeyManagers (replicas).
type memStore struct {
	mu    sync.Mutex
	rows  []SigningKey
	loads int

	lock sync.Mutex // rotation lock, try-semantics via TryLock
}

func (s *memStore) Load(context.Context) ([]SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	var out []SigningKey
	for _, r := range s.rows {
		if r.Status != StatusRevoked {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ActivatedAt.After(out[j].ActivatedAt) })
	return out, nil
}

func (s *memStore) Insert(_ context.Context, sk SigningKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, sk)
	return nil
}

func (s *memStore) Promote(_ context.Context, pendingID uuid.UUID, retire []uuid.UUID, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rows {
		switch {
		case s.rows[i].ID == pendingID && s.rows[i].Status == StatusPending:
			s.rows[i].Status, s.rows[i].ActivatedAt = StatusActive, now
		default:
			for _, id := range retire {
				if s.rows[i].ID == id && s.rows[i].Status == StatusActive {
					t := now
					s.rows[i].Status, s.rows[i].RotatedAt = StatusRotated, &t
				}
			}
		}
	}
	return nil
}

func (s *memStore) Revoke(_ context.Context, kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rows {
		if s.rows[i].KeyID == kid {
			s.rows[i].Status = StatusRevoked
		}
	}
	return nil
}

func (s *memStore) WithRotationLock(ctx context.Context, fn func(context.Context) error) (bool, error) {
	if !s.lock.TryLock() {
		return false, nil
	}
	defer s.lock.Unlock()
	return true, fn(ctx)
}

func (s *memStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rows)
}

func (s *memStore) loadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loads
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newReplica(t *testing.T, store keyStore, clock *fakeClock, opts Options) *KeyManager {
	t.Helper()
	km, err := newKeyManager(store, make([]byte, 32), zap.NewNop())
	require.NoError(t, err)
	km.Configure(opts)
	km.now = clock.Now
	return km
}

func testOpts() Options {
	return Options{
		PublishDelay:       75 * time.Minute,
		ReloadInterval:     time.Minute,
		RetireAfter:        24 * time.Hour,
		MissReloadInterval: 10 * time.Second,
		KeyLifetime:        10 * 24 * time.Hour,
		RotationThreshold:  7 * 24 * time.Hour,
	}
}

func kidsByStatus(km *KeyManager) map[string]string {
	out := map[string]string{}
	for _, k := range km.AllPublicKeys() {
		out[k.KeyID] = k.Status
	}
	return out
}

// bootstrap returns a replica whose active key is inside the rotation threshold.
func bootstrap(t *testing.T) (*KeyManager, *memStore, *fakeClock, string) {
	t.Helper()
	store := &memStore{}
	clock := &fakeClock{t: time.Now()}
	km := newReplica(t, store, clock, testOpts())
	require.NoError(t, km.Initialize(context.Background()))
	_, kid, err := km.ActiveKey()
	require.NoError(t, err)
	clock.Advance(4 * 24 * time.Hour) // 10d lifetime - 4d = 6d left < 7d threshold
	return km, store, clock, kid
}

func TestPendingKeyPublishedButNotSigning(t *testing.T) {
	km, _, _, oldKID := bootstrap(t)
	ctx := context.Background()

	require.NoError(t, km.Maintain(ctx))

	_, signKID, err := km.ActiveKey()
	require.NoError(t, err)
	assert.Equal(t, oldKID, signKID, "pending key must not sign")

	st := kidsByStatus(km)
	require.Len(t, st, 2)
	var pendingKID string
	for kid, s := range st {
		if s == StatusPending {
			pendingKID = kid
		}
	}
	require.NotEmpty(t, pendingKID, "pending key must be published in JWKS")
	_, err = km.PublicKey(pendingKID)
	assert.NoError(t, err)

	// Further passes inside the publish window are idempotent.
	require.NoError(t, km.Maintain(ctx))
	assert.Len(t, kidsByStatus(km), 2)
}

func TestPendingKeyActivatesAfterPublishDelay(t *testing.T) {
	km, _, clock, oldKID := bootstrap(t)
	ctx := context.Background()
	require.NoError(t, km.Maintain(ctx))

	clock.Advance(74 * time.Minute)
	require.NoError(t, km.Maintain(ctx))
	_, kid, _ := km.ActiveKey()
	assert.Equal(t, oldKID, kid, "still inside the publish delay")

	clock.Advance(2 * time.Minute)
	v := km.Version()
	require.NoError(t, km.Maintain(ctx))
	_, kid, _ = km.ActiveKey()
	assert.NotEqual(t, oldKID, kid, "new key signs after the delay")
	assert.Equal(t, StatusRotated, kidsByStatus(km)[oldKID])
	assert.Equal(t, StatusActive, kidsByStatus(km)[kid])
	assert.NotEqual(t, v, km.Version(), "key-set version must change so JWKS caches refresh")
}

func TestRotatedKeyRetiredAfterGrace(t *testing.T) {
	km, _, clock, oldKID := bootstrap(t)
	ctx := context.Background()
	require.NoError(t, km.Maintain(ctx))
	clock.Advance(76 * time.Minute)
	require.NoError(t, km.Maintain(ctx))
	require.Contains(t, kidsByStatus(km), oldKID)

	clock.Advance(23 * time.Hour)
	require.NoError(t, km.Reload(ctx))
	assert.Contains(t, kidsByStatus(km), oldKID, "rotated key stays in JWKS within grace")

	clock.Advance(2 * time.Hour)
	require.NoError(t, km.Reload(ctx))
	assert.NotContains(t, kidsByStatus(km), oldKID, "rotated key dropped after RetireAfter")
}

func TestSecondReplicaPicksUpNewKeyAfterReload(t *testing.T) {
	km1, store, clock, oldKID := bootstrap(t)
	ctx := context.Background()
	km2 := newReplica(t, store, clock, testOpts())
	require.NoError(t, km2.Initialize(ctx))

	require.NoError(t, km1.Maintain(ctx))
	require.Len(t, kidsByStatus(km2), 1, "replica 2 has not reloaded yet")

	require.NoError(t, km2.Reload(ctx))
	st := kidsByStatus(km2)
	require.Len(t, st, 2)

	clock.Advance(76 * time.Minute)
	require.NoError(t, km1.Maintain(ctx))
	_, kid2, _ := km2.ActiveKey()
	assert.Equal(t, oldKID, kid2, "replica 2 still signs with the old key before reload")

	require.NoError(t, km2.Reload(ctx))
	_, kid1, _ := km1.ActiveKey()
	_, kid2, _ = km2.ActiveKey()
	assert.Equal(t, kid1, kid2, "replicas converge on the newest active key")
	assert.NotEqual(t, oldKID, kid2)
}

func TestSingleRotatorUnderConcurrency(t *testing.T) {
	_, store, clock, _ := bootstrap(t)
	ctx := context.Background()

	const replicas = 8
	kms := make([]*KeyManager, replicas)
	for i := range kms {
		kms[i] = newReplica(t, store, clock, testOpts())
		require.NoError(t, kms[i].Initialize(ctx))
	}
	before := store.count()

	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, km := range kms {
		wg.Add(1)
		go func(km *KeyManager) {
			defer wg.Done()
			<-start
			assert.NoError(t, km.Maintain(ctx))
		}(km)
	}
	close(start)
	wg.Wait()

	assert.Equal(t, before+1, store.count(), "exactly one replica may publish the next key")
}

func TestRotateIsIdempotentWhilePending(t *testing.T) {
	km, store, _, _ := bootstrap(t)
	ctx := context.Background()
	require.NoError(t, km.Rotate(ctx))
	n := store.count()
	require.NoError(t, km.Rotate(ctx))
	assert.Equal(t, n, store.count())
}

func TestUnknownKidTriggersRateLimitedReload(t *testing.T) {
	km1, store, clock, _ := bootstrap(t)
	ctx := context.Background()
	km2 := newReplica(t, store, clock, testOpts())
	require.NoError(t, km2.Initialize(ctx))

	require.NoError(t, km1.Maintain(ctx))
	var pendingKID string
	for kid, s := range kidsByStatus(km1) {
		if s == StatusPending {
			pendingKID = kid
		}
	}
	require.NotEmpty(t, pendingKID)

	_, err := km2.PublicKey(pendingKID)
	require.NoError(t, err, "unknown kid must trigger a reload that finds the key")

	// A different unknown kid inside the rate-limit window must not hit the store.
	loads := store.loadCount()
	_, err = km2.PublicKey("nope")
	assert.Error(t, err)
	_, err = km2.PublicKey(fmt.Sprintf("nope-%d", 2))
	assert.Error(t, err)
	assert.LessOrEqual(t, store.loadCount()-loads, 1, "at most one reload within the window")

	clock.Advance(11 * time.Second)
	loads = store.loadCount()
	_, err = km2.PublicKey("nope")
	assert.Error(t, err)
	assert.Equal(t, loads+1, store.loadCount(), "reload allowed again after the window")
}

func TestReloadPicksOldestActiveAndPromoteLeavesOne(t *testing.T) {
	store := &memStore{}
	clock := &fakeClock{t: time.Now()}
	km := newReplica(t, store, clock, testOpts())
	ctx := context.Background()
	base := clock.Now()
	var kids []string
	for _, age := range []time.Duration{3 * time.Hour, 2 * time.Hour, time.Hour} {
		require.NoError(t, km.insertNewKey(ctx, AlgorithmRS256, StatusActive, base.Add(-age)))
		kids = append(kids, store.rows[len(store.rows)-1].KeyID)
	}
	require.NoError(t, km.Initialize(ctx))
	_, kid, err := km.ActiveKey()
	require.NoError(t, err)
	assert.Equal(t, kids[0], kid, "oldest active key keeps signing")

	// Rotate: enter threshold window (10d lifetime), publish, activate.
	clock.Advance(4 * 24 * time.Hour)
	require.NoError(t, km.Maintain(ctx))
	clock.Advance(76 * time.Minute)
	require.NoError(t, km.Maintain(ctx))
	active := 0
	for _, st := range kidsByStatus(km) {
		if st == StatusActive {
			active++
		}
	}
	assert.Equal(t, 1, active, "exactly one active key after promote")
}

func TestReloadDropsRevokedPrevActive(t *testing.T) {
	km, store, _, oldKID := bootstrap(t)
	ctx := context.Background()
	store.mu.Lock()
	for i := range store.rows {
		if store.rows[i].KeyID == oldKID {
			store.rows[i].Status = StatusRevoked
		}
	}
	store.mu.Unlock()
	require.NoError(t, km.Reload(ctx))
	_, _, err := km.ActiveKey()
	assert.Error(t, err, "revoked previous signer must not keep signing")
	require.NoError(t, km.Maintain(ctx))
	_, kid, err := km.ActiveKey()
	require.NoError(t, err)
	assert.NotEqual(t, oldKID, kid)
}

// rotateRow marks the row with kid as rotated at the given time.
func rotateRow(store *memStore, kid string, at time.Time) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for i := range store.rows {
		if store.rows[i].KeyID == kid {
			store.rows[i].Status, store.rows[i].RotatedAt = StatusRotated, &at
		}
	}
}

func TestMaintainSkipsWhenSignerRotated(t *testing.T) {
	km, store, clock, oldKID := bootstrap(t)
	ctx := context.Background()
	rotateRow(store, oldKID, clock.Now())
	require.NoError(t, km.Reload(ctx)) // partial view: no active row, young rotated signer kept
	_, kid, err := km.ActiveKey()
	require.NoError(t, err)
	require.Equal(t, oldKID, kid)

	before := store.count()
	require.NoError(t, km.Rotate(ctx)) // force=true must not publish either
	assert.Equal(t, before, store.count(), "no key published while signing with a rotated key")
}

func TestReloadRotatedPrevActiveKeptWhenYoungDroppedWhenOld(t *testing.T) {
	km, store, clock, oldKID := bootstrap(t)
	ctx := context.Background()
	rotateRow(store, oldKID, clock.Now())

	clock.Advance(testOpts().RetireAfter/2 - time.Minute)
	require.NoError(t, km.Reload(ctx))
	_, kid, err := km.ActiveKey()
	require.NoError(t, err)
	assert.Equal(t, oldKID, kid, "young rotated signer kept")

	clock.Advance(2 * time.Minute)
	require.NoError(t, km.Reload(ctx))
	_, _, err = km.ActiveKey()
	assert.Error(t, err, "rotated signer older than RetireAfter/2 dropped")
}
