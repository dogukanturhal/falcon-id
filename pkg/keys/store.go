// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// rotationAdvisoryLockID is the pg_try_advisory_lock key electing the single signing
// key rotator across replicas. ASCII "keyrotat".
const rotationAdvisoryLockID int64 = 0x6B65_7972_6F74_6174

// keyStore is the persistence and election seam of the KeyManager. The production
// implementation is Postgres; tests use an in-memory store shared by several managers
// to model replicas.
type keyStore interface {
	// Load returns pending, active and rotated keys, newest activation first.
	Load(ctx context.Context) ([]SigningKey, error)
	Insert(ctx context.Context, sk SigningKey) error
	// Promote atomically sets pending -> active and each retire id active -> rotated.
	Promote(ctx context.Context, pendingID uuid.UUID, retire []uuid.UUID, now time.Time) error
	Revoke(ctx context.Context, kid string) error
	// WithRotationLock runs fn only if this caller wins the cross-replica rotation
	// lock (non-blocking). acquired is false when another replica holds it.
	WithRotationLock(ctx context.Context, fn func(ctx context.Context) error) (acquired bool, err error)
}

type pgStore struct{ pool *pgxpool.Pool }

func newPGStore(pool *pgxpool.Pool) *pgStore { return &pgStore{pool: pool} }

func (s *pgStore) Load(ctx context.Context) ([]SigningKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, algorithm, private_key_enc, public_key_pem, key_id, status, activated_at, rotated_at, expires_at, created_at
		 FROM iam_signing_keys
		 WHERE status IN ($1, $2, $3)
		 ORDER BY activated_at DESC`,
		StatusPending, StatusActive, StatusRotated,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []SigningKey
	for rows.Next() {
		var k SigningKey
		if err := rows.Scan(&k.ID, &k.Algorithm, &k.PrivateKeyEnc, &k.PublicKeyPEM, &k.KeyID, &k.Status, &k.ActivatedAt, &k.RotatedAt, &k.ExpiresAt, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan signing key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *pgStore) Insert(ctx context.Context, sk SigningKey) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO iam_signing_keys (id, algorithm, private_key_enc, public_key_pem, key_id, status, activated_at, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		sk.ID, sk.Algorithm, sk.PrivateKeyEnc, sk.PublicKeyPEM, sk.KeyID, sk.Status, sk.ActivatedAt, sk.ExpiresAt, sk.CreatedAt,
	)
	return err
}

func (s *pgStore) Promote(ctx context.Context, pendingID uuid.UUID, retire []uuid.UUID, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	// activated_at moves to the real activation instant so "newest active" ordering holds.
	tag, err := tx.Exec(ctx,
		`UPDATE iam_signing_keys SET status = $1, activated_at = $2 WHERE id = $3 AND status = $4`,
		StatusActive, now, pendingID, StatusPending,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("pending signing key %s not found", pendingID)
	}
	if len(retire) > 0 {
		if _, err := tx.Exec(ctx,
			`UPDATE iam_signing_keys SET status = $1, rotated_at = $2 WHERE id = ANY($3) AND status = $4`,
			StatusRotated, now, retire, StatusActive,
		); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *pgStore) Revoke(ctx context.Context, kid string) error {
	_, err := s.pool.Exec(ctx, `UPDATE iam_signing_keys SET status = $1 WHERE key_id = $2`, StatusRevoked, kid)
	return err
}

// WithRotationLock holds a session-level advisory lock on a dedicated connection for
// the duration of fn (a pool conn is pinned, so lock and unlock hit the same session).
func (s *pgStore) WithRotationLock(ctx context.Context, fn func(ctx context.Context) error) (bool, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return false, fmt.Errorf("acquire rotation lock conn: %w", err)
	}
	defer conn.Release()

	var got bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", rotationAdvisoryLockID).Scan(&got); err != nil {
		return false, fmt.Errorf("try rotation advisory lock: %w", err)
	}
	if !got {
		return false, nil
	}
	defer func() {
		// Must be a session-mode connection (never the transaction pooler): the
		// advisory lock lives on this backend session, so unlock has to hit it.
		// Fresh bounded ctx: unlock must run even if ctx was cancelled.
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var released bool
		uerr := conn.QueryRow(uctx, "SELECT pg_advisory_unlock($1)", rotationAdvisoryLockID).Scan(&released)
		if uerr != nil || !released {
			// Never return a connection that may still hold the lock to the pool.
			_ = conn.Hijack().Close(context.Background())
		}
	}()
	return true, fn(ctx)
}
