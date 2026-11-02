// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

type roleRevokeClient interface {
	DeleteUserRole(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (string, error)
}

// RoleRevokeDrainer owns role.revoked rows in the existing permission outbox.
// Row locks are held through the bounded SpiceDB call and acknowledgement:
// replica races are excluded and a crash rolls back the claim automatically.
// Unlike the generic outbox, a security revoke never exhausts its retries.
type RoleRevokeDrainer struct {
	db     repositories.DBPool
	client roleRevokeClient
	log    *zap.Logger
}

func NewRoleRevokeDrainer(db repositories.DBPool, client roleRevokeClient, log *zap.Logger) *RoleRevokeDrainer {
	if log == nil {
		log = zap.NewNop()
	}
	return &RoleRevokeDrainer{db: db, client: client, log: log}
}

// Start performs a startup sweep, then retries due rows every second.
func (d *RoleRevokeDrainer) Start(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := d.Drain(ctx, uuid.Nil); err != nil && ctx.Err() == nil {
			d.log.Warn("Role revoke outbox drain failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Drain attempts due rows, optionally scoped to a user for the post-commit
// fast path. Failures are durably rescheduled, never returned as a failed revoke.
func (d *RoleRevokeDrainer) Drain(ctx context.Context, userID uuid.UUID) error {
	// Bound each sweep as well as each RPC; a dead SpiceDB must not block
	// shutdown or a role-edit response for an entire batch of timeouts.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for i := 0; i < 100; i++ {
		found, err := d.attempt(ctx, userID)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
	}
	return nil
}

func (d *RoleRevokeDrainer) attempt(ctx context.Context, onlyUser uuid.UUID) (bool, error) {
	tx, err := d.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck
	var id, tenantID uuid.UUID
	var resourceID, subjectID string
	var attempts int
	err = tx.QueryRow(ctx, `SELECT id, tenant_id, resource_id, subject_id, retry_count
		FROM iam_permission_outbox WHERE event_type = 'role.revoked'
		AND status IN ('pending','failed') AND (next_retry_at IS NULL OR next_retry_at <= NOW())
		AND ($1::uuid = '00000000-0000-0000-0000-000000000000' OR subject_id = tenant_id::text || '/' || $1::text)
		ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED`, onlyUser).Scan(&id, &tenantID, &resourceID, &subjectID, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	prefix := tenantID.String() + "/"
	roleID, roleErr := uuid.Parse(strings.TrimPrefix(resourceID, prefix))
	userID, userErr := uuid.Parse(strings.TrimPrefix(subjectID, prefix))
	if roleErr != nil || userErr != nil || !strings.HasPrefix(resourceID, prefix) || !strings.HasPrefix(subjectID, prefix) {
		return false, fmt.Errorf("invalid role revoke tuple %s", id)
	}
	// Serialize with role edits; don't delete a later regrant or a live JIT
	// role preserved by the bulk role picker. Superseded revokes are complete.
	if _, err := tx.Exec(ctx, "SELECT id FROM iam_users WHERE id = $1 FOR UPDATE", userID); err != nil {
		return false, err
	}
	var regranted bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM iam_user_roles
		WHERE user_id=$1 AND role_id=$2 AND (expires_at IS NULL OR expires_at>NOW()))
		OR EXISTS (SELECT 1 FROM iam_jit_access_grants WHERE user_id=$1 AND role_id=$2
		AND tenant_id=$3 AND status='active' AND expires_at>NOW())`, userID, roleID, tenantID).Scan(&regranted); err != nil {
		return false, err
	}
	var deleteErr error
	if !regranted {
		if d.client == nil {
			deleteErr = errors.New("SpiceDB client unavailable")
		} else {
			rpcCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			_, deleteErr = d.client.DeleteUserRole(rpcCtx, tenantID, userID, roleID)
			cancel()
		}
	}
	if deleteErr != nil {
		_, err = tx.Exec(ctx, `UPDATE iam_permission_outbox SET status='failed',
		 retry_count=LEAST(retry_count::bigint+1,2147483647)::integer, error_message=$2, next_retry_at=$3
		 WHERE id=$1`, id, deleteErr.Error(), time.Now().Add(repositories.RoleRevokeRetryDelay(attempts+1)))
		d.log.Warn("SpiceDB role revoke queued for retry", zap.String("event_id", id.String()), zap.Error(deleteErr))
	} else {
		_, err = tx.Exec(ctx, `UPDATE iam_permission_outbox SET status='completed',
		 processed_at=NOW(), error_message=NULL, next_retry_at=NULL WHERE id=$1`, id)
	}
	if err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}
