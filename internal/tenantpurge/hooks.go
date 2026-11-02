// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantpurge

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/sessionsweep"
	"github.com/dogukanturhal/falcon-id/internal/tenantstatus"
	sharedpurge "github.com/dogukanturhal/platform-shared/tenantpurge"
)

// revokeSessionsSQL ends the sessions of the tenant's home users and every session
// opened inside the tenant (visiting members).
const revokeSessionsSQL = `
UPDATE iam_sessions s
   SET is_active = false, ended_at = NOW(), end_reason = $2
  FROM iam_users u
 WHERE s.user_id = u.id
   AND (u.tenant_id = $1 OR s.tenant_id = $1)
   AND s.is_active = true
RETURNING s.id, s.user_id`

const revokeTokensSQL = `
UPDATE iam_oauth_tokens
   SET is_revoked = true, revoked_at = NOW()
 WHERE is_revoked = false
   AND (tenant_id = $1
        OR user_id IN (SELECT id FROM iam_users WHERE tenant_id = $1))`

func (h *hooks) key(cmd sharedpurge.Command) string { return cmd.RunID + "/" + cmd.TenantID }

// scoped opens a transaction scoped to the tenant (app.current_tenant_id), plus the
// immutability bypass when purge is true.
func (h *hooks) scoped(ctx context.Context, tenantID string, purge bool) (sharedpurge.Tx, error) {
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	if err := setTenantScope(ctx, tx, tenantID); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("set tenant scope: %w", err)
	}
	if purge {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_purge', 'on', true)"); err != nil {
			_ = tx.Rollback(ctx)
			return nil, fmt.Errorf("set purge mode: %w", err)
		}
	}
	return tx, nil
}

func sumCounts(m map[string]int64) int64 {
	var n int64
	for _, v := range m {
		n += v
	}
	return n
}

// runControl runs one phase of the control-plane sweep and folds its outcome in.
func (h *hooks) runControl(ctx context.Context, cmd sharedpurge.Command) (sharedpurge.ExternalEffect, error) {
	ack := h.control.Handle(ctx, cmd)
	outcome := sharedpurge.OutcomeOK
	if cmd.Phase == sharedpurge.PhasePlan {
		outcome = sharedpurge.OutcomePlanned
	}
	eff := sharedpurge.NewExternalEffect("falcon_id_control_db", "rows", "sweep:"+strconv.FormatInt(sumCounts(ack.Counts), 10), outcome)
	switch ack.Status {
	case sharedpurge.StatusBlocked:
		return eff, sharedpurge.Blocked("control database: " + ack.Error)
	case sharedpurge.StatusFailed:
		eff.Outcome = sharedpurge.OutcomeFailed
		return eff, fmt.Errorf("control database: %s", ack.Error)
	}
	return eff, nil
}

// Plan reports the account classification and the control-plane dry run.
func (h *hooks) Plan(ctx context.Context, cmd sharedpurge.Command) (sharedpurge.PlanReport, error) {
	var rep sharedpurge.PlanReport
	tx, err := h.scoped(ctx, cmd.TenantID, false)
	if err != nil {
		return rep, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	plan, err := classifyUsers(ctx, tx, cmd.TenantID)
	if err != nil {
		return rep, err
	}
	planned := func(kind, action string) {
		rep.External = append(rep.External, sharedpurge.NewExternalEffect(kind, cmd.TenantID, action, sharedpurge.OutcomePlanned))
	}
	planned("falcon_id_users", "delete:"+strconv.Itoa(len(plan.Delete)))
	planned("falcon_id_users", "rehome_kept:"+strconv.Itoa(len(plan.Rehome)))
	planned("falcon_id_users", "release_visiting_membership:"+strconv.FormatInt(plan.Visitors, 10))
	planned("spicedb", "delete_relationships")
	if h.control != nil {
		eff, err := h.runControl(ctx, cmd)
		rep.External = append(rep.External, eff)
		if err != nil {
			var be *sharedpurge.BlockedError
			if errors.As(err, &be) {
				rep.Blockers = append(rep.Blockers, be.Reason)
			} else {
				return rep, err
			}
		}
	}
	return rep, nil
}

// Quiesce ends the tenant's sessions and revokes its OAuth tokens so nobody can act
// in it while the erase runs.
func (h *hooks) Quiesce(ctx context.Context, cmd sharedpurge.Command) ([]sharedpurge.ExternalEffect, error) {
	tenant, err := uuid.Parse(cmd.TenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant id")
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	sessions, err := sessionsweep.End(ctx, tx, revokeSessionsSQL, tenantstatus.EndReasonTenantSuspended, "", tenant, tenantstatus.EndReasonTenantSuspended)
	if err != nil {
		return nil, fmt.Errorf("revoke sessions: %w", err)
	}
	tag, err := tx.Exec(ctx, revokeTokensSQL, tenant)
	if err != nil {
		return nil, fmt.Errorf("revoke oauth tokens: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return []sharedpurge.ExternalEffect{
		sharedpurge.NewExternalEffect("falcon_id_sessions", cmd.TenantID, "revoke:"+strconv.FormatInt(sessions, 10), sharedpurge.OutcomeOK),
		sharedpurge.NewExternalEffect("falcon_id_oauth_tokens", cmd.TenantID, "revoke:"+strconv.FormatInt(tag.RowsAffected(), 10), sharedpurge.OutcomeOK),
	}, nil
}

// BeforeErase sweeps the control-plane database.
func (h *hooks) BeforeErase(ctx context.Context, cmd sharedpurge.Command) ([]sharedpurge.ExternalEffect, error) {
	if h.control == nil {
		return nil, nil
	}
	eff, err := h.runControl(ctx, cmd)
	return []sharedpurge.ExternalEffect{eff}, err
}

// EraseTx handles the accounts around the tenant before the catalog sweep deletes
// the tenant's own rows.
func (h *hooks) EraseTx(ctx context.Context, cmd sharedpurge.Command, tx sharedpurge.Tx) error {
	plan, err := classifyUsers(ctx, tx, cmd.TenantID)
	if err != nil {
		return err
	}
	if err := rehomeUsers(ctx, tx, cmd.TenantID, plan); err != nil {
		return err
	}
	skipped, err := anonymiseAudit(ctx, tx, cmd.TenantID)
	if err != nil {
		return fmt.Errorf("anonymise audit log: %w", err)
	}
	if skipped {
		h.log.Warn("tenant purge: role cannot update iam_audit_log, actor fields not anonymised", zap.String("run_id", cmd.RunID))
	}
	refs, err := eraseUserReferences(ctx, tx, plan.Delete)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.deleted[h.key(cmd)] = plan.Delete
	h.mu.Unlock()
	h.log.Info("tenant purge: accounts classified",
		zap.String("run_id", cmd.RunID), zap.Int("deleted", len(plan.Delete)), zap.Int("rehomed", len(plan.Rehome)),
		zap.Int64("visiting_released", plan.Visitors), zap.Int64("dependent_rows", sumCounts(refs)))
	return nil
}

// AfterErase deletes the iam_tenants row last and then the SpiceDB relationships;
// by then the reconcilers have nothing left to rewrite them from.
func (h *hooks) AfterErase(ctx context.Context, cmd sharedpurge.Command) ([]sharedpurge.ExternalEffect, error) {
	tx, err := h.scoped(ctx, cmd.TenantID, true)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `DELETE FROM iam_tenants WHERE id = $1::uuid`, cmd.TenantID); err != nil {
		return nil, fmt.Errorf("delete iam_tenants row: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	committed = true

	h.mu.Lock()
	users := h.deleted[h.key(cmd)]
	delete(h.deleted, h.key(cmd))
	h.mu.Unlock()
	n, err := h.spicedb.PurgeTenant(ctx, cmd.TenantID, users)
	eff := sharedpurge.NewExternalEffect("spicedb", cmd.TenantID, "delete_relationships:"+strconv.FormatInt(n, 10), sharedpurge.OutcomeOK)
	if err != nil {
		eff.Outcome = sharedpurge.OutcomeFailed
		return []sharedpurge.ExternalEffect{eff}, nil // BuildAck marks the phase failed; the retry repeats this step
	}
	return []sharedpurge.ExternalEffect{eff}, nil
}
