// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// Errors returned by PlatformJITService. Handlers map these to HTTP
// statuses (see internal/handlers/platform_jit_handler.go).
var (
	// ErrPlatformRoleNotStandingAssignable is returned when a caller tries
	// to directly grant a non-platform_viewer role_key without a backing
	// active elevation - maps to 403 platform_role_not_standing_assignable.
	ErrPlatformRoleNotStandingAssignable = errors.New("platform_role_not_standing_assignable")
	// ErrNotPlatformInternalUser is returned when the subject user does
	// not belong to the Platform-internal tenant.
	ErrNotPlatformInternalUser = errors.New("platform_role_requires_internal_tenant")
	// ErrSelfApprovalNotAllowed is returned by the two-person rule.
	ErrSelfApprovalNotAllowed = errors.New("self_approval_not_allowed")
	// ErrElevationNotPending is returned when approving/activating a
	// non-pending/non-approved elevation.
	ErrElevationNotPending = errors.New("elevation_not_in_expected_state")
	// ErrInvalidRoleKey is returned for an unrecognized role_key.
	ErrInvalidRoleKey = errors.New("invalid_role_key")
	// ErrDurationExceedsCap is returned when a request exceeds the
	// standing-JIT (8h) or break-glass (1h) duration cap.
	ErrDurationExceedsCap = errors.New("duration_exceeds_cap")
)

// platformSpiceDBClient defines the SpiceDB operations required by
// PlatformJITService. *spicedb.Client satisfies this via Go's structural
// interfaces, matching the jitSpiceDBClient pattern in jit_access_service.go.
type platformSpiceDBClient interface {
	WritePlatformElevation(ctx context.Context, userID uuid.UUID, roleKey string, expiresAt time.Time) (string, error)
	DeletePlatformElevation(ctx context.Context, userID uuid.UUID, roleKey string) (string, error)
}

// platformUserTenantLookup resolves a user's tenant_id, used to enforce
// the Platform-internal-tenant membership rule at the service layer
// (in addition to, not instead of, the DB trigger - see migration 0016).
type platformUserTenantLookup interface {
	GetUserTenantID(ctx context.Context, userID uuid.UUID) (uuid.UUID, error)
}

// PlatformJITService implements the platform-plane JIT elevation +
// break-glass state machine (the product roadmap §4.1,
// the product specification §12.4).
type PlatformJITService struct {
	repo         *repositories.PlatformElevationRepository
	users        platformUserTenantLookup
	spicedb      platformSpiceDBClient
	auditService *AuditService
	logger       *zap.Logger
}

// NewPlatformJITService creates a new PlatformJITService.
func NewPlatformJITService(
	repo *repositories.PlatformElevationRepository,
	users platformUserTenantLookup,
	spicedb platformSpiceDBClient,
	auditService *AuditService,
	logger *zap.Logger,
) *PlatformJITService {
	return &PlatformJITService{
		repo:         repo,
		users:        users,
		spicedb:      spicedb,
		auditService: auditService,
		logger:       logger,
	}
}

func (s *PlatformJITService) requireInternalTenant(ctx context.Context, userID uuid.UUID) error {
	tenantID, err := s.users.GetUserTenantID(ctx, userID)
	if err != nil {
		return fmt.Errorf("PlatformJITService: resolve user tenant: %w", err)
	}
	if tenantID.String() != models.HexxlockInternalTenantID {
		return ErrNotPlatformInternalUser
	}
	return nil
}

// appendTransition writes one hash-chained audit row AND a
// AuditService.LogUserAction entry. Both are best-effort logged on
// failure, never fatal to the caller's transition - the elevation's own
// status column is the source of truth; the transition log and the
// general audit log are both secondary records of it. See migration
// 0016's header for why two separate audit paths exist.
func (s *PlatformJITService) appendTransition(ctx context.Context, e *models.PlatformElevation, fromStatus *string, actorID *uuid.UUID, action string, details map[string]interface{}) {
	prevHash, err := s.repo.LastTransitionHash(ctx, e.ID)
	if err != nil {
		s.logger.Error("PlatformJITService: failed to read prev transition hash", zap.Error(err), zap.String("elevation_id", e.ID.String()))
		prevHash = ""
	}

	detailsJSON, _ := json.Marshal(details)
	occurredAt := time.Now().UTC()

	actor := ""
	if actorID != nil {
		actor = actorID.String()
	}
	entryHash := ComputeImmutableEntryHash(prevHash, occurredAt, actor, action, "iam_jit_elevations", e.ID.String(), string(detailsJSON))

	if err := s.repo.AppendTransition(ctx, e.ID, fromStatus, string(e.Status), actorID, occurredAt, prevHash, entryHash, detailsJSON); err != nil {
		s.logger.Error("PlatformJITService: failed to append transition", zap.Error(err), zap.String("elevation_id", e.ID.String()))
	}

	if s.auditService != nil {
		internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
		s.auditService.LogUserAction(ctx, internalTenantID, actorID, &e.RequesterID, action, true, details)
	}
}

// RequestElevation creates a pending iam_jit_elevations row. reason and
// duration cap are validated by the model's binding tags upstream; this
// also re-validates server-side (never trust client-side-only validation)
// and enforces the Platform-internal-tenant membership rule on the
// requester.
func (s *PlatformJITService) RequestElevation(ctx context.Context, requesterID uuid.UUID, roleKey string, tenantScope *uuid.UUID, reason string, duration time.Duration) (*models.PlatformElevation, error) {
	if !models.IsValidPlatformRoleKey(roleKey) {
		return nil, ErrInvalidRoleKey
	}
	if duration <= 0 || duration > models.PlatformElevationMaxDuration {
		return nil, ErrDurationExceedsCap
	}
	if err := s.requireInternalTenant(ctx, requesterID); err != nil {
		return nil, err
	}

	e := &models.PlatformElevation{
		RequesterID:              requesterID,
		RoleKey:                  models.PlatformRoleKey(roleKey),
		TenantScope:              tenantScope,
		Reason:                   reason,
		Status:                   models.PlatformElevationPending,
		RequestedDurationSeconds: int(duration.Seconds()),
	}
	if err := s.repo.CreateElevation(ctx, e); err != nil {
		return nil, fmt.Errorf("PlatformJITService.RequestElevation: %w", err)
	}

	s.appendTransition(ctx, e, nil, &requesterID, "platform_jit_elevation_requested", map[string]interface{}{
		"role_key": roleKey, "reason": reason, "duration_seconds": e.RequestedDurationSeconds,
	})
	return e, nil
}

// ApproveElevation applies the two-person rule (approver_id must differ
// from requester_id - also enforced by the DB CHECK constraint as a
// second layer) and flips pending -> approved. Does NOT activate the
// SpiceDB grant yet; ActivateElevation does that as a separate step so an
// approval can be recorded even if the activation call happens later
// (e.g. scheduled for a maintenance window).
func (s *PlatformJITService) ApproveElevation(ctx context.Context, elevationID, approverID uuid.UUID) (*models.PlatformElevation, error) {
	e, err := s.repo.GetElevationByID(ctx, elevationID)
	if err != nil {
		return nil, err
	}
	if e.RequesterID == approverID {
		return nil, ErrSelfApprovalNotAllowed
	}
	if e.Status != models.PlatformElevationPending {
		return nil, ErrElevationNotPending
	}
	if err := s.requireInternalTenant(ctx, approverID); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if err := s.repo.UpdateElevationStatus(ctx, elevationID, models.PlatformElevationPending, models.PlatformElevationApproved,
		`, approver_id = $4, approved_at = $5`, approverID, now); err != nil {
		return nil, fmt.Errorf("PlatformJITService.ApproveElevation: %w", err)
	}

	e.Status = models.PlatformElevationApproved
	e.ApproverID = &approverID
	e.ApprovedAt = &now
	prevStatus := string(models.PlatformElevationPending)
	s.appendTransition(ctx, e, &prevStatus, &approverID, "platform_jit_elevation_approved", map[string]interface{}{"approver_id": approverID.String()})
	return e, nil
}

// ActivateElevation materializes the grant: writes the SpiceDB
// relationship FIRST (mirrors jit_access_service.go's ActivateGrant
// ordering - SpiceDB is the runtime PDP, so a DB row with no
// corresponding relationship is merely inert, while a relationship with
// no DB row would be a live, unaudited grant), then persists
// iam_platform_roles + flips iam_jit_elevations to active. Rolls back the
// SpiceDB write if the DB persist fails.
func (s *PlatformJITService) ActivateElevation(ctx context.Context, elevationID uuid.UUID) (*models.PlatformElevation, error) {
	e, err := s.repo.GetElevationByID(ctx, elevationID)
	if err != nil {
		return nil, err
	}
	if e.Status != models.PlatformElevationApproved {
		return nil, ErrElevationNotPending
	}

	expiresAt := time.Now().UTC().Add(time.Duration(e.RequestedDurationSeconds) * time.Second)

	zedToken, err := s.spicedb.WritePlatformElevation(ctx, e.RequesterID, string(e.RoleKey), expiresAt)
	if err != nil {
		return nil, fmt.Errorf("PlatformJITService.ActivateElevation: spicedb write: %w", err)
	}

	if err := s.repo.UpdateElevationStatus(ctx, elevationID, models.PlatformElevationApproved, models.PlatformElevationActive,
		`, expires_at = $4, spicedb_activate_zed_token = $5`, expiresAt, zedToken); err != nil {
		if _, delErr := s.spicedb.DeletePlatformElevation(ctx, e.RequesterID, string(e.RoleKey)); delErr != nil {
			s.logger.Error("PlatformJITService.ActivateElevation: failed to roll back SpiceDB write after DB persist failure",
				zap.Error(delErr), zap.String("elevation_id", elevationID.String()))
		}
		return nil, fmt.Errorf("PlatformJITService.ActivateElevation: persist: %w", err)
	}

	if err := s.repo.UpsertPlatformRole(ctx, &models.PlatformRole{UserID: e.RequesterID, RoleKey: e.RoleKey, GrantedBy: e.ApproverID}); err != nil {
		// The SpiceDB relationship (already the runtime authority) and the
		// iam_jit_elevations row are both correct at this point; the
		// iam_platform_roles row is a secondary projection for the admin
		// UI/roster - log and continue rather than roll back an already-
		// active, already-audited grant.
		s.logger.Error("PlatformJITService.ActivateElevation: failed to upsert iam_platform_roles projection",
			zap.Error(err), zap.String("elevation_id", elevationID.String()))
	}

	e.Status = models.PlatformElevationActive
	e.ExpiresAt = &expiresAt
	e.SpiceDBActivateZedToken = &zedToken
	prevStatus := string(models.PlatformElevationApproved)
	s.appendTransition(ctx, e, &prevStatus, e.ApproverID, "platform_jit_elevation_activated", map[string]interface{}{"expires_at": expiresAt})
	return e, nil
}

// RequestBreakGlass performs the immediate self-grant: creates the
// elevation row AND activates it in the same call (no prior approval -
// that's the point of break-glass), pages via the metric + structured log
// (RecordBreakGlassActivation), and starts the 24h retroactive-approval
// SLA clock (RunBreakGlassSLASweep enforces it later).
func (s *PlatformJITService) RequestBreakGlass(ctx context.Context, requesterID uuid.UUID, roleKey string, tenantScope *uuid.UUID, reason string, duration time.Duration) (*models.PlatformElevation, error) {
	if !models.IsValidPlatformRoleKey(roleKey) {
		return nil, ErrInvalidRoleKey
	}
	if duration <= 0 || duration > models.BreakGlassMaxDuration {
		return nil, ErrDurationExceedsCap
	}
	if err := s.requireInternalTenant(ctx, requesterID); err != nil {
		return nil, err
	}

	expiresAt := time.Now().UTC().Add(duration)

	zedToken, err := s.spicedb.WritePlatformElevation(ctx, requesterID, roleKey, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("PlatformJITService.RequestBreakGlass: spicedb write: %w", err)
	}

	e := &models.PlatformElevation{
		RequesterID:              requesterID,
		RoleKey:                  models.PlatformRoleKey(roleKey),
		TenantScope:              tenantScope,
		Reason:                   reason,
		Status:                   models.PlatformElevationActive,
		RequestedDurationSeconds: int(duration.Seconds()),
		ExpiresAt:                &expiresAt,
		IsBreakGlass:             true,
		SpiceDBActivateZedToken:  &zedToken,
	}
	if err := s.repo.CreateElevation(ctx, e); err != nil {
		if _, delErr := s.spicedb.DeletePlatformElevation(ctx, requesterID, roleKey); delErr != nil {
			s.logger.Error("PlatformJITService.RequestBreakGlass: failed to roll back SpiceDB write after DB persist failure",
				zap.Error(delErr), zap.String("requester_id", requesterID.String()))
		}
		return nil, fmt.Errorf("PlatformJITService.RequestBreakGlass: %w", err)
	}

	if err := s.repo.UpsertPlatformRole(ctx, &models.PlatformRole{UserID: requesterID, RoleKey: e.RoleKey}); err != nil {
		s.logger.Error("PlatformJITService.RequestBreakGlass: failed to upsert iam_platform_roles projection",
			zap.Error(err), zap.String("elevation_id", e.ID.String()))
	}

	RecordBreakGlassActivation(roleKey)
	s.logger.Error("PLATFORM BREAK-GLASS ACTIVATED - immediate self-grant, retroactive approval required within 24h",
		zap.String("requester_id", requesterID.String()),
		zap.String("role_key", roleKey),
		zap.String("reason", reason),
		zap.Time("expires_at", expiresAt),
		zap.String("elevation_id", e.ID.String()),
	)

	s.appendTransition(ctx, e, nil, &requesterID, "platform_break_glass_activated", map[string]interface{}{
		"role_key": roleKey, "reason": reason, "expires_at": expiresAt,
	})
	return e, nil
}

// RetroactivelyApprove records retroactive approval of a break-glass
// grant. Two-person rule applies here too: the retroactive approver must
// differ from the requester (also enforced by the DB CHECK).
func (s *PlatformJITService) RetroactivelyApprove(ctx context.Context, elevationID, approverID uuid.UUID) (*models.PlatformElevation, error) {
	e, err := s.repo.GetElevationByID(ctx, elevationID)
	if err != nil {
		return nil, err
	}
	if !e.IsBreakGlass {
		return nil, ErrElevationNotPending
	}
	if e.RequesterID == approverID {
		return nil, ErrSelfApprovalNotAllowed
	}
	if e.RetroactiveApprovedAt != nil {
		return e, nil // idempotent: already approved
	}
	if err := s.requireInternalTenant(ctx, approverID); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if uErr := s.repo.SetRetroactiveApproval(ctx, elevationID, approverID, now); uErr != nil {
		return nil, fmt.Errorf("PlatformJITService.RetroactivelyApprove: %w", uErr)
	}

	e.RetroactiveApproverID = &approverID
	e.RetroactiveApprovedAt = &now
	fromStatus := string(e.Status)
	s.appendTransition(ctx, e, &fromStatus, &approverID, "platform_break_glass_retroactively_approved", map[string]interface{}{"approver_id": approverID.String()})
	return e, nil
}

// RevokeElevation explicitly revokes an active grant (operator-initiated,
// distinct from the automatic expiry sweep). SpiceDB delete happens
// FIRST - same fail-closed ordering as ExpireGrants/RevokeGrant in
// jit_access_service.go: if the DB update then fails, the relationship
// is already gone (fail-closed is safe), and the sweep will pick the row
// up again since it's still marked 'active' with a passed-or-future
// expires_at handled by the next manual retry - logged loudly either way.
func (s *PlatformJITService) RevokeElevation(ctx context.Context, elevationID, revokedByID uuid.UUID) error {
	e, err := s.repo.GetElevationByID(ctx, elevationID)
	if err != nil {
		return err
	}
	if e.Status != models.PlatformElevationActive {
		return ErrElevationNotPending
	}

	zedToken, err := s.spicedb.DeletePlatformElevation(ctx, e.RequesterID, string(e.RoleKey))
	if err != nil {
		return fmt.Errorf("PlatformJITService.RevokeElevation: spicedb delete: %w", err)
	}

	if err := s.repo.UpdateElevationStatus(ctx, elevationID, models.PlatformElevationActive, models.PlatformElevationRevoked,
		`, spicedb_revoke_zed_token = $4`, zedToken); err != nil {
		return fmt.Errorf("PlatformJITService.RevokeElevation: %w", err)
	}

	if err := s.repo.DeletePlatformRole(ctx, e.RequesterID, e.RoleKey); err != nil {
		s.logger.Error("PlatformJITService.RevokeElevation: failed to delete iam_platform_roles projection",
			zap.Error(err), zap.String("elevation_id", elevationID.String()))
	}

	e.Status = models.PlatformElevationRevoked
	fromStatus := string(models.PlatformElevationActive)
	s.appendTransition(ctx, e, &fromStatus, &revokedByID, "platform_jit_elevation_revoked", map[string]interface{}{"revoked_by": revokedByID.String()})
	return nil
}

// RunExpirySweep is the DB-driven, idempotent auto-revoke job. It is
// intentionally NOT an in-memory timer (survives restarts/multiple
// replicas: any replica's next scheduled run picks up whatever the
// previous run left, because the WHERE clause is derived from durable
// DB state - status='active' AND expires_at < now() - not from an
// in-process countdown). Mirrors jit_access_service.go's ExpireGrants:
// SpiceDB delete first, then mark expired, continuing past per-row
// errors and returning the last one (so a caller/cron wrapper can alert
// on it without one bad row blocking every other expiry in the batch).
func (s *PlatformJITService) RunExpirySweep(ctx context.Context, batchSize int) (revoked int, lastErr error) {
	elevations, err := s.repo.ListExpiredActive(ctx, batchSize)
	if err != nil {
		return 0, fmt.Errorf("PlatformJITService.RunExpirySweep: list: %w", err)
	}

	for _, e := range elevations {
		if _, delErr := s.spicedb.DeletePlatformElevation(ctx, e.RequesterID, string(e.RoleKey)); delErr != nil {
			s.logger.Error("PlatformJITService.RunExpirySweep: spicedb delete failed, will retry next pass",
				zap.Error(delErr), zap.String("elevation_id", e.ID.String()))
			lastErr = delErr
			continue
		}

		if err := s.repo.UpdateElevationStatus(ctx, e.ID, models.PlatformElevationActive, models.PlatformElevationExpired, ""); err != nil {
			if !errors.Is(err, repositories.ErrPlatformElevationNotFound) {
				s.logger.Error("PlatformJITService.RunExpirySweep: failed to mark expired", zap.Error(err), zap.String("elevation_id", e.ID.String()))
				lastErr = err
			}
			// ErrPlatformElevationNotFound here means status already
			// changed since ListExpiredActive read it (another sweep
			// replica won the race) - the SpiceDB relationship for that
			// row is already gone from THIS call's delete above, which is
			// harmless (idempotent DELETE), so treat as success.
			continue
		}

		if err := s.repo.DeletePlatformRole(ctx, e.RequesterID, e.RoleKey); err != nil {
			s.logger.Error("PlatformJITService.RunExpirySweep: failed to delete iam_platform_roles projection",
				zap.Error(err), zap.String("elevation_id", e.ID.String()))
		}

		fromStatus := string(models.PlatformElevationActive)
		e.Status = models.PlatformElevationExpired
		s.appendTransition(ctx, e, &fromStatus, nil, "platform_jit_elevation_auto_expired", map[string]interface{}{"swept_at": time.Now().UTC()})
		RecordPlatformElevationSweepRevoke(string(e.RoleKey))
		revoked++
	}

	return revoked, lastErr
}

// RunBreakGlassSLASweep enforces the 24h retroactive-approval SLA: any
// break-glass grant created more than 24h ago with no
// retroactive_approved_at is flagged break_glass_violation=true and
// revoked (SpiceDB delete + iam_platform_roles projection removed), same
// as an ordinary expiry. DB-driven and idempotent for the same reason as
// RunExpirySweep - ListBreakGlassSLAPending's WHERE clause excludes
// already-flagged rows, so a repeated pass over the same row is a no-op
// once flagged.
func (s *PlatformJITService) RunBreakGlassSLASweep(ctx context.Context, batchSize int) (violations int, lastErr error) {
	pending, err := s.repo.ListBreakGlassSLAPending(ctx, batchSize)
	if err != nil {
		return 0, fmt.Errorf("PlatformJITService.RunBreakGlassSLASweep: list: %w", err)
	}

	cutoff := time.Now().UTC().Add(-models.BreakGlassRetroactiveApprovalSLA)

	for _, e := range pending {
		if e.CreatedAt.After(cutoff) {
			continue // still within the 24h SLA window
		}

		if err := s.repo.FlagBreakGlassViolation(ctx, e.ID); err != nil {
			s.logger.Error("PlatformJITService.RunBreakGlassSLASweep: failed to flag violation", zap.Error(err), zap.String("elevation_id", e.ID.String()))
			lastErr = err
			continue
		}

		if e.Status == models.PlatformElevationActive {
			if _, delErr := s.spicedb.DeletePlatformElevation(ctx, e.RequesterID, string(e.RoleKey)); delErr != nil {
				s.logger.Error("PlatformJITService.RunBreakGlassSLASweep: spicedb delete failed", zap.Error(delErr), zap.String("elevation_id", e.ID.String()))
				lastErr = delErr
			}
			if err := s.repo.UpdateElevationStatus(ctx, e.ID, models.PlatformElevationActive, models.PlatformElevationRevoked, ""); err != nil && !errors.Is(err, repositories.ErrPlatformElevationNotFound) {
				s.logger.Error("PlatformJITService.RunBreakGlassSLASweep: failed to mark revoked", zap.Error(err), zap.String("elevation_id", e.ID.String()))
				lastErr = err
			}
			if err := s.repo.DeletePlatformRole(ctx, e.RequesterID, e.RoleKey); err != nil {
				s.logger.Error("PlatformJITService.RunBreakGlassSLASweep: failed to delete iam_platform_roles projection", zap.Error(err), zap.String("elevation_id", e.ID.String()))
			}
			e.Status = models.PlatformElevationRevoked
		}

		s.logger.Error("PLATFORM BREAK-GLASS SLA VIOLATION - no retroactive approval within 24h, auto-revoked",
			zap.String("elevation_id", e.ID.String()),
			zap.String("requester_id", e.RequesterID.String()),
			zap.String("role_key", string(e.RoleKey)),
			zap.Time("created_at", e.CreatedAt),
		)
		RecordBreakGlassViolation(string(e.RoleKey))

		fromStatus := string(e.Status)
		s.appendTransition(ctx, e, &fromStatus, nil, "platform_break_glass_sla_violation", map[string]interface{}{"created_at": e.CreatedAt})
		violations++
	}

	return violations, lastErr
}

// GrantStandingRole implements the direct admin grant path
// (POST /internal/v1/platform-roles). Only platform_viewer may be
// granted this way - any other role_key is rejected with
// ErrPlatformRoleNotStandingAssignable BEFORE any DB write is attempted
// (the migration 0016 iam_platform_roles_enforce trigger enforces the
// identical rule as defense in depth, in case this check is ever bypassed
// by a future code path - see the migration's header comment).
func (s *PlatformJITService) GrantStandingRole(ctx context.Context, grantedByID, targetUserID uuid.UUID, roleKey string) (*models.PlatformRole, error) {
	if !models.IsValidPlatformRoleKey(roleKey) {
		return nil, ErrInvalidRoleKey
	}
	if models.PlatformRoleKey(roleKey) != models.PlatformRoleViewer {
		return nil, ErrPlatformRoleNotStandingAssignable
	}
	if err := s.requireInternalTenant(ctx, targetUserID); err != nil {
		return nil, err
	}

	role := &models.PlatformRole{UserID: targetUserID, RoleKey: models.PlatformRoleViewer, GrantedBy: &grantedByID}
	if err := s.repo.UpsertPlatformRole(ctx, role); err != nil {
		return nil, fmt.Errorf("PlatformJITService.GrantStandingRole: %w", err)
	}

	// Mirror the standing viewer into hxl_platform so the operator token
	// exchange (ops_perms from SpiceDB) sees it. Optional capability of the
	// SpiceDB client; idempotent (TOUCH), so a retry after a failure here
	// converges.
	if w, ok := s.spicedb.(interface {
		WritePlatformStandingRole(ctx context.Context, userID uuid.UUID, roleKey string) (string, error)
	}); ok {
		if _, wErr := w.WritePlatformStandingRole(ctx, targetUserID, roleKey); wErr != nil {
			return nil, fmt.Errorf("PlatformJITService.GrantStandingRole: spicedb: %w", wErr)
		}
	}

	if s.auditService != nil {
		internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
		s.auditService.LogUserAction(ctx, internalTenantID, &grantedByID, &targetUserID, "platform_standing_role_granted", true, map[string]interface{}{"role_key": roleKey})
	}
	return role, nil
}

// ListStandingRoles returns every user currently holding
// platform_viewer - the roster the /internal/v1/platform-roles GET
// endpoint serves.
func (s *PlatformJITService) ListStandingRoles(ctx context.Context) ([]*models.PlatformRole, error) {
	return s.repo.ListPlatformRoles(ctx)
}

// DefaultElevationPageSize / MaxElevationPageSize bound the `page_size`
// query param on the GET /jit-elevations, /break-glass and
// /jit-elevations/:id/transitions listings — an unbounded page size
// would let a caller force a full-table scan/response. Mirrors the
// page/page_size convention used elsewhere in this codebase (see e.g.
// AdminHandler.ListAuditLogs).
const (
	DefaultElevationPageSize = 20
	MaxElevationPageSize     = 200
)

// normalizeListPage clamps caller-supplied page/page_size query params
// to sane bounds and returns the equivalent SQL limit/offset.
func normalizeListPage(page, pageSize int) (normPage, normPageSize, limit, offset int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = DefaultElevationPageSize
	}
	if pageSize > MaxElevationPageSize {
		pageSize = MaxElevationPageSize
	}
	return page, pageSize, pageSize, (page - 1) * pageSize
}

func totalPages(total, pageSize int) int {
	if pageSize <= 0 {
		return 0
	}
	n := total / pageSize
	if total%pageSize != 0 {
		n++
	}
	return n
}

// ListElevations returns a filtered, paginated page of standing JIT
// elevation requests for GET /internal/v1/jit-elevations
// (filter.BreakGlassOnly forced to false).
func (s *PlatformJITService) ListElevations(ctx context.Context, filter models.ElevationListFilter, page, pageSize int) (*models.ElevationListResponse, error) {
	notBreakGlass := false
	filter.BreakGlassOnly = &notBreakGlass
	page, pageSize, limit, offset := normalizeListPage(page, pageSize)
	result, err := s.repo.ListElevations(ctx, filter, limit, offset)
	if err != nil {
		return nil, err
	}
	return &models.ElevationListResponse{
		Elevations: nonNilElevations(result.Items),
		Total:      result.Total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages(result.Total, pageSize),
	}, nil
}

// nonNilElevations keeps an empty page encoding as [] rather than null; the
// console reads elevations.length.
func nonNilElevations(items []*models.PlatformElevation) []*models.PlatformElevation {
	if items == nil {
		return []*models.PlatformElevation{}
	}
	return items
}

// ListBreakGlass returns a filtered, paginated page of break-glass
// elevations for GET /internal/v1/break-glass (filter.BreakGlassOnly
// forced to true).
func (s *PlatformJITService) ListBreakGlass(ctx context.Context, filter models.ElevationListFilter, page, pageSize int) (*models.ElevationListResponse, error) {
	breakGlassOnly := true
	filter.BreakGlassOnly = &breakGlassOnly
	page, pageSize, limit, offset := normalizeListPage(page, pageSize)
	result, err := s.repo.ListElevations(ctx, filter, limit, offset)
	if err != nil {
		return nil, err
	}
	return &models.ElevationListResponse{
		Elevations: nonNilElevations(result.Items),
		Total:      result.Total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages(result.Total, pageSize),
	}, nil
}

// ListTransitions returns a paginated page of the append-only
// hash-chain audit trail for GET
// /internal/v1/jit-elevations/:id/transitions. elevationID is required
// (this is a per-elevation audit view, not a global feed) - the handler
// enforces that before calling in.
func (s *PlatformJITService) ListTransitions(ctx context.Context, elevationID uuid.UUID, page, pageSize int) (*models.TransitionListResponse, error) {
	page, pageSize, limit, offset := normalizeListPage(page, pageSize)
	result, err := s.repo.ListTransitions(ctx, &elevationID, limit, offset)
	if err != nil {
		return nil, err
	}
	return &models.TransitionListResponse{
		Transitions: result.Items,
		Total:       result.Total,
		Page:        page,
		PageSize:    pageSize,
		TotalPages:  totalPages(result.Total, pageSize),
	}, nil
}
