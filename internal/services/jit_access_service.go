// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"go.uber.org/zap"
)

// Errors returned by JITAccessService's eligibility/step-up gate. Handlers
// map these to specific HTTP statuses (403/428) rather than a generic 400.
var (
	// ErrNotEligible is returned when the requesting user has no standing
	// iam_jit_eligible row for the requested role at all.
	ErrNotEligible = errors.New("user is not eligible for just-in-time access to this role")
	// ErrEligibilityWindow is returned when an eligibility row exists but its
	// valid_from/valid_until window does not currently cover "now".
	ErrEligibilityWindow = errors.New("eligibility for this role is not currently within its valid window")
	// ErrDurationExceedsEligibility is returned when the requested duration
	// exceeds the max_duration_seconds ceiling set on the eligibility row.
	ErrDurationExceedsEligibility = errors.New("requested duration exceeds the maximum allowed for this eligibility")
	// ErrStepUpRequired is returned when the eligibility row requires a
	// recent step-up MFA verification and the caller's session does not have
	// one on file.
	ErrStepUpRequired = errors.New("a recent step-up MFA verification is required to request this role")
)

// jitStepUpMaxAge bounds how recent a step-up MFA verification must be to
// satisfy an eligibility row with RequiresMFA=true. Matches the default used
// elsewhere in the codebase for sensitive-action step-up (see
// internal/middleware/step_up.go callers).
const jitStepUpMaxAge = 5 * time.Minute

// JITStepUpAction is the step-up action string associated with requesting
// JIT access. Recorded/queried against iam_step_up_verifications.
const JITStepUpAction = "jit_access_request"

// jitSpiceDBClient defines the SpiceDB operations required by
// JITAccessService. Its shape matches pkg/spicedb.Client's WriteUserRoleUntil/
// DeleteUserRole directly (uuid-based, tenant-scoped role#member writes) so
// *spicedb.Client can be passed in as-is with no adapter type — Go's
// structural interfaces make that satisfaction automatic. SpiceDB is the
// sole runtime authority AuthorizationEngine.CheckPermission consults, so
// these calls are the actual enforcement boundary for a JIT grant, not a
// side effect of it.
type jitSpiceDBClient interface {
	// WriteUserRoleUntil grants tenantID-scoped role membership to userID for
	// roleID, caveated with active_elevation(expires_at) so it stops passing
	// checks at expiresAt even if the expiry sweeper is late. Returns the
	// SpiceDB zedtoken for the write.
	WriteUserRoleUntil(ctx context.Context, tenantID, userID, roleID uuid.UUID, expiresAt time.Time) (string, error)
	// DeleteUserRole revokes the tenantID-scoped role membership.
	DeleteUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error)
}

// jitAccessServiceRepo defines the persistence contract for JIT access grants.
type jitAccessServiceRepo interface {
	// Create persists a new grant, populating its ID and CreatedAt.
	Create(ctx context.Context, grant *models.JITAccessGrant) error

	// GetByID returns the grant identified by id.
	GetByID(ctx context.Context, id uuid.UUID) (*models.JITAccessGrant, error)

	// UpdateStatus atomically transitions a grant to a new status.
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.JITAccessStatus) error
	// FinalizeGrant persists status, projection removal and the delete outbox
	// atomically.
	FinalizeGrant(ctx context.Context, grant *models.JITAccessGrant, status models.JITAccessStatus) error
	// QueueActivationRollback durably compensates a failed activation without
	// overwriting a concurrent grant-state transition.
	QueueActivationRollback(ctx context.Context, grant *models.JITAccessGrant) error

	// Approve records approval metadata and transitions the grant to "approved".
	Approve(ctx context.Context, id, approverID uuid.UUID, startsAt time.Time) error

	// Activate transitions a grant from "approved" to "active".
	Activate(ctx context.Context, id uuid.UUID) error

	// ListByTenant returns all grants for a tenant, optionally filtered by status.
	ListByTenant(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]*models.JITAccessGrant, int64, error)

	// ListExpiredActive returns all grants whose status is "active" and whose
	// expires_at is in the past, up to a given limit.
	ListExpiredActive(ctx context.Context, limit int) ([]*models.JITAccessGrant, error)
}

// jitEligibleRepo defines the eligibility lookup required by JITAccessService
// to gate elevation. Matches *repositories.JITEligibleRepository.
type jitEligibleRepo interface {
	// GetForUserRole returns the eligibility row for (user, role), or
	// (nil, nil) when no such row exists.
	GetForUserRole(ctx context.Context, userID, roleID uuid.UUID) (*models.JITEligible, error)
}

// jitStepUpRepo defines the step-up MFA verification lookup required to
// satisfy eligibility rows with RequiresMFA=true. Matches
// *repositories.StepUpVerificationRepository (also used directly by
// middleware.StepUpMiddleware).
type jitStepUpRepo interface {
	HasRecentVerification(ctx context.Context, sessionID uuid.UUID, action string, maxAge time.Duration) (bool, error)
}

// jitUserRoleWriter writes the secondary, best-effort iam_user_roles
// time-boxed projection of an active JIT grant. This projection is NOT the
// authorization boundary — SpiceDB is — but keeps the grant visible to the
// team/role picker, audit queries, and admin priority checks that already
// filter on iam_user_roles.expires_at. Matches *repositories.UserRepository.
type jitUserRoleWriter interface {
	AddTimeBoundRole(ctx context.Context, userID, roleID, assignedBy uuid.UUID, expiresAt time.Time) (uuid.UUID, error)
	RemoveTimeBoundRole(ctx context.Context, userID, roleID uuid.UUID) error
}

// JITAccessService manages just-in-time access grants: request, approval,
// activation, expiry, and revocation. Elevation is gated by a standing
// iam_jit_eligible record (who MAY request the role, and under what
// constraints — max duration, MFA, approval); enforcement of an active grant
// happens exclusively through the SpiceDB role#member relationship written
// in ActivateGrant, because AuthorizationEngine.CheckPermission consults
// SpiceDB only. The iam_user_roles time-boxed row written alongside it is a
// secondary, best-effort projection for UI/audit visibility.
type JITAccessService struct {
	repo         jitAccessServiceRepo
	eligible     jitEligibleRepo
	stepUp       jitStepUpRepo
	userRoles    jitUserRoleWriter
	spicedb      jitSpiceDBClient
	roleRevokes  roleRevokeDrain
	auditService *AuditService
	logger       *zap.Logger
}

// NewJITAccessService creates a new JITAccessService. spicedb must be
// non-nil in any environment that serves traffic: ActivateGrant fails closed
// if a SpiceDB write fails. Revokes/expiry commit to PostgreSQL with a durable
// delete outbox, so a SpiceDB outage cannot prevent a revoke. See
// AuthorizationEngine.CheckPermission, which denies when its own SpiceDB
// client is nil.
func NewJITAccessService(
	repo jitAccessServiceRepo,
	eligible jitEligibleRepo,
	stepUp jitStepUpRepo,
	userRoles jitUserRoleWriter,
	spicedb jitSpiceDBClient,
	auditService *AuditService,
	logger *zap.Logger,
) *JITAccessService {
	return &JITAccessService{
		repo:         repo,
		eligible:     eligible,
		stepUp:       stepUp,
		userRoles:    userRoles,
		spicedb:      spicedb,
		auditService: auditService,
		logger:       logger,
	}
}

func (s *JITAccessService) SetRoleRevokeDrainer(d roleRevokeDrain) { s.roleRevokes = d }

func (s *JITAccessService) drainRevokes(ctx context.Context, userID uuid.UUID) {
	if s.roleRevokes != nil {
		if err := s.roleRevokes.Drain(ctx, userID); err != nil {
			s.logger.Warn("JIT role revokes remain durably queued", zap.Error(err))
		}
	}
}

// checkEligibility loads and validates the (user, role) eligibility row for a
// RequestAccess call: it must exist, be within its validity window, and the
// requested duration must not exceed its cap. When it requires MFA, sessionID
// must have a recent step-up verification for JITStepUpAction on file. On
// success it returns the eligibility row so the caller can also read
// RequiresApproval.
func (s *JITAccessService) checkEligibility(
	ctx context.Context,
	userID, roleID, sessionID uuid.UUID,
	requestedDuration int,
) (*models.JITEligible, error) {
	elig, err := s.eligible.GetForUserRole(ctx, userID, roleID)
	if err != nil {
		return nil, fmt.Errorf("JITAccessService.checkEligibility: %w", err)
	}
	if elig == nil {
		return nil, ErrNotEligible
	}
	if !elig.IsCurrentlyValid() {
		return nil, ErrEligibilityWindow
	}
	if elig.MaxDurationSeconds > 0 && requestedDuration > elig.MaxDurationSeconds {
		return nil, ErrDurationExceedsEligibility
	}
	if elig.RequiresMFA {
		verified, err := s.stepUp.HasRecentVerification(ctx, sessionID, JITStepUpAction, jitStepUpMaxAge)
		if err != nil {
			return nil, fmt.Errorf("JITAccessService.checkEligibility: step-up lookup: %w", err)
		}
		if !verified {
			return nil, ErrStepUpRequired
		}
	}
	return elig, nil
}

// RequestAccess creates a new just-in-time access grant in the "pending"
// state, after verifying the requester is eligible for the target role: a
// standing iam_jit_eligible row must exist, be within its validity window,
// permit the requested duration, and — if it requires MFA — the caller's
// session must carry a recent step-up verification. sessionID identifies the
// caller's current session for the step-up check and is ignored when the
// eligibility row does not require MFA.
func (s *JITAccessService) RequestAccess(
	ctx context.Context,
	tenantID, sessionID uuid.UUID,
	req *models.CreateJITAccessRequest,
) (*models.JITAccessGrant, error) {
	elig, err := s.checkEligibility(ctx, req.UserID, req.RoleID, sessionID, req.Duration)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	grant := &models.JITAccessGrant{
		UserID:        req.UserID,
		RoleID:        req.RoleID,
		TenantID:      tenantID,
		Justification: req.Justification,
		RequestedAt:   now,
		// StartsAt and ExpiresAt are resolved relative to now; they will be
		// updated again on approval if an explicit start time is provided.
		StartsAt:  now,
		ExpiresAt: now.Add(time.Duration(req.Duration) * time.Second),
		Status:    models.JITAccessStatusPending,
	}

	if err := s.repo.Create(ctx, grant); err != nil {
		return nil, fmt.Errorf("JITAccessService.RequestAccess: %w", err)
	}

	s.logger.Info("JIT access requested",
		zap.String("grant_id", grant.ID.String()),
		zap.String("user_id", req.UserID.String()),
		zap.String("role_id", req.RoleID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.Bool("requires_approval", elig.RequiresApproval),
	)

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, &req.UserID, nil, "jit_access_requested", true, map[string]interface{}{
			"grant_id":      grant.ID.String(),
			"role_id":       req.RoleID.String(),
			"justification": req.Justification,
			"expires_at":    grant.ExpiresAt,
		})
	}

	return grant, nil
}

// getGrantInTenant fetches a grant by ID and asserts it belongs to
// tenantID before returning it. Every direct-object lookup on a JIT grant
// (approve, activate, revoke) must go through this rather than
// s.repo.GetByID directly: GetByID itself is not tenant-scoped, so calling
// it bare lets an authenticated caller from any tenant act on another
// tenant's grant by guessing/enumerating its UUID (t-437). A cross-tenant
// grant is reported as not found, not as "wrong tenant", so the response
// gives no signal that the ID exists at all.
func (s *JITAccessService) getGrantInTenant(ctx context.Context, grantID, tenantID uuid.UUID) (*models.JITAccessGrant, error) {
	grant, err := s.repo.GetByID(ctx, grantID)
	if err != nil {
		return nil, fmt.Errorf("JIT access grant not found: %w", err)
	}
	if grant == nil || grant.TenantID != tenantID {
		return nil, fmt.Errorf("JIT access grant not found")
	}
	return grant, nil
}

// ApproveAccess transitions a pending grant to the "approved" state and
// records the approver's identity. If req.StartsAt is set, the grant will
// become active at that future time; otherwise it starts immediately and
// ActivateGrant should be called right away.
//
// Self-approval is rejected UNLESS the eligibility row backing this grant
// has RequiresApproval=false, in which case the requester is allowed to
// approve (in practice: activate) their own pre-approved elevation. Absence
// of an eligibility row (it was revoked between request and approval) is
// treated as requiring approval, i.e. self-approval stays blocked.
func (s *JITAccessService) ApproveAccess(
	ctx context.Context,
	grantID, approverID, approverTenantID uuid.UUID,
) (*models.JITAccessGrant, error) {
	grant, err := s.getGrantInTenant(ctx, grantID, approverTenantID)
	if err != nil {
		return nil, err
	}

	if grant.Status != models.JITAccessStatusPending {
		return nil, fmt.Errorf("grant is not in pending state (current: %s)", grant.Status)
	}

	if approverID == grant.UserID {
		elig, err := s.eligible.GetForUserRole(ctx, grant.UserID, grant.RoleID)
		if err != nil {
			return nil, fmt.Errorf("JITAccessService.ApproveAccess: eligibility lookup: %w", err)
		}
		if elig == nil || elig.RequiresApproval {
			return nil, fmt.Errorf("cannot approve your own JIT access request")
		}
	}

	if err := s.repo.Approve(ctx, grantID, approverID, grant.StartsAt); err != nil {
		return nil, fmt.Errorf("JITAccessService.ApproveAccess: %w", err)
	}

	s.logger.Info("JIT access approved",
		zap.String("grant_id", grantID.String()),
		zap.String("approver_id", approverID.String()),
	)

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, grant.TenantID, &approverID, &grant.UserID, "jit_access_approved", true, map[string]interface{}{
			"grant_id": grantID.String(),
			"role_id":  grant.RoleID.String(),
		})
	}

	return s.repo.GetByID(ctx, grantID)
}

// ActivateGrant transitions an approved grant to the "active" state and
// writes the corresponding role membership to SpiceDB so that the user
// immediately acquires the role for the duration of the grant. The SpiceDB
// write is the actual enforcement boundary: AuthorizationEngine.CheckPermission
// is SpiceDB-only and never consults iam_user_roles or grant status, so this
// call must succeed for the grant to confer any permission at all. If it
// fails, activation fails and the grant remains "approved" — it is never
// marked "active" without the corresponding SpiceDB relationship existing.
//
// A secondary, best-effort iam_user_roles time-boxed row is written after the
// SpiceDB write succeeds, purely for UI/audit visibility (team picker, role
// priority, admin-count checks already filter on its expires_at). Its
// failure is logged but does not fail activation or roll back the SpiceDB
// write, since SpiceDB is already authoritative at that point.
func (s *JITAccessService) ActivateGrant(ctx context.Context, grantID, tenantID uuid.UUID) error {
	grant, err := s.getGrantInTenant(ctx, grantID, tenantID)
	if err != nil {
		return err
	}

	if grant.Status != models.JITAccessStatusApproved {
		return fmt.Errorf("grant is not in approved state (current: %s)", grant.Status)
	}

	if grant.IsExpired() {
		if markErr := s.repo.UpdateStatus(ctx, grantID, models.JITAccessStatusExpired); markErr != nil {
			s.logger.Warn("Failed to mark expired grant during activation",
				zap.String("grant_id", grantID.String()),
				zap.Error(markErr),
			)
		}
		return fmt.Errorf("grant %s has already expired", grantID)
	}

	if s.spicedb == nil {
		return fmt.Errorf("JITAccessService.ActivateGrant: SpiceDB client unavailable")
	}
	if _, err := s.spicedb.WriteUserRoleUntil(ctx, grant.TenantID, grant.UserID, grant.RoleID, grant.ExpiresAt); err != nil {
		return fmt.Errorf("JITAccessService.ActivateGrant write SpiceDB relationship: %w", err)
	}

	if err := s.repo.Activate(ctx, grantID); err != nil {
		// Roll back the SpiceDB write: an active-looking grant with no
		// SpiceDB relationship is harmless (denies by default), but a
		// SpiceDB relationship for a grant that failed to persist as
		// "active" would silently outlive its own bookkeeping.
		if delErr := s.repo.QueueActivationRollback(ctx, grant); delErr != nil {
			s.logger.Error("Failed to queue SpiceDB relationship rollback after activation failure",
				zap.String("grant_id", grantID.String()),
				zap.Error(delErr),
			)
			return fmt.Errorf("JITAccessService.ActivateGrant persist: %w; compensation: %v", err, delErr)
		}
		s.drainRevokes(ctx, grant.UserID)
		return fmt.Errorf("JITAccessService.ActivateGrant persist: %w", err)
	}

	assignedBy := grant.UserID
	if grant.ApprovedBy != nil {
		assignedBy = *grant.ApprovedBy
	}
	if _, err := s.userRoles.AddTimeBoundRole(ctx, grant.UserID, grant.RoleID, assignedBy, grant.ExpiresAt); err != nil {
		// Best-effort: SpiceDB is already authoritative and already written.
		// Losing this projection only affects UI/audit visibility, not
		// enforcement, so we log and continue rather than fail activation.
		s.logger.Warn("Failed to write secondary iam_user_roles projection for JIT grant (SpiceDB write already succeeded; enforcement unaffected)",
			zap.String("grant_id", grantID.String()),
			zap.Error(err),
		)
	}

	s.logger.Info("JIT access grant activated",
		zap.String("grant_id", grantID.String()),
		zap.String("user_id", grant.UserID.String()),
		zap.String("role_id", grant.RoleID.String()),
		zap.Time("expires_at", grant.ExpiresAt),
	)

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, grant.TenantID, nil, &grant.UserID, "jit_access_activated", true, map[string]interface{}{
			"grant_id":   grantID.String(),
			"role_id":    grant.RoleID.String(),
			"expires_at": grant.ExpiresAt,
		})
	}

	return nil
}

// ExpireGrants is intended to be called by a background worker on a regular
// schedule (e.g. every minute). It finds all grants that are in the "active"
// state but whose expires_at is in the past. Status, projection removal and
// the durable SpiceDB delete commit together; the post-commit fast path and
// the short-interval outbox worker enforce the delete even during outages.
func (s *JITAccessService) ExpireGrants(ctx context.Context) error {
	const batchLimit = 100

	expired, err := s.repo.ListExpiredActive(ctx, batchLimit)
	if err != nil {
		return fmt.Errorf("JITAccessService.ExpireGrants list: %w", err)
	}

	var lastErr error
	for _, grant := range expired {
		if err := s.repo.FinalizeGrant(ctx, grant, models.JITAccessStatusExpired); err != nil {
			s.logger.Error("Failed to mark grant as expired",
				zap.String("grant_id", grant.ID.String()),
				zap.Error(err),
			)
			lastErr = err
			continue
		}

		s.drainRevokes(ctx, grant.UserID)

		s.logger.Info("JIT access grant expired",
			zap.String("grant_id", grant.ID.String()),
			zap.String("user_id", grant.UserID.String()),
			zap.String("role_id", grant.RoleID.String()),
		)

		if s.auditService != nil {
			s.auditService.LogUserAction(ctx, grant.TenantID, nil, &grant.UserID, "jit_access_expired", true, map[string]interface{}{
				"grant_id":   grant.ID.String(),
				"role_id":    grant.RoleID.String(),
				"expires_at": grant.ExpiresAt,
			})
		}
	}

	return lastErr
}

// RevokeGrant commits revocation and the durable delete before attempting
// SpiceDB. An outage leaves a retryable row, not an active PostgreSQL grant.
func (s *JITAccessService) RevokeGrant(ctx context.Context, grantID, revokerID, revokerTenantID uuid.UUID) error {
	grant, err := s.getGrantInTenant(ctx, grantID, revokerTenantID)
	if err != nil {
		return err
	}

	if grant.Status == models.JITAccessStatusExpired || grant.Status == models.JITAccessStatusRevoked {
		return fmt.Errorf("grant is already %s", grant.Status)
	}

	if err := s.repo.FinalizeGrant(ctx, grant, models.JITAccessStatusRevoked); err != nil {
		return fmt.Errorf("JITAccessService.RevokeGrant persist: %w", err)
	}

	s.drainRevokes(ctx, grant.UserID)

	s.logger.Info("JIT access grant revoked",
		zap.String("grant_id", grantID.String()),
		zap.String("revoker_id", revokerID.String()),
	)

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, grant.TenantID, &revokerID, &grant.UserID, "jit_access_revoked", true, map[string]interface{}{
			"grant_id": grantID.String(),
			"role_id":  grant.RoleID.String(),
		})
	}

	return nil
}

// ListGrants returns a paginated list of JIT grants for the given tenant,
// optionally filtered by status string (empty = all statuses).
func (s *JITAccessService) ListGrants(
	ctx context.Context,
	tenantID uuid.UUID,
	status string,
	page, pageSize int,
) ([]*models.JITAccessGrant, int64, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}

	grants, total, err := s.repo.ListByTenant(ctx, tenantID, status, page, pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("JITAccessService.ListGrants: %w", err)
	}
	return grants, total, nil
}

// ListPendingElevations returns all pending JIT access grants visible to the
// given approver across their tenant. The current implementation returns all
// tenant-wide pending grants; a future iteration can layer role-based approval
// policy filtering on top once approval policies are modelled.
func (s *JITAccessService) ListPendingElevations(ctx context.Context, tenantID, approverID uuid.UUID) ([]*models.JITAccessGrant, error) {
	// Fetch all pending grants for the tenant using a generous page size so
	// that the governance dashboard receives the full set in a single call.
	const maxPending = 10000
	grants, _, err := s.repo.ListByTenant(ctx, tenantID, string(models.JITAccessStatusPending), 1, maxPending)
	if err != nil {
		return nil, fmt.Errorf("JITAccessService.ListPendingElevations: %w", err)
	}

	s.logger.Info("Listed pending JIT elevations",
		zap.String("approver_id", approverID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.Int("count", len(grants)),
	)

	return grants, nil
}
