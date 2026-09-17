// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// dataDeletionSessionRepo defines the session repository methods needed by DataDeletionService.
type dataDeletionSessionRepo interface {
	EndAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error
}

// dataDeletionOAuthRepo defines the OAuth repository methods needed
// by DataDeletionService for actually invalidating tokens after the
// Phase 3 cutover. iam_oauth_tokens is the single token store post-
// Phase-3; sweeping by user_id covers every relying party the user
// signed into. Without this, deleted users' OAuth tokens would stay
// valid until natural expiry — a real security gap.
type dataDeletionOAuthRepo interface {
	RevokeAllUserOAuthTokens(ctx context.Context, userID uuid.UUID, reason string) error
}

// dataDeletionDeviceRepo defines the device repository methods needed by DataDeletionService.
type dataDeletionDeviceRepo interface {
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
}

// dataDeletionMFARepo defines the MFA repository methods needed by DataDeletionService.
type dataDeletionMFARepo interface {
	DeleteAllRecoveryCodes(ctx context.Context, userID uuid.UUID) error
	DeleteUserEmailVerifications(ctx context.Context, userID uuid.UUID) error
	DeleteMFAPendingSetup(ctx context.Context, userID uuid.UUID) error
}

// DeletionRepository handles database operations for deletion requests
type DeletionRepository struct {
	db *pgxpool.Pool
}

// NewDeletionRepository creates a new deletion repository
func NewDeletionRepository(db *pgxpool.Pool) *DeletionRepository {
	return &DeletionRepository{db: db}
}

// Create creates a new deletion request
func (r *DeletionRepository) Create(ctx context.Context, req *models.DeletionRequest) error {
	query := `
		INSERT INTO iam_deletion_requests (
			id, tenant_id, user_id, status, requested_at, scheduled_delete_at,
			legal_hold, legal_hold_reason, legal_hold_set_at, legal_hold_set_by,
			requested_by, notes
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		) RETURNING created_at, updated_at`

	if req.ID == uuid.Nil {
		req.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		req.ID, req.TenantID, req.UserID, req.Status, req.RequestedAt, req.ScheduledDeleteAt,
		req.LegalHold, req.LegalHoldReason, req.LegalHoldSetAt, req.LegalHoldSetBy,
		req.RequestedBy, req.Notes,
	).Scan(&req.CreatedAt, &req.UpdatedAt)
}

// GetByID retrieves a deletion request by ID
func (r *DeletionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DeletionRequest, error) {
	req := &models.DeletionRequest{}
	query := `
		SELECT id, tenant_id, user_id, status, requested_at, scheduled_delete_at,
			   processed_at, completed_at, legal_hold, legal_hold_reason, legal_hold_set_at,
			   legal_hold_set_by, requested_by, notes, error_message, created_at, updated_at
		FROM iam_deletion_requests
		WHERE id = $1
	`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&req.ID, &req.TenantID, &req.UserID, &req.Status, &req.RequestedAt, &req.ScheduledDeleteAt,
		&req.ProcessedAt, &req.CompletedAt, &req.LegalHold, &req.LegalHoldReason, &req.LegalHoldSetAt,
		&req.LegalHoldSetBy, &req.RequestedBy, &req.Notes, &req.ErrorMessage, &req.CreatedAt, &req.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return req, nil
}

// GetByUserID retrieves the latest deletion request for a user
func (r *DeletionRepository) GetByUserID(ctx context.Context, userID uuid.UUID) (*models.DeletionRequest, error) {
	req := &models.DeletionRequest{}
	query := `
		SELECT id, tenant_id, user_id, status, requested_at, scheduled_delete_at,
			   processed_at, completed_at, legal_hold, legal_hold_reason, legal_hold_set_at,
			   legal_hold_set_by, requested_by, notes, error_message, created_at, updated_at
		FROM iam_deletion_requests
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`

	err := r.db.QueryRow(ctx, query, userID).Scan(
		&req.ID, &req.TenantID, &req.UserID, &req.Status, &req.RequestedAt, &req.ScheduledDeleteAt,
		&req.ProcessedAt, &req.CompletedAt, &req.LegalHold, &req.LegalHoldReason, &req.LegalHoldSetAt,
		&req.LegalHoldSetBy, &req.RequestedBy, &req.Notes, &req.ErrorMessage, &req.CreatedAt, &req.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("GetByUserID: %w", err)
	}
	return req, nil
}

// Update updates a deletion request
func (r *DeletionRepository) Update(ctx context.Context, req *models.DeletionRequest) error {
	query := `
		UPDATE iam_deletion_requests
		SET status = $1, processed_at = $2, completed_at = $3,
		    legal_hold = $4, legal_hold_reason = $5, legal_hold_set_at = $6,
		    legal_hold_set_by = $7, error_message = $8, updated_at = NOW()
		WHERE id = $9
	`

	_, err := r.db.Exec(ctx, query,
		req.Status, req.ProcessedAt, req.CompletedAt,
		req.LegalHold, req.LegalHoldReason, req.LegalHoldSetAt,
		req.LegalHoldSetBy, req.ErrorMessage, req.ID,
	)
	if err != nil {
		return fmt.Errorf("Update: %w", err)
	}
	return nil
}

// GetPendingDeletions retrieves all pending deletion requests that are ready to process
func (r *DeletionRepository) GetPendingDeletions(ctx context.Context, limit int) ([]*models.DeletionRequest, error) {
	query := `
		SELECT id, tenant_id, user_id, status, requested_at, scheduled_delete_at,
			   processed_at, completed_at, legal_hold, legal_hold_reason, legal_hold_set_at,
			   legal_hold_set_by, requested_by, notes, error_message, created_at, updated_at
		FROM iam_deletion_requests
		WHERE status = $1
		  AND legal_hold = false
		  AND scheduled_delete_at <= NOW()
		ORDER BY scheduled_delete_at ASC
		LIMIT $2
	`

	rows, err := r.db.Query(ctx, query, models.DeletionRequestStatusScheduled, limit)
	if err != nil {
		return nil, fmt.Errorf("GetPendingDeletions: %w", err)
	}
	defer rows.Close()

	var requests []*models.DeletionRequest
	for rows.Next() {
		req := &models.DeletionRequest{}
		err := rows.Scan(
			&req.ID, &req.TenantID, &req.UserID, &req.Status, &req.RequestedAt, &req.ScheduledDeleteAt,
			&req.ProcessedAt, &req.CompletedAt, &req.LegalHold, &req.LegalHoldReason, &req.LegalHoldSetAt,
			&req.LegalHoldSetBy, &req.RequestedBy, &req.Notes, &req.ErrorMessage, &req.CreatedAt, &req.UpdatedAt,
		)
		if err != nil {
			logger.Warn("Failed to scan deletion request", zap.Error(err))
			continue
		}
		requests = append(requests, req)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetPendingDeletions: row iteration error: %w", err)
	}

	return requests, nil
}

// DataDeletionService handles GDPR data deletion requests
type DataDeletionService struct {
	deletionRepo *DeletionRepository
	userRepo     interface{} // not currently called directly via method calls
	sessionRepo  dataDeletionSessionRepo
	oauthRepo    dataDeletionOAuthRepo // real OAuth-token sweep; nil-safe
	deviceRepo   dataDeletionDeviceRepo
	mfaRepo      dataDeletionMFARepo
	auditService *AuditService
	db           *pgxpool.Pool
}

// NewDataDeletionService creates a new data deletion service
func NewDataDeletionService(
	deletionRepo *DeletionRepository,
	userRepo interface{},
	sessionRepo dataDeletionSessionRepo,
	deviceRepo dataDeletionDeviceRepo,
	mfaRepo dataDeletionMFARepo,
	auditService *AuditService,
	db *pgxpool.Pool,
) *DataDeletionService {
	return &DataDeletionService{
		deletionRepo: deletionRepo,
		userRepo:     userRepo,
		sessionRepo:  sessionRepo,
		deviceRepo:   deviceRepo,
		mfaRepo:      mfaRepo,
		auditService: auditService,
		db:           db,
	}
}

// SetOAuthRepository wires the OAuth-token store so DeleteUser can
// actually invalidate tokens after Phase 3 dropped iam_refresh_tokens.
// Optional — when unwired, DeleteUser logs a warning and skips the
// OAuth sweep (test stubs that don't supply this dep continue to
// work). Production wiring lives in cmd/services.go.
func (s *DataDeletionService) SetOAuthRepository(repo dataDeletionOAuthRepo) {
	s.oauthRepo = repo
}

// RequestDeletion creates a new deletion request with 30-day grace period
func (s *DataDeletionService) RequestDeletion(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, requestedBy *uuid.UUID, notes *string) (*models.DeletionRequest, error) {
	logger.Info("Creating deletion request",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	// Check if there's an existing pending/scheduled deletion request
	existing, err := s.deletionRepo.GetByUserID(ctx, userID)
	if err == nil && existing != nil {
		// Check if the existing request is still active
		if existing.Status == models.DeletionRequestStatusPending ||
			existing.Status == models.DeletionRequestStatusScheduled {
			return existing, nil // Return existing request
		}
	}

	// Create new deletion request with 30-day grace period
	now := time.Now()
	scheduledDeleteAt := now.Add(30 * 24 * time.Hour)

	request := &models.DeletionRequest{
		TenantID:          tenantID,
		UserID:            userID,
		Status:            models.DeletionRequestStatusScheduled,
		RequestedAt:       now,
		ScheduledDeleteAt: &scheduledDeleteAt,
		LegalHold:         false,
		RequestedBy:       requestedBy,
		Notes:             notes,
	}

	if err := s.deletionRepo.Create(ctx, request); err != nil {
		return nil, fmt.Errorf("failed to create deletion request: %w", err)
	}

	// Audit log
	s.auditService.LogUserAction(ctx, tenantID, &userID, requestedBy, "deletion_requested", true, map[string]interface{}{
		"deletion_request_id": request.ID.String(),
		"scheduled_delete_at": scheduledDeleteAt.Format(time.RFC3339),
	})

	logger.Info("Deletion request created",
		zap.String("request_id", request.ID.String()),
		zap.String("user_id", userID.String()),
		zap.Time("scheduled_delete_at", scheduledDeleteAt),
	)

	return request, nil
}

// CancelDeletion cancels a pending deletion request
func (s *DataDeletionService) CancelDeletion(ctx context.Context, requestID uuid.UUID, cancelledBy uuid.UUID) error {
	request, err := s.deletionRepo.GetByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("failed to get deletion request: %w", err)
	}

	if request.Status != models.DeletionRequestStatusPending &&
		request.Status != models.DeletionRequestStatusScheduled {
		return fmt.Errorf("cannot cancel deletion request in status: %s", request.Status)
	}

	request.Status = models.DeletionRequestStatusCancelled
	now := time.Now()
	request.ProcessedAt = &now

	if err := s.deletionRepo.Update(ctx, request); err != nil {
		return fmt.Errorf("failed to update deletion request: %w", err)
	}

	// Audit log
	s.auditService.LogUserAction(ctx, request.TenantID, &request.UserID, &cancelledBy, "deletion_cancelled", true, map[string]interface{}{
		"deletion_request_id": request.ID.String(),
	})

	logger.Info("Deletion request cancelled",
		zap.String("request_id", request.ID.String()),
		zap.String("user_id", request.UserID.String()),
	)

	return nil
}

// SetLegalHold sets a legal hold on a deletion request
func (s *DataDeletionService) SetLegalHold(ctx context.Context, requestID uuid.UUID, reason string, setBy uuid.UUID) error {
	request, err := s.deletionRepo.GetByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("failed to get deletion request: %w", err)
	}

	request.LegalHold = true
	request.LegalHoldReason = &reason
	now := time.Now()
	request.LegalHoldSetAt = &now
	request.LegalHoldSetBy = &setBy

	if err := s.deletionRepo.Update(ctx, request); err != nil {
		return fmt.Errorf("failed to update deletion request: %w", err)
	}

	// Audit log
	s.auditService.LogUserAction(ctx, request.TenantID, &request.UserID, &setBy, "legal_hold_set", true, map[string]interface{}{
		"deletion_request_id": request.ID.String(),
		"reason":              reason,
	})

	logger.Info("Legal hold set on deletion request",
		zap.String("request_id", request.ID.String()),
		zap.String("user_id", request.UserID.String()),
		zap.String("reason", reason),
	)

	return nil
}

// RemoveLegalHold removes a legal hold from a deletion request
func (s *DataDeletionService) RemoveLegalHold(ctx context.Context, requestID uuid.UUID, removedBy uuid.UUID) error {
	request, err := s.deletionRepo.GetByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("failed to get deletion request: %w", err)
	}

	request.LegalHold = false
	request.LegalHoldReason = nil
	request.LegalHoldSetAt = nil
	request.LegalHoldSetBy = nil

	if err := s.deletionRepo.Update(ctx, request); err != nil {
		return fmt.Errorf("failed to update deletion request: %w", err)
	}

	// Audit log
	s.auditService.LogUserAction(ctx, request.TenantID, &request.UserID, &removedBy, "legal_hold_removed", true, map[string]interface{}{
		"deletion_request_id": request.ID.String(),
	})

	logger.Info("Legal hold removed from deletion request",
		zap.String("request_id", request.ID.String()),
		zap.String("user_id", request.UserID.String()),
	)

	return nil
}

// ProcessDeletion processes a scheduled deletion request (called by background worker)
func (s *DataDeletionService) ProcessDeletion(ctx context.Context, requestID uuid.UUID) error {
	request, err := s.deletionRepo.GetByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("failed to get deletion request: %w", err)
	}

	// Check if legal hold is active
	if request.LegalHold {
		logger.Warn("Cannot process deletion request with active legal hold",
			zap.String("request_id", request.ID.String()),
		)
		return fmt.Errorf("deletion request has active legal hold")
	}

	// Update status to processing
	request.Status = models.DeletionRequestStatusProcessing
	now := time.Now()
	request.ProcessedAt = &now

	if err := s.deletionRepo.Update(ctx, request); err != nil {
		return fmt.Errorf("failed to update deletion request status: %w", err)
	}

	logger.Info("Processing deletion request",
		zap.String("request_id", request.ID.String()),
		zap.String("user_id", request.UserID.String()),
	)

	// Cascade deletion across all modules
	if err := s.cascadeDelete(ctx, request.UserID, request.TenantID); err != nil {
		// Mark as failed
		request.Status = models.DeletionRequestStatusFailed
		errMsg := err.Error()
		request.ErrorMessage = &errMsg
		if updateErr := s.deletionRepo.Update(ctx, request); updateErr != nil {
			logger.Error("Failed to update deletion request status after cascade failure",
				zap.String("request_id", request.ID.String()),
				zap.Error(updateErr),
			)
		}

		logger.Error("Failed to cascade delete user data",
			zap.String("request_id", request.ID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("cascade deletion failed: %w", err)
	}

	// Mark as completed
	request.Status = models.DeletionRequestStatusCompleted
	completedAt := time.Now()
	request.CompletedAt = &completedAt

	if err := s.deletionRepo.Update(ctx, request); err != nil {
		return fmt.Errorf("failed to mark deletion as completed: %w", err)
	}

	// Audit log
	s.auditService.LogUserAction(ctx, request.TenantID, &request.UserID, nil, "user_deleted", true, map[string]interface{}{
		"deletion_request_id": request.ID.String(),
	})

	logger.Info("Deletion request completed successfully",
		zap.String("request_id", request.ID.String()),
		zap.String("user_id", request.UserID.String()),
	)

	return nil
}

// cascadeDelete performs cascade deletion of user data across all modules
func (s *DataDeletionService) cascadeDelete(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) error {
	logger.Info("Starting cascade deletion",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	// 1. End all sessions
	if err := s.sessionRepo.EndAllUserSessions(ctx, userID, "user_deleted"); err != nil {
		logger.Warn("Failed to end user sessions", zap.Error(err))
	}

	// 2. Revoke all OAuth tokens.
	//
	// Sweeps every iam_oauth_tokens row for this user, marking
	// is_revoked=true. Without it, deleted users' OAuth tokens stay
	// valid until natural expiry — a real GDPR / right-to-be-forgotten
	// gap. iam_refresh_tokens was dropped in mig 233; the OAuth side
	// is the only token surface remaining.
	if s.oauthRepo != nil {
		if err := s.oauthRepo.RevokeAllUserOAuthTokens(ctx, userID, "user_deleted"); err != nil {
			logger.Warn("Failed to revoke user OAuth tokens", zap.Error(err))
		}
	} else {
		logger.Warn("DataDeletionService: oauth repo not wired; OAuth tokens for deleted user remain valid until natural expiry",
			zap.String("user_id", userID.String()))
	}

	// 3. Delete devices
	if err := s.deviceRepo.DeleteByUserID(ctx, userID); err != nil {
		logger.Warn("Failed to delete user devices", zap.Error(err))
	}

	// 4. Delete MFA data
	if err := s.mfaRepo.DeleteAllRecoveryCodes(ctx, userID); err != nil {
		logger.Warn("Failed to delete recovery codes", zap.Error(err))
	}
	if err := s.mfaRepo.DeleteUserEmailVerifications(ctx, userID); err != nil {
		logger.Warn("Failed to delete email verifications", zap.Error(err))
	}
	if err := s.mfaRepo.DeleteMFAPendingSetup(ctx, userID); err != nil {
		logger.Warn("Failed to delete MFA pending setup", zap.Error(err))
	}

	// 5. Anonymize user record (soft delete)
	// Instead of hard delete, we anonymize for audit trail compliance
	anonymizedEmail := fmt.Sprintf("deleted-%s@deleted.local", userID.String())
	anonymizedUsername := fmt.Sprintf("deleted-%s", userID.String()[:8])

	query := `
		UPDATE iam_users
		SET username = $1,
		    email = $2,
		    password_hash = NULL,
		    first_name = NULL,
		    last_name = NULL,
		    display_name = NULL,
		    phone = NULL,
		    department = NULL,
		    title = NULL,
		    avatar_url = NULL,
		    mfa_secret = NULL,
		    is_active = false,
		    updated_at = NOW()
		WHERE id = $3 AND tenant_id = $4
	`

	if _, err := s.db.Exec(ctx, query, anonymizedUsername, anonymizedEmail, userID, tenantID); err != nil {
		return fmt.Errorf("failed to anonymize user record: %w", err)
	}

	logger.Info("User data anonymized successfully",
		zap.String("user_id", userID.String()),
	)

	// TODO: In a full implementation, we would also:
	// - Call CRM service to delete/anonymize customer data
	// - Call HR service to delete/anonymize employee data
	// - Call Accounting service to anonymize transaction data (keep for legal compliance)
	// - Delete files from MinIO
	// - Delete audit logs from Cassandra (or anonymize based on retention policy)

	return nil
}

// GetDeletionRequest retrieves a deletion request by ID
func (s *DataDeletionService) GetDeletionRequest(ctx context.Context, requestID uuid.UUID) (*models.DeletionRequest, error) {
	return s.deletionRepo.GetByID(ctx, requestID)
}

// GetDB returns the database pool for nested operations
func (s *DataDeletionService) GetDB() *pgxpool.Pool {
	return s.db
}
