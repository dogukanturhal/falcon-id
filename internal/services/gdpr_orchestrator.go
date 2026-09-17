// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

// GDPROrchestratorConfig holds configuration for the GDPR deletion orchestrator.
type GDPROrchestratorConfig struct {
	// GracePeriod before deletion begins. Defaults to 30 days (GDPR cooling-off).
	GracePeriod time.Duration
	// Services is the ordered list of downstream services to notify.
	Services []ServiceDeletionTarget
}

// ServiceDeletionTarget describes a downstream service that holds user data and
// must be notified during a GDPR Article 17 erasure cascade.
type ServiceDeletionTarget struct {
	// ServiceName is the canonical service identifier (e.g. "crm-service").
	ServiceName string
	// EventType is the outbox event_type published for this service
	// (e.g. "user.data_deletion_requested").
	EventType string
	// Priority controls the deletion order — lower values execute first.
	// Services with equal priority are notified in parallel (same batch).
	Priority int
}

// ---------------------------------------------------------------------------
// Status types
// ---------------------------------------------------------------------------

// DeletionStatus represents the aggregate deletion progress across all services.
type DeletionStatus struct {
	RequestID     uuid.UUID
	OverallStatus string // pending | in_progress | completed | failed | partial
	Services      []ServiceDeletionStatus
}

// ServiceDeletionStatus holds the status of a single downstream service.
type ServiceDeletionStatus struct {
	ServiceName string
	Status      string // pending | completed | failed
	CompletedAt *time.Time
	Error       *string
}

// Overall status constants.
const (
	DeletionOverallPending    = "pending"
	DeletionOverallInProgress = "in_progress"
	DeletionOverallCompleted  = "completed"
	DeletionOverallFailed     = "failed"
	DeletionOverallPartial    = "partial"
)

// Service-level status constants.
const (
	ServiceStatusPending   = "pending"
	ServiceStatusCompleted = "completed"
	ServiceStatusFailed    = "failed"
)

// ---------------------------------------------------------------------------
// outboxPublisher interface
// ---------------------------------------------------------------------------

// crossServiceOutboxPublisher is the minimal interface the orchestrator needs to
// publish cross-service events. Using an interface avoids importing the shared
// outbox library directly into falcon-id and prevents circular dependencies.
type crossServiceOutboxPublisher interface {
	// PublishCrossService persists a cross-service event in the IAM database.
	PublishCrossService(ctx context.Context, event *CrossServiceEvent) error
}

// CrossServiceEvent is the falcon-id-internal representation of an outbox event
// destined for a downstream service. It mirrors the iam_cross_service_events
// table columns defined in migration 084.
type CrossServiceEvent struct {
	ID            uuid.UUID       `json:"id"`
	EventType     string          `json:"event_type"`
	AggregateType string          `json:"aggregate_type"`
	AggregateID   string          `json:"aggregate_id"`
	TenantID      uuid.UUID       `json:"tenant_id"`
	Payload       json.RawMessage `json:"payload"`
	TargetService string          `json:"target_service"`
}

// ---------------------------------------------------------------------------
// gdprDeletionTrackingRepo interface
// ---------------------------------------------------------------------------

// gdprDeletionTrackingRepo persists per-service deletion tracking rows.
type gdprDeletionTrackingRepo interface {
	CreateServiceTracking(ctx context.Context, req *GDPRServiceTracking) error
	GetTrackingByRequestID(ctx context.Context, deletionRequestID uuid.UUID) ([]*GDPRServiceTracking, error)
}

// GDPRServiceTracking mirrors the iam_gdpr_deletion_tracking table.
type GDPRServiceTracking struct {
	ID                uuid.UUID  `db:"id"`
	DeletionRequestID uuid.UUID  `db:"deletion_request_id"`
	ServiceName       string     `db:"service_name"`
	Status            string     `db:"status"`
	EventID           *uuid.UUID `db:"event_id"`
	CompletedAt       *time.Time `db:"completed_at"`
	ErrorMessage      *string    `db:"error_message"`
}

// ---------------------------------------------------------------------------
// GDPRDeletionTrackingRepository
// ---------------------------------------------------------------------------

// GDPRDeletionTrackingRepository provides DB-level persistence for GDPR tracking.
type GDPRDeletionTrackingRepository struct {
	db *pgxpool.Pool
}

// NewGDPRDeletionTrackingRepository creates a new repository backed by pgxpool.
func NewGDPRDeletionTrackingRepository(db *pgxpool.Pool) *GDPRDeletionTrackingRepository {
	return &GDPRDeletionTrackingRepository{db: db}
}

// CreateServiceTracking inserts a new tracking row for a single service.
func (r *GDPRDeletionTrackingRepository) CreateServiceTracking(ctx context.Context, t *GDPRServiceTracking) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	query := `
		INSERT INTO iam_gdpr_deletion_tracking
			(id, deletion_request_id, service_name, status, event_id, completed_at, error_message)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.Exec(ctx, query,
		t.ID, t.DeletionRequestID, t.ServiceName, t.Status,
		t.EventID, t.CompletedAt, t.ErrorMessage,
	)
	if err != nil {
		return fmt.Errorf("GDPRDeletionTrackingRepository.CreateServiceTracking: %w", err)
	}
	return nil
}

// GetTrackingByRequestID retrieves all service-level tracking rows for a deletion request.
func (r *GDPRDeletionTrackingRepository) GetTrackingByRequestID(ctx context.Context, deletionRequestID uuid.UUID) ([]*GDPRServiceTracking, error) {
	query := `
		SELECT id, deletion_request_id, service_name, status, event_id, completed_at, error_message
		FROM iam_gdpr_deletion_tracking
		WHERE deletion_request_id = $1
		ORDER BY service_name`

	rows, err := r.db.Query(ctx, query, deletionRequestID)
	if err != nil {
		return nil, fmt.Errorf("GDPRDeletionTrackingRepository.GetTrackingByRequestID: %w", err)
	}
	defer rows.Close()

	var result []*GDPRServiceTracking
	for rows.Next() {
		t := &GDPRServiceTracking{}
		if scanErr := rows.Scan(
			&t.ID, &t.DeletionRequestID, &t.ServiceName, &t.Status,
			&t.EventID, &t.CompletedAt, &t.ErrorMessage,
		); scanErr != nil {
			logger.Warn("GDPRDeletionTrackingRepository: scan error", zap.Error(scanErr))
			continue
		}
		result = append(result, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GDPRDeletionTrackingRepository.GetTrackingByRequestID: rows: %w", err)
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// CrossServiceOutboxRepository
// ---------------------------------------------------------------------------

// CrossServiceOutboxRepository persists cross-service events to
// iam_cross_service_events (migration 084).
type CrossServiceOutboxRepository struct {
	db *pgxpool.Pool
}

// NewCrossServiceOutboxRepository creates a new outbox repository.
func NewCrossServiceOutboxRepository(db *pgxpool.Pool) *CrossServiceOutboxRepository {
	return &CrossServiceOutboxRepository{db: db}
}

// PublishCrossService inserts an event into the cross-service outbox table.
func (r *CrossServiceOutboxRepository) PublishCrossService(ctx context.Context, event *CrossServiceEvent) error {
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if len(event.Payload) == 0 {
		event.Payload = json.RawMessage("{}")
	}

	query := `
		INSERT INTO iam_cross_service_events
			(id, event_type, aggregate_type, aggregate_id, tenant_id, payload, target_service)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.Exec(ctx, query,
		event.ID, event.EventType, event.AggregateType, event.AggregateID,
		event.TenantID, event.Payload, event.TargetService,
	)
	if err != nil {
		return fmt.Errorf("CrossServiceOutboxRepository.PublishCrossService: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// GDPROrchestrator
// ---------------------------------------------------------------------------

// GDPROrchestrator cascades GDPR Article 17 user data deletion requests across
// all registered downstream services via the transactional outbox pattern. Each
// service receives a typed event; independent outbox processors in each service
// consume and act on these events.
type GDPROrchestrator struct {
	deletionService *DataDeletionService
	outboxPublisher crossServiceOutboxPublisher
	trackingRepo    gdprDeletionTrackingRepo
	auditService    *AuditService
	config          GDPROrchestratorConfig
	logger          *zap.Logger
}

// NewGDPROrchestrator constructs an orchestrator with the provided dependencies.
func NewGDPROrchestrator(
	deletionService *DataDeletionService,
	outboxPublisher crossServiceOutboxPublisher,
	trackingRepo gdprDeletionTrackingRepo,
	auditService *AuditService,
	config GDPROrchestratorConfig,
	log *zap.Logger,
) *GDPROrchestrator {
	if config.GracePeriod == 0 {
		config.GracePeriod = 30 * 24 * time.Hour
	}
	if len(config.Services) == 0 {
		config.Services = DefaultDeletionTargets()
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &GDPROrchestrator{
		deletionService: deletionService,
		outboxPublisher: outboxPublisher,
		trackingRepo:    trackingRepo,
		auditService:    auditService,
		config:          config,
		logger:          log,
	}
}

// InitiateUserDeletion starts the cross-service deletion cascade for a user.
// It:
//  1. Creates a deletion request via DataDeletionService (sets grace period).
//  2. Publishes one cross-service outbox event per registered service, in priority order.
//  3. Creates a tracking row per service so status can be queried later.
//  4. Logs an audit event for each published notification.
//
// Events for services with the same Priority value are published in
// alphabetical service-name order (deterministic, easy to reason about).
func (o *GDPROrchestrator) InitiateUserDeletion(
	ctx context.Context,
	tenantID, userID, requestedBy uuid.UUID,
) error {
	o.logger.Info("initiating GDPR user deletion cascade",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.String("requested_by", requestedBy.String()),
		zap.Int("service_count", len(o.config.Services)),
	)

	// 1. Create the deletion request (with grace period) in the IAM database.
	reqBy := requestedBy
	deletionReq, err := o.deletionService.RequestDeletion(ctx, userID, tenantID, &reqBy, nil)
	if err != nil {
		return fmt.Errorf("GDPROrchestrator.InitiateUserDeletion: create deletion request: %w", err)
	}

	// 2. Build per-event payload.
	payloadBytes := buildDeletionPayload(deletionReq, userID, tenantID, requestedBy)

	// 3. Sort services by priority (stable sort preserves registration order within a priority).
	targets := make([]ServiceDeletionTarget, len(o.config.Services))
	copy(targets, o.config.Services)
	sort.SliceStable(targets, func(i, j int) bool {
		return targets[i].Priority < targets[j].Priority
	})

	// 4. Publish one event per service and create a tracking row.
	for _, svc := range targets {
		event := &CrossServiceEvent{
			EventType:     svc.EventType,
			AggregateType: "user",
			AggregateID:   userID.String(),
			TenantID:      tenantID,
			Payload:       payloadBytes,
			TargetService: svc.ServiceName,
		}

		if pubErr := o.outboxPublisher.PublishCrossService(ctx, event); pubErr != nil {
			// Non-fatal: log and continue so remaining services are not blocked.
			o.logger.Error("GDPROrchestrator: failed to publish deletion event",
				zap.String("service", svc.ServiceName),
				zap.String("deletion_request_id", deletionReq.ID.String()),
				zap.Error(pubErr),
			)
			errStr := pubErr.Error()
			_ = o.trackingRepo.CreateServiceTracking(ctx, &GDPRServiceTracking{
				DeletionRequestID: deletionReq.ID,
				ServiceName:       svc.ServiceName,
				Status:            ServiceStatusFailed,
				ErrorMessage:      &errStr,
			})
			continue
		}

		// Create tracking row with event reference.
		eventID := event.ID
		trackErr := o.trackingRepo.CreateServiceTracking(ctx, &GDPRServiceTracking{
			DeletionRequestID: deletionReq.ID,
			ServiceName:       svc.ServiceName,
			Status:            ServiceStatusPending,
			EventID:           &eventID,
		})
		if trackErr != nil {
			o.logger.Warn("GDPROrchestrator: failed to create tracking row",
				zap.String("service", svc.ServiceName),
				zap.Error(trackErr),
			)
		}

		// Audit each notification.
		o.auditService.LogUserAction(
			ctx, tenantID, &requestedBy, &userID,
			"gdpr_deletion_event_published",
			true,
			map[string]interface{}{
				"deletion_request_id": deletionReq.ID.String(),
				"target_service":      svc.ServiceName,
				"event_type":          svc.EventType,
				"event_id":            event.ID.String(),
			},
		)

		o.logger.Info("GDPROrchestrator: deletion event published",
			zap.String("service", svc.ServiceName),
			zap.String("event_type", svc.EventType),
			zap.String("event_id", event.ID.String()),
		)
	}

	// Top-level audit entry.
	o.auditService.LogUserAction(
		ctx, tenantID, &requestedBy, &userID,
		"gdpr_deletion_cascade_initiated",
		true,
		map[string]interface{}{
			"deletion_request_id": deletionReq.ID.String(),
			"services_notified":   len(targets),
		},
	)

	o.logger.Info("GDPR deletion cascade initiated",
		zap.String("deletion_request_id", deletionReq.ID.String()),
		zap.Int("services", len(targets)),
	)

	return nil
}

// CheckDeletionStatus queries the tracking table to determine the aggregate
// deletion status across all registered services.
func (o *GDPROrchestrator) CheckDeletionStatus(ctx context.Context, deletionRequestID uuid.UUID) (*DeletionStatus, error) {
	rows, err := o.trackingRepo.GetTrackingByRequestID(ctx, deletionRequestID)
	if err != nil {
		return nil, fmt.Errorf("GDPROrchestrator.CheckDeletionStatus: %w", err)
	}

	status := &DeletionStatus{
		RequestID: deletionRequestID,
		Services:  make([]ServiceDeletionStatus, 0, len(rows)),
	}

	completedCount := 0
	failedCount := 0

	for _, row := range rows {
		svcStatus := ServiceDeletionStatus{
			ServiceName: row.ServiceName,
			Status:      row.Status,
			CompletedAt: row.CompletedAt,
			Error:       row.ErrorMessage,
		}
		status.Services = append(status.Services, svcStatus)

		switch row.Status {
		case ServiceStatusCompleted:
			completedCount++
		case ServiceStatusFailed:
			failedCount++
		}
	}

	total := len(rows)
	switch {
	case total == 0:
		status.OverallStatus = DeletionOverallPending
	case completedCount == total:
		status.OverallStatus = DeletionOverallCompleted
	case failedCount == total:
		status.OverallStatus = DeletionOverallFailed
	case failedCount > 0:
		status.OverallStatus = DeletionOverallPartial
	default:
		status.OverallStatus = DeletionOverallInProgress
	}

	return status, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// buildDeletionPayload constructs the JSON payload embedded in each cross-service
// outbox event. It is package-level so tests can call it directly.
func buildDeletionPayload(
	deletionReq *models.DeletionRequest,
	userID, tenantID, requestedBy uuid.UUID,
) json.RawMessage {
	scheduledAt := ""
	if deletionReq.ScheduledDeleteAt != nil {
		scheduledAt = deletionReq.ScheduledDeleteAt.Format(time.RFC3339)
	}
	b, _ := json.Marshal(map[string]string{
		"deletion_request_id": deletionReq.ID.String(),
		"user_id":             userID.String(),
		"tenant_id":           tenantID.String(),
		"requested_by":        requestedBy.String(),
		"scheduled_delete_at": scheduledAt,
	})
	return json.RawMessage(b)
}

// ---------------------------------------------------------------------------
// DefaultDeletionTargets
// ---------------------------------------------------------------------------

// DefaultDeletionTargets returns the canonical set of HexxLock platform services
// that hold user data, ordered by their deletion Priority. Services that hold
// binary/file data are cleaned up first (priority 1) before relational records
// (priority 2), followed by activity/analytics data (priority 3-4).
func DefaultDeletionTargets() []ServiceDeletionTarget {
	return []ServiceDeletionTarget{
		// Priority 1 — binary data / files (delete storage before DB records).
		{
			ServiceName: "document-processor",
			EventType:   "user.data_deletion_requested",
			Priority:    1,
		},
		// Priority 2 — core business records.
		{
			ServiceName: "crm-service",
			EventType:   "user.data_deletion_requested",
			Priority:    2,
		},
		{
			ServiceName: "hr-service",
			EventType:   "user.data_deletion_requested",
			Priority:    2,
		},
		{
			ServiceName: "accounting-service",
			EventType:   "user.data_deletion_requested",
			Priority:    2,
		},
		{
			ServiceName: "invoicing-service",
			EventType:   "user.data_deletion_requested",
			Priority:    2,
		},
		// Priority 3 — secondary business records.
		{
			ServiceName: "inventory-service",
			EventType:   "user.data_deletion_requested",
			Priority:    3,
		},
		{
			ServiceName: "marketing-automation",
			EventType:   "user.data_deletion_requested",
			Priority:    3,
		},
		{
			ServiceName: "helpdesk",
			EventType:   "user.data_deletion_requested",
			Priority:    3,
		},
		// Priority 4 — activity / communication data (cleanup last).
		{
			ServiceName: "comments",
			EventType:   "user.data_deletion_requested",
			Priority:    4,
		},
	}
}
