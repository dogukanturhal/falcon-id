// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ThreatCorrelationService analyses event streams and emits ThreatEvent records
// when suspicious patterns are detected. Detected events are forwarded to the
// SIEMService for external delivery.
//
// The service also acts as an integration bridge to the ITDRDetectionPipeline:
// when a pipeline is configured via SetDetectionPipeline, AnalyzeEvent will
// additionally route events through the pipeline so ITDR signals are emitted
// alongside legacy ThreatEvents.
type ThreatCorrelationService struct {
	db                *pgxpool.Pool
	siemService       *SIEMService
	auditService      *AuditService
	detectionPipeline ITDRDetectionPipeline
	logger            *zap.Logger
}

// NewThreatCorrelationService creates a new ThreatCorrelationService.
func NewThreatCorrelationService(
	db *pgxpool.Pool,
	siemService *SIEMService,
	auditService *AuditService,
	log *zap.Logger,
) *ThreatCorrelationService {
	if log == nil {
		log = zap.NewNop()
	}
	return &ThreatCorrelationService{
		db:           db,
		siemService:  siemService,
		auditService: auditService,
		logger:       log,
	}
}

// SetDetectionPipeline wires the ITDR detection pipeline into the correlation
// service.  When set, AnalyzeEvent routes events through the pipeline after the
// legacy detectors, ensuring that ITDR threat signals are produced for every
// applicable event.  Setter injection is used to avoid circular dependencies
// between the two service types.
func (s *ThreatCorrelationService) SetDetectionPipeline(pipeline ITDRDetectionPipeline) {
	s.detectionPipeline = pipeline
}

// EmitFromPipelineResult persists a ThreatEvent for each ITDR ThreatSignal
// that was emitted by the detection pipeline, bridging the new ITDR signal
// model with the existing iam_threat_events table used by the SIEM service.
//
// Signals are mapped to ThreatEvents with the same severity.  This ensures
// that SIEM webhooks and existing alert tooling continue to receive
// notifications even when detections originate from the ITDR pipeline.
// processITDRLoginEvent builds an ITDRLoginEvent from metadata and routes it through the detection pipeline.
func (s *ThreatCorrelationService) processITDRLoginEvent(ctx context.Context, ip string, success bool, metadata map[string]interface{}, logTag string) {
	uid := parseUUIDFromMeta(metadata, "user_id")
	tid := parseUUIDFromMeta(metadata, "tenant_id")
	event := models.ITDRLoginEvent{
		UserID:     uid,
		IPAddress:  ip,
		Success:    success,
		OccurredAt: time.Now(),
		TenantID:   tid,
	}
	if lat, ok := metadata["geo_lat"].(float64); ok {
		event.GeoLat = lat
	}
	if lon, ok := metadata["geo_lon"].(float64); ok {
		event.GeoLon = lon
	}
	result, err := s.detectionPipeline.ProcessLoginEvent(ctx, event)
	if err != nil {
		s.logger.Warn("AnalyzeEvent: ITDR pipeline error for "+logTag, zap.Error(err))
	}
	s.EmitFromPipelineResult(ctx, result)
}

// parseUUIDFromMeta extracts and parses a UUID string from a metadata map, returning nil on failure.
func parseUUIDFromMeta(metadata map[string]interface{}, key string) *uuid.UUID {
	raw, _ := metadata[key].(string)
	if raw == "" {
		return nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil
	}
	return &id
}

// EmitFromPipelineResult publishes threat signals from an ITDR detection pipeline result.
func (s *ThreatCorrelationService) EmitFromPipelineResult(
	ctx context.Context,
	result *models.ITDRDetectionResult,
) {
	if result == nil || !result.HasSignals() {
		return
	}

	for _, sig := range result.Signals {
		detailsJSON, _ := json.Marshal(sig.Details)

		// Map ThreatSignalSeverity → ThreatSeverity (same string values).
		severity := models.ThreatSeverity(sig.Severity)

		event := &models.ThreatEvent{
			ID:        uuid.New(),
			TenantID:  sig.TenantID,
			UserID:    sig.UserID,
			EventType: string(sig.SignalType),
			Severity:  severity,
			Details:   detailsJSON,
			Status:    models.ThreatEventStatusOpen,
			CreatedAt: time.Now(),
		}

		if err := s.pushEvent(ctx, event); err != nil {
			s.logger.Warn("ThreatCorrelationService: failed to push ITDR pipeline event to SIEM",
				zap.String("signal_type", string(sig.SignalType)),
				zap.Error(err),
			)
		}
	}
}

// DetectCredentialStuffing counts failed login attempts from a single IP within
// the given window. When the count meets or exceeds threshold a ThreatEvent is
// created and pushed to the SIEM; nil is returned when below the threshold.
func (s *ThreatCorrelationService) DetectCredentialStuffing(
	ctx context.Context,
	ip string,
	window time.Duration,
	threshold int,
) (*models.ThreatEvent, error) {
	since := time.Now().Add(-window)

	var count int64
	err := s.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM iam_audit_log
		WHERE ip_address = $1
		  AND action = 'login'
		  AND success = false
		  AND created_at >= $2`,
		ip, since,
	).Scan(&count)
	if err != nil {
		return nil, fmt.Errorf("ThreatCorrelationService.DetectCredentialStuffing: query: %w", err)
	}

	if count < int64(threshold) {
		return nil, nil
	}

	detailsJSON, _ := json.Marshal(map[string]interface{}{
		"failed_attempts": count,
		"window_seconds":  window.Seconds(),
		"threshold":       threshold,
	})

	parsedIP := net.ParseIP(ip)
	event := &models.ThreatEvent{
		ID:        uuid.New(),
		EventType: "credential_stuffing",
		Severity:  models.ThreatSeverityHigh,
		SourceIP:  &parsedIP,
		Details:   detailsJSON,
		Status:    models.ThreatEventStatusOpen,
		CreatedAt: time.Now(),
	}

	if err := s.pushEvent(ctx, event); err != nil {
		s.logger.Warn("ThreatCorrelationService: failed to push credential stuffing event",
			zap.String("ip", ip),
			zap.Error(err),
		)
	}

	return event, nil
}

// DetectImpossibleTravel checks whether the user has had a recent login from a
// different IP. If two distinct IPs are observed a ThreatEvent is created as a
// possible account-sharing or account-takeover signal.
func (s *ThreatCorrelationService) DetectImpossibleTravel(
	ctx context.Context,
	userID uuid.UUID,
	currentIP string,
) (*models.ThreatEvent, error) {
	// Look up the last successful login IP before now.
	var lastIP string
	var lastLoginAt time.Time

	err := s.db.QueryRow(ctx, `
		SELECT COALESCE(ip_address, '') AS ip_address, created_at
		FROM iam_audit_log
		WHERE user_id = $1
		  AND action = 'login'
		  AND success = true
		ORDER BY created_at DESC
		LIMIT 1`,
		userID,
	).Scan(&lastIP, &lastLoginAt)
	if err != nil {
		// No prior login record — nothing to compare; not an error.
		return nil, nil //nolint:nilerr // intentional: no prior login record means nothing to compare, not an error condition
	}

	// If the IPs match or either is empty there is no signal.
	if lastIP == "" || currentIP == "" || lastIP == currentIP {
		return nil, nil
	}

	detailsJSON, _ := json.Marshal(map[string]interface{}{
		"previous_ip":      lastIP,
		"current_ip":       currentIP,
		"last_login_at":    lastLoginAt.UTC().Format(time.RFC3339),
		"time_since_login": time.Since(lastLoginAt).String(),
	})

	parsedIP := net.ParseIP(currentIP)
	event := &models.ThreatEvent{
		ID:        uuid.New(),
		EventType: "impossible_travel",
		Severity:  models.ThreatSeverityMedium,
		UserID:    &userID,
		SourceIP:  &parsedIP,
		Details:   detailsJSON,
		Status:    models.ThreatEventStatusOpen,
		CreatedAt: time.Now(),
	}

	if err := s.pushEvent(ctx, event); err != nil {
		s.logger.Warn("ThreatCorrelationService: failed to push impossible travel event",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
	}

	return event, nil
}

// DetectBulkPermissionChanges counts permission change events for a tenant within
// the given window. When the count meets or exceeds threshold a ThreatEvent is
// created indicating a potential privilege escalation or account takeover.
func (s *ThreatCorrelationService) DetectBulkPermissionChanges(
	ctx context.Context,
	tenantID uuid.UUID,
	window time.Duration,
	threshold int,
) (*models.ThreatEvent, error) {
	since := time.Now().Add(-window)

	var count int64
	err := s.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM iam_audit_log
		WHERE tenant_id = $1
		  AND action IN ('permission_granted', 'permission_revoked', 'role_assigned', 'role_removed')
		  AND created_at >= $2`,
		tenantID, since,
	).Scan(&count)
	if err != nil {
		return nil, fmt.Errorf("ThreatCorrelationService.DetectBulkPermissionChanges: query: %w", err)
	}

	if count < int64(threshold) {
		return nil, nil
	}

	detailsJSON, _ := json.Marshal(map[string]interface{}{
		"change_count":   count,
		"window_seconds": window.Seconds(),
		"threshold":      threshold,
	})

	event := &models.ThreatEvent{
		ID:        uuid.New(),
		EventType: "bulk_permission_changes",
		Severity:  models.ThreatSeverityHigh,
		TenantID:  &tenantID,
		Details:   detailsJSON,
		Status:    models.ThreatEventStatusOpen,
		CreatedAt: time.Now(),
	}

	if err := s.pushEvent(ctx, event); err != nil {
		s.logger.Warn("ThreatCorrelationService: failed to push bulk permission changes event",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
	}

	return event, nil
}

// AnalyzeEvent is a generic entry point that dispatches to specific detection
// routines based on the incoming eventType. Unknown types are silently ignored.
//
// When an ITDRDetectionPipeline has been wired via SetDetectionPipeline, login
// events are additionally routed through the pipeline so that ITDR threat
// signals are emitted alongside legacy ThreatEvents.  Any signals produced by
// the pipeline are bridged back to the SIEM via EmitFromPipelineResult.
func (s *ThreatCorrelationService) AnalyzeEvent(
	ctx context.Context,
	eventType string,
	metadata map[string]interface{},
) error {
	switch eventType {
	case "login_failed":
		ip, _ := metadata["ip_address"].(string)
		if ip == "" {
			return nil
		}
		if _, err := s.DetectCredentialStuffing(ctx, ip, 15*time.Minute, 10); err != nil {
			return err
		}

		// Route failed login through ITDR pipeline for velocity-based detection.
		if s.detectionPipeline != nil {
			s.processITDRLoginEvent(ctx, ip, false, metadata, "login_failed")
		}

		return nil

	case "login_success":
		rawUserID, _ := metadata["user_id"].(string)
		ip, _ := metadata["ip_address"].(string)
		if rawUserID == "" || ip == "" {
			return nil
		}
		userID, err := uuid.Parse(rawUserID)
		if err != nil {
			return fmt.Errorf("AnalyzeEvent: invalid user_id %q: %w", rawUserID, err)
		}
		if _, err := s.DetectImpossibleTravel(ctx, userID, ip); err != nil {
			return err
		}

		// Route successful login through ITDR pipeline.
		if s.detectionPipeline != nil {
			s.processITDRLoginEvent(ctx, ip, true, metadata, "login_success")
		}

		return nil

	case "permission_changed":
		rawTenantID, _ := metadata["tenant_id"].(string)
		if rawTenantID == "" {
			return nil
		}
		tenantID, err := uuid.Parse(rawTenantID)
		if err != nil {
			return fmt.Errorf("AnalyzeEvent: invalid tenant_id %q: %w", rawTenantID, err)
		}
		_, err = s.DetectBulkPermissionChanges(ctx, tenantID, 5*time.Minute, 20)
		return err

	default:
		// Unknown event types are not an error.
		return nil
	}
}

// ListEvents returns a paginated slice of threat events filtered by the given params.
func (s *ThreatCorrelationService) ListEvents(
	ctx context.Context,
	params models.ThreatEventListParams,
) ([]models.ThreatEvent, int64, error) {
	baseWhere := "WHERE 1=1"
	args := []interface{}{}
	argIdx := 1

	if params.Severity != "" {
		baseWhere += fmt.Sprintf(" AND severity = $%d", argIdx)
		args = append(args, params.Severity)
		argIdx++
	}
	if params.Status != "" {
		baseWhere += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, params.Status)
		argIdx++
	}
	if params.Type != "" {
		baseWhere += fmt.Sprintf(" AND event_type = $%d", argIdx)
		args = append(args, params.Type)
		argIdx++
	}
	if params.TenantID != nil {
		baseWhere += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, *params.TenantID)
		argIdx++
	}
	if params.UserID != nil {
		baseWhere += fmt.Sprintf(" AND user_id = $%d", argIdx)
		args = append(args, *params.UserID)
		argIdx++
	}
	if params.From != nil {
		baseWhere += fmt.Sprintf(" AND created_at >= $%d", argIdx)
		args = append(args, *params.From)
		argIdx++
	}
	if params.To != nil {
		baseWhere += fmt.Sprintf(" AND created_at <= $%d", argIdx)
		args = append(args, *params.To)
		argIdx++
	}

	// Count total
	var total int64
	countQuery := "SELECT COUNT(*) FROM iam_threat_events " + baseWhere
	if err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ThreatCorrelationService.ListEvents: count: %w", err)
	}

	// Fetch page
	offset := (params.Page - 1) * params.PageSize
	selectQuery := fmt.Sprintf(
		`SELECT id, tenant_id, event_type, severity, source_ip, user_id, details, correlated_events, status, created_at, resolved_at, resolved_by
		 FROM iam_threat_events %s
		 ORDER BY created_at DESC
		 LIMIT $%d OFFSET $%d`,
		baseWhere, argIdx, argIdx+1,
	)
	args = append(args, params.PageSize, offset)

	rows, err := s.db.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("ThreatCorrelationService.ListEvents: query: %w", err)
	}
	defer rows.Close()

	var events []models.ThreatEvent
	for rows.Next() {
		var e models.ThreatEvent
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.EventType, &e.Severity,
			&e.SourceIP, &e.UserID, &e.Details, &e.CorrelatedEvents,
			&e.Status, &e.CreatedAt, &e.ResolvedAt, &e.ResolvedBy,
		); err != nil {
			return nil, 0, fmt.Errorf("ThreatCorrelationService.ListEvents: scan: %w", err)
		}
		events = append(events, e)
	}

	return events, total, nil
}

// GetEventByID returns a single threat event by its ID.
func (s *ThreatCorrelationService) GetEventByID(
	ctx context.Context,
	id uuid.UUID,
) (*models.ThreatEvent, error) {
	var e models.ThreatEvent
	err := s.db.QueryRow(ctx,
		`SELECT id, tenant_id, event_type, severity, source_ip, user_id, details, correlated_events, status, created_at, resolved_at, resolved_by
		 FROM iam_threat_events WHERE id = $1`, id,
	).Scan(
		&e.ID, &e.TenantID, &e.EventType, &e.Severity,
		&e.SourceIP, &e.UserID, &e.Details, &e.CorrelatedEvents,
		&e.Status, &e.CreatedAt, &e.ResolvedAt, &e.ResolvedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("ThreatCorrelationService.GetEventByID: %w", err)
	}
	return &e, nil
}

// UpdateEventStatus transitions a threat event to a new status.
func (s *ThreatCorrelationService) UpdateEventStatus(
	ctx context.Context,
	id uuid.UUID,
	status models.ThreatEventStatus,
	resolvedBy *uuid.UUID,
) error {
	var resolvedAt *time.Time
	if status == models.ThreatEventStatusResolved || status == models.ThreatEventStatusFalsePositive {
		now := time.Now()
		resolvedAt = &now
	}

	_, err := s.db.Exec(ctx,
		`UPDATE iam_threat_events SET status = $1, resolved_at = $2, resolved_by = $3 WHERE id = $4`,
		status, resolvedAt, resolvedBy, id,
	)
	if err != nil {
		return fmt.Errorf("ThreatCorrelationService.UpdateEventStatus: %w", err)
	}
	return nil
}

// pushEvent forwards a ThreatEvent to the SIEM service. It is a no-op when the
// SIEMService is not configured.
func (s *ThreatCorrelationService) pushEvent(ctx context.Context, event *models.ThreatEvent) error {
	if s.siemService == nil {
		return nil
	}
	return s.siemService.PushEvent(ctx, event)
}
