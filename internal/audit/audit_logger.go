// SPDX-License-Identifier: AGPL-3.0-or-later

// Package audit provides structured audit logging for IAM events.
package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const msgAuditLogBufferFull = "audit log buffer full"

// Logger defines the interface for audit logging operations
type Logger interface {
	// LogRelationshipChange logs a relationship creation or deletion
	LogRelationshipChange(ctx context.Context, entry RelationshipAuditEntry) error

	// LogPermissionCheck logs a permission check result
	LogPermissionCheck(ctx context.Context, entry PermissionCheckAuditEntry) error

	// LogSecurityEvent logs a security-related event
	LogSecurityEvent(ctx context.Context, entry SecurityAuditEntry) error

	// QueryAuditLogs retrieves audit logs based on filters
	QueryAuditLogs(ctx context.Context, filter Filter) ([]Log, int64, error)

	// GetAuditStats returns audit statistics for a tenant
	GetAuditStats(ctx context.Context, tenantID uuid.UUID, startDate, endDate time.Time) (*Stats, error)

	// DetectSuspiciousActivity detects potential unauthorized access attempts
	DetectSuspiciousActivity(ctx context.Context, tenantID uuid.UUID, lookbackHours, denialThreshold int) ([]SuspiciousActivity, error)

	// Close releases all resources
	Close() error
}

// AsyncAuditLogger implements asynchronous audit logging
type AsyncAuditLogger struct {
	repo       Repository
	entries    chan *Log
	stopCh     chan struct{}
	stopOnce   sync.Once
	doneCh     chan struct{}
	bufferSize int
	flushSize  int
}

// NewAsyncAuditLogger creates a new asynchronous audit logger
func NewAsyncAuditLogger(repo Repository, bufferSize, flushSize int) *AsyncAuditLogger {
	if bufferSize <= 0 {
		bufferSize = 1000
	}
	if flushSize <= 0 || flushSize > bufferSize {
		flushSize = 100
	}

	logger := &AsyncAuditLogger{
		repo:       repo,
		entries:    make(chan *Log, bufferSize),
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		bufferSize: bufferSize,
		flushSize:  flushSize,
	}

	// Start background worker
	go logger.worker()

	return logger
}

// worker processes audit log entries asynchronously
func (l *AsyncAuditLogger) worker() {
	defer close(l.doneCh)

	batch := make([]*Log, 0, l.flushSize)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := l.repo.BatchCreate(ctx, batch); err != nil {
			logger.Log.Error("Failed to flush audit log batch",
				zap.Int("batch_size", len(batch)),
				zap.Error(err),
			)
		} else {
			logger.Log.Debug("Flushed audit log batch",
				zap.Int("batch_size", len(batch)),
			)
		}

		batch = batch[:0]
	}

	for {
		select {
		case <-l.stopCh:
			// Flush remaining entries
			flush()
			// Drain channel
			for len(l.entries) > 0 {
				entry := <-l.entries
				batch = append(batch, entry)
				if len(batch) >= l.flushSize {
					flush()
				}
			}
			flush()
			return

		case entry := <-l.entries:
			batch = append(batch, entry)
			if len(batch) >= l.flushSize {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

// LogRelationshipChange logs a relationship creation or deletion
func (l *AsyncAuditLogger) LogRelationshipChange(_ context.Context, entry RelationshipAuditEntry) error {
	auditLog := &Log{
		ID:           uuid.New(),
		TenantID:     entry.TenantID,
		ActorID:      entry.ActorID,
		ActorType:    entry.ActorType,
		Action:       entry.Action,
		ResourceType: entry.ResourceType,
		ResourceID:   entry.ResourceID,
		Relation:     &entry.Relation,
		SubjectType:  &entry.SubjectType,
		SubjectID:    &entry.SubjectID,
		Result:       ResultSuccess,
		Metadata:     entry.Metadata,
		IPAddress:    stringPtr(entry.IPAddress),
		UserAgent:    stringPtr(entry.UserAgent),
		RequestID:    stringPtr(entry.RequestID),
		CreatedAt:    time.Now(),
	}

	select {
	case l.entries <- auditLog:
		return nil
	default:
		// Buffer full - log warning but don't block
		logger.Log.Warn("Audit log buffer full, dropping entry",
			zap.String("action", string(entry.Action)),
			zap.String("resource", fmt.Sprintf("%s:%s", entry.ResourceType, entry.ResourceID)),
		)
		return errors.New(msgAuditLogBufferFull)
	}
}

// LogPermissionCheck logs a permission check result
func (l *AsyncAuditLogger) LogPermissionCheck(_ context.Context, entry PermissionCheckAuditEntry) error {
	action := ActionPermissionChecked
	result := ResultSuccess
	var errorMsg *string

	if !entry.Result {
		action = ActionPermissionDenied
		result = ResultDenied
	}

	if entry.ErrorMessage != "" {
		action = ActionPermissionError
		result = ResultError
		errorMsg = &entry.ErrorMessage
	}

	latencyMs := entry.Latency.Milliseconds()

	auditLog := &Log{
		ID:           uuid.New(),
		TenantID:     entry.TenantID,
		ActorID:      entry.ActorID,
		ActorType:    ActorTypeUser, // Permission checks are always from users
		Action:       action,
		ResourceType: entry.ResourceType,
		ResourceID:   entry.ResourceID,
		Relation:     &entry.Permission,
		Result:       result,
		IPAddress:    stringPtr(entry.IPAddress),
		UserAgent:    stringPtr(entry.UserAgent),
		RequestID:    stringPtr(entry.RequestID),
		ErrorMessage: errorMsg,
		LatencyMs:    &latencyMs,
		CreatedAt:    time.Now(),
	}

	select {
	case l.entries <- auditLog:
		return nil
	default:
		logger.Log.Warn("Audit log buffer full, dropping permission check",
			zap.String("resource", fmt.Sprintf("%s:%s", entry.ResourceType, entry.ResourceID)),
			zap.String("permission", entry.Permission),
		)
		return errors.New(msgAuditLogBufferFull)
	}
}

// LogSecurityEvent logs a security-related event
func (l *AsyncAuditLogger) LogSecurityEvent(_ context.Context, entry SecurityAuditEntry) error {
	metadata := map[string]interface{}{
		"event_type": entry.EventType,
		"details":    entry.Details,
		"severity":   entry.Severity,
	}

	auditLog := &Log{
		ID:           uuid.New(),
		TenantID:     entry.TenantID,
		ActorID:      entry.ActorID,
		ActorType:    ActorTypeUser,
		Action:       ActionPermissionDenied, // Security events are typically denials
		ResourceType: entry.ResourceType,
		ResourceID:   entry.ResourceID,
		Result:       ResultDenied,
		Metadata:     metadata,
		IPAddress:    stringPtr(entry.IPAddress),
		UserAgent:    stringPtr(entry.UserAgent),
		RequestID:    stringPtr(entry.RequestID),
		CreatedAt:    time.Now(),
	}

	select {
	case l.entries <- auditLog:
		return nil
	default:
		logger.Log.Warn("Audit log buffer full, dropping security event",
			zap.String("event_type", entry.EventType),
			zap.String("severity", entry.Severity),
		)
		return errors.New(msgAuditLogBufferFull)
	}
}

// QueryAuditLogs retrieves audit logs based on filters
func (l *AsyncAuditLogger) QueryAuditLogs(ctx context.Context, filter Filter) ([]Log, int64, error) {
	return l.repo.Query(ctx, filter)
}

// GetAuditStats returns audit statistics for a tenant
func (l *AsyncAuditLogger) GetAuditStats(ctx context.Context, tenantID uuid.UUID, startDate, endDate time.Time) (*Stats, error) {
	return l.repo.GetStats(ctx, &tenantID, startDate, endDate)
}

// DetectSuspiciousActivity detects potential unauthorized access attempts
func (l *AsyncAuditLogger) DetectSuspiciousActivity(ctx context.Context, tenantID uuid.UUID, lookbackHours, denialThreshold int) ([]SuspiciousActivity, error) {
	return l.repo.DetectSuspiciousActivity(ctx, tenantID, lookbackHours, denialThreshold)
}

// Close gracefully shuts down the audit logger
func (l *AsyncAuditLogger) Close() error {
	l.stopOnce.Do(func() { close(l.stopCh) })
	<-l.doneCh
	return nil
}

// stringPtr converts a string to a pointer, returning nil for empty strings
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
