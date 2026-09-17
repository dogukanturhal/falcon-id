// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// Repository defines the interface for audit log persistence
type Repository interface {
	// Create inserts a single audit log entry
	Create(ctx context.Context, log *Log) error

	// BatchCreate inserts multiple audit log entries in a single transaction
	BatchCreate(ctx context.Context, logs []*Log) error

	// Query retrieves audit logs based on filters
	Query(ctx context.Context, filter Filter) ([]Log, int64, error)

	// GetByID retrieves a specific audit log entry
	GetByID(ctx context.Context, id uuid.UUID) (*Log, error)

	// GetStats returns audit statistics
	GetStats(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*Stats, error)

	// DetectSuspiciousActivity detects potential unauthorized access attempts
	DetectSuspiciousActivity(ctx context.Context, tenantID uuid.UUID, lookbackHours, denialThreshold int) ([]SuspiciousActivity, error)

	// CleanupOldLogs deletes audit logs older than retention period
	CleanupOldLogs(ctx context.Context, retentionDays int) (int64, error)
}

// PostgresAuditRepository implements Repository using PostgreSQL
type PostgresAuditRepository struct {
	db *sqlx.DB
}

// NewPostgresAuditRepository creates a new PostgreSQL audit repository
func NewPostgresAuditRepository(db *sqlx.DB) *PostgresAuditRepository {
	return &PostgresAuditRepository{db: db}
}

// Create inserts a single audit log entry
func (r *PostgresAuditRepository) Create(ctx context.Context, log *Log) error {
	metadataJSON, err := json.Marshal(log.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO iam_audit_logs (
			id, tenant_id, actor_id, actor_type, action, resource_type, resource_id,
			relation, subject_type, subject_id, result, metadata, ip_address,
			user_agent, request_id, error_message, latency_ms, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
		)`

	_, err = r.db.ExecContext(ctx, query,
		log.ID, log.TenantID, log.ActorID, log.ActorType, log.Action, log.ResourceType,
		log.ResourceID, log.Relation, log.SubjectType, log.SubjectID, log.Result,
		metadataJSON, log.IPAddress, log.UserAgent, log.RequestID, log.ErrorMessage,
		log.LatencyMs, log.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// BatchCreate inserts multiple audit log entries in a single transaction
func (r *PostgresAuditRepository) BatchCreate(ctx context.Context, logs []*Log) error {
	if len(logs) == 0 {
		return nil
	}

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO iam_audit_logs (
			id, tenant_id, actor_id, actor_type, action, resource_type, resource_id,
			relation, subject_type, subject_id, result, metadata, ip_address,
			user_agent, request_id, error_message, latency_ms, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
		)`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close() //nolint:errcheck

	for _, log := range logs {
		metadataJSON, err := json.Marshal(log.Metadata)
		if err != nil {
			logger.Log.Error("Failed to marshal metadata, skipping entry",
				zap.String("id", log.ID.String()),
				zap.Error(err),
			)
			continue
		}

		_, err = stmt.ExecContext(ctx,
			log.ID, log.TenantID, log.ActorID, log.ActorType, log.Action, log.ResourceType,
			log.ResourceID, log.Relation, log.SubjectType, log.SubjectID, log.Result,
			metadataJSON, log.IPAddress, log.UserAgent, log.RequestID, log.ErrorMessage,
			log.LatencyMs, log.CreatedAt,
		)
		if err != nil {
			logger.Log.Error("Failed to insert audit log entry",
				zap.String("id", log.ID.String()),
				zap.Error(err),
			)
			// Continue with other entries rather than failing the entire batch
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Query retrieves audit logs based on filters
func (r *PostgresAuditRepository) Query(ctx context.Context, filter Filter) ([]Log, int64, error) {
	whereClause, args, argPos := buildAuditLogWhere(filter)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM iam_audit_logs %s", whereClause)
	var total int64
	if err := r.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	limit, offset := normalizeAuditPagination(filter.Limit, filter.Offset)
	query := fmt.Sprintf(`
		SELECT id, tenant_id, actor_id, actor_type, action, resource_type, resource_id,
			   relation, subject_type, subject_id, result, metadata, ip_address,
			   user_agent, request_id, error_message, latency_ms, created_at
		FROM iam_audit_logs
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argPos, argPos+1)

	rows, err := r.db.QueryxContext(ctx, query, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	logs := make([]Log, 0)
	for rows.Next() {
		log, err := scanAuditLog(rows)
		if err != nil {
			return nil, 0, err
		}
		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating audit logs: %w", err)
	}

	return logs, total, nil
}

// buildAuditLogWhere constructs the WHERE clause and positional args for audit log queries.
func buildAuditLogWhere(filter Filter) (string, []interface{}, int) {
	where := "WHERE 1=1"
	args := make([]interface{}, 0)
	pos := 1

	if filter.TenantID != nil {
		where += fmt.Sprintf(" AND tenant_id = $%d", pos)
		args = append(args, *filter.TenantID)
		pos++
	}
	if filter.ActorID != nil {
		where += fmt.Sprintf(" AND actor_id = $%d", pos)
		args = append(args, *filter.ActorID)
		pos++
	}
	if filter.Action != nil {
		where += fmt.Sprintf(" AND action = $%d", pos)
		args = append(args, *filter.Action)
		pos++
	}
	if filter.ResourceType != nil {
		where += fmt.Sprintf(" AND resource_type = $%d", pos)
		args = append(args, *filter.ResourceType)
		pos++
	}
	if filter.ResourceID != nil {
		where += fmt.Sprintf(" AND resource_id = $%d", pos)
		args = append(args, *filter.ResourceID)
		pos++
	}
	if filter.Result != nil {
		where += fmt.Sprintf(" AND result = $%d", pos)
		args = append(args, *filter.Result)
		pos++
	}
	if filter.StartDate != nil {
		where += fmt.Sprintf(" AND created_at >= $%d", pos)
		args = append(args, *filter.StartDate)
		pos++
	}
	if filter.EndDate != nil {
		where += fmt.Sprintf(" AND created_at <= $%d", pos)
		args = append(args, *filter.EndDate)
		pos++
	}
	return where, args, pos
}

// normalizeAuditPagination clamps limit and offset to valid ranges.
func normalizeAuditPagination(limit, offset int) (int, int) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// scanAuditLog scans one audit log row and unmarshals its metadata JSON.
func scanAuditLog(rows interface{ Scan(...interface{}) error }) (Log, error) {
	var log Log
	var metadataJSON []byte
	err := rows.Scan(
		&log.ID, &log.TenantID, &log.ActorID, &log.ActorType, &log.Action,
		&log.ResourceType, &log.ResourceID, &log.Relation, &log.SubjectType,
		&log.SubjectID, &log.Result, &metadataJSON, &log.IPAddress, &log.UserAgent,
		&log.RequestID, &log.ErrorMessage, &log.LatencyMs, &log.CreatedAt,
	)
	if err != nil {
		return log, fmt.Errorf("failed to scan audit log: %w", err)
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &log.Metadata); err != nil {
			logger.Log.Error("Failed to unmarshal metadata",
				zap.String("id", log.ID.String()),
				zap.Error(err),
			)
		}
	}
	return log, nil
}

// GetByID retrieves a specific audit log entry
func (r *PostgresAuditRepository) GetByID(ctx context.Context, id uuid.UUID) (*Log, error) {
	query := `
		SELECT id, tenant_id, actor_id, actor_type, action, resource_type, resource_id,
			   relation, subject_type, subject_id, result, metadata, ip_address,
			   user_agent, request_id, error_message, latency_ms, created_at
		FROM iam_audit_logs
		WHERE id = $1`

	var log Log
	var metadataJSON []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&log.ID, &log.TenantID, &log.ActorID, &log.ActorType, &log.Action,
		&log.ResourceType, &log.ResourceID, &log.Relation, &log.SubjectType,
		&log.SubjectID, &log.Result, &metadataJSON, &log.IPAddress, &log.UserAgent,
		&log.RequestID, &log.ErrorMessage, &log.LatencyMs, &log.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("audit log not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get audit log: %w", err)
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &log.Metadata); err != nil {
			logger.Log.Error("Failed to unmarshal metadata",
				zap.String("id", log.ID.String()),
				zap.Error(err),
			)
		}
	}

	return &log, nil
}

// GetStats returns audit statistics
func (r *PostgresAuditRepository) GetStats(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*Stats, error) {
	query := `SELECT * FROM get_iam_audit_stats($1, $2, $3)`

	var stats Stats
	err := r.db.GetContext(ctx, &stats, query, tenantID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit stats: %w", err)
	}

	return &stats, nil
}

// DetectSuspiciousActivity detects potential unauthorized access attempts
func (r *PostgresAuditRepository) DetectSuspiciousActivity(ctx context.Context, tenantID uuid.UUID, lookbackHours, denialThreshold int) ([]SuspiciousActivity, error) {
	query := `SELECT * FROM detect_suspicious_iam_activity($1, $2, $3)`

	rows, err := r.db.QueryxContext(ctx, query, tenantID, lookbackHours, denialThreshold)
	if err != nil {
		return nil, fmt.Errorf("failed to detect suspicious activity: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	activities := make([]SuspiciousActivity, 0)
	for rows.Next() {
		var activity SuspiciousActivity
		var sampleActionsJSON []byte

		err := rows.Scan(
			&activity.ActorID,
			&activity.DenialCount,
			&activity.UniqueResources,
			&activity.FirstDenial,
			&activity.LastDenial,
			&sampleActionsJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan suspicious activity: %w", err)
		}

		if len(sampleActionsJSON) > 0 {
			if err := json.Unmarshal(sampleActionsJSON, &activity.SampleActions); err != nil {
				logger.Log.Error("Failed to unmarshal sample actions",
					zap.String("actor_id", activity.ActorID.String()),
					zap.Error(err),
				)
			}
		}

		activities = append(activities, activity)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating suspicious activities: %w", err)
	}

	return activities, nil
}

// CleanupOldLogs deletes audit logs older than retention period
func (r *PostgresAuditRepository) CleanupOldLogs(ctx context.Context, retentionDays int) (int64, error) {
	query := `SELECT * FROM cleanup_iam_audit_logs($1)`

	var deletedCount int64
	err := r.db.GetContext(ctx, &deletedCount, query, retentionDays)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old logs: %w", err)
	}

	logger.Log.Info("Cleaned up old audit logs",
		zap.Int("retention_days", retentionDays),
		zap.Int64("deleted_count", deletedCount),
	)

	return deletedCount, nil
}
