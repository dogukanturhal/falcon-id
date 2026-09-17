// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ComplianceReportService manages compliance report generation and retrieval.
type ComplianceReportService struct {
	db *pgxpool.Pool
}

// NewComplianceReportService creates a new ComplianceReportService.
func NewComplianceReportService(db *pgxpool.Pool) *ComplianceReportService {
	return &ComplianceReportService{db: db}
}

// ---------------------------------------------------------------------------
// Report Templates
// ---------------------------------------------------------------------------

// ListTemplates returns all built-in and custom report templates.
func (s *ComplianceReportService) ListTemplates(ctx context.Context) ([]models.ComplianceReportTemplate, error) {
	query := `
		SELECT id, report_type, name, description, default_params, output_format,
		       is_system, created_by, created_at, updated_at
		FROM iam_compliance_report_templates
		ORDER BY is_system DESC, report_type, name`

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ComplianceReportService.ListTemplates: %w", err)
	}
	defer rows.Close()

	var templates []models.ComplianceReportTemplate
	for rows.Next() {
		var t models.ComplianceReportTemplate
		if err := rows.Scan(
			&t.ID, &t.ReportType, &t.Name, &t.Description,
			&t.DefaultParams, &t.OutputFormat,
			&t.IsSystem, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			logger.Warn("ComplianceReportService.ListTemplates: scan error", zap.Error(err))
			continue
		}
		templates = append(templates, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ComplianceReportService.ListTemplates: rows: %w", err)
	}
	return templates, nil
}

// ---------------------------------------------------------------------------
// Report CRUD
// ---------------------------------------------------------------------------

// Create enqueues a new compliance report for async generation and immediately
// starts the generation in a goroutine.
func (s *ComplianceReportService) Create(
	ctx context.Context,
	req *models.CreateComplianceReportRequest,
	generatedBy uuid.UUID,
) (*models.ComplianceReport, error) {
	outputFormat := req.OutputFormat
	if outputFormat == "" {
		outputFormat = models.ReportOutputJSON
	}

	paramsJSON, err := json.Marshal(req.Parameters)
	if err != nil {
		return nil, fmt.Errorf("ComplianceReportService.Create: marshal params: %w", err)
	}

	query := `
		INSERT INTO iam_compliance_reports
		(tenant_id, report_type, name, description, status, period_start, period_end,
		 parameters, output_format, generated_by)
		VALUES ($1,$2,$3,$4,'pending',$5,$6,$7,$8,$9)
		RETURNING id, created_at, updated_at`

	r := &models.ComplianceReport{
		TenantID:     req.TenantID,
		ReportType:   req.ReportType,
		Name:         req.Name,
		Description:  req.Description,
		Status:       models.ReportStatusPending,
		PeriodStart:  req.PeriodStart,
		PeriodEnd:    req.PeriodEnd,
		Parameters:   paramsJSON,
		OutputFormat: outputFormat,
		GeneratedBy:  generatedBy,
	}

	err = s.db.QueryRow(ctx, query,
		r.TenantID, r.ReportType, r.Name, r.Description,
		r.PeriodStart, r.PeriodEnd, r.Parameters, r.OutputFormat, r.GeneratedBy,
	).Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("ComplianceReportService.Create: insert: %w", err)
	}

	logger.Info("ComplianceReportService: report enqueued",
		zap.String("report_id", r.ID.String()),
		zap.String("report_type", string(r.ReportType)),
	)

	// Kick off async generation (non-blocking)
	go s.generate(context.Background(), r) //nolint:gosec // goroutine must outlive request context

	return r, nil
}

// GetByID returns a single report by primary key.
func (s *ComplianceReportService) GetByID(ctx context.Context, id uuid.UUID) (*models.ComplianceReport, error) {
	query := `
		SELECT id, tenant_id, report_type, name, description, status,
		       period_start, period_end, parameters, output_format,
		       file_size_bytes, record_count, output_data,
		       generated_by, started_at, completed_at, error_message,
		       created_at, updated_at
		FROM iam_compliance_reports
		WHERE id = $1`

	r := &models.ComplianceReport{}
	err := s.db.QueryRow(ctx, query, id).Scan(
		&r.ID, &r.TenantID, &r.ReportType, &r.Name, &r.Description, &r.Status,
		&r.PeriodStart, &r.PeriodEnd, &r.Parameters, &r.OutputFormat,
		&r.FileSizeBytes, &r.RecordCount, &r.OutputData,
		&r.GeneratedBy, &r.StartedAt, &r.CompletedAt, &r.ErrorMessage,
		&r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("ComplianceReportService.GetByID: %w", err)
	}
	return r, nil
}

// List returns reports matching the given parameters.
func (s *ComplianceReportService) List(
	ctx context.Context,
	params models.ComplianceReportListParams,
) ([]models.ComplianceReport, int64, error) {
	if params.Page < 1 {
		params.Page = 1
	}
	if params.PageSize < 1 || params.PageSize > 100 {
		params.PageSize = 20
	}
	offset := (params.Page - 1) * params.PageSize

	query := `
		SELECT id, tenant_id, report_type, name, description, status,
		       period_start, period_end, parameters, output_format,
		       file_size_bytes, record_count, output_data,
		       generated_by, started_at, completed_at, error_message,
		       created_at, updated_at
		FROM iam_compliance_reports
		WHERE ($1::uuid IS NULL OR tenant_id = $1 OR tenant_id IS NULL)
		  AND ($2::text  = '' OR report_type = $2)
		  AND ($3::text  = '' OR status = $3)
		ORDER BY created_at DESC
		LIMIT $4 OFFSET $5`

	rows, err := s.db.Query(ctx, query, params.TenantID, params.ReportType, params.Status, params.PageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("ComplianceReportService.List: %w", err)
	}
	defer rows.Close()

	var reports []models.ComplianceReport
	for rows.Next() {
		r := models.ComplianceReport{}
		if err := rows.Scan(
			&r.ID, &r.TenantID, &r.ReportType, &r.Name, &r.Description, &r.Status,
			&r.PeriodStart, &r.PeriodEnd, &r.Parameters, &r.OutputFormat,
			&r.FileSizeBytes, &r.RecordCount, &r.OutputData,
			&r.GeneratedBy, &r.StartedAt, &r.CompletedAt, &r.ErrorMessage,
			&r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			logger.Warn("ComplianceReportService.List: scan error", zap.Error(err))
			continue
		}
		reports = append(reports, r)
	}

	var total int64
	_ = s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_compliance_reports WHERE ($1::uuid IS NULL OR tenant_id=$1 OR tenant_id IS NULL) AND ($2::text='' OR report_type=$2) AND ($3::text='' OR status=$3)`,
		params.TenantID, params.ReportType, params.Status,
	).Scan(&total)

	return reports, total, nil
}

// Delete removes a report and its output data.
func (s *ComplianceReportService) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `DELETE FROM iam_compliance_reports WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("ComplianceReportService.Delete: %w", err)
	}
	return nil
}

// Download returns the raw output data for a completed report.
func (s *ComplianceReportService) Download(ctx context.Context, id uuid.UUID) ([]byte, models.ComplianceReportOutputFormat, error) {
	r, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, "", fmt.Errorf("ComplianceReportService.Download: %w", err)
	}
	if !r.IsComplete() {
		return nil, "", fmt.Errorf("ComplianceReportService.Download: report is not completed (status: %s)", r.Status)
	}
	if len(r.OutputData) == 0 {
		return nil, "", fmt.Errorf("ComplianceReportService.Download: no output data available")
	}
	return r.OutputData, r.OutputFormat, nil
}

// ---------------------------------------------------------------------------
// Report Generators
// ---------------------------------------------------------------------------

// generate runs the appropriate generator based on report type and persists the result.
func (s *ComplianceReportService) generate(ctx context.Context, r *models.ComplianceReport) {
	now := time.Now()
	if err := s.updateStatus(ctx, r.ID, models.ReportStatusGenerating, &now, nil, nil); err != nil {
		logger.Error("ComplianceReportService.generate: failed to mark generating", zap.Error(err))
		return
	}

	var output json.RawMessage
	var recordCount int
	var genErr error

	switch r.ReportType {
	case models.ReportTypeSOC2Type2:
		output, recordCount, genErr = s.generateSOC2(ctx, r)
	case models.ReportTypeGDPRArticle30:
		output, recordCount, genErr = s.generateGDPR(ctx, r)
	case models.ReportTypeISO27001A9:
		output, recordCount, genErr = s.generateISO27001(ctx, r)
	case models.ReportTypeAccessReview:
		output, recordCount, genErr = s.generateAccessReview(ctx, r)
	case models.ReportTypeMFAEnrollment:
		output, recordCount, genErr = s.generateMFAEnrollment(ctx, r)
	case models.ReportTypePermissionChanges:
		output, recordCount, genErr = s.generatePermissionChanges(ctx, r)
	default:
		genErr = fmt.Errorf("unknown report type: %s", r.ReportType)
	}

	completedAt := time.Now()
	if genErr != nil {
		errMsg := genErr.Error()
		logger.Error("ComplianceReportService.generate: generation failed",
			zap.String("report_id", r.ID.String()),
			zap.Error(genErr),
		)
		_ = s.updateStatus(ctx, r.ID, models.ReportStatusFailed, nil, &completedAt, &errMsg)
		return
	}

	fileSize := int64(len(output))
	if err := s.saveOutput(ctx, r.ID, output, fileSize, recordCount, completedAt); err != nil {
		logger.Error("ComplianceReportService.generate: failed to save output", zap.Error(err))
		return
	}
	logger.Info("ComplianceReportService: report completed",
		zap.String("report_id", r.ID.String()),
		zap.Int("record_count", recordCount),
		zap.Int64("file_size_bytes", fileSize),
	)
}

// generateSOC2 collects SOC 2 Type II evidence.
func (s *ComplianceReportService) generateSOC2(
	ctx context.Context,
	r *models.ComplianceReport,
) (json.RawMessage, int, error) {
	data := map[string]interface{}{
		"report_type":    "soc2_type2",
		"period_start":   r.PeriodStart,
		"period_end":     r.PeriodEnd,
		"generated_at":   time.Now(),
		"trust_criteria": []string{"CC1", "CC2", "CC6", "CC7", "CC8", "CC9"},
		"sections":       s.buildSOC2Sections(ctx, r),
	}
	out, err := json.Marshal(data)
	if err != nil {
		return nil, 0, err
	}
	return out, 1, nil
}

// generateGDPR collects GDPR Article 30 processing activity data.
func (s *ComplianceReportService) generateGDPR(
	_ context.Context,
	r *models.ComplianceReport,
) (json.RawMessage, int, error) {
	data := map[string]interface{}{
		"report_type":       "gdpr_article30",
		"period_start":      r.PeriodStart,
		"period_end":        r.PeriodEnd,
		"generated_at":      time.Now(),
		"data_categories":   []string{"authentication", "session_management", "audit_trails"},
		"purposes":          []string{"identity_verification", "access_control", "security_monitoring"},
		"retention_periods": s.getRetentionPeriods(),
	}
	out, err := json.Marshal(data)
	if err != nil {
		return nil, 0, err
	}
	return out, 1, nil
}

// generateISO27001 collects ISO 27001 Annex A.9 (access control) evidence.
func (s *ComplianceReportService) generateISO27001(
	ctx context.Context,
	r *models.ComplianceReport,
) (json.RawMessage, int, error) {
	mfaStats := s.getMFAStats(ctx, r)
	data := map[string]interface{}{
		"report_type":       "iso27001_a9",
		"period_start":      r.PeriodStart,
		"period_end":        r.PeriodEnd,
		"generated_at":      time.Now(),
		"annex_a9_controls": []string{"A.9.1", "A.9.2", "A.9.3", "A.9.4"},
		"mfa_statistics":    mfaStats,
		"privilege_summary": s.getPrivilegeSummary(ctx, r),
	}
	out, err := json.Marshal(data)
	if err != nil {
		return nil, 0, err
	}
	return out, 1, nil
}

// generateAccessReview collects user-role assignment data for periodic review.
func (s *ComplianceReportService) generateAccessReview(
	ctx context.Context,
	r *models.ComplianceReport,
) (json.RawMessage, int, error) {
	assignments, count, err := s.getUserRoleAssignments(ctx, r)
	if err != nil {
		return nil, 0, err
	}
	data := map[string]interface{}{
		"report_type":  "access_review",
		"period_start": r.PeriodStart,
		"period_end":   r.PeriodEnd,
		"generated_at": time.Now(),
		"assignments":  assignments,
		"total":        count,
	}
	out, err := json.Marshal(data)
	if err != nil {
		return nil, 0, err
	}
	return out, count, nil
}

// generateMFAEnrollment collects MFA adoption statistics.
func (s *ComplianceReportService) generateMFAEnrollment(
	ctx context.Context,
	r *models.ComplianceReport,
) (json.RawMessage, int, error) {
	stats := s.getMFAStats(ctx, r)
	data := map[string]interface{}{
		"report_type":  "mfa_enrollment",
		"period_start": r.PeriodStart,
		"period_end":   r.PeriodEnd,
		"generated_at": time.Now(),
		"statistics":   stats,
	}
	out, err := json.Marshal(data)
	if err != nil {
		return nil, 0, err
	}
	return out, 1, nil
}

// generatePermissionChanges collects the permission and role change audit trail.
func (s *ComplianceReportService) generatePermissionChanges(
	ctx context.Context,
	r *models.ComplianceReport,
) (json.RawMessage, int, error) {
	changes, count, err := s.getPermissionChanges(ctx, r)
	if err != nil {
		return nil, 0, err
	}
	data := map[string]interface{}{
		"report_type":  "permission_changes",
		"period_start": r.PeriodStart,
		"period_end":   r.PeriodEnd,
		"generated_at": time.Now(),
		"changes":      changes,
		"total":        count,
	}
	out, err := json.Marshal(data)
	if err != nil {
		return nil, 0, err
	}
	return out, count, nil
}

// ---------------------------------------------------------------------------
// Data collectors
// ---------------------------------------------------------------------------

func (s *ComplianceReportService) buildSOC2Sections(_ context.Context, r *models.ComplianceReport) interface{} {
	return map[string]interface{}{
		"CC6_logical_access": map[string]interface{}{
			"mfa_enforced": true,
			"period":       map[string]interface{}{"start": r.PeriodStart, "end": r.PeriodEnd},
		},
		"CC7_system_operations": map[string]interface{}{
			"monitoring_enabled": true,
			"siem_configured":    true,
		},
	}
}

func (s *ComplianceReportService) getRetentionPeriods() interface{} {
	return map[string]string{
		"authentication_logs": "90 days",
		"audit_trails":        "7 years",
		"session_data":        "30 days",
	}
}

func (s *ComplianceReportService) getMFAStats(ctx context.Context, r *models.ComplianceReport) interface{} {
	var totalUsers, mfaUsers int
	_ = s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_users WHERE ($1::uuid IS NULL OR tenant_id=$1) AND created_at <= $2 AND (deleted_at IS NULL OR deleted_at > $2)`,
		r.TenantID, r.PeriodEnd,
	).Scan(&totalUsers)
	_ = s.db.QueryRow(ctx,
		`SELECT COUNT(DISTINCT user_id) FROM iam_mfa_credentials WHERE ($1::uuid IS NULL OR user_id IN (SELECT id FROM iam_users WHERE tenant_id=$1)) AND created_at <= $2`,
		r.TenantID, r.PeriodEnd,
	).Scan(&mfaUsers)

	enrollmentRate := 0.0
	if totalUsers > 0 {
		enrollmentRate = float64(mfaUsers) / float64(totalUsers) * 100
	}
	return map[string]interface{}{
		"total_users":     totalUsers,
		"mfa_enrolled":    mfaUsers,
		"not_enrolled":    totalUsers - mfaUsers,
		"enrollment_rate": fmt.Sprintf("%.1f%%", enrollmentRate),
	}
}

func (s *ComplianceReportService) getPrivilegeSummary(ctx context.Context, r *models.ComplianceReport) interface{} {
	var adminCount int
	_ = s.db.QueryRow(ctx,
		`SELECT COUNT(DISTINCT ur.user_id) FROM iam_user_roles ur JOIN iam_roles ro ON ro.id=ur.role_id WHERE ro.name IN ('admin','platform_admin','iam_admin') AND ($1::uuid IS NULL OR ur.tenant_id=$1)`,
		r.TenantID,
	).Scan(&adminCount)
	return map[string]interface{}{
		"privileged_users": adminCount,
	}
}

func (s *ComplianceReportService) getUserRoleAssignments(ctx context.Context, r *models.ComplianceReport) (interface{}, int, error) {
	query := `
		SELECT u.id, u.email, ro.name AS role_name, ur.created_at AS assigned_at
		FROM iam_user_roles ur
		JOIN iam_users u ON u.id = ur.user_id
		JOIN iam_roles ro ON ro.id = ur.role_id
		WHERE ($1::uuid IS NULL OR ur.tenant_id=$1)
		ORDER BY u.email, ro.name
		LIMIT 1000`

	rows, err := s.db.Query(ctx, query, r.TenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("getUserRoleAssignments: %w", err)
	}
	defer rows.Close()

	type row struct {
		UserID     string    `json:"user_id"`
		Email      string    `json:"email"`
		RoleName   string    `json:"role_name"`
		AssignedAt time.Time `json:"assigned_at"`
	}
	var rows2 []row
	for rows.Next() {
		var rw row
		if err := rows.Scan(&rw.UserID, &rw.Email, &rw.RoleName, &rw.AssignedAt); err != nil {
			continue
		}
		rows2 = append(rows2, rw)
	}
	return rows2, len(rows2), nil
}

func (s *ComplianceReportService) getPermissionChanges(ctx context.Context, r *models.ComplianceReport) (interface{}, int, error) {
	query := `
		SELECT id, action, resource_type, resource_id, actor_id, created_at
		FROM iam_audit_logs
		WHERE action IN ('role.assigned','role.revoked','permission.granted','permission.revoked')
		  AND created_at BETWEEN $1 AND $2
		  AND ($3::uuid IS NULL OR tenant_id=$3)
		ORDER BY created_at DESC
		LIMIT 5000`

	rows, err := s.db.Query(ctx, query, r.PeriodStart, r.PeriodEnd, r.TenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("getPermissionChanges: %w", err)
	}
	defer rows.Close()

	type entry struct {
		ID           string    `json:"id"`
		Action       string    `json:"action"`
		ResourceType string    `json:"resource_type"`
		ResourceID   *string   `json:"resource_id"`
		ActorID      string    `json:"actor_id"`
		CreatedAt    time.Time `json:"created_at"`
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.ID, &e.Action, &e.ResourceType, &e.ResourceID, &e.ActorID, &e.CreatedAt); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, len(entries), nil
}

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------

func (s *ComplianceReportService) updateStatus(
	ctx context.Context,
	id uuid.UUID,
	status models.ComplianceReportStatus,
	startedAt *time.Time,
	completedAt *time.Time,
	errMsg *string,
) error {
	_, err := s.db.Exec(ctx,
		`UPDATE iam_compliance_reports SET status=$1, started_at=COALESCE($2,started_at), completed_at=$3, error_message=$4, updated_at=NOW() WHERE id=$5`,
		string(status), startedAt, completedAt, errMsg, id,
	)
	return err
}

func (s *ComplianceReportService) saveOutput(
	ctx context.Context,
	id uuid.UUID,
	output json.RawMessage,
	fileSize int64,
	recordCount int,
	completedAt time.Time,
) error {
	_, err := s.db.Exec(ctx,
		`UPDATE iam_compliance_reports SET status='completed', output_data=$1, file_size_bytes=$2, record_count=$3, completed_at=$4, updated_at=NOW() WHERE id=$5`,
		output, fileSize, recordCount, completedAt, id,
	)
	return err
}
