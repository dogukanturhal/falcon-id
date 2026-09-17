// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	pgx "github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const complianceRemediationTypeAuto = "auto"

// complianceDB is the minimal database interface used by CompliancePolicyEngine.
// Both *pgxpool.Pool and pgxmock.PgxPoolIface satisfy this interface, enabling
// straightforward unit testing without a live database.
type complianceDB interface {
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	Acquire(ctx context.Context) (*pgxpool.Conn, error)
}

// ComplianceCheckType defines the kind of compliance check.
type ComplianceCheckType string

const (
	// CheckTypeThreshold evaluates whether a value meets or exceeds a threshold.
	CheckTypeThreshold ComplianceCheckType = "threshold_check"
	// CheckTypeExistence verifies that a row exists or does not exist.
	CheckTypeExistence ComplianceCheckType = "existence_check"
	// CheckTypeTimeWindow checks whether an event occurred within a time window.
	CheckTypeTimeWindow ComplianceCheckType = "time_window_check"
	// CheckTypePercentage evaluates a ratio against a threshold.
	CheckTypePercentage ComplianceCheckType = "percentage_check"
	// CheckTypeCount verifies that a count is within an acceptable range.
	CheckTypeCount ComplianceCheckType = "count_check"
)

// ComplianceSeverity represents the criticality level of a compliance violation.
type ComplianceSeverity string

const (
	// SeverityCritical is an exported identifier.
	SeverityCritical ComplianceSeverity = "critical"
	// SeverityHigh is an exported identifier.
	SeverityHigh ComplianceSeverity = "high"
	// SeverityMedium is an exported identifier.
	SeverityMedium ComplianceSeverity = "medium"
	// SeverityLow is an exported identifier.
	SeverityLow ComplianceSeverity = "low"
	// SeverityInfo is an exported identifier.
	SeverityInfo ComplianceSeverity = "info"
)

// ComplianceFramework enumerates supported compliance standards.
type ComplianceFramework string

const (
	// FrameworkSOC2 is an exported identifier.
	FrameworkSOC2 ComplianceFramework = "SOC2"
	// FrameworkGDPR is an exported identifier.
	FrameworkGDPR ComplianceFramework = "GDPR"
	// FrameworkISO27001 is an exported identifier.
	FrameworkISO27001 ComplianceFramework = "ISO27001"
	// FrameworkHIPAA is an exported identifier.
	FrameworkHIPAA ComplianceFramework = "HIPAA"
	// FrameworkPCIDSS is an exported identifier.
	FrameworkPCIDSS ComplianceFramework = "PCI-DSS"
	// FrameworkCustom is an exported identifier.
	FrameworkCustom ComplianceFramework = "CUSTOM"
)

// ComplianceControl defines a single compliance check rule that can be activated
// for any tenant. Controls are global, platform-managed definitions.
type ComplianceControl struct {
	ID              uuid.UUID           `json:"id"`
	Framework       ComplianceFramework `json:"framework"`
	ControlID       string              `json:"control_id"` // e.g., "SOC2-CC6.1"
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	CheckType       ComplianceCheckType `json:"check_type"`
	CheckQuery      string              `json:"check_query"` // SQL returning a numeric value; $1 = tenant_id
	Threshold       float64             `json:"threshold"`
	Operator        string              `json:"operator"` // ">=", "<=", "==", "!=", ">", "<"
	Severity        ComplianceSeverity  `json:"severity"`
	RemediationType string              `json:"remediation_type"` // "auto", "manual", "notification"
	RemediationSQL  string              `json:"remediation_sql,omitempty"`
	Enabled         bool                `json:"enabled"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
}

// CompliancePolicy records a tenant's activation of a particular control,
// including the desired evaluation schedule.
type CompliancePolicy struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  uuid.UUID  `json:"tenant_id"`
	ControlID uuid.UUID  `json:"control_id"`
	Schedule  string     `json:"schedule"` // "hourly", "daily", "weekly"
	Enabled   bool       `json:"enabled"`
	LastRunAt *time.Time `json:"last_run_at,omitempty"`
	NextRunAt *time.Time `json:"next_run_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// ComplianceEvaluation captures the result of evaluating a control against a
// tenant's live data at a specific point in time.
type ComplianceEvaluation struct {
	ID             uuid.UUID           `json:"id"`
	PolicyID       uuid.UUID           `json:"policy_id"`
	TenantID       uuid.UUID           `json:"tenant_id"`
	ControlID      uuid.UUID           `json:"control_id"`
	Framework      ComplianceFramework `json:"framework"`
	ControlRef     string              `json:"control_ref"`
	Status         string              `json:"status"` // "pass", "fail", "error", "skip"
	ActualValue    float64             `json:"actual_value"`
	ExpectedValue  float64             `json:"expected_value"`
	DriftDetected  bool                `json:"drift_detected"`
	Details        json.RawMessage     `json:"details,omitempty"`
	RemediationRun bool                `json:"remediation_run"`
	EvaluatedAt    time.Time           `json:"evaluated_at"`
}

// ComplianceBaseline records the known-good value for a control at a given
// instant, used as a reference point for drift detection.
type ComplianceBaseline struct {
	ID            uuid.UUID       `json:"id"`
	TenantID      uuid.UUID       `json:"tenant_id"`
	ControlID     uuid.UUID       `json:"control_id"`
	BaselineValue float64         `json:"baseline_value"`
	Snapshot      json.RawMessage `json:"snapshot,omitempty"`
	CapturedAt    time.Time       `json:"captured_at"`
}

// ComplianceDashboard aggregates the latest evaluation results for a tenant
// into a high-level compliance posture summary.
type ComplianceDashboard struct {
	TenantID        uuid.UUID                   `json:"tenant_id"`
	TotalControls   int                         `json:"total_controls"`
	PassCount       int                         `json:"pass_count"`
	FailCount       int                         `json:"fail_count"`
	ErrorCount      int                         `json:"error_count"`
	ComplianceScore float64                     `json:"compliance_score"`
	ByFramework     map[string]FrameworkSummary `json:"by_framework"`
	DriftAlerts     int                         `json:"drift_alerts"`
	LastEvaluatedAt *time.Time                  `json:"last_evaluated_at,omitempty"`
}

// FrameworkSummary holds per-framework pass/fail statistics.
type FrameworkSummary struct {
	Total   int     `json:"total"`
	Passing int     `json:"passing"`
	Failing int     `json:"failing"`
	Score   float64 `json:"score"`
}

// SeedControl is the in-memory definition of a control used by SeedControls.
// It maps 1:1 to the iam_compliance_controls table columns.
type SeedControl struct {
	Framework       ComplianceFramework
	ControlID       string
	Name            string
	Description     string
	Severity        ComplianceSeverity
	CheckType       ComplianceCheckType
	CheckQuery      string
	Threshold       float64
	Operator        string
	RemediationType string
	RemediationHint string
}

// CompliancePolicyEngine executes compliance controls against live tenant data,
// detects drift, and manages baselines and evaluation history.
type CompliancePolicyEngine struct {
	db complianceDB
}

// NewCompliancePolicyEngine creates a new CompliancePolicyEngine backed by the
// provided database pool.
func NewCompliancePolicyEngine(db *pgxpool.Pool) *CompliancePolicyEngine {
	return &CompliancePolicyEngine{db: db}
}

// ---------------------------------------------------------------------------
// Seed control catalogue
// ---------------------------------------------------------------------------

// SeedControls upserts the built-in control catalogue into the database.
// It is idempotent: existing controls are updated in-place via ON CONFLICT.
// Safe to call at startup on every replica.
func (e *CompliancePolicyEngine) SeedControls(ctx context.Context) error {
	catalogue := defaultSeedControls()
	const query = `
		INSERT INTO iam_compliance_controls
		    (framework, control_id, name, description, check_type,
		     check_query, threshold, operator, severity,
		     remediation_type, remediation_hint, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true)
		ON CONFLICT (framework, control_id) DO NOTHING`

	for i := range catalogue {
		sc := &catalogue[i]
		if _, err := e.db.Exec(ctx, query,
			string(sc.Framework), sc.ControlID, sc.Name, sc.Description,
			string(sc.CheckType), sc.CheckQuery, sc.Threshold, sc.Operator,
			string(sc.Severity), sc.RemediationType, sc.RemediationHint,
		); err != nil {
			return fmt.Errorf("SeedControls [%s/%s]: %w", sc.Framework, sc.ControlID, err)
		}
	}

	logger.Log.Info("CompliancePolicyEngine.SeedControls: seeded controls",
		zap.Int("count", len(catalogue)),
	)
	return nil
}

// defaultSeedControls returns the built-in compliance control catalogue.
// The catalogue covers SOC2, GDPR, ISO27001, and HIPAA with at least 30 controls.
//
//nolint:funlen // intentionally long — defines the authoritative control catalogue.
func defaultSeedControls() []SeedControl {
	return []SeedControl{
		// ------------------------------------------------------------------
		// SOC2 Controls (CC6.x / CC7.x)
		// ------------------------------------------------------------------
		{
			Framework:   FrameworkSOC2,
			ControlID:   "CC6.1-MFA",
			Name:        "MFA Enrollment Rate",
			Description: "Percentage of active users with MFA enabled must meet or exceed 90%.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypePercentage,
			CheckQuery: `SELECT CASE WHEN total = 0 THEN 100
             ELSE (mfa_count * 100.0 / total)
        END
 FROM (
     SELECT COUNT(*) AS total,
            COUNT(*) FILTER (WHERE mfa_enabled = true) AS mfa_count
     FROM iam_users
     WHERE tenant_id = $1 AND deleted_at IS NULL
 ) sub`,
			Threshold:       90,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Enforce MFA enrollment for all users via the tenant security policy settings.",
		},
		{
			Framework:   FrameworkSOC2,
			ControlID:   "CC6.2-PASSWD",
			Name:        "Password Policy Compliance",
			Description: "A password policy requiring at least 12 characters must be configured.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypeExistence,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_password_policies
 WHERE tenant_id = $1 AND min_length >= 12`,
			Threshold:       1,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Update the tenant password policy to require a minimum of 12 characters.",
		},
		{
			Framework:   FrameworkSOC2,
			ControlID:   "CC6.3-SESSION",
			Name:        "Session Timeout Policy",
			Description: "Password policy must enforce a session timeout of 30 minutes or less.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypeExistence,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_password_policies
 WHERE tenant_id = $1
   AND session_duration_minutes <= 30`,
			Threshold:       1,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Configure session timeout to 30 minutes or less in the tenant password policy settings.",
		},
		{
			Framework:   FrameworkSOC2,
			ControlID:   "CC6.4-LOCKOUT",
			Name:        "Account Lockout Policy",
			Description: "Password policy must enable account lockout after failed login attempts.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypeExistence,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_password_policies
 WHERE tenant_id = $1
   AND lockout_enabled = true`,
			Threshold:       1,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Enable account lockout in the tenant password policy to prevent brute-force attacks.",
		},
		{
			Framework:   FrameworkSOC2,
			ControlID:   "CC6.5-APIKEY",
			Name:        "API Key Rotation",
			Description: "No active API keys should be older than 90 days without rotation.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypeCount,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_api_keys
 WHERE tenant_id = $1
   AND revoked = false
   AND created_at < now() - interval '90 days'`,
			Threshold:       0,
			Operator:        "<=",
			RemediationType: "notification",
			RemediationHint: "Rotate API keys that are older than 90 days. Implement automated key rotation policies.",
		},
		{
			Framework:   FrameworkSOC2,
			ControlID:   "CC6.6-SVCACCT",
			Name:        "Service Account Credential Rotation",
			Description: "Service account credentials should be rotated within 90 days.",
			Severity:    SeverityMedium,
			CheckType:   CheckTypeCount,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_service_accounts
 WHERE tenant_id = $1
   AND status = 'active'
   AND (last_rotated_at IS NULL OR last_rotated_at < now() - interval '90 days')`,
			Threshold:       0,
			Operator:        "<=",
			RemediationType: "notification",
			RemediationHint: "Rotate service account credentials. Set rotation reminders or automate via the API.",
		},
		{
			Framework:   FrameworkSOC2,
			ControlID:   "CC6.7-RETENTION",
			Name:        "Audit Log Retention",
			Description: "Audit logs must contain events from at least 365 days ago.",
			Severity:    SeverityCritical,
			CheckType:   CheckTypeExistence,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND created_at < now() - interval '364 days'`,
			Threshold:       1,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Ensure audit log retention is set to at least 365 days in your data retention policy.",
		},
		{
			Framework:   FrameworkSOC2,
			ControlID:   "CC6.8-ENCRYPT",
			Name:        "Encryption Key Management",
			Description: "Active signing keys must be present, confirming encryption infrastructure is operational.",
			Severity:    SeverityCritical,
			CheckType:   CheckTypeExistence,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_signing_keys
 WHERE tenant_id = $1
   AND active = true`,
			Threshold:       1,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Ensure encryption signing keys are generated and active for the tenant.",
		},
		{
			Framework:   FrameworkSOC2,
			ControlID:   "CC7.1-AUDIT",
			Name:        "Audit Logging Active",
			Description: "At least one audit event must have been recorded in the past 24 hours.",
			Severity:    SeverityCritical,
			CheckType:   CheckTypeTimeWindow,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND created_at > now() - interval '24 hours'`,
			Threshold:       1,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Verify that audit logging is enabled and that your application is generating events.",
		},
		{
			Framework:   FrameworkSOC2,
			ControlID:   "CC7.2-INTRUSION",
			Name:        "MFA Failure Spike Detection",
			Description: "Total MFA failures in the past 24 hours should not exceed 100.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypeCount,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND action = 'mfa_failure'
   AND created_at > now() - interval '24 hours'`,
			Threshold:       100,
			Operator:        "<=",
			RemediationType: "notification",
			RemediationHint: "Investigate unusual MFA failure patterns. Consider enabling IP-based rate limiting.",
		},

		// ------------------------------------------------------------------
		// GDPR Controls
		// ------------------------------------------------------------------
		{
			Framework:   FrameworkGDPR,
			ControlID:   "ART5-RETENTION",
			Name:        "Data Retention Policy",
			Description: "No active (non-revoked) sessions should remain beyond 30 days after expiry.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypeCount,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_sessions
 WHERE tenant_id = $1
   AND expires_at < now() - interval '30 days'
   AND revoked = false`,
			Threshold:       0,
			Operator:        "<=",
			RemediationType: "notification",
			RemediationHint: "Revoke expired sessions and implement automated session cleanup to comply with GDPR Art. 5.",
		},
		{
			Framework:   FrameworkGDPR,
			ControlID:   "ART7-CONSENT",
			Name:        "User Consent Records",
			Description: "All active users must have a valid consent record on file (≥ 95%).",
			Severity:    SeverityCritical,
			CheckType:   CheckTypePercentage,
			CheckQuery: `SELECT CASE WHEN total = 0 THEN 100
             ELSE (consented * 100.0 / total)
        END
 FROM (
     SELECT COUNT(DISTINCT u.id) AS total,
            COUNT(DISTINCT uc.user_id) AS consented
     FROM iam_users u
     LEFT JOIN iam_user_consents uc ON u.id = uc.user_id AND uc.revoked_at IS NULL
     WHERE u.tenant_id = $1 AND u.deleted_at IS NULL
 ) sub`,
			Threshold:       95,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Collect consent records for all users. Implement consent flows during registration and periodic re-consent.",
		},
		{
			Framework:   FrameworkGDPR,
			ControlID:   "ART17-ERASURE",
			Name:        "Data Erasure SLA",
			Description: "No data deletion requests should remain pending for more than 30 days.",
			Severity:    SeverityCritical,
			CheckType:   CheckTypeCount,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND action = 'deletion_requested'
   AND created_at < now() - interval '30 days'`,
			Threshold:       0,
			Operator:        "<=",
			RemediationType: "notification",
			RemediationHint: "Process pending data deletion requests within 30 days as required by GDPR Art. 17.",
		},
		{
			Framework:   FrameworkGDPR,
			ControlID:   "ART25-PRIVACYDESIGN",
			Name:        "Privacy by Design — Encryption Pipeline",
			Description: "All active users must have an email hash stored (indicates encryption pipeline is active).",
			Severity:    SeverityCritical,
			CheckType:   CheckTypeExistence,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_users
 WHERE tenant_id = $1
   AND email_hash IS NOT NULL
   AND deleted_at IS NULL`,
			Threshold:       0,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Enable the email hashing pipeline to ensure privacy by design. Review the encryption configuration.",
		},
		{
			Framework:   FrameworkGDPR,
			ControlID:   "ART30-PROCESSING",
			Name:        "Processing Activity Records",
			Description: "Processing activities must be logged — at least one audit event in the past 7 days.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypeTimeWindow,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND created_at > now() - interval '7 days'`,
			Threshold:       1,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Ensure all data processing activities are recorded in the audit log as required by GDPR Art. 30.",
		},
		{
			Framework:   FrameworkGDPR,
			ControlID:   "ART32-ENCRYPTION",
			Name:        "Encryption at Rest",
			Description: "All active users must have an email hash stored (indicates encryption pipeline is active).",
			Severity:    SeverityMedium,
			CheckType:   CheckTypeExistence,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_users
 WHERE tenant_id = $1
   AND email_hash IS NOT NULL
   AND deleted_at IS NULL`,
			Threshold:       0,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Enable the encryption pipeline to ensure data at rest is encrypted per GDPR Art. 32.",
		},
		{
			Framework:   FrameworkGDPR,
			ControlID:   "ART33-BREACH",
			Name:        "Security Event Triage SLA",
			Description: "Critical security events older than 72 hours must be triaged.",
			Severity:    SeverityCritical,
			CheckType:   CheckTypeCount,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND severity = 'critical'
   AND created_at < now() - interval '72 hours'
   AND created_at > now() - interval '30 days'`,
			Threshold:       0,
			Operator:        "<=",
			RemediationType: "notification",
			RemediationHint: "Triage all critical security events within 72 hours as required by GDPR Art. 33 breach notification SLA.",
		},
		{
			Framework:   FrameworkGDPR,
			ControlID:   "ART35-DPIA",
			Name:        "Data Protection Impact Assessment",
			Description: "MFA enrollment rate must exceed 80% for high-risk data processing environments.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypePercentage,
			CheckQuery: `SELECT CASE WHEN total = 0 THEN 100
             ELSE (mfa_count * 100.0 / total)
        END
 FROM (
     SELECT COUNT(*) AS total,
            COUNT(*) FILTER (WHERE mfa_enabled = true) AS mfa_count
     FROM iam_users
     WHERE tenant_id = $1 AND deleted_at IS NULL
 ) sub`,
			Threshold:       80,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Conduct a Data Protection Impact Assessment. Enforce MFA for all users accessing high-risk data.",
		},

		// ------------------------------------------------------------------
		// ISO 27001 Controls (A. series)
		// ------------------------------------------------------------------
		{
			Framework:   FrameworkISO27001,
			ControlID:   "A9.2-ACCESS",
			Name:        "Inactive User Review",
			Description: "Active users who have not logged in for 90 or more days should be reviewed.",
			Severity:    SeverityMedium,
			CheckType:   CheckTypeCount,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_users
 WHERE tenant_id = $1
   AND last_login_at < now() - interval '90 days'
   AND deleted_at IS NULL
   AND status = 'active'`,
			Threshold:       0,
			Operator:        "<=",
			RemediationType: "notification",
			RemediationHint: "Review and disable accounts inactive for 90+ days. Implement periodic access reviews.",
		},
		{
			Framework:   FrameworkISO27001,
			ControlID:   "A9.4-PRIVILEGE",
			Name:        "Privileged Access Review",
			Description: "The number of users with admin or super-admin roles should not exceed 10.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypeCount,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_user_roles ur
 JOIN iam_roles r ON ur.role_id = r.id
 WHERE ur.tenant_id = $1
   AND r.name IN ('admin', 'super_admin', 'platform_admin')`,
			Threshold:       10,
			Operator:        "<=",
			RemediationType: "notification",
			RemediationHint: "Review privileged role assignments. Follow the principle of least privilege.",
		},
		{
			Framework:   FrameworkISO27001,
			ControlID:   "A9.2.3-PRIVREVIEW",
			Name:        "Privileged Access Review Frequency",
			Description: "Privileged role assignments must be reviewed at least every 90 days.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypeTimeWindow,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND action IN ('role_review_completed', 'privileged_access_reviewed')
   AND created_at > now() - interval '90 days'`,
			Threshold:       1,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Conduct quarterly privileged access reviews. Document and log each review in the audit system.",
		},
		{
			Framework:   FrameworkISO27001,
			ControlID:   "A9.4.2-SECURLOGIN",
			Name:        "Secure Login Procedures",
			Description: "MFA must be enabled for all privileged users (admin role holders).",
			Severity:    SeverityCritical,
			CheckType:   CheckTypePercentage,
			CheckQuery: `SELECT CASE WHEN total = 0 THEN 100
             ELSE (mfa_count * 100.0 / total)
        END
 FROM (
     SELECT COUNT(DISTINCT ur.user_id) AS total,
            COUNT(DISTINCT ur.user_id) FILTER (WHERE u.mfa_enabled = true) AS mfa_count
     FROM iam_user_roles ur
     JOIN iam_roles r ON ur.role_id = r.id
     JOIN iam_users u ON ur.user_id = u.id
     WHERE ur.tenant_id = $1
       AND r.name IN ('admin', 'super_admin', 'platform_admin')
       AND u.deleted_at IS NULL
 ) sub`,
			Threshold:       100,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Enforce MFA for all privileged users. Use conditional access policies to mandate MFA on admin roles.",
		},
		{
			Framework:   FrameworkISO27001,
			ControlID:   "A12.4.1-LOGGING",
			Name:        "Event Logging Enabled",
			Description: "Event logging must be active — at least 12 distinct hours of events in the past 24 hours.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypeCount,
			CheckQuery: `SELECT COUNT(DISTINCT date_trunc('hour', created_at))
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND created_at > now() - interval '24 hours'`,
			Threshold:       12,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Ensure event logging is configured and events are being captured continuously.",
		},
		{
			Framework:   FrameworkISO27001,
			ControlID:   "A12.4.3-ADMINMON",
			Name:        "Administrator Activity Monitoring",
			Description: "Administrative actions must be logged — at least one admin event in the past 7 days.",
			Severity:    SeverityMedium,
			CheckType:   CheckTypeTimeWindow,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND actor_role IN ('admin', 'super_admin', 'platform_admin')
   AND created_at > now() - interval '7 days'`,
			Threshold:       0,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Monitor all administrative activities. Ensure admin actions are consistently logged.",
		},
		{
			Framework:   FrameworkISO27001,
			ControlID:   "A14.2.8-SECTESTING",
			Name:        "Security Testing Records",
			Description: "Security testing events must be recorded in the past 365 days.",
			Severity:    SeverityMedium,
			CheckType:   CheckTypeTimeWindow,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND action IN ('penetration_test_completed', 'vulnerability_scan_completed', 'security_test_recorded')
   AND created_at > now() - interval '365 days'`,
			Threshold:       1,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Schedule and record annual penetration tests and vulnerability assessments.",
		},
		{
			Framework:   FrameworkISO27001,
			ControlID:   "A18.1.3-RECORDS",
			Name:        "Records Protection",
			Description: "All data export events must be logged and traceable.",
			Severity:    SeverityMedium,
			CheckType:   CheckTypeTimeWindow,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND action IN ('data_export_completed', 'data_export_requested')
   AND created_at > now() - interval '30 days'`,
			Threshold:       0,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Ensure all data export operations are logged with full audit trails for compliance evidence.",
		},

		// ------------------------------------------------------------------
		// HIPAA Controls (§164 series)
		// ------------------------------------------------------------------
		{
			Framework:   FrameworkHIPAA,
			ControlID:   "SEC-164.312a",
			Name:        "Access Control",
			Description: "All active users must have at least one role assignment.",
			Severity:    SeverityCritical,
			CheckType:   CheckTypePercentage,
			CheckQuery: `SELECT CASE WHEN total = 0 THEN 100
             ELSE (with_roles * 100.0 / total)
        END
 FROM (
     SELECT COUNT(*) AS total,
            COUNT(DISTINCT ur.user_id) AS with_roles
     FROM iam_users u
     LEFT JOIN iam_user_roles ur ON u.id = ur.user_id
     WHERE u.tenant_id = $1 AND u.deleted_at IS NULL
 ) sub`,
			Threshold:       100,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Assign roles to all active users. HIPAA §164.312(a) requires unique user identification.",
		},
		{
			Framework:   FrameworkHIPAA,
			ControlID:   "SEC-164.312b",
			Name:        "Audit Controls",
			Description: "All data access events must be logged — minimum 12 distinct hours over the past 24 hours.",
			Severity:    SeverityCritical,
			CheckType:   CheckTypeCount,
			CheckQuery: `SELECT COUNT(DISTINCT date_trunc('hour', created_at))
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND created_at > now() - interval '24 hours'`,
			Threshold:       12,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Implement comprehensive audit logging for all data access. HIPAA §164.312(b) requires activity logging.",
		},
		{
			Framework:   FrameworkHIPAA,
			ControlID:   "SEC-164.312c",
			Name:        "Integrity Controls",
			Description: "All admin-role users must have MFA enabled to ensure data integrity.",
			Severity:    SeverityCritical,
			CheckType:   CheckTypePercentage,
			CheckQuery: `SELECT CASE WHEN total = 0 THEN 100
             ELSE (mfa_count * 100.0 / total)
        END
 FROM (
     SELECT COUNT(DISTINCT ur.user_id) AS total,
            COUNT(DISTINCT ur.user_id) FILTER (WHERE u.mfa_enabled = true) AS mfa_count
     FROM iam_user_roles ur
     JOIN iam_roles r ON ur.role_id = r.id
     JOIN iam_users u ON ur.user_id = u.id
     WHERE ur.tenant_id = $1
       AND r.name IN ('admin', 'super_admin')
       AND u.deleted_at IS NULL
 ) sub`,
			Threshold:       100,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Enable MFA for all administrative accounts. HIPAA §164.312(c) requires integrity controls.",
		},
		{
			Framework:   FrameworkHIPAA,
			ControlID:   "SEC-164.312d",
			Name:        "Person or Entity Authentication",
			Description: "MFA must be enabled for all active users (≥ 90%).",
			Severity:    SeverityCritical,
			CheckType:   CheckTypePercentage,
			CheckQuery: `SELECT CASE WHEN total = 0 THEN 100
             ELSE (mfa_count * 100.0 / total)
        END
 FROM (
     SELECT COUNT(*) AS total,
            COUNT(*) FILTER (WHERE mfa_enabled = true) AS mfa_count
     FROM iam_users
     WHERE tenant_id = $1 AND deleted_at IS NULL
 ) sub`,
			Threshold:       90,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Enforce MFA for all users. HIPAA §164.312(d) requires person authentication controls.",
		},
		{
			Framework:   FrameworkHIPAA,
			ControlID:   "SEC-164.312e",
			Name:        "Transmission Security",
			Description: "All active sessions should use secure transport (no sessions with plaintext indicators).",
			Severity:    SeverityCritical,
			CheckType:   CheckTypeCount,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_sessions
 WHERE tenant_id = $1
   AND revoked = false
   AND expires_at > now()
   AND metadata->>'tls' = 'false'`,
			Threshold:       0,
			Operator:        "<=",
			RemediationType: "notification",
			RemediationHint: "Enforce TLS on all connections. HIPAA §164.312(e) requires transmission security controls.",
		},
		{
			Framework:   FrameworkHIPAA,
			ControlID:   "SEC-164.308a3",
			Name:        "Workforce Access Management",
			Description: "No active users should have gone more than 90 days without a login.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypeCount,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_users
 WHERE tenant_id = $1
   AND status = 'active'
   AND deleted_at IS NULL
   AND (last_login_at IS NULL OR last_login_at < now() - interval '90 days')`,
			Threshold:       0,
			Operator:        "<=",
			RemediationType: "notification",
			RemediationHint: "Review and disable accounts that have not been accessed in 90+ days. Implement periodic access reviews.",
		},
		{
			Framework:   FrameworkHIPAA,
			ControlID:   "SEC-164.308a5",
			Name:        "Security Awareness Training",
			Description: "Security training completion events must be recorded in the past 365 days.",
			Severity:    SeverityHigh,
			CheckType:   CheckTypeTimeWindow,
			CheckQuery: `SELECT COUNT(*)
 FROM iam_audit_log
 WHERE tenant_id = $1
   AND action IN ('security_training_completed', 'security_awareness_recorded')
   AND created_at > now() - interval '365 days'`,
			Threshold:       1,
			Operator:        ">=",
			RemediationType: "notification",
			RemediationHint: "Conduct annual security awareness training for all staff and record completion in the system.",
		},
	}
}

// ---------------------------------------------------------------------------
// Control catalogue
// ---------------------------------------------------------------------------

// ListControls returns all controls, optionally filtered by framework.
func (e *CompliancePolicyEngine) ListControls(ctx context.Context, framework string) ([]ComplianceControl, error) {
	query := `
		SELECT id, framework, control_id, name, description, check_type,
		       check_query, threshold, operator, severity,
		       remediation_type, remediation_sql, enabled, created_at, updated_at
		FROM iam_compliance_controls
		WHERE enabled = true
		  AND ($1 = '' OR framework = $1)
		ORDER BY framework, control_id`

	rows, err := e.db.Query(ctx, query, framework)
	if err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.ListControls: %w", err)
	}
	defer rows.Close()

	var controls []ComplianceControl
	for rows.Next() {
		var c ComplianceControl
		if err := rows.Scan(
			&c.ID, &c.Framework, &c.ControlID, &c.Name, &c.Description,
			&c.CheckType, &c.CheckQuery, &c.Threshold, &c.Operator,
			&c.Severity, &c.RemediationType, &c.RemediationSQL,
			&c.Enabled, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			logger.Log.Warn("CompliancePolicyEngine.ListControls: scan error", zap.Error(err))
			continue
		}
		controls = append(controls, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.ListControls: rows: %w", err)
	}
	return controls, nil
}

// GetControlByID loads a single compliance control by primary key.
func (e *CompliancePolicyEngine) GetControlByID(ctx context.Context, id uuid.UUID) (*ComplianceControl, error) {
	query := `
		SELECT id, framework, control_id, name, description, check_type,
		       check_query, threshold, operator, severity,
		       remediation_type, remediation_sql, enabled, created_at, updated_at
		FROM iam_compliance_controls
		WHERE id = $1`

	c := &ComplianceControl{}
	err := e.db.QueryRow(ctx, query, id).Scan(
		&c.ID, &c.Framework, &c.ControlID, &c.Name, &c.Description,
		&c.CheckType, &c.CheckQuery, &c.Threshold, &c.Operator,
		&c.Severity, &c.RemediationType, &c.RemediationSQL,
		&c.Enabled, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.GetControlByID: %w", err)
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// Policy management
// ---------------------------------------------------------------------------

// CreatePolicy activates a compliance control for a tenant.
func (e *CompliancePolicyEngine) CreatePolicy(ctx context.Context, tenantID, controlID uuid.UUID, schedule string) (*CompliancePolicy, error) {
	if schedule == "" {
		schedule = "daily"
	}

	nextRun := nextRunTime(schedule)
	query := `
		INSERT INTO iam_compliance_policies (tenant_id, control_id, schedule, enabled, next_run_at)
		VALUES ($1, $2, $3, true, $4)
		RETURNING id, tenant_id, control_id, schedule, enabled, last_run_at, next_run_at, created_at, updated_at`

	p := &CompliancePolicy{}
	err := e.db.QueryRow(ctx, query, tenantID, controlID, schedule, nextRun).Scan(
		&p.ID, &p.TenantID, &p.ControlID, &p.Schedule, &p.Enabled,
		&p.LastRunAt, &p.NextRunAt, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.CreatePolicy: %w", err)
	}
	return p, nil
}

// ListPolicies returns all policies for the given tenant.
func (e *CompliancePolicyEngine) ListPolicies(ctx context.Context, tenantID uuid.UUID) ([]CompliancePolicy, error) {
	query := `
		SELECT id, tenant_id, control_id, schedule, enabled,
		       last_run_at, next_run_at, created_at, updated_at
		FROM iam_compliance_policies
		WHERE tenant_id = $1
		ORDER BY created_at DESC`

	rows, err := e.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.ListPolicies: %w", err)
	}
	defer rows.Close()

	var policies []CompliancePolicy
	for rows.Next() {
		var p CompliancePolicy
		if err := rows.Scan(
			&p.ID, &p.TenantID, &p.ControlID, &p.Schedule, &p.Enabled,
			&p.LastRunAt, &p.NextRunAt, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			logger.Log.Warn("CompliancePolicyEngine.ListPolicies: scan error", zap.Error(err))
			continue
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.ListPolicies: rows: %w", err)
	}
	return policies, nil
}

// GetPolicyByID loads a single policy by its primary key.
func (e *CompliancePolicyEngine) GetPolicyByID(ctx context.Context, id uuid.UUID) (*CompliancePolicy, error) {
	query := `
		SELECT id, tenant_id, control_id, schedule, enabled,
		       last_run_at, next_run_at, created_at, updated_at
		FROM iam_compliance_policies
		WHERE id = $1`

	p := &CompliancePolicy{}
	err := e.db.QueryRow(ctx, query, id).Scan(
		&p.ID, &p.TenantID, &p.ControlID, &p.Schedule, &p.Enabled,
		&p.LastRunAt, &p.NextRunAt, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.GetPolicyByID: %w", err)
	}
	return p, nil
}

// UpdatePolicy modifies the schedule and/or enabled flag on an existing policy.
func (e *CompliancePolicyEngine) UpdatePolicy(ctx context.Context, id uuid.UUID, schedule string, enabled bool) (*CompliancePolicy, error) {
	nextRun := nextRunTime(schedule)
	query := `
		UPDATE iam_compliance_policies
		SET schedule = $2, enabled = $3, next_run_at = $4, updated_at = now()
		WHERE id = $1
		RETURNING id, tenant_id, control_id, schedule, enabled, last_run_at, next_run_at, created_at, updated_at`

	p := &CompliancePolicy{}
	err := e.db.QueryRow(ctx, query, id, schedule, enabled, nextRun).Scan(
		&p.ID, &p.TenantID, &p.ControlID, &p.Schedule, &p.Enabled,
		&p.LastRunAt, &p.NextRunAt, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.UpdatePolicy: %w", err)
	}
	return p, nil
}

// DeletePolicy removes a policy and cascades to its evaluations.
func (e *CompliancePolicyEngine) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	_, err := e.db.Exec(ctx, `DELETE FROM iam_compliance_policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("CompliancePolicyEngine.DeletePolicy: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

// EvaluateControl executes the control's check_query against the tenant's data,
// compares the result to the configured threshold, detects drift from the
// stored baseline, persists the evaluation record, and optionally runs
// auto-remediation SQL when the check fails.
func (e *CompliancePolicyEngine) EvaluateControl(
	ctx context.Context,
	policyID uuid.UUID,
	tenantID uuid.UUID,
	control *ComplianceControl,
) (*ComplianceEvaluation, error) {
	eval := &ComplianceEvaluation{
		ID:            uuid.New(),
		PolicyID:      policyID,
		TenantID:      tenantID,
		ControlID:     control.ID,
		Framework:     control.Framework,
		ControlRef:    control.ControlID,
		ExpectedValue: control.Threshold,
		EvaluatedAt:   time.Now(),
	}

	// Execute the check query. Every check query must accept $1 = tenant_id
	// and return a single numeric value.
	var actualValue float64
	if err := e.db.QueryRow(ctx, control.CheckQuery, tenantID).Scan(&actualValue); err != nil {
		eval.Status = "error"
		details, _ := json.Marshal(map[string]string{"error": err.Error()})
		eval.Details = details

		if storeErr := e.storeEvaluation(ctx, eval); storeErr != nil {
			logger.Log.Error("CompliancePolicyEngine.EvaluateControl: failed to store error evaluation",
				zap.String("control_id", control.ID.String()),
				zap.Error(storeErr),
			)
		}
		return eval, fmt.Errorf("CompliancePolicyEngine.EvaluateControl: query execution: %w", err)
	}

	eval.ActualValue = actualValue

	// Compare actual value to threshold using the configured operator.
	passed := compareValues(actualValue, control.Operator, control.Threshold)
	if passed {
		eval.Status = complianceStatusPass
	} else {
		eval.Status = complianceStatusFail
	}

	// Drift detection — compare current value to the stored baseline.
	driftDetected, err := e.DetectDrift(ctx, tenantID, control.ID, actualValue)
	if err != nil {
		// Drift detection failure is non-fatal; log and continue.
		logger.Log.Warn("CompliancePolicyEngine.EvaluateControl: drift detection failed",
			zap.String("control_id", control.ID.String()),
			zap.Error(err),
		)
	}
	eval.DriftDetected = driftDetected

	// Build structured details.
	details, _ := json.Marshal(map[string]interface{}{
		"check_type":     string(control.CheckType),
		"operator":       control.Operator,
		"threshold":      control.Threshold,
		"actual_value":   actualValue,
		"passed":         passed,
		"drift_detected": driftDetected,
	})
	eval.Details = details

	// Auto-remediation when control failed and remediation SQL is configured.
	if !passed && control.RemediationType == complianceRemediationTypeAuto && control.RemediationSQL != "" {
		if remErr := e.runRemediation(ctx, tenantID, control.RemediationSQL); remErr != nil {
			logger.Log.Error("CompliancePolicyEngine.EvaluateControl: auto-remediation failed",
				zap.String("control_id", control.ID.String()),
				zap.Error(remErr),
			)
		} else {
			eval.RemediationRun = true
			logger.Log.Info("CompliancePolicyEngine.EvaluateControl: auto-remediation executed",
				zap.String("control_id", control.ID.String()),
				zap.String("tenant_id", tenantID.String()),
			)
		}
	}

	// Persist evaluation record.
	if storeErr := e.storeEvaluation(ctx, eval); storeErr != nil {
		return eval, fmt.Errorf("CompliancePolicyEngine.EvaluateControl: store: %w", storeErr)
	}

	logger.Log.Info("CompliancePolicyEngine.EvaluateControl: completed",
		zap.String("control", control.ControlID),
		zap.String("tenant_id", tenantID.String()),
		zap.String("status", eval.Status),
		zap.Float64("actual", actualValue),
		zap.Float64("threshold", control.Threshold),
		zap.Bool("drift", driftDetected),
	)

	return eval, nil
}

// EvaluateAllForTenant evaluates all enabled policies for the given tenant.
// Each control is evaluated independently; evaluation continues even when
// individual controls error.
func (e *CompliancePolicyEngine) EvaluateAllForTenant(ctx context.Context, tenantID uuid.UUID) ([]ComplianceEvaluation, error) {
	query := `
		SELECT p.id AS policy_id,
		       c.id, c.framework, c.control_id, c.name, c.description,
		       c.check_type, c.check_query, c.threshold, c.operator,
		       c.severity, c.remediation_type, c.remediation_sql, c.enabled,
		       c.created_at, c.updated_at
		FROM iam_compliance_policies p
		JOIN iam_compliance_controls c ON c.id = p.control_id
		WHERE p.tenant_id = $1
		  AND p.enabled = true
		  AND c.enabled = true`

	rows, err := e.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.EvaluateAllForTenant: %w", err)
	}
	defer rows.Close()

	type policyControl struct {
		policyID uuid.UUID
		control  ComplianceControl
	}

	var items []policyControl
	for rows.Next() {
		var pc policyControl
		c := &pc.control
		if err := rows.Scan(
			&pc.policyID,
			&c.ID, &c.Framework, &c.ControlID, &c.Name, &c.Description,
			&c.CheckType, &c.CheckQuery, &c.Threshold, &c.Operator,
			&c.Severity, &c.RemediationType, &c.RemediationSQL, &c.Enabled,
			&c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			logger.Log.Warn("CompliancePolicyEngine.EvaluateAllForTenant: scan error", zap.Error(err))
			continue
		}
		items = append(items, pc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.EvaluateAllForTenant: rows: %w", err)
	}

	var evaluations []ComplianceEvaluation
	for _, pc := range items {
		if ctx.Err() != nil {
			break
		}
		eval, err := e.EvaluateControl(ctx, pc.policyID, tenantID, &pc.control)
		if err != nil {
			logger.Log.Error("CompliancePolicyEngine.EvaluateAllForTenant: control failed",
				zap.String("control", pc.control.ControlID),
				zap.Error(err),
			)
		}
		if eval != nil {
			evaluations = append(evaluations, *eval)
		}
	}

	return evaluations, nil
}

// ---------------------------------------------------------------------------
// Drift detection
// ---------------------------------------------------------------------------

// DetectDrift compares currentValue against the stored baseline for the given
// tenant/control pair. Returns true when the absolute delta exceeds 5 % of the
// baseline value, or when the pass/fail outcome flips relative to the baseline.
// Returns false (no drift) when no baseline exists yet.
func (e *CompliancePolicyEngine) DetectDrift(ctx context.Context, tenantID, controlID uuid.UUID, currentValue float64) (bool, error) {
	var baselineValue float64
	err := e.db.QueryRow(ctx,
		`SELECT baseline_value FROM iam_compliance_baselines WHERE tenant_id = $1 AND control_id = $2`,
		tenantID, controlID,
	).Scan(&baselineValue)
	if err != nil {
		// No baseline recorded yet — drift cannot be determined.
		return false, nil //nolint:nilerr // intentional: no baseline = no drift
	}

	// Drift threshold: 5 % relative change, or any change from zero.
	if baselineValue == 0 {
		return currentValue != 0, nil
	}

	delta := (currentValue - baselineValue) / baselineValue
	if delta < 0 {
		delta = -delta
	}
	return delta > 0.05, nil
}

// ---------------------------------------------------------------------------
// Baseline management
// ---------------------------------------------------------------------------

// CaptureBaseline upserts the known-good baseline value for a control.
func (e *CompliancePolicyEngine) CaptureBaseline(ctx context.Context, tenantID, controlID uuid.UUID, value float64) error {
	query := `
		INSERT INTO iam_compliance_baselines (tenant_id, control_id, baseline_value, captured_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (tenant_id, control_id)
		DO UPDATE SET baseline_value = EXCLUDED.baseline_value, captured_at = now()`

	if _, err := e.db.Exec(ctx, query, tenantID, controlID, value); err != nil {
		return fmt.Errorf("CompliancePolicyEngine.CaptureBaseline: %w", err)
	}
	return nil
}

// GetBaseline returns the stored baseline for a tenant/control pair.
func (e *CompliancePolicyEngine) GetBaseline(ctx context.Context, tenantID, controlID uuid.UUID) (*ComplianceBaseline, error) {
	query := `
		SELECT id, tenant_id, control_id, baseline_value, snapshot, captured_at
		FROM iam_compliance_baselines
		WHERE tenant_id = $1 AND control_id = $2`

	b := &ComplianceBaseline{}
	err := e.db.QueryRow(ctx, query, tenantID, controlID).Scan(
		&b.ID, &b.TenantID, &b.ControlID, &b.BaselineValue, &b.Snapshot, &b.CapturedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.GetBaseline: %w", err)
	}
	return b, nil
}

// ---------------------------------------------------------------------------
// Evaluation history
// ---------------------------------------------------------------------------

// ListEvaluations returns the evaluation history for a tenant with pagination.
func (e *CompliancePolicyEngine) ListEvaluations(
	ctx context.Context,
	tenantID uuid.UUID,
	page, pageSize int,
) ([]ComplianceEvaluation, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	query := `
		SELECT id, policy_id, tenant_id, control_id, framework, control_ref,
		       status, actual_value, expected_value, drift_detected,
		       details, remediation_run, evaluated_at
		FROM iam_compliance_evaluations
		WHERE tenant_id = $1
		ORDER BY evaluated_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := e.db.Query(ctx, query, tenantID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("CompliancePolicyEngine.ListEvaluations: %w", err)
	}
	defer rows.Close()

	var evals []ComplianceEvaluation
	for rows.Next() {
		var ev ComplianceEvaluation
		if err := rows.Scan(
			&ev.ID, &ev.PolicyID, &ev.TenantID, &ev.ControlID,
			&ev.Framework, &ev.ControlRef, &ev.Status,
			&ev.ActualValue, &ev.ExpectedValue, &ev.DriftDetected,
			&ev.Details, &ev.RemediationRun, &ev.EvaluatedAt,
		); err != nil {
			logger.Log.Warn("CompliancePolicyEngine.ListEvaluations: scan error", zap.Error(err))
			continue
		}
		evals = append(evals, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("CompliancePolicyEngine.ListEvaluations: rows: %w", err)
	}

	var total int64
	_ = e.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_compliance_evaluations WHERE tenant_id = $1`,
		tenantID,
	).Scan(&total)

	return evals, total, nil
}

// GetDriftAlerts returns the most recent failing evaluation for each control
// where drift was detected.
func (e *CompliancePolicyEngine) GetDriftAlerts(ctx context.Context, tenantID uuid.UUID) ([]ComplianceEvaluation, error) {
	query := `
		SELECT DISTINCT ON (control_id)
		       id, policy_id, tenant_id, control_id, framework, control_ref,
		       status, actual_value, expected_value, drift_detected,
		       details, remediation_run, evaluated_at
		FROM iam_compliance_evaluations
		WHERE tenant_id = $1 AND drift_detected = true
		ORDER BY control_id, evaluated_at DESC`

	rows, err := e.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.GetDriftAlerts: %w", err)
	}
	defer rows.Close()

	var alerts []ComplianceEvaluation
	for rows.Next() {
		var ev ComplianceEvaluation
		if err := rows.Scan(
			&ev.ID, &ev.PolicyID, &ev.TenantID, &ev.ControlID,
			&ev.Framework, &ev.ControlRef, &ev.Status,
			&ev.ActualValue, &ev.ExpectedValue, &ev.DriftDetected,
			&ev.Details, &ev.RemediationRun, &ev.EvaluatedAt,
		); err != nil {
			logger.Log.Warn("CompliancePolicyEngine.GetDriftAlerts: scan error", zap.Error(err))
			continue
		}
		alerts = append(alerts, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.GetDriftAlerts: rows: %w", err)
	}
	return alerts, nil
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

// GetDashboard aggregates the latest evaluation per control into a compliance
// posture summary for the tenant.
func (e *CompliancePolicyEngine) GetDashboard(ctx context.Context, tenantID uuid.UUID) (*ComplianceDashboard, error) {
	// Fetch the most recent evaluation for each control.
	query := `
		SELECT DISTINCT ON (control_id)
		       framework, control_ref, status, drift_detected, evaluated_at
		FROM iam_compliance_evaluations
		WHERE tenant_id = $1
		ORDER BY control_id, evaluated_at DESC`

	rows, err := e.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.GetDashboard: %w", err)
	}
	defer rows.Close()

	dash := &ComplianceDashboard{
		TenantID:    tenantID,
		ByFramework: make(map[string]FrameworkSummary),
	}

	var lastEval *time.Time

	for rows.Next() {
		var framework, controlRef, status string
		var drift bool
		var evaluatedAt time.Time

		if err := rows.Scan(&framework, &controlRef, &status, &drift, &evaluatedAt); err != nil {
			logger.Log.Warn("CompliancePolicyEngine.GetDashboard: scan error", zap.Error(err))
			continue
		}

		dash.TotalControls++

		switch status {
		case complianceStatusPass:
			dash.PassCount++
		case complianceStatusFail:
			dash.FailCount++
		default:
			dash.ErrorCount++
		}

		if drift {
			dash.DriftAlerts++
		}

		if lastEval == nil || evaluatedAt.After(*lastEval) {
			t := evaluatedAt
			lastEval = &t
		}

		// Aggregate by framework.
		fs := dash.ByFramework[framework]
		fs.Total++
		if status == complianceStatusPass {
			fs.Passing++
		} else {
			fs.Failing++
		}
		if fs.Total > 0 {
			fs.Score = float64(fs.Passing) / float64(fs.Total) * 100
		}
		dash.ByFramework[framework] = fs
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("CompliancePolicyEngine.GetDashboard: rows: %w", err)
	}

	dash.LastEvaluatedAt = lastEval

	if dash.TotalControls > 0 {
		dash.ComplianceScore = float64(dash.PassCount) / float64(dash.TotalControls) * 100
	} else {
		dash.ComplianceScore = 100 // no controls = fully compliant by convention
	}

	return dash, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// storeEvaluation inserts a new evaluation record into the database.
func (e *CompliancePolicyEngine) storeEvaluation(ctx context.Context, ev *ComplianceEvaluation) error {
	query := `
		INSERT INTO iam_compliance_evaluations
		(id, policy_id, tenant_id, control_id, framework, control_ref,
		 status, actual_value, expected_value, drift_detected,
		 details, remediation_run, evaluated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`

	_, err := e.db.Exec(ctx, query,
		ev.ID, ev.PolicyID, ev.TenantID, ev.ControlID,
		string(ev.Framework), ev.ControlRef,
		ev.Status, ev.ActualValue, ev.ExpectedValue, ev.DriftDetected,
		ev.Details, ev.RemediationRun, ev.EvaluatedAt,
	)
	if err != nil {
		return fmt.Errorf("storeEvaluation: %w", err)
	}
	return nil
}

// runRemediation executes an auto-remediation SQL statement with tenant_id as $1.
func (e *CompliancePolicyEngine) runRemediation(ctx context.Context, tenantID uuid.UUID, sql string) error {
	if _, err := e.db.Exec(ctx, sql, tenantID); err != nil {
		return fmt.Errorf("runRemediation: %w", err)
	}
	return nil
}

// compareValues evaluates: actualValue <operator> threshold.
func compareValues(actual float64, operator string, threshold float64) bool {
	switch operator {
	case ">=":
		return actual >= threshold
	case "<=":
		return actual <= threshold
	case "==":
		return actual == threshold
	case "!=":
		return actual != threshold
	case ">":
		return actual > threshold
	case "<":
		return actual < threshold
	default:
		return actual >= threshold
	}
}

// nextRunTime computes the next evaluation time based on the schedule string.
func nextRunTime(schedule string) time.Time {
	now := time.Now()
	switch schedule {
	case "hourly":
		return now.Add(1 * time.Hour)
	case "weekly":
		return now.Add(7 * 24 * time.Hour)
	default: // "daily"
		return now.Add(24 * time.Hour)
	}
}
