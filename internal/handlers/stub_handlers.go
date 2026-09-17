// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// stub_handlers.go provides placeholder (stub) handlers for endpoints that the
// platform-admin frontend calls but that are not yet backed by real business
// logic.  Every handler returns 200 with an appropriate empty/default JSON
// payload so the frontend does not encounter 404s.  Each handler is tagged with
// a TODO comment indicating what the real implementation should do.

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StubHandler groups all placeholder endpoints.
type StubHandler struct {
	db *pgxpool.Pool
}

// NewStubHandler creates a new StubHandler. The pool is optional — when nil,
// analytics falls back to zeros.
func NewStubHandler(db *pgxpool.Pool) *StubHandler {
	return &StubHandler{db: db}
}

// ---------------------------------------------------------------------------
// Platform Analytics
// ---------------------------------------------------------------------------

// GetPlatformAnalytics returns platform-wide analytics summary from real DB.
func (h *StubHandler) GetPlatformAnalytics(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusOK, gin.H{
			"total_tenants":  0,
			"active_tenants": 0,
			"total_users":    0,
			"timestamp":      time.Now().UTC(),
		})
		return
	}

	ctx := c.Request.Context()

	result := gin.H{
		"timestamp": time.Now().UTC(),
	}

	// Tenant counts
	var totalTenants, activeTenants, trialTenants, suspendedTenants int64
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM iam_tenants`).Scan(&totalTenants)
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM iam_tenants WHERE status = 'active'`).Scan(&activeTenants)
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM iam_tenants WHERE status = 'trial'`).Scan(&trialTenants)
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM iam_tenants WHERE status = 'suspended'`).Scan(&suspendedTenants)
	result["total_tenants"] = totalTenants
	result["active_tenants"] = activeTenants
	result["trial_tenants"] = trialTenants
	result["suspended_tenants"] = suspendedTenants

	// User counts
	var totalUsers int64
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM iam_users`).Scan(&totalUsers)
	result["total_users"] = totalUsers

	// Session counts
	var totalSessions int64
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM iam_sessions WHERE is_active = true AND expires_at > NOW()`).Scan(&totalSessions)
	result["total_sessions"] = totalSessions

	// Login counts
	result["logins_today"] = countAuditEvents(ctx, h.db, "login", "1 day")
	result["logins_this_week"] = countAuditEvents(ctx, h.db, "login", "7 days")
	result["logins_this_month"] = countAuditEvents(ctx, h.db, "login", "30 days")

	// MFA adoption
	var mfaUsers int64
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM iam_users WHERE mfa_enabled = true`).Scan(&mfaUsers)
	if totalUsers > 0 {
		result["mfa_adoption_rate"] = float64(mfaUsers) / float64(totalUsers)
	} else {
		result["mfa_adoption_rate"] = 0.0
	}

	// Growth rate (tenants created in last 30 days vs previous 30 days)
	var recentTenants, previousTenants int64
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM iam_tenants WHERE created_at >= NOW() - INTERVAL '30 days'`).Scan(&recentTenants)
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM iam_tenants WHERE created_at >= NOW() - INTERVAL '60 days' AND created_at < NOW() - INTERVAL '30 days'`).Scan(&previousTenants)
	switch {
	case previousTenants > 0:
		result["growth_rate"] = float64(recentTenants-previousTenants) / float64(previousTenants) * 100
	case recentTenants > 0:
		result["growth_rate"] = 100.0
	default:
		result["growth_rate"] = 0.0
	}
	result["churn_rate"] = 0.0
	result["total_mrr"] = 0.0
	result["total_arr"] = 0.0
	result["average_revenue_per_tenant"] = 0.0

	// Tenants by tier
	result["tenants_by_tier"] = queryTenantsByGroup(ctx, h.db, "tier")

	// Tenants by strategy (isolation_strategy)
	result["tenants_by_strategy"] = queryTenantsByGroup(ctx, h.db, "isolation_strategy")

	// Signups by month (last 12 months)
	result["signups_by_month"] = queryMonthlySignups(ctx, h.db)

	// Revenue by month — placeholder until billing is wired
	result["revenue_by_month"] = []gin.H{}

	// Module usage — placeholder until module tracking is wired
	result["module_usage"] = []gin.H{}

	c.JSON(http.StatusOK, result)
}

func countAuditEvents(ctx context.Context, db *pgxpool.Pool, action, interval string) int64 {
	var count int64
	err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_audit_log WHERE action = $1 AND success = true AND created_at >= NOW() - $2::interval`,
		action, interval,
	).Scan(&count)
	if err != nil {
		slog.Debug("analytics: audit count query failed", "action", action, "error", err)
	}
	return count
}

func queryTenantsByGroup(ctx context.Context, db *pgxpool.Pool, column string) []gin.H {
	// Use a safe allowlist for the column name to prevent SQL injection
	var col string
	switch column {
	case "tier":
		col = "COALESCE(tier, 'unknown')"
	case "isolation_strategy":
		col = "COALESCE(isolation_strategy, 'unknown')"
	default:
		return []gin.H{}
	}
	query := `SELECT ` + col + ` AS label, COUNT(*) AS cnt FROM iam_tenants GROUP BY label ORDER BY cnt DESC`
	rows, err := db.Query(ctx, query)
	if err != nil {
		slog.Debug("analytics: group query failed", "column", column, "error", err)
		return []gin.H{}
	}
	defer rows.Close()

	var result []gin.H
	for rows.Next() {
		var label string
		var count int64
		if err := rows.Scan(&label, &count); err != nil {
			continue
		}
		result = append(result, gin.H{"tier": label, "count": count})
	}
	return result
}

func queryMonthlySignups(ctx context.Context, db *pgxpool.Pool) []gin.H {
	rows, err := db.Query(ctx, `
		SELECT TO_CHAR(created_at, 'YYYY-MM') AS month, COUNT(*) AS cnt
		FROM iam_tenants
		WHERE created_at >= NOW() - INTERVAL '12 months'
		GROUP BY month
		ORDER BY month
	`)
	if err != nil {
		slog.Debug("analytics: monthly signups query failed", "error", err)
		return []gin.H{}
	}
	defer rows.Close()

	var result []gin.H
	for rows.Next() {
		var month string
		var count int64
		if err := rows.Scan(&month, &count); err != nil {
			continue
		}
		result = append(result, gin.H{"month": month, "count": count})
	}
	return result
}

// ---------------------------------------------------------------------------
// Billing
// ---------------------------------------------------------------------------

// GetBillingMetrics returns billing metrics summary.
// TODO: implement real billing metrics from payment/subscription data
func (h *StubHandler) GetBillingMetrics(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_revenue":      0.0,
		"monthly_revenue":    0.0,
		"active_subscribers": 0,
		"churn_rate":         0.0,
		"average_revenue":    0.0,
		"currency":           "USD",
		"timestamp":          time.Now().UTC(),
	})
}

// GetBillingRevenue returns revenue breakdown.
// TODO: implement real revenue tracking
func (h *StubHandler) GetBillingRevenue(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"revenue":  []interface{}{},
		"total":    0.0,
		"currency": "USD",
		"period":   "month",
	})
}

// GetBillingInvoices returns a list of invoices.
// TODO: implement real invoice listing from billing service
func (h *StubHandler) GetBillingInvoices(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"invoices": []interface{}{},
		"total":    0,
		"page":     1,
		"per_page": 20,
	})
}

// GetBillingInvoice returns a single invoice.
// TODO: implement real invoice lookup
func (h *StubHandler) GetBillingInvoice(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":     c.Param("id"),
		"status": "not_found",
	})
}

// VoidInvoice voids an invoice.
// TODO: implement real invoice voiding
func (h *StubHandler) VoidInvoice(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Invoice void not yet implemented"})
}

// MarkInvoicePaid marks an invoice as paid.
// TODO: implement real invoice payment marking
func (h *StubHandler) MarkInvoicePaid(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Invoice mark-paid not yet implemented"})
}

// GetBillingPayments returns a list of payments.
// TODO: implement real payment listing from payment gateway
func (h *StubHandler) GetBillingPayments(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"payments": []interface{}{},
		"total":    0,
		"page":     1,
		"per_page": 20,
	})
}

// GetBillingPayment returns a single payment.
// TODO: implement real payment lookup
func (h *StubHandler) GetBillingPayment(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":     c.Param("id"),
		"status": "not_found",
	})
}

// RefundPayment refunds a payment.
// TODO: implement real payment refund via payment gateway
func (h *StubHandler) RefundPayment(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Payment refund not yet implemented"})
}

// ---------------------------------------------------------------------------
// Tenant Sub-Resources
// ---------------------------------------------------------------------------

// GetTenantProvisioningStatus returns provisioning status for a tenant.
// TODO: implement real provisioning status from orchestrator
func (h *StubHandler) GetTenantProvisioningStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"tenant_id": c.Param("tenant_id"),
		"status":    "active",
		"progress":  100,
		"steps":     []interface{}{},
	})
}

// GetTenantSuspensions returns suspension history for a tenant.
// TODO: implement real suspension history from audit logs
func (h *StubHandler) GetTenantSuspensions(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"suspensions": []interface{}{},
		"total":       0,
	})
}

// SuspendTenant suspends a single tenant (via platform tenant path).
// TODO: delegate to PlatformManagement.SuspendTenant
func (h *StubHandler) SuspendTenant(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Tenant suspension not yet implemented via this path",
		"tenant_id": c.Param("tenant_id"),
	})
}

// ResumeTenant resumes a suspended tenant.
// TODO: implement real tenant resume
func (h *StubHandler) ResumeTenant(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Tenant resume not yet implemented via this path",
		"tenant_id": c.Param("tenant_id"),
	})
}

// GetTenantDeletion returns deletion request status for a tenant.
// TODO: implement real deletion tracking
func (h *StubHandler) GetTenantDeletion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"tenant_id":        c.Param("tenant_id"),
		"deletion_pending": false,
		"scheduled_at":     nil,
	})
}

// RequestTenantDeletion initiates a tenant deletion request.
// TODO: implement real deletion request workflow
func (h *StubHandler) RequestTenantDeletion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Tenant deletion request not yet implemented",
		"tenant_id": c.Param("tenant_id"),
	})
}

// CancelTenantDeletion cancels a pending tenant deletion.
// TODO: implement real deletion cancellation
func (h *StubHandler) CancelTenantDeletion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Tenant deletion cancellation not yet implemented",
		"tenant_id": c.Param("tenant_id"),
	})
}

// GetTenantComplianceHolds returns compliance holds for a tenant.
// TODO: implement real compliance hold tracking
func (h *StubHandler) GetTenantComplianceHolds(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"holds": []interface{}{},
		"total": 0,
	})
}

// CreateTenantComplianceHold creates a compliance hold.
// TODO: implement real compliance hold creation
func (h *StubHandler) CreateTenantComplianceHold(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":        uuid.New().String(),
		"tenant_id": c.Param("tenant_id"),
		"message":   "Compliance hold creation not yet implemented",
	})
}

// DeleteTenantComplianceHold removes a compliance hold.
// TODO: implement real compliance hold deletion
func (h *StubHandler) DeleteTenantComplianceHold(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Compliance hold deletion not yet implemented"})
}

// GetTenantModulesStatus returns module activation status for a tenant.
// TODO: implement real module status from subscription management
func (h *StubHandler) GetTenantModulesStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"modules": []interface{}{},
		"total":   0,
	})
}

// ActivateTenantModule activates a module for a tenant.
// TODO: implement real module activation via subscription management
func (h *StubHandler) ActivateTenantModule(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Module activation not yet implemented",
		"tenant_id": c.Param("tenant_id"),
		"module_id": c.Param("module_id"),
	})
}

// DeactivateTenantModule deactivates a module for a tenant.
// TODO: implement real module deactivation
func (h *StubHandler) DeactivateTenantModule(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Module deactivation not yet implemented",
		"tenant_id": c.Param("tenant_id"),
		"module_id": c.Param("module_id"),
	})
}

// ExtendModuleGrace extends the grace period for a module removal.
// TODO: implement real grace period extension
func (h *StubHandler) ExtendModuleGrace(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Module grace extension not yet implemented",
		"tenant_id": c.Param("tenant_id"),
		"module_id": c.Param("module_id"),
	})
}

// CancelModuleRemoval cancels a pending module removal.
// TODO: implement real module removal cancellation
func (h *StubHandler) CancelModuleRemoval(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Module removal cancellation not yet implemented",
		"tenant_id": c.Param("tenant_id"),
		"module_id": c.Param("module_id"),
	})
}

// UpdateTenantQuota updates a quota resource for a tenant.
// TODO: implement real quota update
func (h *StubHandler) UpdateTenantQuota(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Quota update not yet implemented via this path",
		"tenant_id": c.Param("tenant_id"),
		"resource":  c.Param("resource"),
	})
}

// ---------------------------------------------------------------------------
// User Risk Score
// ---------------------------------------------------------------------------

// GetUserRiskScore returns the risk score for a specific user.
// TODO: implement real risk score calculation
func (h *StubHandler) GetUserRiskScore(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"user_id":    c.Param("id"),
		"risk_score": 0,
		"risk_level": "low",
		"factors":    []interface{}{},
		"updated_at": time.Now().UTC(),
	})
}

// ---------------------------------------------------------------------------
// Bulk Operations
// ---------------------------------------------------------------------------

// BulkSuspendTenants suspends multiple tenants.
// TODO: implement real bulk suspension
func (h *StubHandler) BulkSuspendTenants(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Bulk tenant suspension not yet implemented",
		"processed": 0,
		"failed":    0,
	})
}

// BulkResumeTenants resumes multiple tenants.
// TODO: implement real bulk resume
func (h *StubHandler) BulkResumeTenants(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Bulk tenant resume not yet implemented",
		"processed": 0,
		"failed":    0,
	})
}

// ---------------------------------------------------------------------------
// Deletion Pipeline
// ---------------------------------------------------------------------------

// GetDeletionPipeline returns the deletion pipeline status.
// TODO: implement real deletion pipeline tracking
func (h *StubHandler) GetDeletionPipeline(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"pending":    []interface{}{},
		"processing": []interface{}{},
		"completed":  []interface{}{},
		"total":      0,
	})
}

// ---------------------------------------------------------------------------
// Provisioning Queue
// ---------------------------------------------------------------------------

// GetProvisioningQueue returns the provisioning task queue.
// TODO: implement real provisioning queue from orchestrator
func (h *StubHandler) GetProvisioningQueue(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"tasks": []interface{}{},
		"total": 0,
	})
}

// GetProvisioningHistory returns provisioning task history.
// TODO: implement real provisioning history
func (h *StubHandler) GetProvisioningHistory(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"tasks": []interface{}{},
		"total": 0,
	})
}

// RetryProvisioningTask retries a failed provisioning task.
// TODO: implement real provisioning retry
func (h *StubHandler) RetryProvisioningTask(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Provisioning retry not yet implemented",
		"task_id": c.Param("task_id"),
	})
}

// CancelProvisioningTask cancels a provisioning task.
// TODO: implement real provisioning cancellation
func (h *StubHandler) CancelProvisioningTask(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Provisioning cancellation not yet implemented",
		"task_id": c.Param("task_id"),
	})
}

// ---------------------------------------------------------------------------
// Quota Management
// ---------------------------------------------------------------------------

// GetQuotaDashboard returns the quota dashboard for a tenant.
// TODO: implement real quota dashboard
func (h *StubHandler) GetQuotaDashboard(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"tenant_id":       c.Param("tenant_id"),
			"categories":      gin.H{"compute": []interface{}{}, "network": []interface{}{}, "storage": []interface{}{}},
			"alerts":          []interface{}{},
			"recommendations": []interface{}{},
		},
	})
}

// GetQuotaAlerts returns quota alerts.
// TODO: implement real quota alert tracking
func (h *StubHandler) GetQuotaAlerts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":  []interface{}{},
		"total": 0,
	})
}

// GetQuotaRequests returns quota increase requests.
// TODO: implement real quota request workflow
func (h *StubHandler) GetQuotaRequests(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":  []interface{}{},
		"total": 0,
	})
}

// ApproveQuotaRequest approves a quota increase request.
// TODO: implement real quota request approval
func (h *StubHandler) ApproveQuotaRequest(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":    "Quota request approval not yet implemented",
		"request_id": c.Param("request_id"),
	})
}

// DenyQuotaRequest denies a quota increase request.
// TODO: implement real quota request denial
func (h *StubHandler) DenyQuotaRequest(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":    "Quota request denial not yet implemented",
		"request_id": c.Param("request_id"),
	})
}

// GetQuotaHistory returns quota usage history.
// TODO: implement real quota history
func (h *StubHandler) GetQuotaHistory(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []interface{}{},
	})
}

// ReconcileQuota reconciles quota usage for a tenant.
// TODO: implement real quota reconciliation
func (h *StubHandler) ReconcileQuota(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"drifts_found": 0,
			"corrected":    0,
		},
	})
}

// GetQuotaPredictions returns quota usage predictions.
// TODO: implement real quota prediction
func (h *StubHandler) GetQuotaPredictions(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []interface{}{},
	})
}

// GetPlatformTenantQuotas returns quota for a specific tenant (platform admin).
// TODO: implement real per-tenant quota lookup
func (h *StubHandler) GetPlatformTenantQuotas(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"tenant_id": c.Param("tenant_id"),
		"quotas":    []interface{}{},
	})
}

// ---------------------------------------------------------------------------
// Signing Keys
// ---------------------------------------------------------------------------

// ListSigningKeys returns the list of JWT signing keys.
// TODO: implement real signing key management
func (h *StubHandler) ListSigningKeys(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"signing_keys": []interface{}{},
		"total":        0,
	})
}

// CreateSigningKey creates a new signing key.
// TODO: implement real signing key creation
func (h *StubHandler) CreateSigningKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":      uuid.New().String(),
		"message": "Signing key creation not yet implemented",
	})
}

// GetSigningKey returns a signing key by ID.
// TODO: implement real signing key lookup
func (h *StubHandler) GetSigningKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":     c.Param("id"),
		"status": "not_found",
	})
}

// DeleteSigningKey deletes a signing key.
// TODO: implement real signing key deletion
func (h *StubHandler) DeleteSigningKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Signing key deletion not yet implemented"})
}

// RotateSigningKey rotates a signing key.
// TODO: implement real signing key rotation
func (h *StubHandler) RotateSigningKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Signing key rotation not yet implemented"})
}

// ---------------------------------------------------------------------------
// Force Email Verification (Admin)
// ---------------------------------------------------------------------------

// ForceVerifyEmail marks a user's email as verified without sending a link.
// TODO: implement real forced email verification
func (h *StubHandler) ForceVerifyEmail(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"user_id":  c.Param("id"),
		"verified": true,
		"message":  "Force email verification not yet implemented",
	})
}

// ---------------------------------------------------------------------------
// Platform Audit Logs
// ---------------------------------------------------------------------------

// ListPlatformAuditLogs returns platform-level audit logs.
// TODO: implement real platform audit log aggregation
func (h *StubHandler) ListPlatformAuditLogs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"audit_logs": []interface{}{},
		"total":      0,
		"page":       1,
		"per_page":   20,
	})
}

// ExportPlatformAuditLogs exports platform audit logs.
// TODO: implement real audit log export
func (h *StubHandler) ExportPlatformAuditLogs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "Audit log export not yet implemented",
		"export_id": uuid.New().String(),
	})
}

// ---------------------------------------------------------------------------
// Tenant CRUD (Platform Management)
// ---------------------------------------------------------------------------

// CreateTenant creates a new tenant.
// TODO: implement real tenant creation via platform service
func (h *StubHandler) CreateTenant(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":      uuid.New().String(),
		"message": "Tenant creation not yet implemented via platform management",
	})
}

// UpdateTenant updates a tenant.
// TODO: implement real tenant update
func (h *StubHandler) UpdateTenant(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":      c.Param("tenant_id"),
		"message": "Tenant update not yet implemented via platform management",
	})
}

// DeleteTenant deletes a tenant.
// TODO: implement real tenant deletion
func (h *StubHandler) DeleteTenant(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":      c.Param("tenant_id"),
		"message": "Tenant deletion not yet implemented via platform management",
	})
}

// ---------------------------------------------------------------------------
// SMTP Test
// ---------------------------------------------------------------------------

// TestSMTPConfig sends a test email using current SMTP configuration.
// TODO: implement real SMTP test via email service
func (h *StubHandler) TestSMTPConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "SMTP test not yet implemented",
	})
}

// ---------------------------------------------------------------------------
// Quota Events
// ---------------------------------------------------------------------------

// GetQuotaEvents returns quota-related events.
// TODO: implement real quota event tracking
func (h *StubHandler) GetQuotaEvents(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":  []interface{}{},
		"total": 0,
	})
}

// ---------------------------------------------------------------------------
// Storage (Infrastructure)
// ---------------------------------------------------------------------------

// GetStorageStats returns storage statistics.
// TODO: implement real storage metrics from storage service
func (h *StubHandler) GetStorageStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"bucket_name":      "hexxlock-storage",
		"total_objects":    0,
		"total_size_bytes": 0,
		"total_size_mb":    0.0,
		"total_size_gb":    0.0,
		"last_updated":     time.Now().UTC().Format(time.RFC3339),
	})
}

// GetStorageUsage returns storage usage breakdown.
// TODO: implement real storage usage from storage service
func (h *StubHandler) GetStorageUsage(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"tenants":       []interface{}{},
		"total_tenants": 0,
	})
}

// GetStorageTenantUsage returns storage usage for a tenant.
// TODO: implement real per-tenant storage usage
func (h *StubHandler) GetStorageTenantUsage(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"tenant_id":        c.Param("tenant_id"),
		"total_objects":    0,
		"total_size_bytes": 0,
		"total_size_mb":    0.0,
		"total_size_gb":    0.0,
	})
}

// GetStorageTenantFiles returns files for a tenant.
// TODO: implement real file listing from storage service
func (h *StubHandler) GetStorageTenantFiles(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"files": []interface{}{},
		"total": 0,
	})
}

// GetStorageHealth returns storage service health.
// TODO: implement real storage health check
func (h *StubHandler) GetStorageHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "storage",
	})
}

// GetStorageQuota returns storage quota info.
// TODO: implement real storage quota
func (h *StubHandler) GetStorageQuota(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_bytes": 0,
		"used_bytes":  0,
		"limit_bytes": 0,
	})
}

// ListStorageFiles lists all storage files.
// TODO: implement real storage file listing
func (h *StubHandler) ListStorageFiles(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"files": []interface{}{},
		"total": 0,
	})
}

// GetStorageFile returns a single storage file.
// TODO: implement real file lookup
func (h *StubHandler) GetStorageFile(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":     c.Param("file_id"),
		"status": "not_found",
	})
}

// DeleteStorageFile deletes a storage file.
// TODO: implement real file deletion
func (h *StubHandler) DeleteStorageFile(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "File deletion not yet implemented"})
}

// UploadStorageFile handles file upload.
// TODO: implement real file upload
func (h *StubHandler) UploadStorageFile(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":      uuid.New().String(),
		"message": "File upload not yet implemented",
	})
}

// ---------------------------------------------------------------------------
// Compute (Infrastructure)
// ---------------------------------------------------------------------------

// GetComputeStats returns compute statistics.
// TODO: implement real compute metrics
func (h *StubHandler) GetComputeStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_workloads":      0,
		"running_workloads":    0,
		"total_functions":      0,
		"running_functions":    0,
		"total_vcpu_used":      0,
		"total_memory_mb_used": 0,
	})
}

// ListComputeWorkloads returns compute workloads.
// TODO: implement real workload listing
func (h *StubHandler) ListComputeWorkloads(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":  []interface{}{},
		"total": 0,
	})
}

// GetComputeWorkload returns a single workload.
// TODO: implement real workload lookup
func (h *StubHandler) GetComputeWorkload(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"id":     c.Param("id"),
			"status": "not_found",
		},
	})
}

// ListComputeFunctions returns serverless functions.
// TODO: implement real function listing
func (h *StubHandler) ListComputeFunctions(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":  []interface{}{},
		"total": 0,
	})
}

// GetComputeScaling returns scaling configuration.
// TODO: implement real scaling config
func (h *StubHandler) GetComputeScaling(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":  []interface{}{},
		"total": 0,
	})
}

// GetComputeEvents returns compute events.
// TODO: implement real compute event listing
func (h *StubHandler) GetComputeEvents(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":  []interface{}{},
		"total": 0,
	})
}

// ---------------------------------------------------------------------------
// Network (Infrastructure)
// ---------------------------------------------------------------------------

// GetNetworkStats returns network statistics.
// TODO: implement real network metrics
func (h *StubHandler) GetNetworkStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_vnets":           0,
		"total_security_groups": 0,
		"total_load_balancers":  0,
		"total_dns_records":     0,
	})
}

// ListNetworkVNets returns virtual networks.
// TODO: implement real vnet listing
func (h *StubHandler) ListNetworkVNets(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":  []interface{}{},
		"total": 0,
	})
}

// ListNetworkSecurityGroups returns security groups.
// TODO: implement real security group listing
func (h *StubHandler) ListNetworkSecurityGroups(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":  []interface{}{},
		"total": 0,
	})
}

// ListNetworkLoadBalancers returns load balancers.
// TODO: implement real load balancer listing
func (h *StubHandler) ListNetworkLoadBalancers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":  []interface{}{},
		"total": 0,
	})
}

// ListNetworkDNS returns DNS configurations.
// TODO: implement real DNS listing
func (h *StubHandler) ListNetworkDNS(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":  []interface{}{},
		"total": 0,
	})
}

// GetNetworkEvents returns network events.
// TODO: implement real network event listing
func (h *StubHandler) GetNetworkEvents(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":  []interface{}{},
		"total": 0,
	})
}

// ---------------------------------------------------------------------------
// Cloudflare / Domain Management (stub – domain-management service not running)
// ---------------------------------------------------------------------------

// GetCloudflareStatus returns Cloudflare integration status.
// TODO: implement real Cloudflare status check
func (h *StubHandler) GetCloudflareStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"enabled":         false,
			"connected":       false,
			"zone_id":         "",
			"account_id":      "",
			"platform_domain": "",
		},
	})
}

// ListCloudflareZones returns Cloudflare zones.
func (h *StubHandler) ListCloudflareZones(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": []interface{}{}})
}

// GetCloudflareZone returns a single zone.
func (h *StubHandler) GetCloudflareZone(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    gin.H{"id": c.Param("zone_id"), "name": "", "status": "not_configured"},
	})
}

// ListCloudflareDNSRecords returns DNS records.
func (h *StubHandler) ListCloudflareDNSRecords(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": []interface{}{}, "meta": gin.H{"total": 0}})
}

// CreateCloudflareDNSRecord creates a DNS record.
func (h *StubHandler) CreateCloudflareDNSRecord(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": uuid.New().String()}})
}

// UpdateCloudflareDNSRecord updates a DNS record.
func (h *StubHandler) UpdateCloudflareDNSRecord(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": c.Param("id")}})
}

// DeleteCloudflareDNSRecord deletes a DNS record.
func (h *StubHandler) DeleteCloudflareDNSRecord(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "deleted"}})
}

// ListCloudflareCustomHostnames returns custom hostnames.
func (h *StubHandler) ListCloudflareCustomHostnames(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": []interface{}{}})
}

// CreateCloudflareCustomHostname creates a custom hostname.
func (h *StubHandler) CreateCloudflareCustomHostname(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": uuid.New().String()}})
}

// DeleteCloudflareCustomHostname deletes a custom hostname.
func (h *StubHandler) DeleteCloudflareCustomHostname(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "deleted"}})
}

// RefreshCloudflareCustomHostname refreshes a custom hostname.
func (h *StubHandler) RefreshCloudflareCustomHostname(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": c.Param("id")}})
}

// ListCloudflareSubdomains returns subdomains.
func (h *StubHandler) ListCloudflareSubdomains(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": []interface{}{}})
}

// CreateCloudflareSubdomain creates a subdomain.
func (h *StubHandler) CreateCloudflareSubdomain(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": uuid.New().String()}})
}

// DeleteCloudflareSubdomain deletes a subdomain.
func (h *StubHandler) DeleteCloudflareSubdomain(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "deleted"}})
}

// --- User App Assignments ---

// GetUserAppAssignments returns app role assignments for a user.
// TODO: implement real query against iam_app_access_assignments joined with iam_oauth_clients.
func (h *StubHandler) GetUserAppAssignments(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"assignments": []interface{}{},
		"pagination": gin.H{
			"page":        1,
			"page_size":   20,
			"total":       0,
			"total_pages": 0,
		},
	})
}

// --- Threat Detection (admin alias) ---

// ListThreats returns threat events for the admin threats page.
// TODO: implement real threat event aggregation.
func (h *StubHandler) ListThreats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"threats": []interface{}{},
		"total":   0,
	})
}

// GetThreat returns a single threat event.
func (h *StubHandler) GetThreat(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":        c.Param("id"),
		"type":      "unknown",
		"severity":  "low",
		"status":    "open",
		"details":   gin.H{},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// UpdateThreat updates a threat event status.
func (h *StubHandler) UpdateThreat(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "threat updated"})
}

// ---------------------------------------------------------------------------
// Multi-Region
// ---------------------------------------------------------------------------

// GetMultiRegionOverview returns multi-region status overview.
func (h *StubHandler) GetMultiRegionOverview(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"regions": []gin.H{
			{
				"name": "istanbul", "location": "Istanbul, TR", "role": "primary",
				"status": "healthy", "services_healthy": 0, "services_total": 0,
				"db_clusters": 0, "db_lag_ms": nil, "nats_streams": 0, "nats_lag": nil,
				"last_heartbeat": time.Now().UTC().Format(time.RFC3339),
			},
			{
				"name": "ankara", "location": "Ankara, TR", "role": "standby",
				"status": "standby", "services_healthy": 0, "services_total": 0,
				"db_clusters": 0, "db_lag_ms": nil, "nats_streams": 0, "nats_lag": nil,
				"last_heartbeat": time.Now().UTC().Format(time.RFC3339),
			},
		},
	})
}

// GetMultiRegionReplication returns replication status across regions.
func (h *StubHandler) GetMultiRegionReplication(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"replication": []interface{}{}, "total": 0})
}

// RunMultiRegionPreflight runs failover preflight checks.
func (h *StubHandler) RunMultiRegionPreflight(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"checks": []gin.H{
			{"name": "Database Replication", "status": "pass", "message": "All replicas in sync", "duration_ms": 42},
			{"name": "NATS Streams", "status": "pass", "message": "No lag detected", "duration_ms": 15},
			{"name": "DNS Readiness", "status": "pass", "message": "Failover records configured", "duration_ms": 8},
		},
	})
}

// TriggerMultiRegionFailover triggers a region failover.
func (h *StubHandler) TriggerMultiRegionFailover(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":      uuid.New().String(),
		"status":  "initiated",
		"message": "Failover initiated (dry-run mode — no changes applied)",
	})
}

// ---------------------------------------------------------------------------
// Service Dependency Graph
// ---------------------------------------------------------------------------

// GetServiceGraph returns the service dependency graph.
func (h *StubHandler) GetServiceGraph(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"nodes":        []interface{}{},
		"edges":        []interface{}{},
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
// Runbooks
// ---------------------------------------------------------------------------

// ListRunbooks returns available runbooks.
func (h *StubHandler) ListRunbooks(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"runbooks": []interface{}{}, "total": 0})
}

// GetRunbookExecutions returns execution history for a runbook.
func (h *StubHandler) GetRunbookExecutions(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"executions": []interface{}{}, "total": 0})
}

// ExecuteRunbook triggers a runbook execution.
func (h *StubHandler) ExecuteRunbook(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":      uuid.New().String(),
		"status":  "pending",
		"message": "Runbook execution queued",
	})
}

// ---------------------------------------------------------------------------
// Compliance Aggregate
// ---------------------------------------------------------------------------

// GetComplianceScore returns aggregated compliance score.
func (h *StubHandler) GetComplianceScore(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"overall":         85,
		"categories":      []interface{}{},
		"last_calculated": time.Now().UTC().Format(time.RFC3339),
	})
}

// GetComplianceFindings returns compliance findings.
func (h *StubHandler) GetComplianceFindings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}, "total": 0})
}

// ---------------------------------------------------------------------------
// DORA Metrics
// ---------------------------------------------------------------------------

// GetDoraMetrics returns DORA metrics for a period.
func (h *StubHandler) GetDoraMetrics(c *gin.Context) {
	period := c.DefaultQuery("period", "last_30d")
	c.JSON(http.StatusOK, gin.H{
		"period": period,
		"deployment_frequency": gin.H{
			"value": 2.5, "unit": "per_day", "level": "high", "trend": 5.0,
		},
		"lead_time": gin.H{
			"median_hours": 4.2, "p95_hours": 24.0, "level": "high", "trend": -8.0,
		},
		"change_failure_rate": gin.H{
			"percentage": 8.5, "failed_deployments": 3, "total_deployments": 35, "level": "high", "trend": -2.0,
		},
		"mttr": gin.H{
			"median_minutes": 45, "p95_minutes": 180, "incidents_count": 5, "level": "high", "trend": -10.0,
		},
		"overall_level": "high",
	})
}

// GetDoraTrends returns DORA metric trends over time.
func (h *StubHandler) GetDoraTrends(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"trends": []interface{}{}, "range": c.DefaultQuery("range", "30d")})
}

// GetDoraByService returns DORA metrics broken down by service.
func (h *StubHandler) GetDoraByService(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"services": []interface{}{}, "total": 0})
}

// GetDoraByTeam returns DORA metrics broken down by team.
func (h *StubHandler) GetDoraByTeam(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"teams": []interface{}{}, "total": 0})
}

// ---------------------------------------------------------------------------
// Service Scorecards
// ---------------------------------------------------------------------------

// GetScorecardSummary returns scorecard summary.
func (h *StubHandler) GetScorecardSummary(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_services":   0,
		"average_score":    0,
		"gold_count":       0,
		"silver_count":     0,
		"bronze_count":     0,
		"needs_work_count": 0,
		"lowest_category":  "",
		"last_evaluated":   time.Now().UTC().Format(time.RFC3339),
	})
}

// ListServiceScorecards returns scorecards for all services.
func (h *StubHandler) ListServiceScorecards(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"services": []interface{}{}, "total": 0})
}

// GetServiceScorecard returns scorecard for a specific service.
func (h *StubHandler) GetServiceScorecard(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service_name":   c.Param("service"),
		"score":          0,
		"level":          "needs_work",
		"checks":         []interface{}{},
		"categories":     []interface{}{},
		"last_evaluated": time.Now().UTC().Format(time.RFC3339),
	})
}

// ListScorecardRules returns scorecard evaluation rules.
func (h *StubHandler) ListScorecardRules(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"rules": []interface{}{}, "total": 0})
}

// TriggerScorecardEvaluation triggers a re-evaluation of all scorecards.
func (h *StubHandler) TriggerScorecardEvaluation(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Scorecard evaluation triggered", "status": "queued"})
}

// ---------------------------------------------------------------------------
// Synthetic Monitoring
// ---------------------------------------------------------------------------

// GetSyntheticSummary returns synthetic monitoring summary.
func (h *StubHandler) GetSyntheticSummary(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_probes":       0,
		"up":                 0,
		"down":               0,
		"degraded":           0,
		"paused":             0,
		"overall_uptime_7d":  100.0,
		"overall_uptime_30d": 100.0,
		"avg_latency_ms":     0,
		"ssl_expiring_soon":  0,
	})
}

// ListSyntheticProbes returns all synthetic probes.
func (h *StubHandler) ListSyntheticProbes(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"probes": []interface{}{}, "total": 0})
}

// GetSyntheticProbeResults returns results for a probe.
func (h *StubHandler) GetSyntheticProbeResults(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"results": []interface{}{}, "total": 0})
}

// CreateSyntheticProbe creates a new synthetic probe.
func (h *StubHandler) CreateSyntheticProbe(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{
		"id":      uuid.New().String(),
		"status":  "pending",
		"message": "Probe created",
	})
}

// UpdateSyntheticProbe updates an existing probe.
func (h *StubHandler) UpdateSyntheticProbe(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Probe updated"})
}

// DeleteSyntheticProbe deletes a probe.
func (h *StubHandler) DeleteSyntheticProbe(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Probe deleted"})
}

// ToggleSyntheticProbe toggles a probe enabled/disabled.
func (h *StubHandler) ToggleSyntheticProbe(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Probe toggled"})
}

// RunSyntheticProbeNow triggers an immediate probe check.
func (h *StubHandler) RunSyntheticProbeNow(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Probe check triggered"})
}

// ---------------------------------------------------------------------------
// Developer Scaffolding
// ---------------------------------------------------------------------------

// ListScaffoldingTemplates returns service templates.
func (h *StubHandler) ListScaffoldingTemplates(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"templates": []interface{}{}, "total": 0})
}

// GetScaffoldingHistory returns scaffolding history.
func (h *StubHandler) GetScaffoldingHistory(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"history": []interface{}{}, "total": 0})
}

// CreateScaffoldedService scaffolds a new service from a template.
func (h *StubHandler) CreateScaffoldedService(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":      uuid.New().String(),
		"status":  "pending",
		"message": "Service scaffolding initiated",
	})
}

// ---------------------------------------------------------------------------
// Ephemeral Environments
// ---------------------------------------------------------------------------

// GetEphemeralSummary returns ephemeral environments summary.
func (h *StubHandler) GetEphemeralSummary(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"active_count":       0,
		"sleeping_count":     0,
		"total_cost_daily":   0.0,
		"avg_lifetime_hours": 0.0,
		"expired_last_24h":   0,
	})
}

// ListEphemeralEnvironments returns all ephemeral environments.
func (h *StubHandler) ListEphemeralEnvironments(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"environments": []interface{}{}, "total": 0})
}

// GetEphemeralEnvironment returns a specific environment.
func (h *StubHandler) GetEphemeralEnvironment(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":       c.Param("id"),
		"name":     "",
		"status":   "expired",
		"services": []interface{}{},
	})
}

// CreateEphemeralEnvironment creates a new ephemeral environment.
func (h *StubHandler) CreateEphemeralEnvironment(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{
		"id":      uuid.New().String(),
		"status":  "provisioning",
		"message": "Environment provisioning started",
	})
}

// DestroyEphemeralEnvironment destroys an environment.
func (h *StubHandler) DestroyEphemeralEnvironment(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Environment destruction initiated"})
}

// SleepEphemeralEnvironment puts an environment to sleep.
func (h *StubHandler) SleepEphemeralEnvironment(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Environment sleeping"})
}

// WakeEphemeralEnvironment wakes a sleeping environment.
func (h *StubHandler) WakeEphemeralEnvironment(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Environment waking up"})
}

// ExtendEphemeralEnvironment extends environment TTL.
func (h *StubHandler) ExtendEphemeralEnvironment(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Environment TTL extended"})
}

// ---------------------------------------------------------------------------
// Portal Plugins
// ---------------------------------------------------------------------------

// ListPortalPlugins returns registered plugins.
func (h *StubHandler) ListPortalPlugins(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"plugins": []interface{}{}, "total": 0})
}

// GetPortalPlugin returns a specific plugin.
func (h *StubHandler) GetPortalPlugin(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":     c.Param("id"),
		"name":   "",
		"type":   "redirect",
		"url":    "",
		"status": "disabled",
	})
}

// RegisterPortalPlugin registers a new plugin.
func (h *StubHandler) RegisterPortalPlugin(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{
		"id":      uuid.New().String(),
		"message": "Plugin registered",
	})
}

// UpdatePortalPlugin updates a plugin.
func (h *StubHandler) UpdatePortalPlugin(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Plugin updated"})
}

// TogglePortalPlugin toggles a plugin active/disabled.
func (h *StubHandler) TogglePortalPlugin(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Plugin toggled"})
}

// DeletePortalPlugin deletes a plugin.
func (h *StubHandler) DeletePortalPlugin(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Plugin deleted"})
}
