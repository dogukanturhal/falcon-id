// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// RiskRepository is an exported type.
type RiskRepository struct {
	db *pgxpool.Pool
}

// NewRiskRepository is an exported function.
func NewRiskRepository(db *pgxpool.Pool) *RiskRepository {
	return &RiskRepository{db: db}
}

// CreateSignal creates a new risk signal
func (r *RiskRepository) CreateSignal(ctx context.Context, signal *models.RiskSignal) error {
	if signal.ID == uuid.Nil {
		signal.ID = uuid.New()
	}

	detailsJSON, err := json.Marshal(signal.Details)
	if err != nil {
		return fmt.Errorf("CreateSignal: Marshal failed: %w", err)
	}

	query := `
		INSERT INTO iam_risk_signals (
			id, user_id, session_id, signal_type, risk_score,
			ip_address, user_agent, details
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at`

	return r.db.QueryRow(ctx, query,
		signal.ID, signal.UserID, signal.SessionID, signal.SignalType,
		signal.RiskScore, signal.IPAddress, signal.UserAgent, detailsJSON,
	).Scan(&signal.CreatedAt)
}

// GetSignalByID returns a risk signal by ID
func (r *RiskRepository) GetSignalByID(ctx context.Context, id uuid.UUID) (*models.RiskSignal, error) {
	signal := &models.RiskSignal{}
	var detailsJSON []byte

	query := `
		SELECT id, user_id, session_id, signal_type, risk_score,
			   ip_address, user_agent, details, resolved_at,
			   resolved_by, resolution_note, created_at
		FROM iam_risk_signals WHERE id = $1`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&signal.ID, &signal.UserID, &signal.SessionID, &signal.SignalType,
		&signal.RiskScore, &signal.IPAddress, &signal.UserAgent, &detailsJSON,
		&signal.ResolvedAt, &signal.ResolvedBy, &signal.ResolutionNote, &signal.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetSignalByID: %w", err)
	}

	if len(detailsJSON) > 0 {
		if err := json.Unmarshal(detailsJSON, &signal.Details); err != nil {
			return nil, fmt.Errorf("GetSignalByID: %w", err)
		}
	}

	return signal, nil
}

// GetUserRecentSignals returns recent risk signals for a user
func (r *RiskRepository) GetUserRecentSignals(ctx context.Context, userID uuid.UUID, since time.Time) ([]models.RiskSignal, error) {
	query := `
		SELECT id, user_id, session_id, signal_type, risk_score,
			   ip_address, user_agent, details, resolved_at,
			   resolved_by, resolution_note, created_at
		FROM iam_risk_signals
		WHERE user_id = $1 AND created_at >= $2
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, userID, since)
	if err != nil {
		return nil, fmt.Errorf("GetUserRecentSignals: %w", err)
	}
	defer rows.Close()

	var signals []models.RiskSignal
	for rows.Next() {
		var signal models.RiskSignal
		var detailsJSON []byte

		if err := rows.Scan(
			&signal.ID, &signal.UserID, &signal.SessionID, &signal.SignalType,
			&signal.RiskScore, &signal.IPAddress, &signal.UserAgent, &detailsJSON,
			&signal.ResolvedAt, &signal.ResolvedBy, &signal.ResolutionNote, &signal.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("GetUserRecentSignals: %w", err)
		}

		if len(detailsJSON) > 0 {
			_ = json.Unmarshal(detailsJSON, &signal.Details)
		}

		signals = append(signals, signal)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserRecentSignals: rows iteration: %w", err)
	}

	return signals, nil
}

// GetUnresolvedSignals returns unresolved risk signals for a user
func (r *RiskRepository) GetUnresolvedSignals(ctx context.Context, userID uuid.UUID) ([]models.RiskSignal, error) {
	query := `
		SELECT id, user_id, session_id, signal_type, risk_score,
			   ip_address, user_agent, details, resolved_at,
			   resolved_by, resolution_note, created_at
		FROM iam_risk_signals
		WHERE user_id = $1 AND resolved_at IS NULL
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("GetUnresolvedSignals: %w", err)
	}
	defer rows.Close()

	var signals []models.RiskSignal
	for rows.Next() {
		var signal models.RiskSignal
		var detailsJSON []byte

		if err := rows.Scan(
			&signal.ID, &signal.UserID, &signal.SessionID, &signal.SignalType,
			&signal.RiskScore, &signal.IPAddress, &signal.UserAgent, &detailsJSON,
			&signal.ResolvedAt, &signal.ResolvedBy, &signal.ResolutionNote, &signal.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("GetUnresolvedSignals: %w", err)
		}

		if len(detailsJSON) > 0 {
			_ = json.Unmarshal(detailsJSON, &signal.Details)
		}

		signals = append(signals, signal)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUnresolvedSignals: rows iteration: %w", err)
	}

	return signals, nil
}

// ResolveSignal resolves a risk signal
func (r *RiskRepository) ResolveSignal(ctx context.Context, id uuid.UUID, resolvedBy uuid.UUID, note string) error {
	query := `
		UPDATE iam_risk_signals
		SET resolved_at = NOW(), resolved_by = $1, resolution_note = $2
		WHERE id = $3`

	_, err := r.db.Exec(ctx, query, resolvedBy, note, id)
	if err != nil {
		return fmt.Errorf("ResolveSignal: %w", err)
	}
	return nil
}

// CountFailedAttempts returns the number of failed login attempts in a time window
func (r *RiskRepository) CountFailedAttempts(ctx context.Context, userID uuid.UUID, since time.Time) (int, error) {
	var count int
	query := `
		SELECT COUNT(*) FROM iam_audit_log
		WHERE user_id = $1 AND action = 'login' AND success = false
		  AND created_at >= $2`

	err := r.db.QueryRow(ctx, query, userID, since).Scan(&count)
	if err != nil {
		return count, fmt.Errorf("CountFailedAttempts: %w", err)
	}
	return count, nil
}

// GetPolicies returns active risk policies for a tenant
func (r *RiskRepository) GetPolicies(ctx context.Context, tenantID uuid.UUID) ([]models.RiskPolicy, error) {
	query := `
		SELECT id, tenant_id, name, description, conditions, actions,
			   priority, is_active, created_at, updated_at
		FROM iam_risk_policies
		WHERE tenant_id = $1 AND is_active = true
		ORDER BY priority DESC`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetPolicies: %w", err)
	}
	defer rows.Close()

	var policies []models.RiskPolicy
	for rows.Next() {
		var policy models.RiskPolicy
		var conditionsJSON, actionsJSON []byte

		if err := rows.Scan(
			&policy.ID, &policy.TenantID, &policy.Name, &policy.Description,
			&conditionsJSON, &actionsJSON, &policy.Priority, &policy.IsActive,
			&policy.CreatedAt, &policy.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("GetPolicies: %w", err)
		}

		if len(conditionsJSON) > 0 {
			_ = json.Unmarshal(conditionsJSON, &policy.Conditions)
		}
		if len(actionsJSON) > 0 {
			_ = json.Unmarshal(actionsJSON, &policy.Actions)
		}

		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetPolicies: rows iteration: %w", err)
	}

	return policies, nil
}

// GetAllPolicies returns all risk policies for a tenant (including inactive)
func (r *RiskRepository) GetAllPolicies(ctx context.Context, tenantID uuid.UUID) ([]models.RiskPolicy, error) {
	query := `
		SELECT id, tenant_id, name, description, conditions, actions,
			   priority, is_active, created_at, updated_at
		FROM iam_risk_policies
		WHERE tenant_id = $1
		ORDER BY priority DESC`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetAllPolicies: %w", err)
	}
	defer rows.Close()

	var policies []models.RiskPolicy
	for rows.Next() {
		var policy models.RiskPolicy
		var conditionsJSON, actionsJSON []byte

		if err := rows.Scan(
			&policy.ID, &policy.TenantID, &policy.Name, &policy.Description,
			&conditionsJSON, &actionsJSON, &policy.Priority, &policy.IsActive,
			&policy.CreatedAt, &policy.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("GetAllPolicies: %w", err)
		}

		if len(conditionsJSON) > 0 {
			_ = json.Unmarshal(conditionsJSON, &policy.Conditions)
		}
		if len(actionsJSON) > 0 {
			_ = json.Unmarshal(actionsJSON, &policy.Actions)
		}

		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetAllPolicies: rows iteration: %w", err)
	}

	return policies, nil
}

// GetPolicyByID returns a risk policy by ID
func (r *RiskRepository) GetPolicyByID(ctx context.Context, id uuid.UUID) (*models.RiskPolicy, error) {
	policy := &models.RiskPolicy{}
	var conditionsJSON, actionsJSON []byte

	query := `
		SELECT id, tenant_id, name, description, conditions, actions,
			   priority, is_active, created_at, updated_at
		FROM iam_risk_policies WHERE id = $1`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&policy.ID, &policy.TenantID, &policy.Name, &policy.Description,
		&conditionsJSON, &actionsJSON, &policy.Priority, &policy.IsActive,
		&policy.CreatedAt, &policy.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetPolicyByID: %w", err)
	}

	if len(conditionsJSON) > 0 {
		_ = json.Unmarshal(conditionsJSON, &policy.Conditions)
	}
	if len(actionsJSON) > 0 {
		_ = json.Unmarshal(actionsJSON, &policy.Actions)
	}

	return policy, nil
}

// CreatePolicy creates a new risk policy
func (r *RiskRepository) CreatePolicy(ctx context.Context, policy *models.RiskPolicy) error {
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
	}

	conditionsJSON, err := json.Marshal(policy.Conditions)
	if err != nil {
		return fmt.Errorf("CreatePolicy: Marshal failed: %w", err)
	}

	actionsJSON, err := json.Marshal(policy.Actions)
	if err != nil {
		return fmt.Errorf("CreatePolicy: Marshal failed: %w", err)
	}

	query := `
		INSERT INTO iam_risk_policies (
			id, tenant_id, name, description, conditions, actions, priority, is_active
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		policy.ID, policy.TenantID, policy.Name, policy.Description,
		conditionsJSON, actionsJSON, policy.Priority, policy.IsActive,
	).Scan(&policy.CreatedAt, &policy.UpdatedAt)
}

// UpdatePolicy updates a risk policy
func (r *RiskRepository) UpdatePolicy(ctx context.Context, policy *models.RiskPolicy) error {
	conditionsJSON, err := json.Marshal(policy.Conditions)
	if err != nil {
		return fmt.Errorf("UpdatePolicy: Marshal failed: %w", err)
	}

	actionsJSON, err := json.Marshal(policy.Actions)
	if err != nil {
		return fmt.Errorf("UpdatePolicy: Marshal failed: %w", err)
	}

	query := `
		UPDATE iam_risk_policies
		SET name = $1, description = $2, conditions = $3, actions = $4,
			priority = $5, is_active = $6
		WHERE id = $7
		RETURNING updated_at`

	return r.db.QueryRow(ctx, query,
		policy.Name, policy.Description, conditionsJSON, actionsJSON,
		policy.Priority, policy.IsActive, policy.ID,
	).Scan(&policy.UpdatedAt)
}

// DeletePolicy deletes a risk policy
func (r *RiskRepository) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM iam_risk_policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("DeletePolicy: %w", err)
	}
	return nil
}

// GetThresholds returns risk thresholds for a tenant
func (r *RiskRepository) GetThresholds(ctx context.Context, tenantID uuid.UUID) (*models.RiskThreshold, error) {
	threshold := &models.RiskThreshold{}

	query := `
		SELECT id, tenant_id, low_threshold, medium_threshold, high_threshold,
			   critical_threshold, auto_block_on_critical, block_duration_minutes,
			   notify_user_on_high_risk, notify_admin_on_critical,
			   default_mfa_at_medium, default_mfa_at_high,
			   created_at, updated_at
		FROM iam_risk_thresholds WHERE tenant_id = $1`

	err := r.db.QueryRow(ctx, query, tenantID).Scan(
		&threshold.ID, &threshold.TenantID, &threshold.LowThreshold,
		&threshold.MediumThreshold, &threshold.HighThreshold, &threshold.CriticalThreshold,
		&threshold.AutoBlockOnCritical, &threshold.BlockDurationMinutes,
		&threshold.NotifyUserOnHighRisk, &threshold.NotifyAdminOnCritical,
		&threshold.DefaultMFAAtMedium, &threshold.DefaultMFAAtHigh,
		&threshold.CreatedAt, &threshold.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetThresholds: %w", err)
	}
	return threshold, nil
}

// UpsertThresholds creates or updates risk thresholds
func (r *RiskRepository) UpsertThresholds(ctx context.Context, threshold *models.RiskThreshold) error {
	if threshold.ID == uuid.Nil {
		threshold.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_risk_thresholds (
			id, tenant_id, low_threshold, medium_threshold, high_threshold,
			critical_threshold, auto_block_on_critical, block_duration_minutes,
			notify_user_on_high_risk, notify_admin_on_critical,
			default_mfa_at_medium, default_mfa_at_high
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (tenant_id) DO UPDATE SET
			low_threshold = EXCLUDED.low_threshold,
			medium_threshold = EXCLUDED.medium_threshold,
			high_threshold = EXCLUDED.high_threshold,
			critical_threshold = EXCLUDED.critical_threshold,
			auto_block_on_critical = EXCLUDED.auto_block_on_critical,
			block_duration_minutes = EXCLUDED.block_duration_minutes,
			notify_user_on_high_risk = EXCLUDED.notify_user_on_high_risk,
			notify_admin_on_critical = EXCLUDED.notify_admin_on_critical,
			default_mfa_at_medium = EXCLUDED.default_mfa_at_medium,
			default_mfa_at_high = EXCLUDED.default_mfa_at_high
		RETURNING id, created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		threshold.ID, threshold.TenantID, threshold.LowThreshold,
		threshold.MediumThreshold, threshold.HighThreshold, threshold.CriticalThreshold,
		threshold.AutoBlockOnCritical, threshold.BlockDurationMinutes,
		threshold.NotifyUserOnHighRisk, threshold.NotifyAdminOnCritical,
		threshold.DefaultMFAAtMedium, threshold.DefaultMFAAtHigh,
	).Scan(&threshold.ID, &threshold.CreatedAt, &threshold.UpdatedAt)
}

// CreateLoginRiskEvent records a per-login rollup row in iam_login_risk_events.
// Companion to CreateSignal (per-signal). The event captures cumulative score,
// level, outcome, and the trigger reason — required for SIEM-grade audit and
// threshold tuning. Failures are non-fatal at the call site; this function
// returns the error so callers can decide whether to log-and-continue.
func (r *RiskRepository) CreateLoginRiskEvent(ctx context.Context, event *models.LoginRiskEvent) error {
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_login_risk_events (
			id, user_id, tenant_id, ip_address, user_agent, location,
			total_score, level, signal_count, outcome, mfa_trigger, block_reason,
			asn, asn_org, city, region, is_vpn_hint
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		RETURNING created_at`

	return r.db.QueryRow(ctx, query,
		event.ID, event.UserID, event.TenantID,
		event.IPAddress, event.UserAgent, event.Location,
		event.TotalScore, string(event.Level), event.SignalCount,
		event.Outcome, event.MFATrigger, event.BlockReason,
		event.ASN, event.ASNOrg, event.City, event.Region, event.IsVPNHint,
	).Scan(&event.CreatedAt)
}

// GetUserRecentLoginRiskEvents returns the most recent login risk events for
// a user, ordered newest-first. `since` filters out events older than that.
// `limit` caps the result set; pass <= 0 for the default 50.
//
// Used by the user-facing /api/v1/auth/me/risk-events endpoint that powers
// the "Sign-in security events" section of accounts.example.com — surfaces
// MFA-challenged + blocked logins so users can spot suspicious activity.
func (r *RiskRepository) GetUserRecentLoginRiskEvents(
	ctx context.Context,
	userID uuid.UUID,
	since time.Time,
	limit int,
) ([]models.LoginRiskEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	query := `
		SELECT id, user_id, tenant_id, ip_address, user_agent, location,
		       total_score, level, signal_count, outcome,
		       mfa_trigger, block_reason, created_at,
		       asn, asn_org, city, region, is_vpn_hint
		FROM iam_login_risk_events
		WHERE user_id = $1 AND created_at >= $2
		ORDER BY created_at DESC
		LIMIT $3`

	rows, err := r.db.Query(ctx, query, userID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("GetUserRecentLoginRiskEvents: %w", err)
	}
	defer rows.Close()

	var events []models.LoginRiskEvent
	for rows.Next() {
		var event models.LoginRiskEvent
		var level string
		if err := rows.Scan(
			&event.ID, &event.UserID, &event.TenantID,
			&event.IPAddress, &event.UserAgent, &event.Location,
			&event.TotalScore, &level, &event.SignalCount, &event.Outcome,
			&event.MFATrigger, &event.BlockReason, &event.CreatedAt,
			&event.ASN, &event.ASNOrg, &event.City, &event.Region, &event.IsVPNHint,
		); err != nil {
			return nil, fmt.Errorf("GetUserRecentLoginRiskEvents: scan: %w", err)
		}
		event.Level = models.RiskLevel(level)
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserRecentLoginRiskEvents: rows: %w", err)
	}
	return events, nil
}

// GetUserLoginRiskEventsPaginated returns a page of login risk events for
// the user, ordered newest-first, together with the total row count for
// pagination UI. Backing query for /api/v1/auth/login-history once it
// switches off iam_sessions: iam_sessions only captures successful logins
// (rows are created post-auth), so failed attempts (blocked / mfa_failed)
// never appeared in the user-facing history. iam_login_risk_events is the
// per-attempt event log and shows the full picture.
func (r *RiskRepository) GetUserLoginRiskEventsPaginated(
	ctx context.Context,
	userID uuid.UUID,
	page, pageSize int,
) ([]models.LoginRiskEvent, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	var total int64
	if err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_login_risk_events WHERE user_id = $1`,
		userID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("GetUserLoginRiskEventsPaginated: count: %w", err)
	}

	query := `
		SELECT id, user_id, tenant_id, ip_address, user_agent, location,
		       total_score, level, signal_count, outcome,
		       mfa_trigger, block_reason, created_at,
		       asn, asn_org, city, region, is_vpn_hint
		FROM iam_login_risk_events
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.Query(ctx, query, userID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("GetUserLoginRiskEventsPaginated: %w", err)
	}
	defer rows.Close()

	events := make([]models.LoginRiskEvent, 0, pageSize)
	for rows.Next() {
		var event models.LoginRiskEvent
		var level string
		if err := rows.Scan(
			&event.ID, &event.UserID, &event.TenantID,
			&event.IPAddress, &event.UserAgent, &event.Location,
			&event.TotalScore, &level, &event.SignalCount, &event.Outcome,
			&event.MFATrigger, &event.BlockReason, &event.CreatedAt,
			&event.ASN, &event.ASNOrg, &event.City, &event.Region, &event.IsVPNHint,
		); err != nil {
			return nil, 0, fmt.Errorf("GetUserLoginRiskEventsPaginated: scan: %w", err)
		}
		event.Level = models.RiskLevel(level)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("GetUserLoginRiskEventsPaginated: rows: %w", err)
	}
	return events, total, nil
}

// CleanupOldSignals removes old resolved signals
func (r *RiskRepository) CleanupOldSignals(ctx context.Context, before time.Time) (int64, error) {
	result, err := r.db.Exec(ctx,
		`DELETE FROM iam_risk_signals WHERE resolved_at IS NOT NULL AND created_at < $1`,
		before)
	if err != nil {
		return 0, fmt.Errorf("CleanupOldSignals: %w", err)
	}
	return result.RowsAffected(), nil
}
