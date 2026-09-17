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

// SAMLSPRepository handles SAML SP (inbound federation) database operations
type SAMLSPRepository struct {
	pool *pgxpool.Pool
}

// NewSAMLSPRepository creates a new SAMLSPRepository
func NewSAMLSPRepository(pool *pgxpool.Pool) *SAMLSPRepository {
	return &SAMLSPRepository{pool: pool}
}

// ==================== AuthnRequest Operations ====================

// CreateAuthnRequest stores a new SAML AuthnRequest for replay prevention
func (r *SAMLSPRepository) CreateAuthnRequest(ctx context.Context, req *models.SAMLSPAuthnRequest) error {
	if req.ID == uuid.Nil {
		req.ID = uuid.New()
	}
	req.CreatedAt = time.Now()

	query := `
		INSERT INTO iam_saml_sp_authn_requests (
			id, tenant_id, provider_id, request_id, relay_state,
			acs_url, ip_address, user_agent, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.pool.Exec(ctx, query,
		req.ID, req.TenantID, req.ProviderID, req.RequestID, req.RelayState,
		req.ACSURL, req.IPAddress, req.UserAgent, req.ExpiresAt, req.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("CreateAuthnRequest: %w", err)
	}
	return nil
}

// GetAuthnRequestByRequestID retrieves and consumes an AuthnRequest
func (r *SAMLSPRepository) GetAuthnRequestByRequestID(ctx context.Context, requestID string) (*models.SAMLSPAuthnRequest, error) {
	req := &models.SAMLSPAuthnRequest{}
	query := `
		SELECT id, tenant_id, provider_id, request_id, relay_state,
		       acs_url, ip_address, user_agent, consumed_at, expires_at, created_at
		FROM iam_saml_sp_authn_requests
		WHERE request_id = $1`

	err := r.pool.QueryRow(ctx, query, requestID).Scan(
		&req.ID, &req.TenantID, &req.ProviderID, &req.RequestID, &req.RelayState,
		&req.ACSURL, &req.IPAddress, &req.UserAgent, &req.ConsumedAt, &req.ExpiresAt, &req.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetAuthnRequestByRequestID: %w", err)
	}
	return req, nil
}

// ConsumeAuthnRequest marks an AuthnRequest as consumed (replay prevention)
func (r *SAMLSPRepository) ConsumeAuthnRequest(ctx context.Context, requestID string) error {
	query := `UPDATE iam_saml_sp_authn_requests SET consumed_at = now() WHERE request_id = $1 AND consumed_at IS NULL`
	result, err := r.pool.Exec(ctx, query, requestID)
	if err != nil {
		return fmt.Errorf("ConsumeAuthnRequest: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("authn request not found or already consumed")
	}
	return nil
}

// CleanupExpiredAuthnRequests removes expired requests
func (r *SAMLSPRepository) CleanupExpiredAuthnRequests(ctx context.Context) error {
	query := `DELETE FROM iam_saml_sp_authn_requests WHERE expires_at < now()`
	_, err := r.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("CleanupExpiredAuthnRequests: %w", err)
	}
	return nil
}

// ==================== Assertion Log Operations ====================

// CreateAssertionLog creates a new SAML SP assertion log entry
func (r *SAMLSPRepository) CreateAssertionLog(ctx context.Context, log *models.SAMLSPAssertionLog) error {
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}
	log.CreatedAt = time.Now()

	var attributesJSON []byte
	if log.Attributes != nil {
		var err error
		attributesJSON, err = json.Marshal(log.Attributes)
		if err != nil {
			return fmt.Errorf("CreateAssertionLog: marshal attributes: %w", err)
		}
	}

	query := `
		INSERT INTO iam_saml_sp_assertion_logs (
			id, tenant_id, provider_id, user_id, assertion_id, name_id,
			session_index, issuer, ip_address, user_agent,
			status, error_message, attributes, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	_, err := r.pool.Exec(ctx, query,
		log.ID, log.TenantID, log.ProviderID, log.UserID, log.AssertionID, log.NameID,
		log.SessionIndex, log.Issuer, log.IPAddress, log.UserAgent,
		log.Status, log.ErrorMessage, attributesJSON, log.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("CreateAssertionLog: %w", err)
	}
	return nil
}

// GetAssertionLogs retrieves assertion logs for a provider
func (r *SAMLSPRepository) GetAssertionLogs(ctx context.Context, providerID uuid.UUID, limit int) ([]*models.SAMLSPAssertionLog, error) {
	query := `
		SELECT id, tenant_id, provider_id, user_id, assertion_id, name_id,
		       session_index, issuer, ip_address, user_agent,
		       status, error_message, attributes, created_at
		FROM iam_saml_sp_assertion_logs
		WHERE provider_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.pool.Query(ctx, query, providerID, limit)
	if err != nil {
		return nil, fmt.Errorf("GetAssertionLogs: %w", err)
	}
	defer rows.Close()

	var logs []*models.SAMLSPAssertionLog
	for rows.Next() {
		log := &models.SAMLSPAssertionLog{}
		var attributesJSON []byte
		err := rows.Scan(
			&log.ID, &log.TenantID, &log.ProviderID, &log.UserID, &log.AssertionID, &log.NameID,
			&log.SessionIndex, &log.Issuer, &log.IPAddress, &log.UserAgent,
			&log.Status, &log.ErrorMessage, &attributesJSON, &log.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetAssertionLogs scan: %w", err)
		}
		if len(attributesJSON) > 0 {
			_ = json.Unmarshal(attributesJSON, &log.Attributes)
		}
		logs = append(logs, log)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetAssertionLogs iteration: %w", err)
	}
	return logs, nil
}
