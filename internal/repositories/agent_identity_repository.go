// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const msgAgentNotFound = "agent not found"

// AgentIdentityRepository handles PostgreSQL persistence for agent identities
// and their activity log.
type AgentIdentityRepository struct {
	pool *pgxpool.Pool
}

// NewAgentIdentityRepository creates a new AgentIdentityRepository.
func NewAgentIdentityRepository(pool *pgxpool.Pool) *AgentIdentityRepository {
	return &AgentIdentityRepository{pool: pool}
}

// agentColumns lists every column in iam_agent_identities in the exact order
// used by Scan calls throughout this file.
const agentColumns = `
	id, tenant_id, name, description, type, owner_user_id, status,
	client_id, client_secret_hash,
	capabilities, allowed_tools,
	max_token_ttl, rate_limit_tier,
	allowed_tenants, allowed_apis, ip_allowlist,
	total_requests, total_tokens_used,
	last_active_at, created_at, updated_at`

func scanAgent(row pgx.Row) (*models.AgentIdentity, error) {
	a := &models.AgentIdentity{}
	err := row.Scan(
		&a.ID, &a.TenantID, &a.Name, &a.Description, &a.Type,
		&a.OwnerUserID, &a.Status,
		&a.ClientID, &a.ClientSecretHash,
		&a.Capabilities, &a.AllowedTools,
		&a.MaxTokenTTL, &a.RateLimitTier,
		&a.AllowedTenants, &a.AllowedAPIs, &a.IPAllowlist,
		&a.TotalRequests, &a.TotalTokensUsed,
		&a.LastActiveAt, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Create inserts a new agent identity record.
func (r *AgentIdentityRepository) Create(ctx context.Context, agent *models.AgentIdentity) error {
	query := `
		INSERT INTO iam_agent_identities (
			id, tenant_id, name, description, type, owner_user_id, status,
			client_id, client_secret_hash,
			capabilities, allowed_tools,
			max_token_ttl, rate_limit_tier,
			allowed_tenants, allowed_apis, ip_allowlist,
			total_requests, total_tokens_used,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9,
			$10, $11,
			$12, $13,
			$14, $15, $16,
			$17, $18,
			$19, $20
		)`

	_, err := r.pool.Exec(ctx, query,
		agent.ID, agent.TenantID, agent.Name, agent.Description, agent.Type,
		agent.OwnerUserID, agent.Status,
		agent.ClientID, agent.ClientSecretHash,
		agent.Capabilities, agent.AllowedTools,
		agent.MaxTokenTTL, agent.RateLimitTier,
		agent.AllowedTenants, agent.AllowedAPIs, agent.IPAllowlist,
		agent.TotalRequests, agent.TotalTokensUsed,
		agent.CreatedAt, agent.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("AgentIdentityRepository.Create: %w", err)
	}
	return nil
}

// GetByID retrieves an agent identity by its UUID.
func (r *AgentIdentityRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AgentIdentity, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_agent_identities WHERE id = $1`, agentColumns)
	agent, err := scanAgent(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgAgentNotFound)
		}
		return nil, fmt.Errorf("AgentIdentityRepository.GetByID: %w", err)
	}
	return agent, nil
}

// GetByClientID retrieves an agent identity by its OAuth client_id.
func (r *AgentIdentityRepository) GetByClientID(ctx context.Context, clientID string) (*models.AgentIdentity, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_agent_identities WHERE client_id = $1`, agentColumns)
	agent, err := scanAgent(r.pool.QueryRow(ctx, query, clientID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgAgentNotFound)
		}
		return nil, fmt.Errorf("AgentIdentityRepository.GetByClientID: %w", err)
	}
	return agent, nil
}

// List returns a filtered, paginated list of agents for a given tenant.
func (r *AgentIdentityRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	filters models.AgentListFilters,
	page, pageSize int,
) ([]models.AgentIdentity, int64, error) {
	offset := (page - 1) * pageSize

	where := []string{"tenant_id = $1"}
	args := []interface{}{tenantID}
	idx := 2

	if filters.Type != nil {
		where = append(where, fmt.Sprintf("type = $%d", idx))
		args = append(args, string(*filters.Type))
		idx++
	}
	if filters.Status != nil {
		where = append(where, fmt.Sprintf("status = $%d", idx))
		args = append(args, string(*filters.Status))
		idx++
	}
	if filters.OwnerUserID != nil {
		where = append(where, fmt.Sprintf("owner_user_id = $%d", idx))
		args = append(args, *filters.OwnerUserID)
		idx++
	}
	if filters.Search != "" {
		where = append(where, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", idx, idx))
		args = append(args, "%"+filters.Search+"%")
		idx++
	}

	whereClause := strings.Join(where, " AND ")

	// Count
	var total int64
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM iam_agent_identities WHERE %s`, whereClause)
	if err := r.pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("AgentIdentityRepository.List count: %w", err)
	}

	// Rows
	listQuery := fmt.Sprintf(`
		SELECT %s
		FROM iam_agent_identities
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		agentColumns, whereClause, idx, idx+1,
	)
	args = append(args, pageSize, offset)

	rows, err := r.pool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("AgentIdentityRepository.List query: %w", err)
	}
	defer rows.Close()

	var agents []models.AgentIdentity
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("AgentIdentityRepository.List scan: %w", err)
		}
		agents = append(agents, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("AgentIdentityRepository.List rows: %w", err)
	}

	if agents == nil {
		agents = []models.AgentIdentity{}
	}
	return agents, total, nil
}

// Update persists mutable fields of an agent identity.
func (r *AgentIdentityRepository) Update(ctx context.Context, agent *models.AgentIdentity) error {
	query := `
		UPDATE iam_agent_identities SET
			name = $1, description = $2, owner_user_id = $3, status = $4,
			capabilities = $5, allowed_tools = $6,
			max_token_ttl = $7, rate_limit_tier = $8,
			allowed_tenants = $9, allowed_apis = $10, ip_allowlist = $11,
			updated_at = $12
		WHERE id = $13 AND tenant_id = $14`

	result, err := r.pool.Exec(ctx, query,
		agent.Name, agent.Description, agent.OwnerUserID, agent.Status,
		agent.Capabilities, agent.AllowedTools,
		agent.MaxTokenTTL, agent.RateLimitTier,
		agent.AllowedTenants, agent.AllowedAPIs, agent.IPAllowlist,
		agent.UpdatedAt,
		agent.ID, agent.TenantID,
	)
	if err != nil {
		return fmt.Errorf("AgentIdentityRepository.Update: %w", err)
	}
	if result.RowsAffected() == 0 {
		return errors.New(msgAgentNotFound)
	}
	return nil
}

// UpdateStatus changes the agent status (active / suspended / revoked).
func (r *AgentIdentityRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.AgentStatus) error {
	query := `UPDATE iam_agent_identities SET status = $1, updated_at = $2 WHERE id = $3`
	result, err := r.pool.Exec(ctx, query, string(status), time.Now(), id)
	if err != nil {
		return fmt.Errorf("AgentIdentityRepository.UpdateStatus: %w", err)
	}
	if result.RowsAffected() == 0 {
		return errors.New(msgAgentNotFound)
	}
	return nil
}

// RotateSecret replaces the hashed client secret.
func (r *AgentIdentityRepository) RotateSecret(ctx context.Context, id uuid.UUID, secretHash string) error {
	query := `UPDATE iam_agent_identities SET client_secret_hash = $1, updated_at = $2 WHERE id = $3`
	result, err := r.pool.Exec(ctx, query, secretHash, time.Now(), id)
	if err != nil {
		return fmt.Errorf("AgentIdentityRepository.RotateSecret: %w", err)
	}
	if result.RowsAffected() == 0 {
		return errors.New(msgAgentNotFound)
	}
	return nil
}

// IncrementRequestCount atomically bumps the request counter and updates last_active_at.
func (r *AgentIdentityRepository) IncrementRequestCount(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE iam_agent_identities
		SET total_requests = total_requests + 1, last_active_at = $1
		WHERE id = $2`
	_, err := r.pool.Exec(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("AgentIdentityRepository.IncrementRequestCount: %w", err)
	}
	return nil
}

// ==================== Activity Log ====================

// InsertActivityLog appends an immutable audit record for an agent action.
func (r *AgentIdentityRepository) InsertActivityLog(ctx context.Context, entry *models.AgentActivityLog) error {
	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}
	query := `
		INSERT INTO iam_agent_activity_log (
			id, agent_id, tenant_id, action, path, method,
			ip_address, success, details, created_at, actor_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := r.pool.Exec(ctx, query,
		entry.ID, entry.AgentID, entry.TenantID, entry.Action,
		entry.Path, entry.Method, entry.IPAddress,
		entry.Success, entry.Details, entry.CreatedAt, entry.ActorID,
	)
	if err != nil {
		return fmt.Errorf("AgentIdentityRepository.InsertActivityLog: %w", err)
	}
	return nil
}

// ListActivityLog returns paginated activity log entries for a given agent.
func (r *AgentIdentityRepository) ListActivityLog(
	ctx context.Context,
	agentID uuid.UUID,
	page, pageSize int,
) ([]models.AgentActivityLog, int64, error) {
	offset := (page - 1) * pageSize

	var total int64
	if err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_agent_activity_log WHERE agent_id = $1`,
		agentID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("AgentIdentityRepository.ListActivityLog count: %w", err)
	}

	rows, err := r.pool.Query(ctx, `
		SELECT id, agent_id, tenant_id, action, path, method,
		       ip_address, success, details, created_at, actor_id
		FROM iam_agent_activity_log
		WHERE agent_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`,
		agentID, pageSize, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("AgentIdentityRepository.ListActivityLog query: %w", err)
	}
	defer rows.Close()

	var entries []models.AgentActivityLog
	for rows.Next() {
		var e models.AgentActivityLog
		if err := rows.Scan(
			&e.ID, &e.AgentID, &e.TenantID, &e.Action,
			&e.Path, &e.Method, &e.IPAddress,
			&e.Success, &e.Details, &e.CreatedAt, &e.ActorID,
		); err != nil {
			return nil, 0, fmt.Errorf("AgentIdentityRepository.ListActivityLog scan: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("AgentIdentityRepository.ListActivityLog rows: %w", err)
	}

	if entries == nil {
		entries = []models.AgentActivityLog{}
	}
	return entries, total, nil
}
