// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// agentIdentityRepository is the persistence interface consumed by AgentIdentityService.
// Using a local interface keeps the service decoupled from the concrete repository type
// and makes it straightforward to substitute a mock in tests.
type agentIdentityRepository interface {
	Create(ctx context.Context, agent *models.AgentIdentity) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.AgentIdentity, error)
	GetByClientID(ctx context.Context, clientID string) (*models.AgentIdentity, error)
	List(ctx context.Context, tenantID uuid.UUID, filters models.AgentListFilters, page, pageSize int) ([]models.AgentIdentity, int64, error)
	Update(ctx context.Context, agent *models.AgentIdentity) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.AgentStatus) error
	RotateSecret(ctx context.Context, id uuid.UUID, secretHash string) error
	IncrementRequestCount(ctx context.Context, id uuid.UUID) error
	InsertActivityLog(ctx context.Context, entry *models.AgentActivityLog) error
	ListActivityLog(ctx context.Context, agentID uuid.UUID, page, pageSize int) ([]models.AgentActivityLog, int64, error)
}

// defaultMaxTokenTTL is the default access token TTL in seconds for agents.
// This is intentionally shorter than human tokens (typically 15–60 min) to
// limit the blast radius of a compromised agent credential.
const defaultMaxTokenTTL = 300 // 5 minutes

// clientIDPrefix is prepended to all generated agent client IDs so they are
// easy to recognise in logs and policies.
const clientIDPrefix = "agent_"

// AgentIdentityService manages the full lifecycle of AI agent identities.
type AgentIdentityService struct {
	repo   agentIdentityRepository
	config *config.Config
}

// NewAgentIdentityService creates a new AgentIdentityService.
func NewAgentIdentityService(repo agentIdentityRepository, cfg *config.Config) *AgentIdentityService {
	return &AgentIdentityService{repo: repo, config: cfg}
}

// CreateAgentResult bundles the persisted agent with the one-time plain-text
// secret.  Callers must return client_secret to the API consumer and never
// store it in plaintext.
type CreateAgentResult struct {
	Agent        *models.AgentIdentity
	ClientSecret string // plain-text; returned once
}

// CreateAgent registers a new agent identity and generates OAuth2 client
// credentials (client_id + client_secret).
func (s *AgentIdentityService) CreateAgent(ctx context.Context, tenantID uuid.UUID, req *models.CreateAgentRequest) (*CreateAgentResult, error) {
	clientSecret, secretHash, err := generateAgentClientSecret()
	if err != nil {
		return nil, fmt.Errorf("AgentIdentityService.CreateAgent: generate secret: %w", err)
	}

	clientID := clientIDPrefix + strings.ReplaceAll(uuid.New().String(), "-", "")[:24]

	ttl := req.MaxTokenTTL
	if ttl == 0 {
		ttl = defaultMaxTokenTTL
	}

	tier := req.RateLimitTier
	if tier == "" {
		tier = models.RateLimitTierStandard
	}

	now := time.Now()
	agent := &models.AgentIdentity{
		ID:               uuid.New(),
		TenantID:         tenantID,
		Name:             req.Name,
		Description:      req.Description,
		Type:             req.Type,
		OwnerUserID:      req.OwnerUserID,
		Status:           models.AgentStatusActive,
		ClientID:         clientID,
		ClientSecretHash: secretHash,
		Capabilities:     normaliseStringSlice(req.Capabilities),
		AllowedTools:     normaliseStringSlice(req.AllowedTools),
		MaxTokenTTL:      ttl,
		RateLimitTier:    tier,
		AllowedTenants:   req.AllowedTenants,
		AllowedAPIs:      normaliseStringSlice(req.AllowedAPIs),
		IPAllowlist:      normaliseStringSlice(req.IPAllowlist),
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if agent.AllowedTenants == nil {
		agent.AllowedTenants = []uuid.UUID{}
	}

	if err := s.repo.Create(ctx, agent); err != nil {
		return nil, fmt.Errorf("AgentIdentityService.CreateAgent: %w", err)
	}

	_ = s.recordActivity(ctx, AgentActivityParams{AgentID: agent.ID, TenantID: agent.TenantID, Action: "agent_created", Success: true})

	logger.Info("Agent identity created",
		zap.String("agent_id", agent.ID.String()),
		zap.String("client_id", agent.ClientID),
		zap.String("type", string(agent.Type)),
	)

	return &CreateAgentResult{Agent: agent, ClientSecret: clientSecret}, nil
}

// GetAgent retrieves an agent by ID, scoped to the given tenant.
func (s *AgentIdentityService) GetAgent(ctx context.Context, tenantID, agentID uuid.UUID) (*models.AgentIdentity, error) {
	agent, err := s.repo.GetByID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if agent.TenantID != tenantID {
		// Return same error as not-found to prevent cross-tenant enumeration.
		return nil, fmt.Errorf("agent not found")
	}
	return agent, nil
}

// ListAgents returns a paginated, filtered list of agents for a tenant.
func (s *AgentIdentityService) ListAgents(
	ctx context.Context,
	tenantID uuid.UUID,
	filters models.AgentListFilters,
	page, pageSize int,
) (*models.AgentListResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	agents, total, err := s.repo.List(ctx, tenantID, filters, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("AgentIdentityService.ListAgents: %w", err)
	}

	responses := make([]models.AgentResponse, len(agents))
	for i, a := range agents {
		responses[i] = a.ToResponse()
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize != 0 {
		totalPages++
	}

	return &models.AgentListResponse{
		Agents:     responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// UpdateAgent applies partial updates to an existing agent identity.
func (s *AgentIdentityService) UpdateAgent(ctx context.Context, tenantID, agentID uuid.UUID, req *models.UpdateAgentRequest) (*models.AgentIdentity, error) {
	agent, err := s.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return nil, err
	}

	if agent.Status == models.AgentStatusRevoked {
		return nil, fmt.Errorf("cannot update a revoked agent")
	}

	if req.Name != nil {
		agent.Name = *req.Name
	}
	if req.Description != nil {
		agent.Description = *req.Description
	}
	if req.OwnerUserID != nil {
		agent.OwnerUserID = req.OwnerUserID
	}
	if req.Capabilities != nil {
		agent.Capabilities = normaliseStringSlice(req.Capabilities)
	}
	if req.AllowedTools != nil {
		agent.AllowedTools = normaliseStringSlice(req.AllowedTools)
	}
	if req.MaxTokenTTL != nil {
		agent.MaxTokenTTL = *req.MaxTokenTTL
	}
	if req.RateLimitTier != nil {
		agent.RateLimitTier = *req.RateLimitTier
	}
	if req.AllowedTenants != nil {
		agent.AllowedTenants = req.AllowedTenants
	}
	if req.AllowedAPIs != nil {
		agent.AllowedAPIs = normaliseStringSlice(req.AllowedAPIs)
	}
	if req.IPAllowlist != nil {
		agent.IPAllowlist = normaliseStringSlice(req.IPAllowlist)
	}

	agent.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, agent); err != nil {
		return nil, fmt.Errorf("AgentIdentityService.UpdateAgent: %w", err)
	}

	return agent, nil
}

// SuspendAgent transitions an active agent to "suspended".
// Suspended agents cannot authenticate or receive new tokens but can be reactivated.
func (s *AgentIdentityService) SuspendAgent(ctx context.Context, tenantID, agentID uuid.UUID, actorID *uuid.UUID) error {
	agent, err := s.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return err
	}
	if agent.Status != models.AgentStatusActive {
		return fmt.Errorf("agent is not active (current status: %s)", agent.Status)
	}

	if err := s.repo.UpdateStatus(ctx, agentID, models.AgentStatusSuspended); err != nil {
		return fmt.Errorf("AgentIdentityService.SuspendAgent: %w", err)
	}

	_ = s.recordActivity(ctx, AgentActivityParams{AgentID: agentID, TenantID: tenantID, Action: "agent_suspended", ActorID: actorID, Success: true})

	logger.Info("Agent suspended",
		zap.String("agent_id", agentID.String()),
		zap.Any("actor_id", actorID),
	)
	return nil
}

// RevokeAgent permanently revokes an agent.  Revoked agents cannot be reactivated.
func (s *AgentIdentityService) RevokeAgent(ctx context.Context, tenantID, agentID uuid.UUID, actorID *uuid.UUID) error {
	agent, err := s.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return err
	}
	if agent.Status == models.AgentStatusRevoked {
		return fmt.Errorf("agent is already revoked")
	}

	if err := s.repo.UpdateStatus(ctx, agentID, models.AgentStatusRevoked); err != nil {
		return fmt.Errorf("AgentIdentityService.RevokeAgent: %w", err)
	}

	_ = s.recordActivity(ctx, AgentActivityParams{AgentID: agentID, TenantID: tenantID, Action: "agent_revoked", ActorID: actorID, Success: true})

	logger.Info("Agent revoked",
		zap.String("agent_id", agentID.String()),
		zap.Any("actor_id", actorID),
	)
	return nil
}

// AuthenticateAgent validates client_credentials and returns the agent identity
// if credentials are correct and the agent is active.
func (s *AgentIdentityService) AuthenticateAgent(ctx context.Context, clientID, clientSecret string) (*models.AgentIdentity, error) {
	agent, err := s.repo.GetByClientID(ctx, clientID)
	if err != nil {
		// Prevent timing-based client_id enumeration: always hash even on miss.
		_ = hashSecretConstantTime(clientSecret)
		return nil, fmt.Errorf("invalid client credentials")
	}

	if agent.Status != models.AgentStatusActive {
		return nil, fmt.Errorf("agent is not active (status: %s)", agent.Status)
	}

	ok, err := crypto.VerifyPassword(clientSecret, agent.ClientSecretHash)
	if err != nil || !ok {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return agent, nil
}

// GenerateAgentToken issues a short-lived JWT for the given agent.
// The token carries agent-specific claims (type="agent") so validators can
// distinguish it from human user tokens.
func (s *AgentIdentityService) GenerateAgentToken(_ context.Context, agent *models.AgentIdentity) (*models.AgentTokenResponse, error) {
	now := time.Now()
	ttl := time.Duration(agent.MaxTokenTTL) * time.Second
	if ttl <= 0 {
		ttl = defaultMaxTokenTTL * time.Second
	}
	expiresAt := now.Add(ttl)

	claims := jwt.MapClaims{
		"iss":          s.config.JWTIssuer,
		"sub":          agent.ID.String(),
		"agent_id":     agent.ID.String(),
		"agent_name":   agent.Name,
		"agent_type":   string(agent.Type),
		"type":         "agent",
		"tenant_id":    agent.TenantID.String(),
		"capabilities": agent.Capabilities,
		"iat":          now.Unix(),
		"exp":          expiresAt.Unix(),
		"nbf":          now.Unix(),
		"jti":          uuid.New().String(),
	}
	if agent.OwnerUserID != nil {
		claims["owner_id"] = agent.OwnerUserID.String()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		return nil, fmt.Errorf("AgentIdentityService.GenerateAgentToken: sign: %w", err)
	}

	// Best-effort: bump counter without blocking token issuance.
	go func() { //nolint:gosec // goroutine must outlive request context
		bkgCtx := context.Background()
		_ = s.repo.IncrementRequestCount(bkgCtx, agent.ID)
		_ = s.recordActivity(bkgCtx, AgentActivityParams{AgentID: agent.ID, TenantID: agent.TenantID, Action: "token_issued", Success: true})
	}()

	return &models.AgentTokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   agent.MaxTokenTTL,
		ExpiresAt:   expiresAt,
	}, nil
}

// RotateCredentials generates a new client secret for an agent and returns the
// plain-text value once.
func (s *AgentIdentityService) RotateCredentials(ctx context.Context, tenantID, agentID uuid.UUID) (string, error) {
	agent, err := s.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return "", err
	}
	if agent.Status == models.AgentStatusRevoked {
		return "", fmt.Errorf("cannot rotate credentials of a revoked agent")
	}

	clientSecret, secretHash, err := generateAgentClientSecret()
	if err != nil {
		return "", fmt.Errorf("AgentIdentityService.RotateCredentials: %w", err)
	}

	if err := s.repo.RotateSecret(ctx, agentID, secretHash); err != nil {
		return "", fmt.Errorf("AgentIdentityService.RotateCredentials: %w", err)
	}

	_ = s.recordActivity(ctx, AgentActivityParams{AgentID: agentID, TenantID: tenantID, Action: "credentials_rotated", Success: true})

	logger.Info("Agent credentials rotated",
		zap.String("agent_id", agentID.String()),
	)

	return clientSecret, nil
}

// ValidateAgentScope checks whether the agent is permitted to call the given
// HTTP method + path combination.  An empty AllowedAPIs list grants access to
// all paths (open policy).
func (s *AgentIdentityService) ValidateAgentScope(ctx context.Context, agentID uuid.UUID, path, _ string) (bool, error) {
	agent, err := s.repo.GetByID(ctx, agentID)
	if err != nil {
		return false, err
	}
	if agent.Status != models.AgentStatusActive {
		return false, nil
	}
	if len(agent.AllowedAPIs) == 0 {
		return true, nil
	}
	for _, prefix := range agent.AllowedAPIs {
		if strings.HasPrefix(path, prefix) {
			return true, nil
		}
	}
	return false, nil
}

// AgentActivityParams groups the parameters for recording agent activity,
// reducing function parameter counts below the project linting threshold.
type AgentActivityParams struct {
	AgentID   uuid.UUID
	TenantID  uuid.UUID
	Action    string
	Path      *string
	Method    *string
	IPAddress *string
	ActorID   *uuid.UUID
	Success   bool
}

// RecordAgentActivity appends an audit entry to the agent activity log.
// Callers should treat errors as non-fatal; audit failures must never block
// the primary request path.
func (s *AgentIdentityService) RecordAgentActivity(ctx context.Context, p AgentActivityParams) {
	_ = s.recordActivity(ctx, p)
}

// GetActivityLog returns paginated activity log entries for an agent.
func (s *AgentIdentityService) GetActivityLog(
	ctx context.Context,
	tenantID, agentID uuid.UUID,
	page, pageSize int,
) (*models.AgentActivityListResponse, error) {
	// Verify tenant ownership before exposing log.
	if _, err := s.GetAgent(ctx, tenantID, agentID); err != nil {
		return nil, err
	}

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	entries, total, err := s.repo.ListActivityLog(ctx, agentID, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("AgentIdentityService.GetActivityLog: %w", err)
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize != 0 {
		totalPages++
	}

	return &models.AgentActivityListResponse{
		Events:     entries,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// ==================== internal helpers ====================

func (s *AgentIdentityService) recordActivity(ctx context.Context, p AgentActivityParams) error {
	entry := &models.AgentActivityLog{
		ID:        uuid.New(),
		AgentID:   p.AgentID,
		TenantID:  p.TenantID,
		Action:    p.Action,
		Path:      p.Path,
		Method:    p.Method,
		IPAddress: p.IPAddress,
		ActorID:   p.ActorID,
		Success:   p.Success,
		CreatedAt: time.Now(),
	}
	return s.repo.InsertActivityLog(ctx, entry)
}

// AgentAPICallParams groups the parameters for RecordAgentAPICall,
// reducing its parameter count below the project linting threshold.
type AgentAPICallParams struct {
	AgentID   uuid.UUID
	TenantID  uuid.UUID
	Path      string
	Method    string
	IPAddress string
	Success   bool
	Details   map[string]interface{}
}

// RecordAgentAPICall records an individual API call made by an agent and
// optionally includes the parsed details as a JSON blob.
func (s *AgentIdentityService) RecordAgentAPICall(ctx context.Context, p AgentAPICallParams) {
	entry := &models.AgentActivityLog{
		ID:       uuid.New(),
		AgentID:  p.AgentID,
		TenantID: p.TenantID,
		Action:   "api_call",
		Path:     &p.Path,
		Method:   &p.Method,
		Success:  p.Success,
	}
	if p.IPAddress != "" {
		entry.IPAddress = &p.IPAddress
	}
	if len(p.Details) > 0 {
		if b, err := json.Marshal(p.Details); err == nil {
			s := string(b)
			entry.Details = s
		}
	}
	_ = s.repo.InsertActivityLog(ctx, entry)
}

// generateAgentClientSecret produces a cryptographically random 40-byte secret
// encoded as URL-safe base64, and its Argon2id hash.
func generateAgentClientSecret() (plaintext, hash string, err error) {
	b := make([]byte, 40)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generateClientSecret: %w", err)
	}
	plaintext = base64.RawURLEncoding.EncodeToString(b)

	hash, err = crypto.HashPassword(plaintext, nil)
	if err != nil {
		return "", "", fmt.Errorf("generateClientSecret: hash: %w", err)
	}
	return plaintext, hash, nil
}

// hashSecretConstantTime is a best-effort constant-time sink used to prevent
// timing-based client_id enumeration when no agent is found.
func hashSecretConstantTime(s string) string {
	h, _ := crypto.HashPassword(s, nil)
	return h
}

// normaliseStringSlice ensures nil slices become empty slices so JSON responses
// render as [] instead of null.
func normaliseStringSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
