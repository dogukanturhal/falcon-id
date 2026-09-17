// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// AgentType classifies the nature and autonomy level of an AI agent.
type AgentType string

const (
	// AgentTypeAutonomous is a fully autonomous agent that acts on its own
	// schedule — background jobs, scheduled workflows, autonomous decision loops.
	AgentTypeAutonomous AgentType = "autonomous"

	// AgentTypeInteractive is a user-facing assistant that acts on explicit
	// human triggers — chat agents, copilots, inline assistants.
	AgentTypeInteractive AgentType = "interactive"

	// AgentTypeMCPServer is a Model Context Protocol server that exposes tools
	// to LLM orchestrators.
	AgentTypeMCPServer AgentType = "mcp_server"

	// AgentTypeWorkflow is a multi-step orchestrated workflow agent that chains
	// tool calls and LLM inference steps.
	AgentTypeWorkflow AgentType = "workflow"
)

// AgentStatus represents the current lifecycle state of an agent identity.
type AgentStatus string

const (
	// AgentStatusActive is an exported identifier.
	AgentStatusActive AgentStatus = "active"
	// AgentStatusSuspended is an exported identifier.
	AgentStatusSuspended AgentStatus = "suspended"
	// AgentStatusRevoked is an exported identifier.
	AgentStatusRevoked AgentStatus = "revoked"
)

// RateLimitTier governs how aggressively an agent's token requests are throttled.
type RateLimitTier string

const (
	// RateLimitTierStandard is an exported identifier.
	RateLimitTierStandard RateLimitTier = "standard"
	// RateLimitTierElevated is an exported identifier.
	RateLimitTierElevated RateLimitTier = "elevated"
	// RateLimitTierUnlimited is an exported identifier.
	RateLimitTierUnlimited RateLimitTier = "unlimited"
)

// AgentIdentity is the first-class identity record for an AI agent.
//
// AI agents are distinct from human users and traditional service principals:
// they are owned by a human (accountability), constrained to a declared set of
// capabilities, and issued short-lived tokens by default to limit blast radius
// if an agent misbehaves or is compromised.
type AgentIdentity struct {
	ID          uuid.UUID   `json:"id" db:"id"`
	TenantID    uuid.UUID   `json:"tenant_id" db:"tenant_id"`
	Name        string      `json:"name" db:"name"`
	Description string      `json:"description" db:"description"`
	Type        AgentType   `json:"type" db:"type"`
	OwnerUserID *uuid.UUID  `json:"owner_user_id,omitempty" db:"owner_user_id"`
	Status      AgentStatus `json:"status" db:"status"`

	// Credentials — ClientID is public; ClientSecretHash is stored hashed.
	// The plain-text secret is returned once at creation/rotation time only.
	ClientID         string `json:"client_id" db:"client_id"`
	ClientSecretHash string `json:"-" db:"client_secret_hash"`

	// Capability grants — what this agent is allowed to do.
	Capabilities []string `json:"capabilities" db:"capabilities"`   // e.g. ["read:invoices","write:reports"]
	AllowedTools []string `json:"allowed_tools" db:"allowed_tools"` // MCP tool names

	// Token policy.
	MaxTokenTTL   int           `json:"max_token_ttl" db:"max_token_ttl"` // seconds; default 300
	RateLimitTier RateLimitTier `json:"rate_limit_tier" db:"rate_limit_tier"`

	// Scoping — restrict the blast radius of a compromised agent.
	AllowedTenants []uuid.UUID `json:"allowed_tenants" db:"allowed_tenants"` // cross-tenant access list; nil = own tenant only
	AllowedAPIs    []string    `json:"allowed_apis" db:"allowed_apis"`       // allowed URL path prefixes
	IPAllowlist    []string    `json:"ip_allowlist" db:"ip_allowlist"`       // CIDRs/IPs; empty = unrestricted

	// Audit counters (incremented asynchronously, not transactionally).
	TotalRequests   int64 `json:"total_requests" db:"total_requests"`
	TotalTokensUsed int64 `json:"total_tokens_used" db:"total_tokens_used"`

	LastActiveAt *time.Time `json:"last_active_at,omitempty" db:"last_active_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
}

// AgentActivityLog is an immutable audit record for agent token issuance and
// API calls.  Agents have their own activity log separate from the human audit
// log so operators can filter agent traffic without noise from human sessions.
type AgentActivityLog struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	AgentID   uuid.UUID  `json:"agent_id" db:"agent_id"`
	TenantID  uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Action    string     `json:"action" db:"action"` // "token_issued", "api_call", "suspended", "revoked", "credentials_rotated"
	Path      *string    `json:"path,omitempty" db:"path"`
	Method    *string    `json:"method,omitempty" db:"method"`
	IPAddress *string    `json:"ip_address,omitempty" db:"ip_address"`
	Success   bool       `json:"success" db:"success"`
	Details   string     `json:"details,omitempty" db:"details"` // JSON string for flexibility
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	ActorID   *uuid.UUID `json:"actor_id,omitempty" db:"actor_id"` // human who triggered the action (suspend/revoke)
}

// ==================== Request / Response DTOs ====================

// CreateAgentRequest is the payload for registering a new agent identity.
type CreateAgentRequest struct {
	Name           string        `json:"name" binding:"required,min=2,max=255"`
	Description    string        `json:"description" binding:"omitempty,max=1024"`
	Type           AgentType     `json:"type" binding:"required,oneof=autonomous interactive mcp_server workflow"`
	OwnerUserID    *uuid.UUID    `json:"owner_user_id,omitempty"`
	Capabilities   []string      `json:"capabilities" binding:"omitempty"`
	AllowedTools   []string      `json:"allowed_tools" binding:"omitempty"`
	MaxTokenTTL    int           `json:"max_token_ttl" binding:"omitempty,min=60,max=3600"` // seconds
	RateLimitTier  RateLimitTier `json:"rate_limit_tier" binding:"omitempty,oneof=standard elevated unlimited"`
	AllowedTenants []uuid.UUID   `json:"allowed_tenants" binding:"omitempty"`
	AllowedAPIs    []string      `json:"allowed_apis" binding:"omitempty"`
	IPAllowlist    []string      `json:"ip_allowlist" binding:"omitempty"`
}

// UpdateAgentRequest carries the partial fields that may be mutated.
type UpdateAgentRequest struct {
	Name           *string        `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	Description    *string        `json:"description,omitempty" binding:"omitempty,max=1024"`
	OwnerUserID    *uuid.UUID     `json:"owner_user_id,omitempty"`
	Capabilities   []string       `json:"capabilities,omitempty"`
	AllowedTools   []string       `json:"allowed_tools,omitempty"`
	MaxTokenTTL    *int           `json:"max_token_ttl,omitempty" binding:"omitempty,min=60,max=3600"`
	RateLimitTier  *RateLimitTier `json:"rate_limit_tier,omitempty" binding:"omitempty,oneof=standard elevated unlimited"`
	AllowedTenants []uuid.UUID    `json:"allowed_tenants,omitempty"`
	AllowedAPIs    []string       `json:"allowed_apis,omitempty"`
	IPAllowlist    []string       `json:"ip_allowlist,omitempty"`
}

// AgentResponse is the public view of an agent identity (no secret material).
type AgentResponse struct {
	ID             uuid.UUID     `json:"id"`
	TenantID       uuid.UUID     `json:"tenant_id"`
	Name           string        `json:"name"`
	Description    string        `json:"description"`
	Type           AgentType     `json:"type"`
	OwnerUserID    *uuid.UUID    `json:"owner_user_id,omitempty"`
	Status         AgentStatus   `json:"status"`
	ClientID       string        `json:"client_id"`
	Capabilities   []string      `json:"capabilities"`
	AllowedTools   []string      `json:"allowed_tools"`
	MaxTokenTTL    int           `json:"max_token_ttl"`
	RateLimitTier  RateLimitTier `json:"rate_limit_tier"`
	AllowedTenants []uuid.UUID   `json:"allowed_tenants"`
	AllowedAPIs    []string      `json:"allowed_apis"`
	IPAllowlist    []string      `json:"ip_allowlist"`
	TotalRequests  int64         `json:"total_requests"`
	LastActiveAt   *time.Time    `json:"last_active_at,omitempty"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

// CreateAgentResponse extends AgentResponse with the one-time plain-text secret.
type CreateAgentResponse struct {
	AgentResponse
	ClientSecret string `json:"client_secret"` // shown once; store securely
}

// AgentListResponse is a paginated list of agent identities.
type AgentListResponse struct {
	Agents     []AgentResponse `json:"agents"`
	Total      int64           `json:"total"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
	TotalPages int             `json:"total_pages"`
}

// AgentTokenRequest is the client_credentials grant body sent by an agent.
type AgentTokenRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
}

// AgentTokenResponse carries the issued JWT and metadata.
type AgentTokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresIn   int       `json:"expires_in"` // seconds
	ExpiresAt   time.Time `json:"expires_at"`
}

// AgentClaims are the JWT claims embedded in an agent access token.
// They extend the token with agent-specific fields to distinguish from
// human tokens at validation time.
type AgentClaims struct {
	Issuer       string     `json:"iss"`
	Subject      string     `json:"sub"` // agent UUID
	TenantID     uuid.UUID  `json:"tenant_id"`
	AgentID      uuid.UUID  `json:"agent_id"`
	AgentName    string     `json:"agent_name"`
	AgentType    AgentType  `json:"agent_type"`
	TokenType    string     `json:"type"`         // always "agent"
	Capabilities []string   `json:"capabilities"` // granted capability strings
	OwnerID      *uuid.UUID `json:"owner_id,omitempty"`
	IssuedAt     int64      `json:"iat"`
	ExpiresAt    int64      `json:"exp"`
	NotBefore    int64      `json:"nbf"`
}

// AgentActivityListResponse is a paginated list of activity log entries.
type AgentActivityListResponse struct {
	Events     []AgentActivityLog `json:"events"`
	Total      int64              `json:"total"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	TotalPages int                `json:"total_pages"`
}

// AgentListFilters specifies optional filters for ListAgents.
type AgentListFilters struct {
	Type        *AgentType
	Status      *AgentStatus
	OwnerUserID *uuid.UUID
	Search      string
}

// ToResponse is an exported identifier.
// AgentIdentity is an exported identifier.
// AgentIdentity is an exported identifier.
// toResponse converts an AgentIdentity to its public API representation.
func (a *AgentIdentity) ToResponse() AgentResponse {
	caps := a.Capabilities
	if caps == nil {
		caps = []string{}
	}
	tools := a.AllowedTools
	if tools == nil {
		tools = []string{}
	}
	apis := a.AllowedAPIs
	if apis == nil {
		apis = []string{}
	}
	ips := a.IPAllowlist
	if ips == nil {
		ips = []string{}
	}
	tenants := a.AllowedTenants
	if tenants == nil {
		tenants = []uuid.UUID{}
	}
	return AgentResponse{
		ID:             a.ID,
		TenantID:       a.TenantID,
		Name:           a.Name,
		Description:    a.Description,
		Type:           a.Type,
		OwnerUserID:    a.OwnerUserID,
		Status:         a.Status,
		ClientID:       a.ClientID,
		Capabilities:   caps,
		AllowedTools:   tools,
		MaxTokenTTL:    a.MaxTokenTTL,
		RateLimitTier:  a.RateLimitTier,
		AllowedTenants: tenants,
		AllowedAPIs:    apis,
		IPAllowlist:    ips,
		TotalRequests:  a.TotalRequests,
		LastActiveAt:   a.LastActiveAt,
		CreatedAt:      a.CreatedAt,
		UpdatedAt:      a.UpdatedAt,
	}
}
