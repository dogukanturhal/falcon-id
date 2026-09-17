// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// RoutingWebhookAction represents actions a routing webhook can return
type RoutingWebhookAction string

const (
	// RoutingWebhookActionRedirect is an exported identifier.
	RoutingWebhookActionRedirect RoutingWebhookAction = "redirect"
	// RoutingWebhookActionAllow is an exported identifier.
	RoutingWebhookActionAllow RoutingWebhookAction = "allow"
	// RoutingWebhookActionDeny is an exported identifier.
	RoutingWebhookActionDeny RoutingWebhookAction = "deny"
	// RoutingWebhookActionStepUpMFA is an exported identifier.
	RoutingWebhookActionStepUpMFA RoutingWebhookAction = "step_up_mfa"
	// RoutingWebhookActionPass is an exported identifier.
	RoutingWebhookActionPass RoutingWebhookAction = "pass" // defer to next webhook
)

// RoutingWebhookAuthType represents the webhook authentication type
type RoutingWebhookAuthType string

const (
	// RoutingWebhookAuthNone is an exported identifier.
	RoutingWebhookAuthNone RoutingWebhookAuthType = "none"
	// RoutingWebhookAuthBearer is an exported identifier.
	RoutingWebhookAuthBearer RoutingWebhookAuthType = "bearer"
	// RoutingWebhookAuthBasic is an exported identifier.
	RoutingWebhookAuthBasic RoutingWebhookAuthType = "basic"
	// RoutingWebhookAuthHMAC is an exported identifier.
	RoutingWebhookAuthHMAC RoutingWebhookAuthType = "hmac"
)

// RoutingWebhook represents a routing webhook configuration
type RoutingWebhook struct {
	ID          uuid.UUID `json:"id" db:"id"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	Description *string   `json:"description,omitempty" db:"description"`

	// Endpoint
	URL    string `json:"url" db:"url"`
	Method string `json:"method" db:"method"`

	// Authentication
	AuthType     RoutingWebhookAuthType `json:"auth_type" db:"auth_type"`
	AuthSecret   *string                `json:"-" db:"auth_secret"` // never expose in API
	AuthUsername *string                `json:"auth_username,omitempty" db:"auth_username"`

	// Reliability
	TimeoutMs  int `json:"timeout_ms" db:"timeout_ms"`
	RetryCount int `json:"retry_count" db:"retry_count"`

	// Circuit breaker
	CBEnabled    bool `json:"cb_enabled" db:"cb_enabled"`
	CBThreshold  int  `json:"cb_threshold" db:"cb_threshold"`
	CBTimeoutSec int  `json:"cb_timeout_sec" db:"cb_timeout_sec"`

	// Fallback
	FallbackAction     string     `json:"fallback_action" db:"fallback_action"`
	FallbackProviderID *uuid.UUID `json:"fallback_provider_id,omitempty" db:"fallback_provider_id"`

	// State
	IsEnabled bool `json:"is_enabled" db:"is_enabled"`
	Priority  int  `json:"priority" db:"priority"`

	// Audit
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// RoutingWebhookRequest is the payload sent to the external webhook endpoint
type RoutingWebhookRequest struct {
	// Context
	TenantID      string `json:"tenant_id"`
	EmailDomain   string `json:"email_domain,omitempty"`
	Email         string `json:"email,omitempty"`
	DeviceType    string `json:"device_type,omitempty"`
	NetworkZone   string `json:"network_zone,omitempty"`
	ApplicationID string `json:"application_id,omitempty"`
	ClientIP      string `json:"client_ip,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
	RiskLevel     string `json:"risk_level,omitempty"`

	// Extensible context for custom data
	Custom map[string]interface{} `json:"custom,omitempty"`

	// Request metadata
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
}

// RoutingWebhookResponse is the expected response from the external webhook
type RoutingWebhookResponse struct {
	Action     RoutingWebhookAction   `json:"action"`                // redirect, allow, deny, step_up_mfa, pass
	ProviderID *string                `json:"provider_id,omitempty"` // for action=redirect
	Reason     string                 `json:"reason,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// RoutingWebhookLog represents an execution log entry
type RoutingWebhookLog struct {
	ID        uuid.UUID `json:"id" db:"id"`
	TenantID  uuid.UUID `json:"tenant_id" db:"tenant_id"`
	WebhookID uuid.UUID `json:"webhook_id" db:"webhook_id"`

	// Request
	RequestURL  string          `json:"request_url,omitempty" db:"request_url"`
	RequestBody json.RawMessage `json:"request_body,omitempty" db:"request_body"`

	// Response
	ResponseStatus *int            `json:"response_status,omitempty" db:"response_status"`
	ResponseBody   json.RawMessage `json:"response_body,omitempty" db:"response_body"`
	ResponseMs     *int            `json:"response_ms,omitempty" db:"response_ms"`

	// Result
	ActionTaken  *string    `json:"action_taken,omitempty" db:"action_taken"`
	ProviderID   *uuid.UUID `json:"provider_id,omitempty" db:"provider_id"`
	ErrorMessage *string    `json:"error_message,omitempty" db:"error_message"`
	UsedFallback bool       `json:"used_fallback" db:"used_fallback"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ---- Request/Response DTOs ----

// CreateRoutingWebhookRequest represents a request to create a routing webhook
type CreateRoutingWebhookRequest struct {
	Name        string  `json:"name" binding:"required,min=1,max=100"`
	Description *string `json:"description,omitempty"`

	URL    string `json:"url" binding:"required,url,max=2048"`
	Method string `json:"method,omitempty"` // defaults to POST

	AuthType     string  `json:"auth_type,omitempty"`     // defaults to bearer
	AuthSecret   *string `json:"auth_secret,omitempty"`   // required for bearer/basic/hmac
	AuthUsername *string `json:"auth_username,omitempty"` // required for basic

	TimeoutMs  *int `json:"timeout_ms,omitempty"`
	RetryCount *int `json:"retry_count,omitempty"`

	CBEnabled    *bool `json:"cb_enabled,omitempty"`
	CBThreshold  *int  `json:"cb_threshold,omitempty"`
	CBTimeoutSec *int  `json:"cb_timeout_sec,omitempty"`

	FallbackAction     string     `json:"fallback_action,omitempty"`
	FallbackProviderID *uuid.UUID `json:"fallback_provider_id,omitempty"`

	IsEnabled *bool `json:"is_enabled,omitempty"`
	Priority  *int  `json:"priority,omitempty"`
}

// UpdateRoutingWebhookRequest represents a request to update a routing webhook
type UpdateRoutingWebhookRequest struct {
	Name        *string `json:"name,omitempty" binding:"omitempty,min=1,max=100"`
	Description *string `json:"description,omitempty"`

	URL    *string `json:"url,omitempty" binding:"omitempty,url,max=2048"`
	Method *string `json:"method,omitempty"`

	AuthType     *string `json:"auth_type,omitempty"`
	AuthSecret   *string `json:"auth_secret,omitempty"`
	AuthUsername *string `json:"auth_username,omitempty"`

	TimeoutMs  *int `json:"timeout_ms,omitempty"`
	RetryCount *int `json:"retry_count,omitempty"`

	CBEnabled    *bool `json:"cb_enabled,omitempty"`
	CBThreshold  *int  `json:"cb_threshold,omitempty"`
	CBTimeoutSec *int  `json:"cb_timeout_sec,omitempty"`

	FallbackAction     *string    `json:"fallback_action,omitempty"`
	FallbackProviderID *uuid.UUID `json:"fallback_provider_id,omitempty"`

	IsEnabled *bool `json:"is_enabled,omitempty"`
	Priority  *int  `json:"priority,omitempty"`
}

// RoutingWebhookTestRequest represents a request to test a routing webhook
type RoutingWebhookTestRequest struct {
	EmailDomain   string                 `json:"email_domain,omitempty"`
	Email         string                 `json:"email,omitempty"`
	DeviceType    string                 `json:"device_type,omitempty"`
	NetworkZone   string                 `json:"network_zone,omitempty"`
	ApplicationID string                 `json:"application_id,omitempty"`
	ClientIP      string                 `json:"client_ip,omitempty"`
	UserAgent     string                 `json:"user_agent,omitempty"`
	RiskLevel     string                 `json:"risk_level,omitempty"`
	Custom        map[string]interface{} `json:"custom,omitempty"`
}

// RoutingWebhookTestResponse represents the test result
type RoutingWebhookTestResponse struct {
	Success      bool                    `json:"success"`
	StatusCode   int                     `json:"status_code,omitempty"`
	ResponseBody *RoutingWebhookResponse `json:"response_body,omitempty"`
	DurationMs   int                     `json:"duration_ms,omitempty"`
	ErrorMessage *string                 `json:"error_message,omitempty"`
}

// RoutingWebhookListResponse represents a paginated list of routing webhooks
type RoutingWebhookListResponse struct {
	Webhooks   []*RoutingWebhook `json:"webhooks"`
	Total      int               `json:"total"`
	Page       int               `json:"page"`
	PageSize   int               `json:"page_size"`
	TotalPages int               `json:"total_pages"`
}

// RoutingWebhookLogListResponse represents a paginated list of webhook logs
type RoutingWebhookLogListResponse struct {
	Logs       []*RoutingWebhookLog `json:"logs"`
	Total      int                  `json:"total"`
	Page       int                  `json:"page"`
	PageSize   int                  `json:"page_size"`
	TotalPages int                  `json:"total_pages"`
}

// ValidRoutingWebhookActions is an exported identifier.
func ValidRoutingWebhookActions() []RoutingWebhookAction {
	return []RoutingWebhookAction{
		RoutingWebhookActionRedirect,
		RoutingWebhookActionAllow,
		RoutingWebhookActionDeny,
		RoutingWebhookActionStepUpMFA,
		RoutingWebhookActionPass,
	}
}

// IsValidRoutingWebhookAction is an exported identifier.
func IsValidRoutingWebhookAction(action string) bool {
	for _, a := range ValidRoutingWebhookActions() {
		if string(a) == action {
			return true
		}
	}
	return false
}
