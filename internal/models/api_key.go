// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	TenantID          uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	UserID            uuid.UUID  `json:"user_id" db:"user_id"`
	Name              string     `json:"name" db:"name"`
	Description       *string    `json:"description,omitempty" db:"description"`
	KeyPrefix         string     `json:"key_prefix" db:"key_prefix"`
	KeyHash           string     `json:"-" db:"key_hash"`
	Scopes            []string   `json:"scopes" db:"scopes"`
	IPWhitelist       []string   `json:"ip_whitelist,omitempty" db:"ip_whitelist"`
	AllowedEndpoints  []string   `json:"allowed_endpoints,omitempty" db:"allowed_endpoints"`
	RateLimitOverride *int       `json:"rate_limit_override,omitempty" db:"rate_limit_override"`
	Environment       string     `json:"environment" db:"environment"`
	IsActive          bool       `json:"is_active" db:"is_active"`
	UsageCount        int64      `json:"usage_count" db:"usage_count"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	LastUsedIP        *string    `json:"last_used_ip,omitempty" db:"last_used_ip"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	CreatedBy         *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// APIKeyUsage tracks individual API key usage
type APIKeyUsage struct {
	ID             uuid.UUID `json:"id" db:"id"`
	APIKeyID       uuid.UUID `json:"api_key_id" db:"api_key_id"`
	TenantID       uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Endpoint       string    `json:"endpoint" db:"endpoint"`
	Method         string    `json:"method" db:"method"`
	StatusCode     *int      `json:"status_code,omitempty" db:"status_code"`
	ResponseTimeMs *int      `json:"response_time_ms,omitempty" db:"response_time_ms"`
	IPAddress      *string   `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent      *string   `json:"user_agent,omitempty" db:"user_agent"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

// CreateAPIKeyRequest is the request to create an API key
type CreateAPIKeyRequest struct {
	Name              string   `json:"name" validate:"required,min=1,max=255"`
	Description       *string  `json:"description,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`
	IPWhitelist       []string `json:"ip_whitelist,omitempty"`
	AllowedEndpoints  []string `json:"allowed_endpoints,omitempty"`
	RateLimitOverride *int     `json:"rate_limit_override,omitempty" validate:"omitempty,min=1,max=100000"`
	Environment       *string  `json:"environment,omitempty" validate:"omitempty,oneof=production staging development"`
	ExpiresAt         *string  `json:"expires_at,omitempty"` // ISO 8601 datetime
}

// UpdateAPIKeyRequest is the request to update an API key
type UpdateAPIKeyRequest struct {
	Name              *string  `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Description       *string  `json:"description,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`
	IPWhitelist       []string `json:"ip_whitelist,omitempty"`
	AllowedEndpoints  []string `json:"allowed_endpoints,omitempty"`
	RateLimitOverride *int     `json:"rate_limit_override,omitempty" validate:"omitempty,min=1,max=100000"`
	Environment       *string  `json:"environment,omitempty" validate:"omitempty,oneof=production staging development"`
	IsActive          *bool    `json:"is_active,omitempty"`
	ExpiresAt         *string  `json:"expires_at,omitempty"` // ISO 8601 datetime, empty to clear
}

// APIKeyResponse is the response for an API key (without sensitive data)
type APIKeyResponse struct {
	ID                uuid.UUID  `json:"id"`
	TenantID          uuid.UUID  `json:"tenant_id"`
	UserID            uuid.UUID  `json:"user_id"`
	Name              string     `json:"name"`
	Description       *string    `json:"description,omitempty"`
	KeyPrefix         string     `json:"key_prefix"`
	Scopes            []string   `json:"scopes"`
	IPWhitelist       []string   `json:"ip_whitelist,omitempty"`
	AllowedEndpoints  []string   `json:"allowed_endpoints,omitempty"`
	RateLimitOverride *int       `json:"rate_limit_override,omitempty"`
	Environment       string     `json:"environment"`
	IsActive          bool       `json:"is_active"`
	UsageCount        int64      `json:"usage_count"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP        *string    `json:"last_used_ip,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
}

// APIKeyCreatedResponse includes the full key (only shown once at creation)
type APIKeyCreatedResponse struct {
	APIKeyResponse
	Key string `json:"key"` // The actual API key - only shown at creation
}

// ToResponse converts an APIKey to APIKeyResponse
func (k *APIKey) ToResponse() *APIKeyResponse {
	return &APIKeyResponse{
		ID:                k.ID,
		TenantID:          k.TenantID,
		UserID:            k.UserID,
		Name:              k.Name,
		Description:       k.Description,
		KeyPrefix:         k.KeyPrefix,
		Scopes:            k.Scopes,
		IPWhitelist:       k.IPWhitelist,
		AllowedEndpoints:  k.AllowedEndpoints,
		RateLimitOverride: k.RateLimitOverride,
		Environment:       k.Environment,
		IsActive:          k.IsActive,
		UsageCount:        k.UsageCount,
		LastUsedAt:        k.LastUsedAt,
		LastUsedIP:        k.LastUsedIP,
		CreatedAt:         k.CreatedAt,
		ExpiresAt:         k.ExpiresAt,
		RevokedAt:         k.RevokedAt,
	}
}

// APIKeyUsageStats represents aggregated usage statistics
type APIKeyUsageStats struct {
	TotalRequests     int64           `json:"total_requests"`
	Last24Hours       int64           `json:"last_24_hours"`
	Last7Days         int64           `json:"last_7_days"`
	AvgResponseTimeMs float64         `json:"avg_response_time_ms"`
	TopEndpoints      []EndpointUsage `json:"top_endpoints"`
	ErrorRate         float64         `json:"error_rate"`
}

// EndpointUsage represents usage for a specific endpoint
type EndpointUsage struct {
	Endpoint     string `json:"endpoint"`
	RequestCount int64  `json:"request_count"`
}
