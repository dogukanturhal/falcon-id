// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "time"

// StandardResponse represents a standard API response for Swagger documentation
// @Description Standard API response wrapper
type StandardResponse struct {
	Success   bool        `json:"success" example:"true"`
	RequestID string      `json:"request_id,omitempty" example:"550e8400-e29b-41d4-a716-446655440000"`
	Data      interface{} `json:"data,omitempty"`
	Error     *ErrorBody  `json:"error,omitempty"`
	Meta      *MetaInfo   `json:"meta,omitempty"`
}

// ErrorBody represents error details in a response
// @Description Error details
type ErrorBody struct {
	Code    string                 `json:"code" example:"VALIDATION_ERROR"`
	Message string                 `json:"message" example:"Invalid request parameters"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// MetaInfo represents pagination metadata
// @Description Pagination metadata
type MetaInfo struct {
	Page       int   `json:"page" example:"1"`
	PageSize   int   `json:"page_size" example:"20"`
	TotalItems int64 `json:"total_items" example:"100"`
	TotalPages int   `json:"total_pages" example:"5"`
}

// HealthResponse represents the health check response
// @Description Health check response
type HealthResponse struct {
	Status    string            `json:"status" example:"healthy"`
	Version   string            `json:"version" example:"1.0.0"`
	Uptime    string            `json:"uptime" example:"24h30m15s"`
	Timestamp time.Time         `json:"timestamp"`
	Services  map[string]string `json:"services,omitempty"`
}

// UserSummary represents a brief user information
// @Description Brief user information
type UserSummary struct {
	ID        string   `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Username  string   `json:"username" example:"john.doe"`
	Email     string   `json:"email" example:"john.doe@example.com"`
	FirstName string   `json:"first_name" example:"John"`
	LastName  string   `json:"last_name" example:"Doe"`
	Roles     []string `json:"roles" example:"admin,user"`
}

// RefreshTokenSwaggerRequest represents a token refresh request for Swagger docs
// @Description Refresh token request
type RefreshTokenSwaggerRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required" example:"eyJhbGciOiJIUzI1NiIs..."`
}

// ChangePasswordSwaggerRequest represents a password change request for Swagger docs
// @Description Password change request
type ChangePasswordSwaggerRequest struct {
	CurrentPassword string `json:"current_password" binding:"required" example:"OldP@ss123"`
	NewPassword     string `json:"new_password" binding:"required" example:"NewP@ss456"`
}

// ForgotPasswordSwaggerRequest represents a forgot password request for Swagger docs
// @Description Forgot password request
type ForgotPasswordSwaggerRequest struct {
	Email string `json:"email" binding:"required,email" example:"john.doe@example.com"`
}

// AssignPermissionsRequest represents a request to assign permissions to a role
// @Description Assign permissions to role request
type AssignPermissionsRequest struct {
	PermissionIDs []string `json:"permission_ids" binding:"required" example:"550e8400-e29b-41d4-a716-446655440000,660e8400-e29b-41d4-a716-446655440001"`
}

// SyncLDAPRequest represents a request to sync LDAP users
// @Description LDAP user sync request
type SyncLDAPRequest struct {
	FullSync bool `json:"full_sync" example:"false"`
}

// LinkSocialAccountRequest represents a request to link a social account
// @Description Link social account request
type LinkSocialAccountRequest struct {
	Code        string `json:"code" binding:"required" example:"auth_code_from_provider"`
	RedirectURI string `json:"redirect_uri" example:"https://app.example.com/callback"`
}

// SetPasswordRequest represents a request to set a user's password
// @Description Set user password request
type SetPasswordRequest struct {
	Password   string `json:"password" binding:"required,min=8" example:"NewP@ssw0rd!"`
	MustChange bool   `json:"must_change" example:"true"`
}

// LockUserRequest represents a request to lock a user account
// @Description Lock user account request
type LockUserRequest struct {
	Reason string `json:"reason" binding:"required" example:"Suspicious activity detected"`
}

// ErrorResponse represents an error response for Swagger documentation
// @Description Error response
type ErrorResponse struct {
	Error   string                 `json:"error" example:"Invalid request"`
	Message string                 `json:"message,omitempty" example:"Detailed error message"`
	Code    string                 `json:"code,omitempty" example:"AUTH_001"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// MessageResponse represents a simple message response for Swagger documentation
// @Description Simple message response
type MessageResponse struct {
	Message string `json:"message" example:"Operation completed successfully"`
}

// SuccessResponse represents a simple success response for Swagger documentation
// @Description Success response
type SuccessResponse struct {
	Success bool   `json:"success" example:"true"`
	Message string `json:"message,omitempty" example:"Operation completed successfully"`
}
