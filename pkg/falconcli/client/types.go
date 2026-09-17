// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import "time"

// ListOptions for paginated endpoints.
type ListOptions struct {
	Page     int    `json:"page,omitempty"`
	PageSize int    `json:"page_size,omitempty"`
	Search   string `json:"search,omitempty"`
}

// Auth types

// LoginRequest holds the credentials for authentication.
type LoginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	TenantSlug string `json:"tenant_slug"`
}

// LoginResponse is the successful response from the login endpoint.
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	User         *User  `json:"user,omitempty"`
}

// WhoamiResponse contains the current authenticated user information.
type WhoamiResponse struct {
	ID         string   `json:"id"`
	Email      string   `json:"email"`
	Username   string   `json:"username"`
	TenantID   string   `json:"tenant_id"`
	TenantSlug string   `json:"tenant_slug"`
	Roles      []string `json:"roles,omitempty"`
}

// User represents an identity platform user.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserListResponse is the paginated list of users.
type UserListResponse struct {
	Users      []User `json:"users"`
	Total      int    `json:"total"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
	TotalPages int    `json:"total_pages"`
}

// UserResponse wraps a single user.
type UserResponse struct {
	User
}

// CreateUserRequest holds fields for user creation.
type CreateUserRequest struct {
	Email     string `json:"email"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// Role types

// Role represents an authorization role.
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
}

// RoleListResponse is the paginated list of roles.
type RoleListResponse struct {
	Roles      []Role `json:"roles"`
	Total      int    `json:"total"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
	TotalPages int    `json:"total_pages"`
}

// RoleResponse wraps a single role.
type RoleResponse struct {
	Role
}

// Permission types

// Permission represents a discrete access permission.
type Permission struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// PermissionListResponse is the paginated list of permissions.
type PermissionListResponse struct {
	Permissions []Permission `json:"permissions"`
	Total       int          `json:"total"`
	Page        int          `json:"page"`
	PageSize    int          `json:"page_size"`
	TotalPages  int          `json:"total_pages"`
}

// Tenant types

// Tenant represents a platform tenant.
type Tenant struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Status string `json:"status"`
}

// TenantListResponse is the paginated list of tenants.
type TenantListResponse struct {
	Tenants    []Tenant `json:"tenants"`
	Total      int      `json:"total"`
	Page       int      `json:"page"`
	PageSize   int      `json:"page_size"`
	TotalPages int      `json:"total_pages"`
}

// Realm types

// Realm represents an authentication realm.
type Realm struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	TenantID string `json:"tenant_id"`
	Status   string `json:"status"`
}

// RealmListResponse is the paginated list of realms.
type RealmListResponse struct {
	Realms     []Realm `json:"realms"`
	Total      int     `json:"total"`
	Page       int     `json:"page"`
	PageSize   int     `json:"page_size"`
	TotalPages int     `json:"total_pages"`
}

// Token types

// GenerateTokenRequest holds the fields for API token generation.
type GenerateTokenRequest struct {
	Name      string   `json:"name"`
	ExpiresIn string   `json:"expires_in,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
}

// TokenResponse represents a generated API token.
type TokenResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Key       string `json:"key"`
	ExpiresAt string `json:"expires_at"`
}

// Health types

// HealthResponse is the service health check result.
type HealthResponse struct {
	Status   string            `json:"status"`
	Version  string            `json:"version,omitempty"`
	Services map[string]string `json:"services,omitempty"`
}

// APIError represents an error returned by the Falcon ID API.
type APIError struct {
	StatusCode int
	Code       string `json:"code"`
	Message    string `json:"message"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}
