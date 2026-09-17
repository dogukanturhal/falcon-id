// SPDX-License-Identifier: AGPL-3.0-or-later

// Package apierrors defines API error types and responses.
package apierrors

import (
	"errors"
	"net/http"
	"time"
)

// ErrorCode represents a standardized error code
type ErrorCode string

const (
	// ErrCodeInternal is an exported identifier.
	ErrCodeInternal ErrorCode = "INTERNAL_ERROR"
	// ErrCodeBadRequest is an exported identifier.
	ErrCodeBadRequest ErrorCode = "BAD_REQUEST"
	// ErrCodeValidation is an exported identifier.
	ErrCodeValidation ErrorCode = "VALIDATION_ERROR"
	// ErrCodeNotFound is an exported identifier.
	ErrCodeNotFound ErrorCode = "NOT_FOUND"
	// ErrCodeConflict is an exported identifier.
	ErrCodeConflict ErrorCode = "CONFLICT"
	// ErrCodeForbidden is an exported identifier.
	ErrCodeForbidden ErrorCode = "FORBIDDEN"
	// ErrCodeUnauthorized is an exported identifier.
	ErrCodeUnauthorized ErrorCode = "UNAUTHORIZED"
	// ErrCodeRateLimited is an exported identifier.
	ErrCodeRateLimited ErrorCode = "RATE_LIMITED"
	// ErrCodeServiceUnavailable is an exported identifier.
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"

	// ErrCodeInvalidCredentials is an exported identifier.
	ErrCodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS" //nolint:gosec // not a credential, this is an error code constant
	// ErrCodeAccountLocked is an exported identifier.
	ErrCodeAccountLocked ErrorCode = "ACCOUNT_LOCKED"
	// ErrCodeAccountDisabled is an exported identifier.
	ErrCodeAccountDisabled ErrorCode = "ACCOUNT_DISABLED"
	// ErrCodeSessionExpired is an exported identifier.
	ErrCodeSessionExpired ErrorCode = "SESSION_EXPIRED"
	// ErrCodeTokenExpired is an exported identifier.
	ErrCodeTokenExpired ErrorCode = "TOKEN_EXPIRED"
	// ErrCodeTokenInvalid is an exported identifier.
	ErrCodeTokenInvalid ErrorCode = "TOKEN_INVALID"
	// ErrCodeTokenRevoked is an exported identifier.
	ErrCodeTokenRevoked ErrorCode = "TOKEN_REVOKED"
	// ErrCodeRefreshTokenReused is an exported identifier.
	ErrCodeRefreshTokenReused ErrorCode = "REFRESH_TOKEN_REUSED" //nolint:gosec // not a credential, this is an error code constant

	// ErrCodeMFARequired is an exported identifier.
	ErrCodeMFARequired ErrorCode = "MFA_REQUIRED"
	// ErrCodeMFAInvalid is an exported identifier.
	ErrCodeMFAInvalid ErrorCode = "MFA_INVALID"
	// ErrCodeMFAExpired is an exported identifier.
	ErrCodeMFAExpired ErrorCode = "MFA_EXPIRED"
	// ErrCodeMFANotSetup is an exported identifier.
	ErrCodeMFANotSetup ErrorCode = "MFA_NOT_SETUP"

	// ErrCodePasswordExpired is an exported identifier.
	ErrCodePasswordExpired ErrorCode = "PASSWORD_EXPIRED"
	// ErrCodePasswordPolicyViolation is an exported identifier.
	ErrCodePasswordPolicyViolation ErrorCode = "PASSWORD_POLICY_VIOLATION"
	// ErrCodePasswordReused is an exported identifier.
	ErrCodePasswordReused ErrorCode = "PASSWORD_REUSED"
	// ErrCodePasswordResetRequired is an exported identifier.
	ErrCodePasswordResetRequired ErrorCode = "PASSWORD_RESET_REQUIRED"

	// ErrCodeUserNotFound is an exported identifier.
	ErrCodeUserNotFound ErrorCode = "USER_NOT_FOUND"
	// ErrCodeUserExists is an exported identifier.
	ErrCodeUserExists ErrorCode = "USER_EXISTS"
	// ErrCodeEmailNotVerified is an exported identifier.
	ErrCodeEmailNotVerified ErrorCode = "EMAIL_NOT_VERIFIED"

	// ErrCodeTenantNotFound is an exported identifier.
	ErrCodeTenantNotFound ErrorCode = "TENANT_NOT_FOUND"
	// ErrCodeTenantDisabled is an exported identifier.
	ErrCodeTenantDisabled ErrorCode = "TENANT_DISABLED"
	// ErrCodeTenantLimitExceeded is an exported identifier.
	ErrCodeTenantLimitExceeded ErrorCode = "TENANT_LIMIT_EXCEEDED"

	// ErrCodeInsufficientPermissions is an exported identifier.
	ErrCodeInsufficientPermissions ErrorCode = "INSUFFICIENT_PERMISSIONS"
	// ErrCodeRoleNotFound is an exported identifier.
	ErrCodeRoleNotFound ErrorCode = "ROLE_NOT_FOUND"
)

// APIError represents a standardized API error
type APIError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	StatusCode int                    `json:"-"`
}

// Error implements the error interface
func (e *APIError) Error() string {
	return e.Message
}

// WithDetails adds details to the error
func (e *APIError) WithDetails(details map[string]interface{}) *APIError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	for k, v := range details {
		e.Details[k] = v
	}
	return e
}

// WithDetail adds a single detail to the error
func (e *APIError) WithDetail(key string, value interface{}) *APIError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// New creates a new APIError
func New(code ErrorCode, statusCode int, message string) *APIError {
	return &APIError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
	}
}

// Common error constructors

// Internal returns an internal server error
func Internal(message string) *APIError {
	if message == "" {
		message = "An internal error occurred"
	}
	return New(ErrCodeInternal, http.StatusInternalServerError, message)
}

// BadRequest returns a bad request error
func BadRequest(message string) *APIError {
	if message == "" {
		message = "Bad request"
	}
	return New(ErrCodeBadRequest, http.StatusBadRequest, message)
}

// ValidationFailed returns a validation error with field details
func ValidationFailed(message string, fields map[string]string) *APIError {
	if message == "" {
		message = "Validation failed"
	}
	err := New(ErrCodeValidation, http.StatusBadRequest, message)
	if fields != nil {
		details := make(map[string]interface{})
		for k, v := range fields {
			details[k] = v
		}
		err.Details = details
	}
	return err
}

// NotFound returns a not found error
func NotFound(resource string) *APIError {
	message := "Resource not found"
	if resource != "" {
		message = resource + " not found"
	}
	return New(ErrCodeNotFound, http.StatusNotFound, message)
}

// Conflict returns a conflict error
func Conflict(message string) *APIError {
	if message == "" {
		message = "Resource already exists"
	}
	return New(ErrCodeConflict, http.StatusConflict, message)
}

// Unauthorized returns an unauthorized error
func Unauthorized(message string) *APIError {
	if message == "" {
		message = "Unauthorized"
	}
	return New(ErrCodeUnauthorized, http.StatusUnauthorized, message)
}

// Forbidden returns a forbidden error
func Forbidden(message string) *APIError {
	if message == "" {
		message = "Forbidden"
	}
	return New(ErrCodeForbidden, http.StatusForbidden, message)
}

// RateLimited returns a rate limited error with retry-after
func RateLimited(retryAfter time.Duration) *APIError {
	err := New(ErrCodeRateLimited, http.StatusTooManyRequests, "Rate limit exceeded")
	err.Details = map[string]interface{}{
		"retry_after_seconds": int(retryAfter.Seconds()),
	}
	return err
}

// Authentication-specific errors

// InvalidCredentials returns an invalid credentials error
func InvalidCredentials() *APIError {
	return New(ErrCodeInvalidCredentials, http.StatusUnauthorized, "Invalid username or password")
}

// AccountLocked returns an account locked error
func AccountLocked(until *time.Time, reason string) *APIError {
	err := New(ErrCodeAccountLocked, http.StatusForbidden, "Account is locked")
	details := make(map[string]interface{})
	if until != nil {
		details["locked_until"] = until.Format(time.RFC3339)
	}
	if reason != "" {
		details["reason"] = reason
	}
	if len(details) > 0 {
		err.Details = details
	}
	return err
}

// AccountDisabled returns an account disabled error
func AccountDisabled() *APIError {
	return New(ErrCodeAccountDisabled, http.StatusForbidden, "Account is disabled")
}

// SessionExpired returns a session expired error
func SessionExpired() *APIError {
	return New(ErrCodeSessionExpired, http.StatusUnauthorized, "Session has expired")
}

// TokenExpired returns a token expired error
func TokenExpired() *APIError {
	return New(ErrCodeTokenExpired, http.StatusUnauthorized, "Token has expired")
}

// TokenInvalid returns a token invalid error
func TokenInvalid() *APIError {
	return New(ErrCodeTokenInvalid, http.StatusUnauthorized, "Token is invalid")
}

// TokenRevoked returns a token revoked error
func TokenRevoked() *APIError {
	return New(ErrCodeTokenRevoked, http.StatusUnauthorized, "Token has been revoked")
}

// RefreshTokenReused returns a refresh token reuse detection error
func RefreshTokenReused() *APIError {
	err := New(ErrCodeRefreshTokenReused, http.StatusUnauthorized, "Refresh token has already been used. Session terminated for security.")
	err.Details = map[string]interface{}{
		"action": "re-authenticate",
	}
	return err
}

// MFA-specific errors

// MFARequired returns an MFA required error with available methods
func MFARequired(methods []string) *APIError {
	err := New(ErrCodeMFARequired, http.StatusUnauthorized, "Multi-factor authentication required")
	err.Details = map[string]interface{}{
		"available_methods": methods,
	}
	return err
}

// MFAInvalid returns an MFA invalid error
func MFAInvalid() *APIError {
	return New(ErrCodeMFAInvalid, http.StatusUnauthorized, "Invalid MFA code")
}

// MFAExpired returns an MFA expired error
func MFAExpired() *APIError {
	return New(ErrCodeMFAExpired, http.StatusUnauthorized, "MFA code has expired")
}

// Password-specific errors

// PasswordExpired returns a password expired error
func PasswordExpired() *APIError {
	return New(ErrCodePasswordExpired, http.StatusForbidden, "Password has expired")
}

// PasswordPolicyViolation returns a password policy violation error
func PasswordPolicyViolation(violations []string) *APIError {
	err := New(ErrCodePasswordPolicyViolation, http.StatusBadRequest, "Password does not meet policy requirements")
	err.Details = map[string]interface{}{
		"violations": violations,
	}
	return err
}

// Permission-specific errors

// InsufficientPermissions returns an insufficient permissions error
func InsufficientPermissions(required []string) *APIError {
	err := New(ErrCodeInsufficientPermissions, http.StatusForbidden, "Insufficient permissions")
	if len(required) > 0 {
		err.Details = map[string]interface{}{
			"required_permissions": required,
		}
	}
	return err
}

// GetAPIError attempts to extract an APIError from an error
func GetAPIError(err error) *APIError {
	apiErr := &APIError{}
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return nil
}

// IsAPIError checks if an error is an APIError with a specific code
func IsAPIError(err error, code ErrorCode) bool {
	if apiErr := GetAPIError(err); apiErr != nil {
		return apiErr.Code == code
	}
	return false
}
