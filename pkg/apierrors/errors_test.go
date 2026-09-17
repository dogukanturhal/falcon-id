// SPDX-License-Identifier: AGPL-3.0-or-later

package apierrors

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

const testVal1 = "value1"

func TestNew(t *testing.T) {
	code := ErrCodeBadRequest
	statusCode := http.StatusBadRequest
	message := "Test error message"

	err := New(code, statusCode, message)

	if err == nil {
		t.Fatal("New() returned nil")
	}

	if err.Code != code {
		t.Errorf("Code = %v, want %v", err.Code, code)
	}

	if err.StatusCode != statusCode {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, statusCode)
	}

	if err.Message != message {
		t.Errorf("Message = %q, want %q", err.Message, message)
	}

	if err.Details != nil {
		t.Errorf("Details should be nil, got %v", err.Details)
	}
}

func TestAPIError_Error(t *testing.T) {
	message := "Test error message"
	err := New(ErrCodeInternal, http.StatusInternalServerError, message)

	got := err.Error()
	if got != message {
		t.Errorf("Error() = %q, want %q", got, message)
	}
}

func TestAPIError_WithDetails(t *testing.T) {
	err := New(ErrCodeValidation, http.StatusBadRequest, "Validation failed")

	details := map[string]interface{}{
		"field1": "error1",
		"field2": "error2",
	}

	result := err.WithDetails(details)

	if result != err {
		t.Error("WithDetails() should return the same error instance")
	}

	if len(err.Details) != 2 {
		t.Errorf("Details length = %d, want 2", len(err.Details))
	}

	if err.Details["field1"] != "error1" {
		t.Errorf("Details[field1] = %v, want error1", err.Details["field1"])
	}

	if err.Details["field2"] != "error2" {
		t.Errorf("Details[field2] = %v, want error2", err.Details["field2"])
	}
}

func TestAPIError_WithDetails_Merge(t *testing.T) {
	err := New(ErrCodeValidation, http.StatusBadRequest, "Validation failed")

	// Add first set of details
	err.WithDetails(map[string]interface{}{ //nolint:errcheck
		"field1": "error1",
	})

	// Add second set of details
	err.WithDetails(map[string]interface{}{ //nolint:errcheck
		"field2": "error2",
	})

	if len(err.Details) != 2 {
		t.Errorf("Details length = %d, want 2", len(err.Details))
	}

	// Verify both are present
	if err.Details["field1"] != "error1" {
		t.Error("field1 should still be present after second WithDetails")
	}

	if err.Details["field2"] != "error2" {
		t.Error("field2 should be added")
	}
}

func TestAPIError_WithDetail(t *testing.T) {
	err := New(ErrCodeInternal, http.StatusInternalServerError, "Error")

	result := err.WithDetail("key1", testVal1)

	if result != err {
		t.Error("WithDetail() should return the same error instance")
	}

	if len(err.Details) != 1 {
		t.Errorf("Details length = %d, want 1", len(err.Details))
	}

	if err.Details["key1"] != testVal1 {
		t.Errorf("Details[key1] = %v, want value1", err.Details["key1"])
	}
}

func TestAPIError_WithDetail_Multiple(t *testing.T) {
	err := New(ErrCodeInternal, http.StatusInternalServerError, "Error")

	err.WithDetail("key1", testVal1).WithDetail("key2", 123).WithDetail("key3", true) //nolint:errcheck

	if len(err.Details) != 3 {
		t.Errorf("Details length = %d, want 3", len(err.Details))
	}

	if err.Details["key1"] != testVal1 {
		t.Errorf("Details[key1] = %v, want value1", err.Details["key1"])
	}

	if err.Details["key2"] != 123 {
		t.Errorf("Details[key2] = %v, want 123", err.Details["key2"])
	}

	if err.Details["key3"] != true {
		t.Errorf("Details[key3] = %v, want true", err.Details["key3"])
	}
}

func TestInternal(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "With custom message",
			message:         "Database connection failed",
			expectedMessage: "Database connection failed",
		},
		{
			name:            "With empty message",
			message:         "",
			expectedMessage: "An internal error occurred",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Internal(tt.message)

			if err.Code != ErrCodeInternal {
				t.Errorf("Code = %v, want %v", err.Code, ErrCodeInternal)
			}

			if err.StatusCode != http.StatusInternalServerError {
				t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusInternalServerError)
			}

			if err.Message != tt.expectedMessage {
				t.Errorf("Message = %q, want %q", err.Message, tt.expectedMessage)
			}
		})
	}
}

func TestBadRequest(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "With custom message",
			message:         "Invalid input format",
			expectedMessage: "Invalid input format",
		},
		{
			name:            "With empty message",
			message:         "",
			expectedMessage: "Bad request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := BadRequest(tt.message)

			if err.Code != ErrCodeBadRequest {
				t.Errorf("Code = %v, want %v", err.Code, ErrCodeBadRequest)
			}

			if err.StatusCode != http.StatusBadRequest {
				t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusBadRequest)
			}

			if err.Message != tt.expectedMessage {
				t.Errorf("Message = %q, want %q", err.Message, tt.expectedMessage)
			}
		})
	}
}

func TestValidationFailed(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		fields          map[string]string
		expectedMessage string
	}{
		{
			name:            "With fields",
			message:         "Validation errors",
			fields:          map[string]string{"email": "invalid format", "age": "must be positive"},
			expectedMessage: "Validation errors",
		},
		{
			name:            "Without fields",
			message:         "Validation errors",
			fields:          nil,
			expectedMessage: "Validation errors",
		},
		{
			name:            "Empty message with fields",
			message:         "",
			fields:          map[string]string{"name": "required"},
			expectedMessage: "Validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidationFailed(tt.message, tt.fields)

			if err.Code != ErrCodeValidation {
				t.Errorf("Code = %v, want %v", err.Code, ErrCodeValidation)
			}

			if err.StatusCode != http.StatusBadRequest {
				t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusBadRequest)
			}

			if err.Message != tt.expectedMessage {
				t.Errorf("Message = %q, want %q", err.Message, tt.expectedMessage)
			}

			if tt.fields != nil {
				if len(err.Details) != len(tt.fields) {
					t.Errorf("Details length = %d, want %d", len(err.Details), len(tt.fields))
				}

				for key, value := range tt.fields {
					if err.Details[key] != value {
						t.Errorf("Details[%s] = %v, want %v", key, err.Details[key], value)
					}
				}
			}
		})
	}
}

func TestNotFound(t *testing.T) {
	tests := []struct {
		name            string
		resource        string
		expectedMessage string
	}{
		{
			name:            "With resource name",
			resource:        "User",
			expectedMessage: "User not found",
		},
		{
			name:            "Without resource name",
			resource:        "",
			expectedMessage: "Resource not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NotFound(tt.resource)

			if err.Code != ErrCodeNotFound {
				t.Errorf("Code = %v, want %v", err.Code, ErrCodeNotFound)
			}

			if err.StatusCode != http.StatusNotFound {
				t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusNotFound)
			}

			if err.Message != tt.expectedMessage {
				t.Errorf("Message = %q, want %q", err.Message, tt.expectedMessage)
			}
		})
	}
}

func TestConflict(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "With custom message",
			message:         "Email already exists",
			expectedMessage: "Email already exists",
		},
		{
			name:            "With empty message",
			message:         "",
			expectedMessage: "Resource already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Conflict(tt.message)

			if err.Code != ErrCodeConflict {
				t.Errorf("Code = %v, want %v", err.Code, ErrCodeConflict)
			}

			if err.StatusCode != http.StatusConflict {
				t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusConflict)
			}

			if err.Message != tt.expectedMessage {
				t.Errorf("Message = %q, want %q", err.Message, tt.expectedMessage)
			}
		})
	}
}

func TestUnauthorized(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "With custom message",
			message:         "Invalid token",
			expectedMessage: "Invalid token",
		},
		{
			name:            "With empty message",
			message:         "",
			expectedMessage: "Unauthorized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Unauthorized(tt.message)

			if err.Code != ErrCodeUnauthorized {
				t.Errorf("Code = %v, want %v", err.Code, ErrCodeUnauthorized)
			}

			if err.StatusCode != http.StatusUnauthorized {
				t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusUnauthorized)
			}

			if err.Message != tt.expectedMessage {
				t.Errorf("Message = %q, want %q", err.Message, tt.expectedMessage)
			}
		})
	}
}

func TestForbidden(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "With custom message",
			message:         "Access denied",
			expectedMessage: "Access denied",
		},
		{
			name:            "With empty message",
			message:         "",
			expectedMessage: "Forbidden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Forbidden(tt.message)

			if err.Code != ErrCodeForbidden {
				t.Errorf("Code = %v, want %v", err.Code, ErrCodeForbidden)
			}

			if err.StatusCode != http.StatusForbidden {
				t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusForbidden)
			}

			if err.Message != tt.expectedMessage {
				t.Errorf("Message = %q, want %q", err.Message, tt.expectedMessage)
			}
		})
	}
}

func TestRateLimited(t *testing.T) {
	retryAfter := 60 * time.Second
	err := RateLimited(retryAfter)

	if err.Code != ErrCodeRateLimited {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeRateLimited)
	}

	if err.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusTooManyRequests)
	}

	if err.Message != "Rate limit exceeded" {
		t.Errorf("Message = %q, want 'Rate limit exceeded'", err.Message)
	}

	if err.Details == nil {
		t.Fatal("Details should not be nil")
	}

	retrySeconds, ok := err.Details["retry_after_seconds"].(int)
	if !ok {
		t.Fatal("retry_after_seconds should be an int")
	}

	if retrySeconds != 60 {
		t.Errorf("retry_after_seconds = %d, want 60", retrySeconds)
	}
}

func TestInvalidCredentials(t *testing.T) {
	err := InvalidCredentials()

	if err.Code != ErrCodeInvalidCredentials {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeInvalidCredentials)
	}

	if err.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusUnauthorized)
	}

	if err.Message != "Invalid username or password" {
		t.Errorf("Message = %q, want 'Invalid username or password'", err.Message)
	}
}

func TestAccountLocked(t *testing.T) {
	tests := []struct {
		name   string
		until  *time.Time
		reason string
	}{
		{
			name:   "With until time and reason",
			until:  func() *time.Time { t := time.Now().Add(1 * time.Hour); return &t }(),
			reason: "Too many failed attempts",
		},
		{
			name:   "Without until time",
			until:  nil,
			reason: "Admin locked",
		},
		{
			name:   "Without reason",
			until:  func() *time.Time { t := time.Now().Add(1 * time.Hour); return &t }(),
			reason: "",
		},
		{
			name:   "Without both",
			until:  nil,
			reason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AccountLocked(tt.until, tt.reason)

			if err.Code != ErrCodeAccountLocked {
				t.Errorf("Code = %v, want %v", err.Code, ErrCodeAccountLocked)
			}

			if err.StatusCode != http.StatusForbidden {
				t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusForbidden)
			}

			assertAccountLockedDetails(t, err, tt.until, tt.reason)
		})
	}
}

func assertAccountLockedDetails(t *testing.T, err *APIError, until *time.Time, reason string) {
	t.Helper()
	if until == nil && reason == "" {
		return
	}
	if err.Details == nil {
		t.Error("Details should not be nil when until or reason is provided")
		return
	}
	if until != nil {
		if _, ok := err.Details["locked_until"]; !ok {
			t.Error("Details should contain locked_until")
		}
	}
	if reason != "" {
		if err.Details["reason"] != reason {
			t.Errorf("Details[reason] = %v, want %v", err.Details["reason"], reason)
		}
	}
}

func TestAccountDisabled(t *testing.T) {
	err := AccountDisabled()

	if err.Code != ErrCodeAccountDisabled {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeAccountDisabled)
	}

	if err.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusForbidden)
	}

	if err.Message != "Account is disabled" {
		t.Errorf("Message = %q, want 'Account is disabled'", err.Message)
	}
}

func TestSessionExpired(t *testing.T) {
	err := SessionExpired()

	if err.Code != ErrCodeSessionExpired {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeSessionExpired)
	}

	if err.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusUnauthorized)
	}
}

func TestTokenExpired(t *testing.T) {
	err := TokenExpired()

	if err.Code != ErrCodeTokenExpired {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeTokenExpired)
	}

	if err.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusUnauthorized)
	}
}

func TestTokenInvalid(t *testing.T) {
	err := TokenInvalid()

	if err.Code != ErrCodeTokenInvalid {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeTokenInvalid)
	}

	if err.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusUnauthorized)
	}
}

func TestTokenRevoked(t *testing.T) {
	err := TokenRevoked()

	if err.Code != ErrCodeTokenRevoked {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeTokenRevoked)
	}

	if err.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusUnauthorized)
	}
}

func TestRefreshTokenReused(t *testing.T) {
	err := RefreshTokenReused()

	if err.Code != ErrCodeRefreshTokenReused {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeRefreshTokenReused)
	}

	if err.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusUnauthorized)
	}

	if err.Details == nil {
		t.Fatal("Details should not be nil")
	}

	action, ok := err.Details["action"].(string)
	if !ok {
		t.Fatal("action should be a string")
	}

	if action != "re-authenticate" {
		t.Errorf("action = %q, want 're-authenticate'", action)
	}
}

func TestMFARequired(t *testing.T) {
	methods := []string{"totp", "sms"}
	err := MFARequired(methods)

	if err.Code != ErrCodeMFARequired {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeMFARequired)
	}

	if err.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusUnauthorized)
	}

	if err.Details == nil {
		t.Fatal("Details should not be nil")
	}

	availableMethods, ok := err.Details["available_methods"].([]string)
	if !ok {
		t.Fatal("available_methods should be a []string")
	}

	if len(availableMethods) != len(methods) {
		t.Errorf("available_methods length = %d, want %d", len(availableMethods), len(methods))
	}
}

func TestMFAInvalid(t *testing.T) {
	err := MFAInvalid()

	if err.Code != ErrCodeMFAInvalid {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeMFAInvalid)
	}

	if err.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusUnauthorized)
	}
}

func TestMFAExpired(t *testing.T) {
	err := MFAExpired()

	if err.Code != ErrCodeMFAExpired {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodeMFAExpired)
	}

	if err.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusUnauthorized)
	}
}

func TestPasswordExpired(t *testing.T) {
	err := PasswordExpired()

	if err.Code != ErrCodePasswordExpired {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodePasswordExpired)
	}

	if err.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusForbidden)
	}
}

func TestPasswordPolicyViolation(t *testing.T) {
	violations := []string{"too short", "no uppercase", "no numbers"}
	err := PasswordPolicyViolation(violations)

	if err.Code != ErrCodePasswordPolicyViolation {
		t.Errorf("Code = %v, want %v", err.Code, ErrCodePasswordPolicyViolation)
	}

	if err.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusBadRequest)
	}

	if err.Details == nil {
		t.Fatal("Details should not be nil")
	}

	gotViolations, ok := err.Details["violations"].([]string)
	if !ok {
		t.Fatal("violations should be a []string")
	}

	if len(gotViolations) != len(violations) {
		t.Errorf("violations length = %d, want %d", len(gotViolations), len(violations))
	}
}

func TestInsufficientPermissions(t *testing.T) {
	tests := []struct {
		name     string
		required []string
	}{
		{
			name:     "With required permissions",
			required: []string{"read:users", "write:users"},
		},
		{
			name:     "Without required permissions",
			required: []string{},
		},
		{
			name:     "Nil required permissions",
			required: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := InsufficientPermissions(tt.required)

			if err.Code != ErrCodeInsufficientPermissions {
				t.Errorf("Code = %v, want %v", err.Code, ErrCodeInsufficientPermissions)
			}

			if err.StatusCode != http.StatusForbidden {
				t.Errorf("StatusCode = %d, want %d", err.StatusCode, http.StatusForbidden)
			}

			if len(tt.required) > 0 {
				if err.Details == nil {
					t.Fatal("Details should not be nil when required permissions provided")
				}

				requiredPerms, ok := err.Details["required_permissions"].([]string)
				if !ok {
					t.Fatal("required_permissions should be a []string")
				}

				if len(requiredPerms) != len(tt.required) {
					t.Errorf("required_permissions length = %d, want %d", len(requiredPerms), len(tt.required))
				}
			}
		})
	}
}

func TestGetAPIError(t *testing.T) {
	t.Run("With APIError", func(t *testing.T) {
		apiErr := BadRequest("test")
		got := GetAPIError(apiErr)

		if got != apiErr {
			t.Error("GetAPIError() should return the same APIError")
		}
	})

	t.Run("With standard error", func(t *testing.T) {
		stdErr := errors.New("standard error")
		got := GetAPIError(stdErr)

		if got != nil {
			t.Errorf("GetAPIError() = %v, want nil for standard error", got)
		}
	})

	t.Run("With nil error", func(t *testing.T) {
		got := GetAPIError(nil)

		if got != nil {
			t.Errorf("GetAPIError() = %v, want nil", got)
		}
	})
}

func TestIsAPIError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code ErrorCode
		want bool
	}{
		{
			name: "Matching APIError",
			err:  BadRequest("test"),
			code: ErrCodeBadRequest,
			want: true,
		},
		{
			name: "Non-matching APIError",
			err:  BadRequest("test"),
			code: ErrCodeNotFound,
			want: false,
		},
		{
			name: "Standard error",
			err:  errors.New("test"),
			code: ErrCodeBadRequest,
			want: false,
		},
		{
			name: "Nil error",
			err:  nil,
			code: ErrCodeBadRequest,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAPIError(tt.err, tt.code)
			if got != tt.want {
				t.Errorf("IsAPIError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrorCode_Values(t *testing.T) {
	// Test that all error codes are defined correctly
	codes := []ErrorCode{
		ErrCodeInternal,
		ErrCodeBadRequest,
		ErrCodeValidation,
		ErrCodeNotFound,
		ErrCodeConflict,
		ErrCodeForbidden,
		ErrCodeUnauthorized,
		ErrCodeRateLimited,
		ErrCodeServiceUnavailable,
		ErrCodeInvalidCredentials,
		ErrCodeAccountLocked,
		ErrCodeAccountDisabled,
		ErrCodeSessionExpired,
		ErrCodeTokenExpired,
		ErrCodeTokenInvalid,
		ErrCodeTokenRevoked,
		ErrCodeRefreshTokenReused,
		ErrCodeMFARequired,
		ErrCodeMFAInvalid,
		ErrCodeMFAExpired,
		ErrCodeMFANotSetup,
		ErrCodePasswordExpired,
		ErrCodePasswordPolicyViolation,
		ErrCodePasswordReused,
		ErrCodePasswordResetRequired,
		ErrCodeUserNotFound,
		ErrCodeUserExists,
		ErrCodeEmailNotVerified,
		ErrCodeTenantNotFound,
		ErrCodeTenantDisabled,
		ErrCodeTenantLimitExceeded,
		ErrCodeInsufficientPermissions,
		ErrCodeRoleNotFound,
	}

	// Verify all codes are non-empty strings
	for _, code := range codes {
		if string(code) == "" {
			t.Errorf("ErrorCode %v is empty", code)
		}
	}
}

func TestAPIError_Chaining(t *testing.T) {
	// Test method chaining
	err := BadRequest("test").
		WithDetail("key1", testVal1).
		WithDetail("key2", "value2").
		WithDetails(map[string]interface{}{"key3": "value3"})

	if len(err.Details) != 3 {
		t.Errorf("Details length = %d, want 3", len(err.Details))
	}

	if err.Details["key1"] != testVal1 {
		t.Error("key1 not set correctly")
	}

	if err.Details["key2"] != "value2" {
		t.Error("key2 not set correctly")
	}

	if err.Details["key3"] != "value3" {
		t.Error("key3 not set correctly")
	}
}
