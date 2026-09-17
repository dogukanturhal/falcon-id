// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const testSecret = "test-secret-key-for-jwt-signing-32chars" // gitleaks:allow — test fixture, not a real credential

// createTestToken creates a test JWT token with the given parameters
func createTestToken(secret string, tenantID, userID uuid.UUID, expiresAt time.Time) string {
	claims := jwt.MapClaims{
		"iss":         "falcon-id",
		"sub":         userID.String(),
		"tenant_id":   tenantID.String(),
		"user_id":     userID.String(),
		"username":    "testuser",
		"email":       "test@example.com",
		"roles":       []string{"admin"},
		"permissions": []string{"subscription:admin", "payment:read"},
		"session_id":  uuid.New().String(),
		"iat":         time.Now().Unix(),
		"exp":         expiresAt.Unix(),
		"nbf":         time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func TestValidateAccessToken_ValidToken(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	expiresAt := time.Now().Add(time.Hour)

	tokenString := createTestToken(testSecret, tenantID, userID, expiresAt)

	config := &Config{
		JWTSecret: testSecret,
		JWTIssuer: "falcon-id",
	}
	validator := NewTokenValidator(config)

	claims, err := validator.ValidateAccessToken(tokenString)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if claims.TenantID != tenantID {
		t.Errorf("Expected tenant ID %s, got %s", tenantID, claims.TenantID)
	}

	if claims.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claims.UserID)
	}

	if claims.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got %s", claims.Username)
	}

	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Errorf("Expected roles ['admin'], got %v", claims.Roles)
	}
}

func TestValidateAccessToken_ExpiredToken(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	expiresAt := time.Now().Add(-time.Hour) // Expired 1 hour ago

	tokenString := createTestToken(testSecret, tenantID, userID, expiresAt)

	config := &Config{
		JWTSecret: testSecret,
	}
	validator := NewTokenValidator(config)

	_, err := validator.ValidateAccessToken(tokenString)
	if err == nil {
		t.Fatal("Expected error for expired token, got nil")
	}
}

func TestValidateAccessToken_InvalidSignature(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	expiresAt := time.Now().Add(time.Hour)

	// Create token with different secret
	tokenString := createTestToken("different-secret-key-32characters", tenantID, userID, expiresAt)

	config := &Config{
		JWTSecret: testSecret, // Different from the one used to create token
	}
	validator := NewTokenValidator(config)

	_, err := validator.ValidateAccessToken(tokenString)
	if err == nil {
		t.Fatal("Expected error for invalid signature, got nil")
	}
}

func TestValidateAccessToken_EmptyToken(t *testing.T) {
	config := &Config{
		JWTSecret: testSecret,
	}
	validator := NewTokenValidator(config)

	_, err := validator.ValidateAccessToken("")
	if err == nil {
		t.Fatal("Expected error for empty token, got nil")
	}
}

func TestValidateAccessToken_MalformedToken(t *testing.T) {
	config := &Config{
		JWTSecret: testSecret,
	}
	validator := NewTokenValidator(config)

	_, err := validator.ValidateAccessToken("not-a-valid-jwt-token")
	if err == nil {
		t.Fatal("Expected error for malformed token, got nil")
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantToken  string
		wantErr    bool
	}{
		{ //nolint:gosec // test fixture value, not a real credential
			name:       "Valid bearer token",
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test", // gitleaks:allow — test fixture, not a real credential
			wantErr:    false,
		},
		{ //nolint:gosec // test fixture value, not a real credential
			name:       "Valid bearer token lowercase",
			authHeader: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test", // gitleaks:allow — test fixture, not a real credential
			wantErr:    false,
		},
		{
			name:       "Empty header",
			authHeader: "",
			wantToken:  "",
			wantErr:    true,
		},
		{
			name:       "Missing bearer prefix",
			authHeader: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test", // gitleaks:allow — test fixture, not a real credential
			wantToken:  "",
			wantErr:    true,
		},
		{
			name:       "Wrong prefix",
			authHeader: "Basic dXNlcjpwYXNz",
			wantToken:  "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ExtractBearerToken(tt.authHeader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractBearerToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if token != tt.wantToken {
				t.Errorf("ExtractBearerToken() = %v, want %v", token, tt.wantToken)
			}
		})
	}
}

func TestParseTokenUnverified(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	expiresAt := time.Now().Add(time.Hour)

	tokenString := createTestToken(testSecret, tenantID, userID, expiresAt)

	claims, err := ParseTokenUnverified(tokenString)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if claims.TenantID != tenantID {
		t.Errorf("Expected tenant ID %s, got %s", tenantID, claims.TenantID)
	}
}
