// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// apiKeyServiceRepo defines the repository methods needed by APIKeyService.
type apiKeyServiceRepo interface {
	Create(ctx context.Context, key *models.APIKey) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error)
	GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.APIKey, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error)
	Update(ctx context.Context, key *models.APIKey) error
	Revoke(ctx context.Context, id uuid.UUID) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetByPrefix(ctx context.Context, prefix string) (*models.APIKey, error)
	UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error
	LogUsage(ctx context.Context, usage *models.APIKeyUsage) error
	GetUsageStats(ctx context.Context, keyID uuid.UUID) (*models.APIKeyUsageStats, error)
}

const msgAPIKeyNotFoundSvc = "API key not found" //nolint:gosec // not a credential, this is a prefix constant for key generation

// APIKeyService handles API key operations
type APIKeyService struct {
	repo apiKeyServiceRepo
}

// NewAPIKeyService is an exported function.
func NewAPIKeyService(repo apiKeyServiceRepo) *APIKeyService {
	return &APIKeyService{
		repo: repo,
	}
}

// GenerateAPIKey generates a new API key with prefix
func (s *APIKeyService) GenerateAPIKey() (key string, prefix string, err error) {
	// Generate 32 bytes of random data for the key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Create the full key with a recognizable prefix
	key = "hxk_" + base64.URLEncoding.EncodeToString(keyBytes)

	// Use first 8 characters after prefix as the identifier
	prefix = key[4:12] // Skip "hxk_" and take next 8 chars

	return key, prefix, nil
}

// Create creates a new API key
func (s *APIKeyService) Create(ctx context.Context, tenantID, userID uuid.UUID, req *models.CreateAPIKeyRequest) (*models.APIKeyCreatedResponse, error) {
	// Generate the API key
	key, prefix, err := s.GenerateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("Create: GenerateAPIKey failed: %w", err)
	}

	// Hash the key for storage
	keyHash, err := crypto.HashPassword(key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to hash API key: %w", err)
	}

	apiKey := &models.APIKey{
		TenantID:          tenantID,
		UserID:            userID,
		Name:              req.Name,
		Description:       req.Description,
		KeyPrefix:         prefix,
		KeyHash:           keyHash,
		Scopes:            req.Scopes,
		IPWhitelist:       req.IPWhitelist,
		AllowedEndpoints:  req.AllowedEndpoints,
		RateLimitOverride: req.RateLimitOverride,
		Environment:       "production",
		IsActive:          true,
		CreatedBy:         &userID,
	}

	if req.Environment != nil {
		apiKey.Environment = *req.Environment
	}

	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("invalid expires_at format: use ISO 8601 format")
		}
		apiKey.ExpiresAt = &t
	}

	if err := s.repo.Create(ctx, apiKey); err != nil {
		return nil, fmt.Errorf("Create: %w", err)
	}

	logger.Info("API key created",
		zap.String("key_id", apiKey.ID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.String("name", apiKey.Name),
	)

	// Return the response with the actual key (only time it's shown)
	response := &models.APIKeyCreatedResponse{
		APIKeyResponse: *apiKey.ToResponse(),
		Key:            key,
	}

	return response, nil
}

// GetByID retrieves an API key by ID
func (s *APIKeyService) GetByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error) {
	return s.repo.GetByID(ctx, id)
}

// List lists all API keys for a tenant
func (s *APIKeyService) List(ctx context.Context, tenantID uuid.UUID) ([]*models.APIKey, error) {
	return s.repo.GetByTenantID(ctx, tenantID)
}

// ListByUser lists all API keys for a user
func (s *APIKeyService) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	return s.repo.GetByUserID(ctx, userID)
}

// Update updates an API key
func (s *APIKeyService) Update(ctx context.Context, tenantID, keyID uuid.UUID, req *models.UpdateAPIKeyRequest) (*models.APIKey, error) {
	key, err := s.repo.GetByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("Update: %w", err)
	}
	if key == nil {
		return nil, errors.New(msgAPIKeyNotFoundSvc)
	}

	// Verify tenant ownership
	if key.TenantID != tenantID {
		return nil, errors.New(msgAPIKeyNotFoundSvc)
	}

	// Apply updates
	if err := applyAPIKeyUpdates(key, req); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, key); err != nil {
		return nil, fmt.Errorf("Update: %w", err)
	}

	logger.Info("API key updated",
		zap.String("key_id", key.ID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return key, nil
}

// Revoke revokes an API key
func (s *APIKeyService) Revoke(ctx context.Context, tenantID, keyID uuid.UUID) error {
	key, err := s.repo.GetByID(ctx, keyID)
	if err != nil {
		return fmt.Errorf("Revoke: %w", err)
	}
	if key == nil {
		return errors.New(msgAPIKeyNotFoundSvc)
	}

	// Verify tenant ownership
	if key.TenantID != tenantID {
		return errors.New(msgAPIKeyNotFoundSvc)
	}

	if err := s.repo.Revoke(ctx, keyID); err != nil {
		return fmt.Errorf("Revoke: %w", err)
	}

	logger.Info("API key revoked",
		zap.String("key_id", keyID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return nil
}

// Delete permanently deletes an API key
func (s *APIKeyService) Delete(ctx context.Context, tenantID, keyID uuid.UUID) error {
	key, err := s.repo.GetByID(ctx, keyID)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if key == nil {
		return errors.New(msgAPIKeyNotFoundSvc)
	}

	// Verify tenant ownership
	if key.TenantID != tenantID {
		return errors.New(msgAPIKeyNotFoundSvc)
	}

	if err := s.repo.Delete(ctx, keyID); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}

	logger.Info("API key deleted",
		zap.String("key_id", keyID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return nil
}

// Regenerate regenerates an API key (creates new key, revokes old one)
func (s *APIKeyService) Regenerate(ctx context.Context, tenantID, keyID uuid.UUID) (*models.APIKeyCreatedResponse, error) {
	key, err := s.repo.GetByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("Regenerate: %w", err)
	}
	if key == nil {
		return nil, errors.New(msgAPIKeyNotFoundSvc)
	}

	// Verify tenant ownership
	if key.TenantID != tenantID {
		return nil, errors.New(msgAPIKeyNotFoundSvc)
	}

	// Create new key with same settings
	req := &models.CreateAPIKeyRequest{
		Name:              key.Name + " (regenerated)",
		Description:       key.Description,
		Scopes:            key.Scopes,
		IPWhitelist:       key.IPWhitelist,
		AllowedEndpoints:  key.AllowedEndpoints,
		RateLimitOverride: key.RateLimitOverride,
		Environment:       &key.Environment,
	}

	newKey, err := s.Create(ctx, tenantID, key.UserID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create new key: %w", err)
	}

	// Revoke old key — return error if revocation fails to prevent both keys being active
	if err := s.repo.Revoke(ctx, keyID); err != nil {
		logger.Error("Failed to revoke old API key after regeneration",
			zap.String("old_key_id", keyID.String()),
			zap.String("new_key_id", newKey.ID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("new key created but old key revocation failed: %w", err)
	}

	logger.Info("API key regenerated",
		zap.String("old_key_id", keyID.String()),
		zap.String("new_key_id", newKey.ID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return newKey, nil
}

// ValidateAPIKey validates an API key and returns the key row when it
// is currently usable, or an error describing the specific failure.
//
// Failure modes (post-2026-05-21):
//   - key not found                              → "API key not found" (unknown prefix)
//   - prefix matches but key hash does not       → "invalid API key"   (wrong key)
//   - key is_active=false                        → "API key is deactivated" + structured warn
//   - key revoked_at is set                      → "API key is revoked"     + structured warn
//   - key expires_at is in the past              → "API key is expired"     + structured warn
//
// Pre-2026-05-21 the repo's WHERE clause filtered on all three state
// columns, collapsing every revoked / deactivated / expired replay
// attempt into the same "unknown prefix" path. The repo no longer
// filters, so this method is the single audit-trail boundary that
// distinguishes the four security-relevant cases.
//
// IMPORTANT: the hash-verify step deliberately runs BEFORE the state
// branches — an attacker probing the prefix space (8 chars) without
// the full key cannot tell apart "this prefix was never issued" from
// "this prefix was issued and revoked". Only callers who already
// know the key hash trigger the revoked/expired/deactivated audit
// signals.
func (s *APIKeyService) ValidateAPIKey(ctx context.Context, keyString string) (*models.APIKey, error) {
	// API key format: hxk_<base64-encoded-random-bytes>
	if !strings.HasPrefix(keyString, "hxk_") {
		return nil, fmt.Errorf("invalid API key format")
	}

	// Extract prefix (first 8 chars after "hxk_")
	if len(keyString) < 12 {
		return nil, fmt.Errorf("invalid API key format")
	}
	prefix := keyString[4:12]

	// Look up key by prefix
	key, err := s.repo.GetByPrefix(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup API key: %w", err)
	}
	if key == nil {
		return nil, errors.New(msgAPIKeyNotFoundSvc)
	}

	// Verify the full key hash BEFORE the state branches so prefix-
	// space scanners get the same "invalid" response whether or not
	// the prefix matches a revoked key.
	valid, hashErr := crypto.VerifyPassword(keyString, key.KeyHash)
	if hashErr != nil || !valid {
		return nil, fmt.Errorf("invalid API key")
	}

	// Past the hash gate — the caller has the actual key bytes. State
	// failures are now safe to differentiate, and each emits a
	// dedicated audit dimension so the SOC can pivot.
	if key.RevokedAt != nil {
		logger.Warn("api_key_replay.revoked_attempted",
			zap.String("tenant_id", key.TenantID.String()),
			zap.String("key_id", key.ID.String()),
			zap.Time("revoked_at", *key.RevokedAt),
		)
		return nil, fmt.Errorf("API key is revoked")
	}
	if !key.IsActive {
		logger.Warn("api_key_replay.deactivated_attempted",
			zap.String("tenant_id", key.TenantID.String()),
			zap.String("key_id", key.ID.String()),
		)
		return nil, fmt.Errorf("API key is deactivated")
	}
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		logger.Warn("api_key_replay.expired_attempted",
			zap.String("tenant_id", key.TenantID.String()),
			zap.String("key_id", key.ID.String()),
			zap.Time("expired_at", *key.ExpiresAt),
		)
		return nil, fmt.Errorf("API key is expired")
	}

	return key, nil
}

// APIKeyUsageRecord groups the parameters for RecordUsage,
// reducing its parameter count below the project linting threshold.
type APIKeyUsageRecord struct {
	KeyID          uuid.UUID
	TenantID       uuid.UUID
	Endpoint       string
	Method         string
	IP             string
	StatusCode     int
	ResponseTimeMs int
}

// RecordUsage records API key usage
func (s *APIKeyService) RecordUsage(ctx context.Context, r APIKeyUsageRecord) {
	keyID := r.KeyID
	tenantID := r.TenantID
	endpoint := r.Endpoint
	method := r.Method
	ip := r.IP
	statusCode := r.StatusCode
	responseTimeMs := r.ResponseTimeMs
	// Detach from request context so goroutines survive after handler returns
	bgCtx := context.WithoutCancel(ctx)

	// Update last used timestamp
	go func() {
		if err := s.repo.UpdateLastUsed(bgCtx, keyID, ip); err != nil {
			logger.Error("Failed to update API key last used", zap.Error(err))
		}
	}()

	// Log detailed usage
	go func() {
		usage := &models.APIKeyUsage{
			APIKeyID:       keyID,
			TenantID:       tenantID,
			Endpoint:       endpoint,
			Method:         method,
			StatusCode:     &statusCode,
			ResponseTimeMs: &responseTimeMs,
			IPAddress:      &ip,
		}
		if err := s.repo.LogUsage(bgCtx, usage); err != nil {
			logger.Error("Failed to log API key usage", zap.Error(err))
		}
	}()
}

// applyAPIKeyUpdates applies non-nil fields from the update request onto the
// existing key. It returns an error only for invalid field values (e.g. a
// malformed timestamp).
func applyAPIKeyUpdates(key *models.APIKey, req *models.UpdateAPIKeyRequest) error {
	if req.Name != nil {
		key.Name = *req.Name
	}
	if req.Description != nil {
		key.Description = req.Description
	}
	if req.Scopes != nil {
		key.Scopes = req.Scopes
	}
	if req.IPWhitelist != nil {
		key.IPWhitelist = req.IPWhitelist
	}
	if req.AllowedEndpoints != nil {
		key.AllowedEndpoints = req.AllowedEndpoints
	}
	if req.RateLimitOverride != nil {
		key.RateLimitOverride = req.RateLimitOverride
	}
	if req.Environment != nil {
		key.Environment = *req.Environment
	}
	if req.IsActive != nil {
		key.IsActive = *req.IsActive
	}
	if req.ExpiresAt != nil {
		if *req.ExpiresAt == "" {
			key.ExpiresAt = nil
		} else {
			t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				return fmt.Errorf("invalid expires_at format: use ISO 8601 format")
			}
			key.ExpiresAt = &t
		}
	}
	return nil
}

// GetUsageStats retrieves usage statistics for an API key
func (s *APIKeyService) GetUsageStats(ctx context.Context, tenantID, keyID uuid.UUID) (*models.APIKeyUsageStats, error) {
	key, err := s.repo.GetByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("GetUsageStats: %w", err)
	}
	if key == nil {
		return nil, errors.New(msgAPIKeyNotFoundSvc)
	}

	// Verify tenant ownership
	if key.TenantID != tenantID {
		return nil, errors.New(msgAPIKeyNotFoundSvc)
	}

	return s.repo.GetUsageStats(ctx, keyID)
}
