// SPDX-License-Identifier: AGPL-3.0-or-later

// Package spicedb provides ZedToken storage for consistency guarantees.
// ZedTokens solve the "New Enemy Problem" from Google Zanzibar by ensuring
// that permission checks see the latest relationship changes.
package spicedb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const spicedbObjectTypeUserRole = "user_role"

// ErrTokenNotFound is returned when a ZedToken is not found for a resource
var ErrTokenNotFound = fmt.Errorf("zed token not found")

// ZedTokenStore interface for storing/retrieving tokens.
// Implementations must be thread-safe.
type ZedTokenStore interface {
	// StoreToken stores a token for a resource
	StoreToken(ctx context.Context, tenantID uuid.UUID, resourceType, resourceID, token string) error

	// GetToken retrieves a token for a resource
	GetToken(ctx context.Context, tenantID uuid.UUID, resourceType, resourceID string) (string, error)

	// GetTokens retrieves tokens for multiple resources (batch operation)
	GetTokens(ctx context.Context, tenantID uuid.UUID, resourceType string, resourceIDs []string) (map[string]string, error)

	// DeleteToken removes a token for a resource
	DeleteToken(ctx context.Context, tenantID uuid.UUID, resourceType, resourceID string) error

	// CleanupOldTokens removes tokens older than the specified duration
	CleanupOldTokens(ctx context.Context, olderThan time.Duration) (int64, error)
}

// PostgresZedTokenStore implements ZedTokenStore using PostgreSQL.
// It supports both dedicated columns (iam_users, iam_roles, iam_user_roles)
// and a generic key-value table (iam_zed_tokens) for other resources.
type PostgresZedTokenStore struct {
	db *pgxpool.Pool
}

// NewPostgresZedTokenStore creates a new PostgreSQL-backed ZedToken store.
func NewPostgresZedTokenStore(db *pgxpool.Pool) *PostgresZedTokenStore {
	return &PostgresZedTokenStore{db: db}
}

// StoreToken stores a ZedToken for a resource.
// Uses dedicated columns for users, roles, and user_roles.
// Uses iam_zed_tokens table for all other resource types.
func (s *PostgresZedTokenStore) StoreToken(ctx context.Context, tenantID uuid.UUID, resourceType, resourceID, token string) error {
	var err error

	switch resourceType {
	case spicedbObjectTypeUser:
		err = s.storeUserToken(ctx, resourceID, token)
	case spicedbObjectTypeRole:
		err = s.storeRoleToken(ctx, tenantID, resourceID, token)
	case spicedbObjectTypeUserRole:
		err = s.storeUserRoleToken(ctx, resourceID, token)
	default:
		err = s.storeGenericToken(ctx, tenantID, resourceType, resourceID, token)
	}

	if err != nil {
		logger.Log.Error("Failed to store ZedToken",
			zap.Error(err),
			zap.String("tenant_id", tenantID.String()),
			zap.String("resource_type", resourceType),
			zap.String("resource_id", resourceID),
		)
		return fmt.Errorf("failed to store ZedToken for %s/%s: %w", resourceType, resourceID, err)
	}

	logger.Log.Debug("Stored ZedToken",
		zap.String("tenant_id", tenantID.String()),
		zap.String("resource_type", resourceType),
		zap.String("resource_id", resourceID),
	)

	return nil
}

// GetToken retrieves a ZedToken for a resource.
func (s *PostgresZedTokenStore) GetToken(ctx context.Context, tenantID uuid.UUID, resourceType, resourceID string) (string, error) {
	var token string
	var err error

	switch resourceType {
	case spicedbObjectTypeUser:
		token, err = s.getUserToken(ctx, resourceID)
	case spicedbObjectTypeRole:
		token, err = s.getRoleToken(ctx, tenantID, resourceID)
	case spicedbObjectTypeUserRole:
		token, err = s.getUserRoleToken(ctx, resourceID)
	default:
		token, err = s.getGenericToken(ctx, tenantID, resourceType, resourceID)
	}

	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return "", ErrTokenNotFound
		}
		return "", fmt.Errorf("failed to get ZedToken for %s/%s: %w", resourceType, resourceID, err)
	}

	return token, nil
}

// GetTokens retrieves tokens for multiple resources in a batch.
// This is more efficient than calling GetToken multiple times.
func (s *PostgresZedTokenStore) GetTokens(ctx context.Context, tenantID uuid.UUID, resourceType string, resourceIDs []string) (map[string]string, error) {
	if len(resourceIDs) == 0 {
		return make(map[string]string), nil
	}

	tokens := make(map[string]string)

	// For small batches, just loop (simpler implementation)
	// For large batches, we could optimize with a single query
	for _, resourceID := range resourceIDs {
		token, err := s.GetToken(ctx, tenantID, resourceType, resourceID)
		if err != nil && !errors.Is(err, ErrTokenNotFound) {
			return nil, fmt.Errorf("GetTokens: GetToken failed: %w", err)
		}
		if err == nil {
			tokens[resourceID] = token
		}
	}

	return tokens, nil
}

// DeleteToken removes a ZedToken for a resource.
func (s *PostgresZedTokenStore) DeleteToken(ctx context.Context, tenantID uuid.UUID, resourceType, resourceID string) error {
	var err error

	switch resourceType {
	case spicedbObjectTypeUser:
		err = s.deleteUserToken(ctx, resourceID)
	case spicedbObjectTypeRole:
		err = s.deleteRoleToken(ctx, tenantID, resourceID)
	case spicedbObjectTypeUserRole:
		err = s.deleteUserRoleToken(ctx, resourceID)
	default:
		err = s.deleteGenericToken(ctx, tenantID, resourceType, resourceID)
	}

	if err != nil {
		return fmt.Errorf("failed to delete ZedToken for %s/%s: %w", resourceType, resourceID, err)
	}

	return nil
}

// CleanupOldTokens removes tokens older than the specified duration.
// Returns the number of tokens deleted.
func (s *PostgresZedTokenStore) CleanupOldTokens(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)

	result, err := s.db.Exec(ctx,
		`DELETE FROM iam_zed_tokens WHERE updated_at < $1`,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old ZedTokens: %w", err)
	}

	return result.RowsAffected(), nil
}

// =====================================================
// Internal helper methods for specific resource types
// =====================================================

func (s *PostgresZedTokenStore) storeUserToken(ctx context.Context, userID, token string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE iam_users SET zed_token = $1 WHERE id = $2`,
		token, userID,
	)
	if err != nil {
		return fmt.Errorf("storeUserToken: %w", err)
	}
	return nil
}

func (s *PostgresZedTokenStore) getUserToken(ctx context.Context, userID string) (string, error) {
	var token *string
	err := s.db.QueryRow(ctx,
		`SELECT zed_token FROM iam_users WHERE id = $1`,
		userID,
	).Scan(&token)
	if err != nil {
		return "", fmt.Errorf("getUserToken: %w", err)
	}
	if token == nil {
		return "", ErrTokenNotFound
	}
	return *token, nil
}

func (s *PostgresZedTokenStore) deleteUserToken(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE iam_users SET zed_token = NULL WHERE id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("deleteUserToken: %w", err)
	}
	return nil
}

func (s *PostgresZedTokenStore) storeRoleToken(ctx context.Context, tenantID uuid.UUID, roleID, token string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE iam_roles SET zed_token = $1 WHERE id = $2 AND tenant_id = $3`,
		token, roleID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("storeRoleToken: %w", err)
	}
	return nil
}

func (s *PostgresZedTokenStore) getRoleToken(ctx context.Context, tenantID uuid.UUID, roleID string) (string, error) {
	var token *string
	err := s.db.QueryRow(ctx,
		`SELECT zed_token FROM iam_roles WHERE id = $1 AND tenant_id = $2`,
		roleID, tenantID,
	).Scan(&token)
	if err != nil {
		return "", fmt.Errorf("getRoleToken: %w", err)
	}
	if token == nil {
		return "", ErrTokenNotFound
	}
	return *token, nil
}

func (s *PostgresZedTokenStore) deleteRoleToken(ctx context.Context, tenantID uuid.UUID, roleID string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE iam_roles SET zed_token = NULL WHERE id = $1 AND tenant_id = $2`,
		roleID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("deleteRoleToken: %w", err)
	}
	return nil
}

func (s *PostgresZedTokenStore) storeUserRoleToken(ctx context.Context, userRoleKey, token string) error {
	// userRoleKey format: "userID_roleID"
	// We need to parse it to get both IDs
	parts := strings.SplitN(userRoleKey, "_", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid user_role key format: %s (expected userID_roleID)", userRoleKey)
	}

	userID, err := uuid.Parse(parts[0])
	if err != nil {
		return fmt.Errorf("invalid user ID in key %s: %w", userRoleKey, err)
	}

	roleID, err := uuid.Parse(parts[1])
	if err != nil {
		return fmt.Errorf("invalid role ID in key %s: %w", userRoleKey, err)
	}

	_, err = s.db.Exec(ctx,
		`UPDATE iam_user_roles SET zed_token = $1 WHERE user_id = $2 AND role_id = $3`,
		token, userID, roleID,
	)
	if err != nil {
		return fmt.Errorf("storeUserRoleToken: %w", err)
	}
	return nil
}

func (s *PostgresZedTokenStore) getUserRoleToken(ctx context.Context, userRoleKey string) (string, error) {
	parts := strings.SplitN(userRoleKey, "_", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid user_role key format: %s (expected userID_roleID)", userRoleKey)
	}

	userID, err := uuid.Parse(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid user ID in key %s: %w", userRoleKey, err)
	}

	roleID, err := uuid.Parse(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid role ID in key %s: %w", userRoleKey, err)
	}

	var token *string
	err = s.db.QueryRow(ctx,
		`SELECT zed_token FROM iam_user_roles WHERE user_id = $1 AND role_id = $2`,
		userID, roleID,
	).Scan(&token)
	if err != nil {
		return "", fmt.Errorf("getUserRoleToken: %w", err)
	}
	if token == nil {
		return "", ErrTokenNotFound
	}
	return *token, nil
}

func (s *PostgresZedTokenStore) deleteUserRoleToken(ctx context.Context, userRoleKey string) error {
	parts := strings.SplitN(userRoleKey, "_", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid user_role key format: %s (expected userID_roleID)", userRoleKey)
	}

	userID, err := uuid.Parse(parts[0])
	if err != nil {
		return fmt.Errorf("invalid user ID in key %s: %w", userRoleKey, err)
	}

	roleID, err := uuid.Parse(parts[1])
	if err != nil {
		return fmt.Errorf("invalid role ID in key %s: %w", userRoleKey, err)
	}

	_, err = s.db.Exec(ctx,
		`UPDATE iam_user_roles SET zed_token = NULL WHERE user_id = $1 AND role_id = $2`,
		userID, roleID,
	)
	if err != nil {
		return fmt.Errorf("deleteUserRoleToken: %w", err)
	}
	return nil
}

func (s *PostgresZedTokenStore) storeGenericToken(ctx context.Context, tenantID uuid.UUID, resourceType, resourceID, token string) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO iam_zed_tokens (resource_type, resource_id, token, tenant_id, updated_at)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (resource_type, resource_id, tenant_id)
		 DO UPDATE SET token = $3, updated_at = NOW()`,
		resourceType, resourceID, token, tenantID,
	)
	if err != nil {
		return fmt.Errorf("storeGenericToken: %w", err)
	}
	return nil
}

func (s *PostgresZedTokenStore) getGenericToken(ctx context.Context, tenantID uuid.UUID, resourceType, resourceID string) (string, error) {
	var token string
	err := s.db.QueryRow(ctx,
		`SELECT token FROM iam_zed_tokens
		 WHERE resource_type = $1 AND resource_id = $2 AND tenant_id = $3`,
		resourceType, resourceID, tenantID,
	).Scan(&token)
	if err != nil {
		return "", fmt.Errorf("getGenericToken: %w", err)
	}
	return token, nil
}

func (s *PostgresZedTokenStore) deleteGenericToken(ctx context.Context, tenantID uuid.UUID, resourceType, resourceID string) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM iam_zed_tokens
		 WHERE resource_type = $1 AND resource_id = $2 AND tenant_id = $3`,
		resourceType, resourceID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("deleteGenericToken: %w", err)
	}
	return nil
}
