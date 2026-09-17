// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockZedTokenStore is a mock implementation for testing
type MockZedTokenStore struct {
	tokens map[string]string
}

func NewMockZedTokenStore() *MockZedTokenStore {
	return &MockZedTokenStore{
		tokens: make(map[string]string),
	}
}

func (m *MockZedTokenStore) StoreToken(_ context.Context, tenantID uuid.UUID, resourceType, resourceID, token string) error {
	key := m.makeKey(tenantID, resourceType, resourceID)
	m.tokens[key] = token
	return nil
}

func (m *MockZedTokenStore) GetToken(_ context.Context, tenantID uuid.UUID, resourceType, resourceID string) (string, error) {
	key := m.makeKey(tenantID, resourceType, resourceID)
	token, exists := m.tokens[key]
	if !exists {
		return "", ErrTokenNotFound
	}
	return token, nil
}

func (m *MockZedTokenStore) GetTokens(ctx context.Context, tenantID uuid.UUID, resourceType string, resourceIDs []string) (map[string]string, error) {
	result := make(map[string]string)
	for _, resourceID := range resourceIDs {
		token, err := m.GetToken(ctx, tenantID, resourceType, resourceID)
		if err == nil {
			result[resourceID] = token
		}
	}
	return result, nil
}

func (m *MockZedTokenStore) DeleteToken(_ context.Context, tenantID uuid.UUID, resourceType, resourceID string) error {
	key := m.makeKey(tenantID, resourceType, resourceID)
	delete(m.tokens, key)
	return nil
}

func (m *MockZedTokenStore) CleanupOldTokens(_ context.Context, _ time.Duration) (int64, error) {
	// Mock implementation - just clear all for testing
	count := int64(len(m.tokens))
	m.tokens = make(map[string]string)
	return count, nil
}

func (m *MockZedTokenStore) makeKey(tenantID uuid.UUID, resourceType, resourceID string) string {
	return tenantID.String() + ":" + resourceType + ":" + resourceID
}

func TestZedTokenStore_StoreAndRetrieve(t *testing.T) {
	ctx := context.Background()
	store := NewMockZedTokenStore()
	tenantID := uuid.New()
	token := "test-token-123"

	// Store token for a user
	err := store.StoreToken(ctx, tenantID, "user", "user-1", token)
	require.NoError(t, err)

	// Retrieve token
	retrieved, err := store.GetToken(ctx, tenantID, "user", "user-1")
	require.NoError(t, err)
	assert.Equal(t, token, retrieved)
}

func TestZedTokenStore_NotFound(t *testing.T) {
	ctx := context.Background()
	store := NewMockZedTokenStore()
	tenantID := uuid.New()

	// Try to get non-existent token
	_, err := store.GetToken(ctx, tenantID, "user", "user-1")
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

func TestZedTokenStore_BatchGet(t *testing.T) {
	ctx := context.Background()
	store := NewMockZedTokenStore()
	tenantID := uuid.New()

	// Store multiple tokens
	_ = store.StoreToken(ctx, tenantID, "invoice", "inv-1", "token-1")
	_ = store.StoreToken(ctx, tenantID, "invoice", "inv-2", "token-2")
	_ = store.StoreToken(ctx, tenantID, "invoice", "inv-3", "token-3")

	// Get batch
	tokens, err := store.GetTokens(ctx, tenantID, "invoice", []string{"inv-1", "inv-2", "inv-3", "inv-4"})
	require.NoError(t, err)

	assert.Len(t, tokens, 3) // inv-4 not found, so only 3
	assert.Equal(t, "token-1", tokens["inv-1"])
	assert.Equal(t, "token-2", tokens["inv-2"])
	assert.Equal(t, "token-3", tokens["inv-3"])
}

func TestZedTokenStore_Delete(t *testing.T) {
	ctx := context.Background()
	store := NewMockZedTokenStore()
	tenantID := uuid.New()

	// Store token
	_ = store.StoreToken(ctx, tenantID, "user", "user-1", "token-1")

	// Verify it exists
	_, err := store.GetToken(ctx, tenantID, "user", "user-1")
	require.NoError(t, err)

	// Delete token
	err = store.DeleteToken(ctx, tenantID, "user", "user-1")
	require.NoError(t, err)

	// Verify it's gone
	_, err = store.GetToken(ctx, tenantID, "user", "user-1")
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

func TestZedTokenStore_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	store := NewMockZedTokenStore()
	tenant1 := uuid.New()
	tenant2 := uuid.New()

	// Store same resource ID for different tenants
	_ = store.StoreToken(ctx, tenant1, "user", "user-1", "tenant1-token")
	_ = store.StoreToken(ctx, tenant2, "user", "user-1", "tenant2-token")

	// Verify tenant isolation
	token1, err := store.GetToken(ctx, tenant1, "user", "user-1")
	require.NoError(t, err)
	assert.Equal(t, "tenant1-token", token1)

	token2, err := store.GetToken(ctx, tenant2, "user", "user-1")
	require.NoError(t, err)
	assert.Equal(t, "tenant2-token", token2)
}

func TestZedTokenStore_Cleanup(t *testing.T) {
	ctx := context.Background()
	store := NewMockZedTokenStore()
	tenantID := uuid.New()

	// Store multiple tokens
	_ = store.StoreToken(ctx, tenantID, "invoice", "inv-1", "token-1")
	_ = store.StoreToken(ctx, tenantID, "invoice", "inv-2", "token-2")
	_ = store.StoreToken(ctx, tenantID, "invoice", "inv-3", "token-3")

	// Cleanup
	deleted, err := store.CleanupOldTokens(ctx, 7*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(3), deleted)

	// Verify all gone
	_, err = store.GetToken(ctx, tenantID, "invoice", "inv-1")
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

// Example: How to use ZedTokens in practice
func ExampleZedTokenStore_userRoleAssignment() {
	ctx := context.Background()
	store := NewMockZedTokenStore()
	tenantID := uuid.New()
	userID := uuid.New()
	roleID := uuid.New()

	// Simulate writing user-role relationship to SpiceDB
	// In real code, this would be: token, _ := client.WriteUserRole(...)
	zedToken := "GhUKEzE3MTI1ODM1OTkwMDAwMDAwMDA=" //nolint:gosec // test fixture value, not a real credential  // gitleaks:allow — test fixture, not a real credential

	// Store the token for the user-role assignment
	userRoleKey := userID.String() + "_" + roleID.String()
	_ = store.StoreToken(ctx, tenantID, "user_role", userRoleKey, zedToken)

	// Later: retrieve token for consistency check
	token, _ := store.GetToken(ctx, tenantID, "user_role", userRoleKey)

	// Use token in permission check
	// In real code: client.CheckPermissionWithConsistency(..., ConsistencyAtLeastAsFresh, token)
	_ = token // Use the token for consistency guarantee
}

// Example: How to use ZedTokens for resource-level permissions
func ExampleZedTokenStore_resourcePermission() {
	ctx := context.Background()
	store := NewMockZedTokenStore()
	tenantID := uuid.New()
	invoiceID := uuid.New()

	// Simulate writing resource relationship to SpiceDB
	// In real code: token, _ := client.WriteResourceRelationship(...)
	zedToken := "GhUKEzE3MTI1ODM1OTkwMDAwMDAwMDA=" //nolint:gosec // test fixture value, not a real credential  // gitleaks:allow — test fixture, not a real credential

	// Store token scoped to this invoice
	_ = store.StoreToken(ctx, tenantID, "invoice", invoiceID.String(), zedToken)

	// Later: check permission with consistency
	token, _ := store.GetToken(ctx, tenantID, "invoice", invoiceID.String())

	// Use token in permission check
	// In real code: client.CheckPermissionWithConsistency(..., ConsistencyAtLeastAsFresh, token)
	_ = token // Use the token for consistency guarantee
}
