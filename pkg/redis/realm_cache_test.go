// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// setupTestRealmCache creates a test Redis server and RealmCache for testing
func setupTestRealmCache(t *testing.T) (*RealmCache, *miniredis.Miniredis) {
	t.Helper()

	// Create a miniredis server
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create miniredis: %v", err)
	}

	// Create a test config
	cfg := &Config{
		URL:             "redis://" + mr.Addr(),
		MaxRetries:      3,
		MinIdleConns:    1,
		MaxIdleConns:    2,
		ConnMaxLifetime: 30 * time.Minute,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
	}

	logger := zap.NewNop()
	client, err := NewClient(cfg, logger)
	if err != nil {
		mr.Close()
		t.Fatalf("Failed to create client: %v", err)
	}

	cache := NewRealmCache(client, "test:realm:", 10*time.Minute)
	return cache, mr
}

func TestNewRealmCache(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	if cache == nil {
		t.Fatal("Expected cache to be non-nil")
	}

	if cache.prefix != "test:realm:" {
		t.Errorf("prefix = %s, want test:realm:", cache.prefix)
	}

	if cache.ttl != 10*time.Minute {
		t.Errorf("ttl = %v, want 10m", cache.ttl)
	}
}

func TestRealmCache_SetAndGetRealmByID(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	ctx := context.Background()

	t.Run("Set and get realm by ID", func(t *testing.T) {
		realmID := uuid.New()
		realm := &CachedRealm{
			ID:              realmID,
			Slug:            "test-realm",
			Name:            "Test Realm",
			Type:            "enterprise",
			Status:          "active",
			ConnectionLimit: 100,
			MaxTenants:      50,
		}

		err := cache.SetRealm(ctx, realm)
		if err != nil {
			t.Fatalf("SetRealm() error = %v", err)
		}

		got, err := cache.GetRealmByID(ctx, realmID)
		if err != nil {
			t.Fatalf("GetRealmByID() error = %v", err)
		}

		if got == nil {
			t.Fatal("GetRealmByID() returned nil")
		}

		if got.ID != realmID {
			t.Errorf("ID = %s, want %s", got.ID, realmID)
		}

		if got.Slug != "test-realm" {
			t.Errorf("Slug = %s, want test-realm", got.Slug)
		}

		if got.Name != "Test Realm" {
			t.Errorf("Name = %s, want Test Realm", got.Name)
		}

		if got.Type != "enterprise" {
			t.Errorf("Type = %s, want enterprise", got.Type)
		}

		if got.Status != "active" {
			t.Errorf("Status = %s, want active", got.Status)
		}
	})

	t.Run("Get non-existent realm by ID", func(t *testing.T) {
		nonExistentID := uuid.New()
		got, err := cache.GetRealmByID(ctx, nonExistentID)
		if err != nil {
			t.Fatalf("GetRealmByID() error = %v", err)
		}

		if got != nil {
			t.Errorf("Expected nil for non-existent realm, got %+v", got)
		}
	})
}

func TestRealmCache_SetAndGetRealmBySlug(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	ctx := context.Background()

	t.Run("Set and get realm by slug", func(t *testing.T) {
		realmID := uuid.New()
		slug := "acme-corp"
		realm := &CachedRealm{
			ID:     realmID,
			Slug:   slug,
			Name:   "ACME Corporation",
			Type:   "shared",
			Status: "active",
		}

		err := cache.SetRealm(ctx, realm)
		if err != nil {
			t.Fatalf("SetRealm() error = %v", err)
		}

		got, err := cache.GetRealmBySlug(ctx, slug)
		if err != nil {
			t.Fatalf("GetRealmBySlug() error = %v", err)
		}

		if got == nil {
			t.Fatal("GetRealmBySlug() returned nil")
		}

		if got.ID != realmID {
			t.Errorf("ID = %s, want %s", got.ID, realmID)
		}

		if got.Slug != slug {
			t.Errorf("Slug = %s, want %s", got.Slug, slug)
		}
	})

	t.Run("Get non-existent realm by slug", func(t *testing.T) {
		got, err := cache.GetRealmBySlug(ctx, "non-existent-slug")
		if err != nil {
			t.Fatalf("GetRealmBySlug() error = %v", err)
		}

		if got != nil {
			t.Errorf("Expected nil for non-existent realm, got %+v", got)
		}
	})
}

func TestRealmCache_DeleteRealm(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	ctx := context.Background()

	realmID := uuid.New()
	slug := "delete-test"
	realm := &CachedRealm{
		ID:     realmID,
		Slug:   slug,
		Name:   "Delete Test Realm",
		Type:   "shared",
		Status: "active",
	}

	// Set realm
	err := cache.SetRealm(ctx, realm)
	if err != nil {
		t.Fatalf("SetRealm() error = %v", err)
	}

	// Verify it exists
	got, err := cache.GetRealmByID(ctx, realmID)
	if err != nil || got == nil {
		t.Fatal("Realm should exist before deletion")
	}

	// Delete realm
	err = cache.DeleteRealm(ctx, realmID, slug)
	if err != nil {
		t.Fatalf("DeleteRealm() error = %v", err)
	}

	// Verify it's deleted by ID
	got, err = cache.GetRealmByID(ctx, realmID)
	if err != nil {
		t.Fatalf("GetRealmByID() error = %v", err)
	}
	if got != nil {
		t.Error("Realm should not exist after deletion (by ID)")
	}

	// Verify it's deleted by slug
	got, err = cache.GetRealmBySlug(ctx, slug)
	if err != nil {
		t.Fatalf("GetRealmBySlug() error = %v", err)
	}
	if got != nil {
		t.Error("Realm should not exist after deletion (by slug)")
	}
}

func TestRealmCache_SetAndGetTenantRealm(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	ctx := context.Background()

	t.Run("Set and get tenant-realm mapping", func(t *testing.T) {
		tenantID := uuid.New()
		realmID := uuid.New()
		mapping := &CachedTenantRealm{
			TenantID:  tenantID,
			RealmID:   realmID,
			RealmSlug: "test-realm",
			RealmType: "enterprise",
			IsPrimary: true,
		}

		err := cache.SetTenantRealm(ctx, mapping)
		if err != nil {
			t.Fatalf("SetTenantRealm() error = %v", err)
		}

		got, err := cache.GetTenantRealm(ctx, tenantID)
		if err != nil {
			t.Fatalf("GetTenantRealm() error = %v", err)
		}

		if got == nil {
			t.Fatal("GetTenantRealm() returned nil")
		}

		if got.TenantID != tenantID {
			t.Errorf("TenantID = %s, want %s", got.TenantID, tenantID)
		}

		if got.RealmID != realmID {
			t.Errorf("RealmID = %s, want %s", got.RealmID, realmID)
		}

		if got.RealmSlug != "test-realm" {
			t.Errorf("RealmSlug = %s, want test-realm", got.RealmSlug)
		}

		if got.RealmType != "enterprise" {
			t.Errorf("RealmType = %s, want enterprise", got.RealmType)
		}

		if !got.IsPrimary {
			t.Error("IsPrimary = false, want true")
		}
	})

	t.Run("Get non-existent tenant-realm mapping", func(t *testing.T) {
		nonExistentID := uuid.New()
		got, err := cache.GetTenantRealm(ctx, nonExistentID)
		if err != nil {
			t.Fatalf("GetTenantRealm() error = %v", err)
		}

		if got != nil {
			t.Errorf("Expected nil for non-existent mapping, got %+v", got)
		}
	})
}

func TestRealmCache_DeleteTenantRealm(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	ctx := context.Background()

	tenantID := uuid.New()
	realmID := uuid.New()
	mapping := &CachedTenantRealm{
		TenantID:  tenantID,
		RealmID:   realmID,
		RealmSlug: "delete-test",
		RealmType: "shared",
		IsPrimary: true,
	}

	// Set mapping
	err := cache.SetTenantRealm(ctx, mapping)
	if err != nil {
		t.Fatalf("SetTenantRealm() error = %v", err)
	}

	// Verify it exists
	got, err := cache.GetTenantRealm(ctx, tenantID)
	if err != nil || got == nil {
		t.Fatal("Mapping should exist before deletion")
	}

	// Delete mapping
	err = cache.DeleteTenantRealm(ctx, tenantID, realmID)
	if err != nil {
		t.Fatalf("DeleteTenantRealm() error = %v", err)
	}

	// Verify it's deleted
	got, err = cache.GetTenantRealm(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetTenantRealm() error = %v", err)
	}
	if got != nil {
		t.Error("Mapping should not exist after deletion")
	}
}

func TestRealmCache_GetRealmTenantCount(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	ctx := context.Background()

	realmID := uuid.New()

	// Initially should be 0
	count, err := cache.GetRealmTenantCount(ctx, realmID)
	if err != nil {
		t.Fatalf("GetRealmTenantCount() error = %v", err)
	}
	if count != 0 {
		t.Errorf("GetRealmTenantCount() = %d, want 0", count)
	}

	// Add some tenants
	for i := 0; i < 3; i++ {
		tenantID := uuid.New()
		mapping := &CachedTenantRealm{
			TenantID:  tenantID,
			RealmID:   realmID,
			RealmSlug: "test-realm",
			RealmType: "shared",
			IsPrimary: true,
		}
		err := cache.SetTenantRealm(ctx, mapping)
		if err != nil {
			t.Fatalf("SetTenantRealm() error = %v", err)
		}
	}

	// Should be 3
	count, err = cache.GetRealmTenantCount(ctx, realmID)
	if err != nil {
		t.Fatalf("GetRealmTenantCount() error = %v", err)
	}
	if count != 3 {
		t.Errorf("GetRealmTenantCount() = %d, want 3", count)
	}
}

func TestRealmCache_Exists(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	ctx := context.Background()

	realmID := uuid.New()

	// Initially should not exist
	exists, err := cache.Exists(ctx, realmID)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if exists {
		t.Error("Exists() = true, want false")
	}

	// Set realm
	realm := &CachedRealm{
		ID:     realmID,
		Slug:   "exists-test",
		Name:   "Exists Test Realm",
		Type:   "shared",
		Status: "active",
	}
	err = cache.SetRealm(ctx, realm)
	if err != nil {
		t.Fatalf("SetRealm() error = %v", err)
	}

	// Should exist now
	exists, err = cache.Exists(ctx, realmID)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Error("Exists() = false, want true")
	}
}

func TestRealmCache_RefreshRealm(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	ctx := context.Background()

	realmID := uuid.New()
	slug := "refresh-test"
	realm := &CachedRealm{
		ID:     realmID,
		Slug:   slug,
		Name:   "Refresh Test Realm",
		Type:   "shared",
		Status: "active",
	}

	err := cache.SetRealm(ctx, realm)
	if err != nil {
		t.Fatalf("SetRealm() error = %v", err)
	}

	// Refresh realm
	err = cache.RefreshRealm(ctx, realmID, slug)
	if err != nil {
		t.Fatalf("RefreshRealm() error = %v", err)
	}

	// Verify still exists
	got, err := cache.GetRealmByID(ctx, realmID)
	if err != nil {
		t.Fatalf("GetRealmByID() error = %v", err)
	}
	if got == nil {
		t.Error("Realm should still exist after refresh")
	}
}

func TestRealmCache_RefreshTenantRealm(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	ctx := context.Background()

	tenantID := uuid.New()
	realmID := uuid.New()
	mapping := &CachedTenantRealm{
		TenantID:  tenantID,
		RealmID:   realmID,
		RealmSlug: "refresh-test",
		RealmType: "shared",
		IsPrimary: true,
	}

	err := cache.SetTenantRealm(ctx, mapping)
	if err != nil {
		t.Fatalf("SetTenantRealm() error = %v", err)
	}

	// Refresh mapping
	err = cache.RefreshTenantRealm(ctx, tenantID, realmID)
	if err != nil {
		t.Fatalf("RefreshTenantRealm() error = %v", err)
	}

	// Verify still exists
	got, err := cache.GetTenantRealm(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetTenantRealm() error = %v", err)
	}
	if got == nil {
		t.Error("Mapping should still exist after refresh")
	}
}

func TestRealmCache_InvalidateRealmTenants(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	ctx := context.Background()

	realmID := uuid.New()
	var tenantIDs []uuid.UUID

	// Add 3 tenants
	for i := 0; i < 3; i++ {
		tenantID := uuid.New()
		tenantIDs = append(tenantIDs, tenantID)
		mapping := &CachedTenantRealm{
			TenantID:  tenantID,
			RealmID:   realmID,
			RealmSlug: "invalidate-test",
			RealmType: "shared",
			IsPrimary: true,
		}
		err := cache.SetTenantRealm(ctx, mapping)
		if err != nil {
			t.Fatalf("SetTenantRealm() error = %v", err)
		}
	}

	// Verify count is 3
	count, err := cache.GetRealmTenantCount(ctx, realmID)
	if err != nil {
		t.Fatalf("GetRealmTenantCount() error = %v", err)
	}
	if count != 3 {
		t.Errorf("GetRealmTenantCount() = %d, want 3", count)
	}

	// Invalidate all
	err = cache.InvalidateRealmTenants(ctx, realmID)
	if err != nil {
		t.Fatalf("InvalidateRealmTenants() error = %v", err)
	}

	// Verify count is 0
	count, err = cache.GetRealmTenantCount(ctx, realmID)
	if err != nil {
		t.Fatalf("GetRealmTenantCount() error = %v", err)
	}
	if count != 0 {
		t.Errorf("GetRealmTenantCount() = %d, want 0", count)
	}

	// Verify each tenant mapping is gone
	for _, tenantID := range tenantIDs {
		got, err := cache.GetTenantRealm(ctx, tenantID)
		if err != nil {
			t.Fatalf("GetTenantRealm() error = %v", err)
		}
		if got != nil {
			t.Errorf("Tenant %s mapping should be invalidated", tenantID)
		}
	}
}

func TestRealmCache_WarmupRealm(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	ctx := context.Background()

	realmID := uuid.New()
	realm := &CachedRealm{
		ID:     realmID,
		Slug:   "warmup-test",
		Name:   "Warmup Test Realm",
		Type:   "enterprise",
		Status: "active",
	}

	var mappings []*CachedTenantRealm
	for i := 0; i < 3; i++ {
		mappings = append(mappings, &CachedTenantRealm{
			TenantID:  uuid.New(),
			RealmID:   realmID,
			RealmSlug: "warmup-test",
			RealmType: "enterprise",
			IsPrimary: true,
		})
	}

	// Warmup
	err := cache.WarmupRealm(ctx, realm, mappings)
	if err != nil {
		t.Fatalf("WarmupRealm() error = %v", err)
	}

	// Verify realm
	got, err := cache.GetRealmByID(ctx, realmID)
	if err != nil {
		t.Fatalf("GetRealmByID() error = %v", err)
	}
	if got == nil {
		t.Error("Realm should exist after warmup")
	}

	gotBySlug, err := cache.GetRealmBySlug(ctx, "warmup-test")
	if err != nil {
		t.Fatalf("GetRealmBySlug() error = %v", err)
	}
	if gotBySlug == nil {
		t.Error("Realm should exist by slug after warmup")
	}

	// Verify tenant count
	count, err := cache.GetRealmTenantCount(ctx, realmID)
	if err != nil {
		t.Fatalf("GetRealmTenantCount() error = %v", err)
	}
	if count != 3 {
		t.Errorf("GetRealmTenantCount() = %d, want 3", count)
	}

	// Verify each tenant mapping
	for _, mapping := range mappings {
		gotMapping, err := cache.GetTenantRealm(ctx, mapping.TenantID)
		if err != nil {
			t.Fatalf("GetTenantRealm() error = %v", err)
		}
		if gotMapping == nil {
			t.Errorf("Tenant %s mapping should exist after warmup", mapping.TenantID)
		}
	}
}

// TestRealmCache_RealmIsolation tests that tenants from different realms are properly isolated
func TestRealmCache_RealmIsolation(t *testing.T) {
	cache, mr := setupTestRealmCache(t)
	defer mr.Close()

	ctx := context.Background()

	// Create two realms
	realm1ID := uuid.New()
	realm2ID := uuid.New()

	realm1 := &CachedRealm{
		ID:     realm1ID,
		Slug:   "realm-1",
		Name:   "Realm One",
		Type:   "enterprise",
		Status: "active",
	}
	realm2 := &CachedRealm{
		ID:     realm2ID,
		Slug:   "realm-2",
		Name:   "Realm Two",
		Type:   "shared",
		Status: "active",
	}

	err := cache.SetRealm(ctx, realm1)
	if err != nil {
		t.Fatalf("SetRealm(realm1) error = %v", err)
	}
	err = cache.SetRealm(ctx, realm2)
	if err != nil {
		t.Fatalf("SetRealm(realm2) error = %v", err)
	}

	// Add tenants to each realm
	tenant1 := uuid.New()
	tenant2 := uuid.New()

	mapping1 := &CachedTenantRealm{
		TenantID:  tenant1,
		RealmID:   realm1ID,
		RealmSlug: "realm-1",
		RealmType: "enterprise",
		IsPrimary: true,
	}
	mapping2 := &CachedTenantRealm{
		TenantID:  tenant2,
		RealmID:   realm2ID,
		RealmSlug: "realm-2",
		RealmType: "shared",
		IsPrimary: true,
	}

	err = cache.SetTenantRealm(ctx, mapping1)
	if err != nil {
		t.Fatalf("SetTenantRealm(mapping1) error = %v", err)
	}
	err = cache.SetTenantRealm(ctx, mapping2)
	if err != nil {
		t.Fatalf("SetTenantRealm(mapping2) error = %v", err)
	}

	// Verify each tenant is in the correct realm
	gotMapping1, err := cache.GetTenantRealm(ctx, tenant1)
	if err != nil {
		t.Fatalf("GetTenantRealm(tenant1) error = %v", err)
	}
	if gotMapping1.RealmID != realm1ID {
		t.Errorf("Tenant 1 RealmID = %s, want %s", gotMapping1.RealmID, realm1ID)
	}

	gotMapping2, err := cache.GetTenantRealm(ctx, tenant2)
	if err != nil {
		t.Fatalf("GetTenantRealm(tenant2) error = %v", err)
	}
	if gotMapping2.RealmID != realm2ID {
		t.Errorf("Tenant 2 RealmID = %s, want %s", gotMapping2.RealmID, realm2ID)
	}

	// Verify realm tenant counts are isolated
	count1, err := cache.GetRealmTenantCount(ctx, realm1ID)
	if err != nil {
		t.Fatalf("GetRealmTenantCount(realm1) error = %v", err)
	}
	if count1 != 1 {
		t.Errorf("Realm 1 tenant count = %d, want 1", count1)
	}

	count2, err := cache.GetRealmTenantCount(ctx, realm2ID)
	if err != nil {
		t.Fatalf("GetRealmTenantCount(realm2) error = %v", err)
	}
	if count2 != 1 {
		t.Errorf("Realm 2 tenant count = %d, want 1", count2)
	}

	// Invalidating one realm should not affect the other
	err = cache.InvalidateRealmTenants(ctx, realm1ID)
	if err != nil {
		t.Fatalf("InvalidateRealmTenants(realm1) error = %v", err)
	}

	// Realm 1 should have 0 tenants
	count1, err = cache.GetRealmTenantCount(ctx, realm1ID)
	if err != nil {
		t.Fatalf("GetRealmTenantCount(realm1) error = %v", err)
	}
	if count1 != 0 {
		t.Errorf("Realm 1 tenant count after invalidation = %d, want 0", count1)
	}

	// Realm 2 should still have 1 tenant
	count2, err = cache.GetRealmTenantCount(ctx, realm2ID)
	if err != nil {
		t.Fatalf("GetRealmTenantCount(realm2) error = %v", err)
	}
	if count2 != 1 {
		t.Errorf("Realm 2 tenant count after realm 1 invalidation = %d, want 1", count2)
	}

	// Tenant 2 should still be accessible
	gotMapping2, err = cache.GetTenantRealm(ctx, tenant2)
	if err != nil {
		t.Fatalf("GetTenantRealm(tenant2) after invalidation error = %v", err)
	}
	if gotMapping2 == nil {
		t.Error("Tenant 2 mapping should still exist after realm 1 invalidation")
	}
}
