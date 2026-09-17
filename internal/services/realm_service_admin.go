// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// ==================== Tenant Management ====================

// AssignTenant assigns a tenant to a realm
func (s *RealmService) AssignTenant(ctx context.Context, realmID, tenantID uuid.UUID, assignedBy *uuid.UUID) error {
	// Verify realm exists and is active
	realm, err := s.repo.GetByID(ctx, realmID)
	if err != nil || realm == nil {
		return fmt.Errorf("realm not found")
	}
	if realm.Status != models.RealmStatusActive {
		return fmt.Errorf("cannot assign tenant to inactive realm")
	}

	// Check tenant quota
	if realm.MaxTenants != nil {
		count, err := s.repo.CountTenantsInRealm(ctx, realmID)
		if err != nil {
			return fmt.Errorf("AssignTenant: %w", err)
		}
		if count >= *realm.MaxTenants {
			return fmt.Errorf("realm has reached maximum tenant limit (%d)", *realm.MaxTenants)
		}
	}

	if err := s.repo.AssignTenant(ctx, realmID, tenantID, assignedBy); err != nil {
		return fmt.Errorf("AssignTenant: %w", err)
	}

	s.logger.Info("Assigned tenant to realm", zap.String("realm_id", realmID.String()), zap.String("tenant_id", tenantID.String()))

	return nil
}

// GetTenantRealm gets the realm for a tenant
func (s *RealmService) GetTenantRealm(ctx context.Context, tenantID uuid.UUID) (*models.Realm, error) {
	return s.repo.GetTenantRealm(ctx, tenantID)
}

// ListRealmTenants lists all tenants in a realm
func (s *RealmService) ListRealmTenants(ctx context.Context, realmID uuid.UUID) ([]models.RealmTenant, error) {
	return s.repo.ListRealmTenants(ctx, realmID)
}

// MigrateTenant migrates a tenant from one realm to another
func (s *RealmService) MigrateTenant(ctx context.Context, tenantID, targetRealmID uuid.UUID, assignedBy *uuid.UUID) error {
	// Verify target realm exists and is active
	targetRealm, err := s.repo.GetByID(ctx, targetRealmID)
	if err != nil || targetRealm == nil {
		return fmt.Errorf("target realm not found")
	}
	if targetRealm.Status != models.RealmStatusActive {
		return fmt.Errorf("cannot migrate tenant to inactive realm")
	}

	// Get current realm
	currentRealm, err := s.repo.GetTenantRealm(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("MigrateTenant: %w", err)
	}

	if currentRealm != nil && currentRealm.ID == targetRealmID {
		return nil // Already in target realm
	}

	// Check target realm tenant quota
	if targetRealm.MaxTenants != nil {
		count, err := s.repo.CountTenantsInRealm(ctx, targetRealmID)
		if err != nil {
			return fmt.Errorf("MigrateTenant: %w", err)
		}
		if count >= *targetRealm.MaxTenants {
			return fmt.Errorf("target realm has reached maximum tenant limit (%d)", *targetRealm.MaxTenants)
		}
	}

	// Perform migration (this will update the realm_tenants table with migration tracking)
	if err := s.repo.AssignTenant(ctx, targetRealmID, tenantID, assignedBy); err != nil {
		return fmt.Errorf("MigrateTenant: %w", err)
	}

	fromSlug := "<none>"
	if currentRealm != nil {
		fromSlug = currentRealm.Slug
	}
	s.logger.Info("Migrated tenant to new realm",
		zap.String("tenant_id", tenantID.String()),
		zap.String("from_realm", fromSlug),
		zap.String("to_realm", targetRealm.Slug),
	)

	return nil
}

// ==================== Admin Assignments ====================

// AssignAdmin assigns a platform admin to a realm
func (s *RealmService) AssignAdmin(ctx context.Context, realmID uuid.UUID, req *models.AssignRealmAdminRequest, createdBy *uuid.UUID) error {
	// Verify realm exists
	realm, err := s.repo.GetByID(ctx, realmID)
	if err != nil || realm == nil {
		return fmt.Errorf("realm not found")
	}

	permissionsJSON := json.RawMessage(`[]`)
	if req.Permissions != nil {
		var err error
		permissionsJSON, err = json.Marshal(req.Permissions)
		if err != nil {
			return fmt.Errorf("failed to marshal permissions: %w", err)
		}
	}

	var allowedTenantIDsJSON json.RawMessage
	if req.AllowedTenantIDs != nil {
		var err error
		allowedTenantIDsJSON, err = json.Marshal(req.AllowedTenantIDs)
		if err != nil {
			return fmt.Errorf("failed to marshal allowed tenant IDs: %w", err)
		}
	}

	assignment := &models.RealmAdminAssignment{
		ID:               uuid.New(),
		RealmID:          realmID,
		AdminID:          req.AdminID,
		Role:             req.Role,
		Permissions:      permissionsJSON,
		AllowedTenantIDs: allowedTenantIDsJSON,
		CreatedBy:        createdBy,
	}

	if err := s.repo.AssignAdmin(ctx, assignment); err != nil {
		return fmt.Errorf("AssignAdmin: %w", err)
	}

	s.logger.Info("Assigned admin to realm", zap.String("realm_id", realmID.String()), zap.String("admin_id", req.AdminID.String()), zap.String("role", string(req.Role)))

	return nil
}

// ListRealmAdmins lists all admin assignments for a realm
func (s *RealmService) ListRealmAdmins(ctx context.Context, realmID uuid.UUID) ([]models.RealmAdminAssignment, error) {
	return s.repo.ListRealmAdmins(ctx, realmID)
}

// RemoveAdmin removes an admin from a realm
func (s *RealmService) RemoveAdmin(ctx context.Context, realmID, adminID uuid.UUID) error {
	return s.repo.RemoveAdmin(ctx, realmID, adminID)
}

// ==================== Audit Logging ====================

// LogAudit logs an audit entry for realm operations
func (s *RealmService) LogAudit(ctx context.Context, log *models.RealmAuditLog) error {
	return s.repo.LogAudit(ctx, log)
}

// ListAuditLogs lists audit logs for a realm
func (s *RealmService) ListAuditLogs(ctx context.Context, realmID uuid.UUID, filters repositories.AuditLogFilters) ([]models.RealmAuditLog, int64, error) {
	if filters.Page < 1 {
		filters.Page = 1
	}
	if filters.PageSize < 1 || filters.PageSize > 100 {
		filters.PageSize = 50
	}
	return s.repo.ListAuditLogs(ctx, realmID, filters)
}

// ==================== Domain Management ====================

// ListDomains lists all domains for a realm
func (s *RealmService) ListDomains(ctx context.Context, realmID uuid.UUID) ([]models.RealmDomain, error) {
	return s.repo.ListDomains(ctx, realmID)
}

// AddDomain adds a custom domain to a realm
func (s *RealmService) AddDomain(ctx context.Context, realmID uuid.UUID, req *models.AddRealmDomainRequest) (*models.RealmDomain, error) {
	// Verify realm exists
	realm, err := s.repo.GetByID(ctx, realmID)
	if err != nil || realm == nil {
		return nil, fmt.Errorf("realm not found")
	}

	// Check if domain already exists
	existingDomain, err := s.repo.GetDomainByName(ctx, req.Domain)
	if err != nil {
		return nil, fmt.Errorf("AddDomain: %w", err)
	}
	if existingDomain != nil {
		return nil, fmt.Errorf("domain '%s' is already registered", req.Domain)
	}

	// Generate verification token
	verificationToken := uuid.New().String()
	verificationMethod := "dns_txt"
	if req.VerificationMethod != "" {
		verificationMethod = req.VerificationMethod
	}

	isPrimary := false
	if req.IsPrimary != nil {
		isPrimary = *req.IsPrimary
	}

	domain := &models.RealmDomain{
		ID:                 uuid.New(),
		RealmID:            realmID,
		Domain:             req.Domain,
		IsPrimary:          isPrimary,
		IsVerified:         false,
		VerificationToken:  &verificationToken,
		VerificationMethod: &verificationMethod,
		SSLEnabled:         false,
	}

	if err := s.repo.CreateDomain(ctx, domain); err != nil {
		return nil, fmt.Errorf("AddDomain: %w", err)
	}

	// If this is the first domain and marked as primary, set it
	if isPrimary {
		if err := s.repo.SetPrimaryDomain(ctx, realmID, domain.ID); err != nil {
			s.logger.Warn("Failed to set domain as primary", zap.String("domain_id", domain.ID.String()), zap.Error(err))
		}
	}

	s.logger.Info("Added domain to realm", zap.String("realm_id", realmID.String()), zap.String("domain", req.Domain))

	return domain, nil
}

// RemoveDomain removes a domain from a realm
func (s *RealmService) RemoveDomain(ctx context.Context, domainID uuid.UUID) error {
	domain, err := s.repo.GetDomainByID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("RemoveDomain: %w", err)
	}
	if domain == nil {
		return fmt.Errorf("domain not found")
	}

	// Don't allow removing the primary domain if there are other domains
	if domain.IsPrimary {
		domains, err := s.repo.ListDomains(ctx, domain.RealmID)
		if err != nil {
			return fmt.Errorf("RemoveDomain: %w", err)
		}
		if len(domains) > 1 {
			return fmt.Errorf("cannot remove primary domain; set another domain as primary first")
		}
	}

	if err := s.repo.DeleteDomain(ctx, domainID); err != nil {
		return fmt.Errorf("RemoveDomain: %w", err)
	}

	// Invalidate cache for this domain
	s.cacheMu.Lock()
	delete(s.cache, "domain:"+domain.Domain)
	s.cacheMu.Unlock()

	s.logger.Info("Removed domain from realm", zap.String("realm_id", domain.RealmID.String()), zap.String("domain", domain.Domain))

	return nil
}

// VerifyDomain marks a domain as verified
func (s *RealmService) VerifyDomain(ctx context.Context, domainID uuid.UUID) (*models.RealmDomain, error) {
	domain, err := s.repo.GetDomainByID(ctx, domainID)
	if err != nil {
		return nil, fmt.Errorf("VerifyDomain: %w", err)
	}
	if domain == nil {
		return nil, fmt.Errorf("domain not found")
	}

	if domain.IsVerified {
		return domain, nil // Already verified
	}

	// In a real implementation, this would perform DNS/HTTP verification
	// For now, we just mark it as verified
	now := time.Now()
	domain.IsVerified = true
	domain.VerifiedAt = &now

	if err := s.repo.UpdateDomain(ctx, domain); err != nil {
		return nil, fmt.Errorf("VerifyDomain: %w", err)
	}

	s.logger.Info("Verified domain", zap.String("realm_id", domain.RealmID.String()), zap.String("domain", domain.Domain))

	return domain, nil
}

// SetPrimaryDomain sets a domain as the primary domain for a realm
func (s *RealmService) SetPrimaryDomain(ctx context.Context, realmID, domainID uuid.UUID) error {
	domain, err := s.repo.GetDomainByID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("SetPrimaryDomain: %w", err)
	}
	if domain == nil {
		return fmt.Errorf("domain not found")
	}
	if domain.RealmID != realmID {
		return fmt.Errorf("domain does not belong to this realm")
	}
	if !domain.IsVerified {
		return fmt.Errorf("domain must be verified before it can be set as primary")
	}

	if err := s.repo.SetPrimaryDomain(ctx, realmID, domainID); err != nil {
		return fmt.Errorf("SetPrimaryDomain: %w", err)
	}

	s.logger.Info("Set primary domain", zap.String("realm_id", realmID.String()), zap.String("domain", domain.Domain))

	return nil
}

// ==================== Cache Management ====================

// InvalidateCache invalidates the cache for a realm
func (s *RealmService) InvalidateCache(slug string) {
	s.cacheMu.Lock()
	delete(s.cache, slug)
	s.cacheMu.Unlock()
}

// InvalidateCacheByID invalidates the cache for a realm by ID
func (s *RealmService) InvalidateCacheByID(ctx context.Context, id uuid.UUID) {
	realm, err := s.repo.GetByID(ctx, id)
	if err == nil && realm != nil {
		s.InvalidateCache(realm.Slug)
	}
}

// ClearCache clears the entire realm cache
func (s *RealmService) ClearCache() {
	s.cacheMu.Lock()
	s.cache = make(map[string]*cachedRealm)
	s.cacheMu.Unlock()
}

// ==================== Helpers ====================

var slugRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

func validateRealmSlug(slug string) error {
	if len(slug) < 2 || len(slug) > 63 {
		return fmt.Errorf("slug must be between 2 and 63 characters")
	}
	if !slugRegex.MatchString(slug) {
		return fmt.Errorf("slug must start and end with alphanumeric characters and contain only lowercase letters, numbers, and hyphens")
	}
	// Reserved slugs
	reserved := []string{"api", "auth", "admin", "platform", "system", "internal", "public", "static", "assets"}
	for _, r := range reserved {
		if slug == r {
			return fmt.Errorf("slug '%s' is reserved", slug)
		}
	}
	return nil
}

func containsUppercase(s string) bool {
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			return true
		}
	}
	return false
}

func containsLowercase(s string) bool {
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			return true
		}
	}
	return false
}

func containsDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func containsSpecial(s, specialChars string) bool {
	for _, r := range s {
		for _, sc := range specialChars {
			if r == sc {
				return true
			}
		}
	}
	return false
}

// GetDefaultRealm returns the default shared realm
func (s *RealmService) GetDefaultRealm(ctx context.Context) (*models.Realm, error) {
	return s.repo.GetDefaultRealm(ctx)
}

// ==================== User-facing Methods ====================

// AvailableRealmInfo represents a realm available to a user
type AvailableRealmInfo struct {
	ID        uuid.UUID        `json:"id"`
	Slug      string           `json:"slug"`
	Name      string           `json:"name"`
	Type      models.RealmType `json:"type"`
	IsPrimary bool             `json:"is_primary"`
}

// GetUserAvailableRealms returns all realms a user has access to
// This includes realms where the user is assigned via realm_admin_assignments
// or realms where the user's tenant is assigned
func (s *RealmService) GetUserAvailableRealms(ctx context.Context, userID uuid.UUID, primaryRealmID uuid.UUID) ([]AvailableRealmInfo, error) {
	realms, err := s.repo.GetUserAvailableRealms(ctx, userID, primaryRealmID)
	if err != nil {
		return nil, fmt.Errorf("GetUserAvailableRealms: %w", err)
	}

	result := make([]AvailableRealmInfo, len(realms))
	for i, r := range realms {
		result[i] = AvailableRealmInfo{
			ID:        r.ID,
			Slug:      r.Slug,
			Name:      r.DisplayName,
			Type:      r.Type,
			IsPrimary: i == 0, // First realm is primary (user's own realm)
		}
	}

	return result, nil
}

// UserHasRealmAccess checks if a user has access to a specific realm
func (s *RealmService) UserHasRealmAccess(ctx context.Context, userID, realmID, primaryRealmID uuid.UUID) (bool, error) {
	return s.repo.UserHasRealmAccess(ctx, userID, realmID, primaryRealmID)
}
