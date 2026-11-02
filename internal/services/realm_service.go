// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

// realmServiceRepo defines the realm repository methods needed by RealmService.
type realmServiceRepo interface {
	SlugExists(ctx context.Context, slug string) (bool, error)
	Create(ctx context.Context, realm *models.Realm) error
	CreateSecurityPolicy(ctx context.Context, policy *models.RealmSecurityPolicy) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Realm, error)
	GetBySlug(ctx context.Context, slug string) (*models.Realm, error)
	GetRealmByDomain(ctx context.Context, domainName string) (*models.Realm, error)
	Update(ctx context.Context, realm *models.Realm) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.RealmStatus) error
	List(ctx context.Context, filters repositories.RealmFilters) ([]models.Realm, int64, error)
	GetSecurityPolicy(ctx context.Context, realmID uuid.UUID) (*models.RealmSecurityPolicy, error)
	UpdateSecurityPolicy(ctx context.Context, policy *models.RealmSecurityPolicy) error
	CreateIdentityProvider(ctx context.Context, idp *models.RealmIdentityProvider) error
	ListIdentityProviders(ctx context.Context, realmID uuid.UUID) ([]models.RealmIdentityProvider, error)
	DeleteIdentityProvider(ctx context.Context, id uuid.UUID) error
	GetIdentityProvider(ctx context.Context, id uuid.UUID) (*models.RealmIdentityProvider, error)
	UpdateIdentityProvider(ctx context.Context, idp *models.RealmIdentityProvider) error
	CountTenantsInRealm(ctx context.Context, realmID uuid.UUID) (int, error)
	AssignTenant(ctx context.Context, realmID, tenantID uuid.UUID, assignedBy *uuid.UUID) error
	GetTenantRealm(ctx context.Context, tenantID uuid.UUID) (*models.Realm, error)
	ListRealmTenants(ctx context.Context, realmID uuid.UUID) ([]models.RealmTenant, error)
	AssignAdmin(ctx context.Context, assignment *models.RealmAdminAssignment) error
	ListRealmAdmins(ctx context.Context, realmID uuid.UUID) ([]models.RealmAdminAssignment, error)
	RemoveAdmin(ctx context.Context, realmID, adminID uuid.UUID) error
	LogAudit(ctx context.Context, log *models.RealmAuditLog) error
	ListAuditLogs(ctx context.Context, realmID uuid.UUID, filters repositories.AuditLogFilters) ([]models.RealmAuditLog, int64, error)
	ListDomains(ctx context.Context, realmID uuid.UUID) ([]models.RealmDomain, error)
	GetDomainByName(ctx context.Context, domainName string) (*models.RealmDomain, error)
	CreateDomain(ctx context.Context, domain *models.RealmDomain) error
	SetPrimaryDomain(ctx context.Context, realmID, domainID uuid.UUID) error
	GetDomainByID(ctx context.Context, domainID uuid.UUID) (*models.RealmDomain, error)
	DeleteDomain(ctx context.Context, domainID uuid.UUID) error
	UpdateDomain(ctx context.Context, domain *models.RealmDomain) error
	// ListTenantIdentityProviders moved to cross-DB orchestration in RealmService
	GetDefaultRealm(ctx context.Context) (*models.Realm, error)
	GetUserAvailableRealms(ctx context.Context, userID uuid.UUID, primaryRealmID uuid.UUID) ([]*models.Realm, error)
	UserHasRealmAccess(ctx context.Context, userID, realmID, primaryRealmID uuid.UUID) (bool, error)
}

// realmIDPRepo defines the IdentityProviderRepository methods needed by RealmService
// for the consolidated IDP architecture.
type realmIDPRepo interface {
	ListByRealm(ctx context.Context, realmID uuid.UUID) ([]*models.IdentityProvider, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.IdentityProvider, error)
	CreateRealmProvider(ctx context.Context, provider *models.IdentityProvider) error
	Update(ctx context.Context, provider *models.IdentityProvider) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListTenantProviderSummaries(ctx context.Context, tenantIDs []uuid.UUID) ([]models.TenantIdentityProviderSummary, error)
}

// RealmDomainProvisioner provisions custom hostnames (e.g., Cloudflare for SaaS)
// when a domain is added to or removed from a realm.
type RealmDomainProvisioner interface {
	ProvisionCustomHostname(ctx context.Context, realmID uuid.UUID, domain string) error
	DeprovisionCustomHostname(ctx context.Context, realmID uuid.UUID, domain string) error
}

// realmWitnessPolicyRepo is the optional per-realm device-witness policy store
// (*repositories.RealmRepository satisfies it).
type realmWitnessPolicyRepo interface {
	GetDeviceWitnessTOTPAllowedByRealm(ctx context.Context, realmID uuid.UUID) (bool, error)
	SetDeviceWitnessTOTPAllowed(ctx context.Context, realmID uuid.UUID, allowed bool) error
}

// realmSessionPolicyRepo is the optional per-realm SSO session policy store
// (*repositories.RealmRepository satisfies it).
type realmSessionPolicyRepo interface {
	GetSessionAbsoluteTTLSeconds(ctx context.Context, realmID uuid.UUID) (*int, error)
	SetSessionAbsoluteTTLSeconds(ctx context.Context, realmID uuid.UUID, secs *int) error
}

// Bounds for realm.session_absolute_ttl_seconds (1h .. 90d).
const (
	MinSessionAbsoluteTTLSeconds = 3600
	MaxSessionAbsoluteTTLSeconds = 90 * 24 * 3600
)

// ErrInvalidSessionTTL is returned for an out-of-range session lifetime.
var ErrInvalidSessionTTL = fmt.Errorf("session_absolute_ttl_seconds must be between %d and %d", MinSessionAbsoluteTTLSeconds, MaxSessionAbsoluteTTLSeconds)

// RealmService provides business logic for realm management
type RealmService struct {
	// sessionPolicy backs the session-policy admin API; nil -> 503.
	sessionPolicy realmSessionPolicyRepo
	// witnessPolicy backs the device-witness-policy admin API; nil -> 503.
	witnessPolicy realmWitnessPolicyRepo
	repo   realmServiceRepo
	config *config.Config
	logger *zap.Logger

	// Consolidated IDP repository (optional; when set, IDP methods use iam_identity_providers)
	idpRepo realmIDPRepo

	// Domain provisioner (optional; when set, domain changes trigger Cloudflare automation)
	domainProvisioner RealmDomainProvisioner

	// L1 in-memory cache for realm lookups (local to this instance)
	cache    map[string]*cachedRealm
	cacheMu  sync.RWMutex
	cacheTTL time.Duration

	// L2 Redis cache for distributed caching (optional, set via SetRedisCache)
	redisCache *redis.RealmCache
}

// SetDomainProvisioner wires an optional Cloudflare domain provisioner.
// When set, adding/removing domains on a realm triggers custom hostname
// provisioning. Errors are logged but non-fatal.
func (s *RealmService) SetDomainProvisioner(prov RealmDomainProvisioner) {
	s.domainProvisioner = prov
	s.logger.Info("Domain provisioner enabled for realm service")
}

type cachedRealm struct {
	realm     *models.Realm
	expiresAt time.Time
}

// NewRealmService creates a new realm service
func NewRealmService(repo realmServiceRepo, cfg *config.Config, log *zap.Logger) *RealmService {
	return &RealmService{
		repo:     repo,
		config:   cfg,
		logger:   log,
		cache:    make(map[string]*cachedRealm),
		cacheTTL: 5 * time.Minute, // Default cache TTL
	}
}

// SetCacheTTL sets the cache TTL for realm lookups
func (s *RealmService) SetCacheTTL(ttl time.Duration) {
	s.cacheTTL = ttl
}

// SetRedisCache sets the Redis cache for distributed caching
// When set, the service uses a two-level caching strategy:
// L1: In-memory cache (fast, local to instance)
// L2: Redis cache (distributed, shared across instances)
func (s *RealmService) SetRedisCache(cache *redis.RealmCache) {
	s.redisCache = cache
	s.logger.Info("Redis cache enabled for realm service")
}

// SetIDPRepository is an exported identifier.
// SetIDPRepository sets the consolidated IdentityProviderRepository.
// When set, realm IDP methods use iam_identity_providers (scope='realm') instead of
// realm_identity_providers, completing the IDP consolidation.
func (s *RealmService) SetIDPRepository(repo realmIDPRepo) {
	s.idpRepo = repo
	s.logger.Info("Consolidated IdP repository set for realm service")
}

// ==================== Realm CRUD ====================

// Create creates a new realm
func (s *RealmService) Create(ctx context.Context, req *models.CreateRealmRequest, createdBy *uuid.UUID) (*models.Realm, error) {
	// Validate slug format
	if err := validateRealmSlug(req.Slug); err != nil {
		return nil, fmt.Errorf("Create: %w", err)
	}

	// Check if slug already exists
	exists, err := s.repo.SlugExists(ctx, req.Slug)
	if err != nil {
		return nil, fmt.Errorf("failed to check slug: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("realm with slug '%s' already exists", req.Slug)
	}

	// Prepare settings JSON
	var settingsJSON json.RawMessage
	if req.Settings != nil {
		var err error
		settingsJSON, err = json.Marshal(req.Settings)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal settings: %w", err)
		}
	} else {
		settingsJSON = json.RawMessage(`{}`)
	}

	// Prepare branding JSON with defaults
	brandingJSON := json.RawMessage(`{
		"logo_url": null,
		"favicon_url": null,
		"primary_color": "#4F46E5",
		"secondary_color": "#10B981",
		"login_background_url": null,
		"custom_css": null
	}`)
	if req.Branding != nil {
		var err error
		brandingJSON, err = json.Marshal(req.Branding)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal branding: %w", err)
		}
	}

	// Prepare features JSON with defaults
	featuresJSON := json.RawMessage(`{
		"mfa_available": true,
		"sso_available": true,
		"api_access": true,
		"custom_domain": false,
		"advanced_audit": false
	}`)

	realm := &models.Realm{
		ID:                uuid.New(),
		Slug:              req.Slug,
		DisplayName:       req.DisplayName,
		Type:              req.Type,
		Status:            models.RealmStatusActive,
		Settings:          settingsJSON,
		Branding:          brandingJSON,
		Features:          featuresJSON,
		MaxTenants:        req.MaxTenants,
		MaxUsersPerTenant: req.MaxUsersPerTenant,
		MaxTotalUsers:     req.MaxTotalUsers,
		CreatedBy:         createdBy,
	}

	if err := s.repo.Create(ctx, realm); err != nil {
		return nil, fmt.Errorf("Create: %w", err)
	}

	// Create default security policy
	policy := &models.RealmSecurityPolicy{RealmID: realm.ID}
	if err := s.repo.CreateSecurityPolicy(ctx, policy); err != nil {
		s.logger.Error("Failed to create default security policy for realm", zap.String("realm_id", realm.ID.String()), zap.Error(err))
		// Don't fail the realm creation, but log the error
	}

	s.logger.Info("Created new realm", zap.String("realm_id", realm.ID.String()), zap.String("slug", realm.Slug), zap.String("type", string(realm.Type)))

	return realm, nil
}

// GetByID retrieves a realm by ID
func (s *RealmService) GetByID(ctx context.Context, id uuid.UUID) (*models.Realm, error) {
	realm, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	if realm == nil {
		return nil, fmt.Errorf("realm not found")
	}

	// Load security policy
	policy, err := s.repo.GetSecurityPolicy(ctx, id)
	if err == nil && policy != nil {
		realm.SecurityPolicy = policy
	}

	return realm, nil
}

// GetBySlug retrieves a realm by slug with two-level caching (L1: memory, L2: Redis)
func (s *RealmService) GetBySlug(ctx context.Context, slug string) (*models.Realm, error) {
	// L1: Check in-memory cache first (fastest)
	s.cacheMu.RLock()
	if cached, ok := s.cache[slug]; ok && time.Now().Before(cached.expiresAt) {
		s.cacheMu.RUnlock()
		return cached.realm, nil
	}
	s.cacheMu.RUnlock()

	// L2: Check Redis cache if available
	if s.redisCache != nil {
		cached, err := s.redisCache.GetRealmBySlug(ctx, slug)
		if err != nil {
			s.logger.Warn("Redis cache error", zap.Error(err), zap.String("slug", slug))
		} else if cached != nil {
			// Convert cached realm to model
			realm := &models.Realm{
				ID:          cached.ID,
				Slug:        cached.Slug,
				DisplayName: cached.Name,
				Type:        models.RealmType(cached.Type),
				Status:      models.RealmStatus(cached.Status),
			}
			// Update L1 cache
			s.cacheMu.Lock()
			s.cache[slug] = &cachedRealm{
				realm:     realm,
				expiresAt: time.Now().Add(s.cacheTTL),
			}
			s.cacheMu.Unlock()
			return realm, nil
		}
	}

	// Fetch from database
	realm, err := s.repo.GetBySlug(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("GetBySlug: %w", err)
	}
	if realm == nil {
		return nil, nil
	}

	// Update L1 in-memory cache
	s.cacheMu.Lock()
	s.cache[slug] = &cachedRealm{
		realm:     realm,
		expiresAt: time.Now().Add(s.cacheTTL),
	}
	s.cacheMu.Unlock()

	// Update L2 Redis cache if available
	if s.redisCache != nil {
		cachedRealm := &redis.CachedRealm{
			ID:     realm.ID,
			Slug:   realm.Slug,
			Name:   realm.DisplayName,
			Type:   string(realm.Type),
			Status: string(realm.Status),
		}
		if err := s.redisCache.SetRealm(ctx, cachedRealm); err != nil {
			s.logger.Warn("Failed to cache realm in Redis", zap.Error(err), zap.String("slug", slug))
		}
	}

	return realm, nil
}

// GetByDomain retrieves a realm by custom domain
func (s *RealmService) GetByDomain(ctx context.Context, domain string) (*models.Realm, error) {
	// Check cache with domain key
	cacheKey := "domain:" + domain
	s.cacheMu.RLock()
	if cached, ok := s.cache[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
		s.cacheMu.RUnlock()
		return cached.realm, nil
	}
	s.cacheMu.RUnlock()

	realm, err := s.repo.GetRealmByDomain(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("GetByDomain: %w", err)
	}
	if realm == nil {
		return nil, nil
	}

	// Update cache
	s.cacheMu.Lock()
	s.cache[cacheKey] = &cachedRealm{
		realm:     realm,
		expiresAt: time.Now().Add(s.cacheTTL),
	}
	s.cacheMu.Unlock()

	return realm, nil
}

// Update updates a realm
func (s *RealmService) Update(ctx context.Context, id uuid.UUID, req *models.UpdateRealmRequest) (*models.Realm, error) {
	realm, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("Update: %w", err)
	}
	if realm == nil {
		return nil, fmt.Errorf("realm not found")
	}

	// Update fields
	if req.DisplayName != nil {
		realm.DisplayName = *req.DisplayName
	}
	if req.Settings != nil {
		settingsJSON, _ := json.Marshal(req.Settings)
		realm.Settings = settingsJSON
	}
	if req.Branding != nil {
		brandingJSON, _ := json.Marshal(req.Branding)
		realm.Branding = brandingJSON
	}
	if req.Features != nil {
		featuresJSON, _ := json.Marshal(req.Features)
		realm.Features = featuresJSON
	}
	if req.MaxTenants != nil {
		realm.MaxTenants = req.MaxTenants
	}
	if req.MaxUsersPerTenant != nil {
		realm.MaxUsersPerTenant = req.MaxUsersPerTenant
	}
	if req.MaxTotalUsers != nil {
		realm.MaxTotalUsers = req.MaxTotalUsers
	}

	if err := s.repo.Update(ctx, realm); err != nil {
		return nil, fmt.Errorf("Update: %w", err)
	}

	// Invalidate cache
	s.InvalidateCache(realm.Slug)

	s.logger.Info("Updated realm", zap.String("realm_id", id.String()), zap.String("slug", realm.Slug))

	return realm, nil
}

// List lists realms with filters
func (s *RealmService) List(ctx context.Context, filters repositories.RealmFilters) (*models.RealmListResponse, error) {
	// Set defaults
	if filters.Page < 1 {
		filters.Page = 1
	}
	if filters.PageSize < 1 || filters.PageSize > 100 {
		filters.PageSize = 20
	}

	realms, total, err := s.repo.List(ctx, filters)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}

	responses := make([]models.RealmResponse, 0, len(realms))
	for _, r := range realms {
		responses = append(responses, *r.ToResponse())
	}

	totalPages := int(total) / filters.PageSize
	if int(total)%filters.PageSize > 0 {
		totalPages++
	}

	return &models.RealmListResponse{
		Realms:     responses,
		Total:      total,
		Page:       filters.Page,
		PageSize:   filters.PageSize,
		TotalPages: totalPages,
	}, nil
}

// ==================== Realm Status Management ====================

// Activate activates a realm
func (s *RealmService) Activate(ctx context.Context, id uuid.UUID) error {
	realm, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("Activate: %w", err)
	}
	if realm == nil {
		return fmt.Errorf("realm not found")
	}

	if realm.Status == models.RealmStatusActive {
		return nil // Already active
	}

	if err := s.repo.UpdateStatus(ctx, id, models.RealmStatusActive); err != nil {
		return fmt.Errorf("Activate: %w", err)
	}

	s.InvalidateCache(realm.Slug)
	s.logger.Info("Activated realm", zap.String("realm_id", id.String()), zap.String("slug", realm.Slug))

	return nil
}

// Suspend suspends a realm
func (s *RealmService) Suspend(ctx context.Context, id uuid.UUID) error {
	realm, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("Suspend: %w", err)
	}
	if realm == nil {
		return fmt.Errorf("realm not found")
	}

	if realm.IsDefault() {
		return fmt.Errorf("cannot suspend the default realm")
	}

	if err := s.repo.UpdateStatus(ctx, id, models.RealmStatusSuspended); err != nil {
		return fmt.Errorf("Suspend: %w", err)
	}

	s.InvalidateCache(realm.Slug)
	s.logger.Info("Suspended realm", zap.String("realm_id", id.String()), zap.String("slug", realm.Slug))

	return nil
}

// Archive archives (soft deletes) a realm
func (s *RealmService) Archive(ctx context.Context, id uuid.UUID) error {
	realm, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("Archive: %w", err)
	}
	if realm == nil {
		return fmt.Errorf("realm not found")
	}

	if realm.IsDefault() {
		return fmt.Errorf("cannot archive the default realm")
	}

	// Check if realm has tenants
	if realm.TenantCount > 0 {
		return fmt.Errorf("cannot archive realm with %d tenants; migrate tenants first", realm.TenantCount)
	}

	if err := s.repo.UpdateStatus(ctx, id, models.RealmStatusArchived); err != nil {
		return fmt.Errorf("Archive: %w", err)
	}

	s.InvalidateCache(realm.Slug)
	s.logger.Info("Archived realm", zap.String("realm_id", id.String()), zap.String("slug", realm.Slug))

	return nil
}

// ==================== Security Policy ====================

// GetSecurityPolicy retrieves the security policy for a realm
func (s *RealmService) GetSecurityPolicy(ctx context.Context, realmID uuid.UUID) (*models.RealmSecurityPolicy, error) {
	policy, err := s.repo.GetSecurityPolicy(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("GetSecurityPolicy: %w", err)
	}
	if policy == nil {
		return nil, fmt.Errorf("security policy not found for realm")
	}
	return policy, nil
}

// UpdateSecurityPolicy updates the security policy for a realm
func (s *RealmService) UpdateSecurityPolicy(ctx context.Context, realmID uuid.UUID, req *models.UpdateRealmSecurityPolicyRequest) (*models.RealmSecurityPolicy, error) {
	policy, err := s.repo.GetSecurityPolicy(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("UpdateSecurityPolicy: %w", err)
	}
	if policy == nil {
		return nil, fmt.Errorf("security policy not found")
	}

	// Apply updates
	if req.PasswordMinLength != nil {
		policy.PasswordMinLength = *req.PasswordMinLength
	}
	if req.PasswordMaxLength != nil {
		policy.PasswordMaxLength = *req.PasswordMaxLength
	}
	if req.PasswordRequireUppercase != nil {
		policy.PasswordRequireUppercase = *req.PasswordRequireUppercase
	}
	if req.PasswordRequireLowercase != nil {
		policy.PasswordRequireLowercase = *req.PasswordRequireLowercase
	}
	if req.PasswordRequireDigits != nil {
		policy.PasswordRequireDigits = *req.PasswordRequireDigits
	}
	if req.PasswordRequireSpecial != nil {
		policy.PasswordRequireSpecial = *req.PasswordRequireSpecial
	}
	if req.PasswordSpecialChars != nil {
		policy.PasswordSpecialChars = req.PasswordSpecialChars
	}
	if req.PasswordMaxAgeDays != nil {
		policy.PasswordMaxAgeDays = req.PasswordMaxAgeDays
	}
	if req.PasswordHistoryCount != nil {
		policy.PasswordHistoryCount = req.PasswordHistoryCount
	}

	if req.MFARequired != nil {
		policy.MFARequired = *req.MFARequired
	}
	if req.MFARequiredForAdmins != nil {
		policy.MFARequiredForAdmins = *req.MFARequiredForAdmins
	}
	if req.MFAMethods != nil {
		methodsJSON, _ := json.Marshal(req.MFAMethods)
		policy.MFAMethods = methodsJSON
	}
	if req.MFAGracePeriodDays != nil {
		policy.MFAGracePeriodDays = req.MFAGracePeriodDays
	}
	if req.MFARememberDeviceDays != nil {
		policy.MFARememberDeviceDays = req.MFARememberDeviceDays
	}
	if req.MFAEnrollmentMaxSkips != nil {
		// Repository CHECK constraint enforces 0..10; reject early with
		// a clear error rather than letting the SQL error bubble up.
		if *req.MFAEnrollmentMaxSkips < 0 || *req.MFAEnrollmentMaxSkips > 10 {
			return nil, fmt.Errorf("mfa_enrollment_max_skips must be between 0 and 10")
		}
		policy.MFAEnrollmentMaxSkips = *req.MFAEnrollmentMaxSkips
	}

	if req.SessionMaxLifetimeHours != nil {
		policy.SessionMaxLifetimeHours = *req.SessionMaxLifetimeHours
	}
	if req.SessionIdleTimeoutMinutes != nil {
		policy.SessionIdleTimeoutMinutes = *req.SessionIdleTimeoutMinutes
	}
	if req.ConcurrentSessionsLimit != nil {
		policy.ConcurrentSessionsLimit = req.ConcurrentSessionsLimit
	}
	if req.SingleSessionPerDevice != nil {
		policy.SingleSessionPerDevice = *req.SingleSessionPerDevice
	}

	if req.MaxFailedAttempts != nil {
		policy.MaxFailedAttempts = *req.MaxFailedAttempts
	}
	if req.LockoutDurationMinutes != nil {
		policy.LockoutDurationMinutes = *req.LockoutDurationMinutes
	}
	if req.ProgressiveLockout != nil {
		policy.ProgressiveLockout = *req.ProgressiveLockout
	}

	if req.IPWhitelist != nil {
		whitelistJSON, _ := json.Marshal(req.IPWhitelist)
		policy.IPWhitelist = whitelistJSON
	}
	if req.IPBlacklist != nil {
		blacklistJSON, _ := json.Marshal(req.IPBlacklist)
		policy.IPBlacklist = blacklistJSON
	}

	if err := s.repo.UpdateSecurityPolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("UpdateSecurityPolicy: %w", err)
	}

	s.logger.Info("Updated realm security policy", zap.String("realm_id", realmID.String()))

	return policy, nil
}

// ValidatePassword validates a password against the realm's security policy
func (s *RealmService) ValidatePassword(ctx context.Context, realmID uuid.UUID, password string) error {
	policy, err := s.GetSecurityPolicy(ctx, realmID)
	if err != nil {
		return fmt.Errorf("ValidatePassword: GetSecurityPolicy failed: %w", err)
	}

	if len(password) < policy.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters", policy.PasswordMinLength)
	}
	if len(password) > policy.PasswordMaxLength {
		return fmt.Errorf("password must be at most %d characters", policy.PasswordMaxLength)
	}
	if policy.PasswordRequireUppercase && !containsUppercase(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if policy.PasswordRequireLowercase && !containsLowercase(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if policy.PasswordRequireDigits && !containsDigit(password) {
		return fmt.Errorf("password must contain at least one digit")
	}
	if policy.PasswordRequireSpecial {
		specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
		if policy.PasswordSpecialChars != nil {
			specialChars = *policy.PasswordSpecialChars
		}
		if !containsSpecial(password, specialChars) {
			return fmt.Errorf("password must contain at least one special character")
		}
	}

	return nil
}

// ==================== Identity Providers ====================

// AddIdentityProvider adds an identity provider to a realm.
// When the consolidated IDP repository is set, creates in iam_identity_providers
// with scope='realm'. Otherwise falls back to the legacy realm_identity_providers table.
func (s *RealmService) AddIdentityProvider(ctx context.Context, realmID uuid.UUID, req *models.CreateRealmIdentityProviderRequest) (*models.RealmIdentityProvider, error) {
	// Verify realm exists
	realm, err := s.repo.GetByID(ctx, realmID)
	if err != nil || realm == nil {
		return nil, fmt.Errorf("realm not found")
	}

	// ── Consolidated path: write to iam_identity_providers with scope='realm' ──
	if s.idpRepo != nil {
		return s.addRealmIDPConsolidated(ctx, realmID, req)
	}

	// ── Legacy path: write to realm_identity_providers ──
	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}
	mappingJSON := json.RawMessage(`{}`)
	if req.AttributeMapping != nil {
		mappingJSON, err = json.Marshal(req.AttributeMapping)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal attribute mapping: %w", err)
		}
	}

	idp := &models.RealmIdentityProvider{
		ID:                 uuid.New(),
		RealmID:            realmID,
		Name:               req.Name,
		DisplayName:        req.DisplayName,
		Type:               req.Type,
		IsEnabled:          true,
		IsDefault:          false,
		Priority:           0,
		Config:             configJSON,
		AttributeMapping:   mappingJSON,
		SyncEnabled:        false,
		AutoProvisionUsers: true,
		AutoUpdateUsers:    true,
	}

	if req.IsEnabled != nil {
		idp.IsEnabled = *req.IsEnabled
	}
	if req.IsDefault != nil {
		idp.IsDefault = *req.IsDefault
	}
	if req.Priority != nil {
		idp.Priority = *req.Priority
	}
	if req.SyncEnabled != nil {
		idp.SyncEnabled = *req.SyncEnabled
	}
	if req.SyncInterval != nil {
		idp.SyncInterval = req.SyncInterval
	}
	if req.AutoProvisionUsers != nil {
		idp.AutoProvisionUsers = *req.AutoProvisionUsers
	}
	if req.AutoUpdateUsers != nil {
		idp.AutoUpdateUsers = *req.AutoUpdateUsers
	}

	if err := s.repo.CreateIdentityProvider(ctx, idp); err != nil {
		return nil, fmt.Errorf("AddIdentityProvider: %w", err)
	}

	s.logger.Info("Added identity provider to realm", zap.String("realm_id", realmID.String()), zap.String("idp_id", idp.ID.String()), zap.String("type", idp.Type))

	return idp, nil
}

// ListIdentityProviders lists identity providers for a realm.
func (s *RealmService) ListIdentityProviders(ctx context.Context, realmID uuid.UUID) ([]models.RealmIdentityProvider, error) {
	if s.idpRepo != nil {
		providers, err := s.idpRepo.ListByRealm(ctx, realmID)
		if err != nil {
			return nil, fmt.Errorf("ListIdentityProviders: %w", err)
		}
		result := make([]models.RealmIdentityProvider, 0, len(providers))
		for _, p := range providers {
			result = append(result, *idpToRealmIDP(p))
		}
		return result, nil
	}
	return s.repo.ListIdentityProviders(ctx, realmID)
}

// RemoveIdentityProvider removes an identity provider from a realm
func (s *RealmService) RemoveIdentityProvider(ctx context.Context, idpID uuid.UUID) error {
	if s.idpRepo != nil {
		return s.idpRepo.Delete(ctx, idpID)
	}
	return s.repo.DeleteIdentityProvider(ctx, idpID)
}

// GetIdentityProvider retrieves a single identity provider by ID
func (s *RealmService) GetIdentityProvider(ctx context.Context, idpID uuid.UUID) (*models.RealmIdentityProvider, error) {
	if s.idpRepo != nil {
		provider, err := s.idpRepo.GetByID(ctx, idpID)
		if err != nil {
			return nil, fmt.Errorf("GetIdentityProvider: %w", err)
		}
		if provider == nil {
			return nil, fmt.Errorf("identity provider not found")
		}
		return idpToRealmIDP(provider), nil
	}
	idp, err := s.repo.GetIdentityProvider(ctx, idpID)
	if err != nil {
		return nil, fmt.Errorf("GetIdentityProvider: %w", err)
	}
	if idp == nil {
		return nil, fmt.Errorf("identity provider not found")
	}
	return idp, nil
}

// UpdateIdentityProvider updates an identity provider
func (s *RealmService) UpdateIdentityProvider(ctx context.Context, idpID uuid.UUID, req *models.UpdateRealmIdentityProviderRequest) (*models.RealmIdentityProvider, error) {
	if s.idpRepo != nil {
		return s.updateIDPConsolidated(ctx, idpID, req)
	}

	// Legacy path
	idp, err := s.repo.GetIdentityProvider(ctx, idpID)
	if err != nil {
		return nil, fmt.Errorf("UpdateIdentityProvider: %w", err)
	}
	if idp == nil {
		return nil, fmt.Errorf("identity provider not found")
	}

	// Apply updates
	if req.Name != nil {
		idp.Name = *req.Name
	}
	if req.DisplayName != nil {
		idp.DisplayName = *req.DisplayName
	}
	if req.IsEnabled != nil {
		idp.IsEnabled = *req.IsEnabled
	}
	if req.IsDefault != nil {
		idp.IsDefault = *req.IsDefault
	}
	if req.Priority != nil {
		idp.Priority = *req.Priority
	}
	if req.Config != nil {
		configJSON, _ := json.Marshal(req.Config)
		idp.Config = configJSON
	}
	if req.AttributeMapping != nil {
		mappingJSON, _ := json.Marshal(req.AttributeMapping)
		idp.AttributeMapping = mappingJSON
	}
	if req.SyncEnabled != nil {
		idp.SyncEnabled = *req.SyncEnabled
	}
	if req.SyncInterval != nil {
		idp.SyncInterval = req.SyncInterval
	}
	if req.AutoProvisionUsers != nil {
		idp.AutoProvisionUsers = *req.AutoProvisionUsers
	}
	if req.AutoUpdateUsers != nil {
		idp.AutoUpdateUsers = *req.AutoUpdateUsers
	}
	if req.AutoDeactivateUsers != nil {
		idp.AutoDeactivateUsers = *req.AutoDeactivateUsers
	}

	if err := s.repo.UpdateIdentityProvider(ctx, idp); err != nil {
		return nil, fmt.Errorf("UpdateIdentityProvider: %w", err)
	}

	s.logger.Info("Updated identity provider", zap.String("idp_id", idpID.String()), zap.String("realm_id", idp.RealmID.String()))

	return idp, nil
}

// updateIDPConsolidated updates an identity provider using the consolidated idpRepo path.
func (s *RealmService) updateIDPConsolidated(ctx context.Context, idpID uuid.UUID, req *models.UpdateRealmIdentityProviderRequest) (*models.RealmIdentityProvider, error) {
	provider, err := s.idpRepo.GetByID(ctx, idpID)
	if err != nil {
		return nil, fmt.Errorf("UpdateIdentityProvider: %w", err)
	}
	if provider == nil {
		return nil, fmt.Errorf("identity provider not found")
	}
	if req.Name != nil {
		provider.Name = *req.Name
	}
	if req.DisplayName != nil {
		provider.DisplayName = *req.DisplayName
	}
	if req.IsEnabled != nil {
		provider.IsEnabled = *req.IsEnabled
	}
	if req.IsDefault != nil {
		provider.IsDefault = *req.IsDefault
	}
	if req.Priority != nil {
		provider.Priority = *req.Priority
	}
	if req.AutoProvisionUsers != nil {
		provider.AutoProvisionUsers = *req.AutoProvisionUsers
	}
	if err := s.idpRepo.Update(ctx, provider); err != nil {
		return nil, fmt.Errorf("UpdateIdentityProvider: %w", err)
	}
	s.logger.Info("Updated realm identity provider (consolidated)", zap.String("idp_id", idpID.String()))
	return idpToRealmIDP(provider), nil
}

// idpToRealmIDP converts a consolidated IdentityProvider to a RealmIdentityProvider
// for backward-compatible API responses.
func idpToRealmIDP(p *models.IdentityProvider) *models.RealmIdentityProvider {
	realmID := uuid.Nil
	if p.RealmID != nil {
		realmID = *p.RealmID
	}
	return &models.RealmIdentityProvider{
		ID:                 p.ID,
		RealmID:            realmID,
		Name:               p.Name,
		DisplayName:        p.DisplayName,
		Type:               p.Type,
		IsEnabled:          p.IsEnabled,
		IsDefault:          p.IsDefault,
		Priority:           p.Priority,
		AutoProvisionUsers: p.AutoProvisionUsers,
		CreatedAt:          p.CreatedAt,
		UpdatedAt:          p.UpdatedAt,
	}
}

// ListTenantIdentityProviders lists tenant-scoped IDPs for all tenants in a realm.
func (s *RealmService) ListTenantIdentityProviders(ctx context.Context, realmID uuid.UUID) ([]models.TenantIdentityProviderSummary, error) {
	// Cross-DB orchestration: realm_tenants is on the control plane,
	// iam_identity_providers + iam_tenants are on the data plane.
	// Step 1: get tenant IDs from control plane
	tenants, err := s.repo.ListRealmTenants(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("ListTenantIdentityProviders: get realm tenants: %w", err)
	}
	if len(tenants) == 0 {
		return nil, nil
	}

	// Step 2: query data plane for IDPs belonging to these tenants
	if s.idpRepo == nil {
		return nil, fmt.Errorf("ListTenantIdentityProviders: idpRepo not configured")
	}
	tenantIDs := make([]uuid.UUID, len(tenants))
	for i, t := range tenants {
		tenantIDs[i] = t.TenantID
	}
	return s.idpRepo.ListTenantProviderSummaries(ctx, tenantIDs)
}

// Tenant management, admin assignments, domain management, cache management,
// helper functions, and user-facing methods are in realm_service_admin.go

// addRealmIDPConsolidated creates a new realm identity provider using the consolidated iam_identity_providers table.
func (s *RealmService) addRealmIDPConsolidated(ctx context.Context, realmID uuid.UUID, req *models.CreateRealmIdentityProviderRequest) (*models.RealmIdentityProvider, error) {
	provider := &models.IdentityProvider{
		ID:                 uuid.New(),
		RealmID:            &realmID,
		Scope:              "realm",
		Type:               req.Type,
		Name:               req.Name,
		DisplayName:        req.DisplayName,
		IsEnabled:          true,
		IsDefault:          false,
		Priority:           0,
		AutoProvisionUsers: true,
	}
	if req.IsEnabled != nil {
		provider.IsEnabled = *req.IsEnabled
	}
	if req.IsDefault != nil {
		provider.IsDefault = *req.IsDefault
	}
	if req.Priority != nil {
		provider.Priority = *req.Priority
	}
	if req.AutoProvisionUsers != nil {
		provider.AutoProvisionUsers = *req.AutoProvisionUsers
	}

	if err := s.idpRepo.CreateRealmProvider(ctx, provider); err != nil {
		return nil, fmt.Errorf("AddIdentityProvider: %w", err)
	}

	s.logger.Info("Added realm identity provider (consolidated)", zap.String("realm_id", realmID.String()), zap.String("idp_id", provider.ID.String()), zap.String("type", provider.Type))
	return idpToRealmIDP(provider), nil
}

// SetWitnessPolicyRepository wires the device-witness policy store.
func (s *RealmService) SetWitnessPolicyRepository(r realmWitnessPolicyRepo) {
	s.witnessPolicy = r
}

// ErrWitnessPolicyUnavailable is returned when the policy store is not wired.
var ErrWitnessPolicyUnavailable = fmt.Errorf("device witness policy store not configured")

// GetDeviceWitnessTOTPAllowed returns the realm's authenticator-app witness flag.
func (s *RealmService) GetDeviceWitnessTOTPAllowed(ctx context.Context, realmID uuid.UUID) (bool, error) {
	if s.witnessPolicy == nil {
		return false, ErrWitnessPolicyUnavailable
	}
	return s.witnessPolicy.GetDeviceWitnessTOTPAllowedByRealm(ctx, realmID)
}

// SetDeviceWitnessTOTPAllowed sets the realm's authenticator-app witness flag.
func (s *RealmService) SetDeviceWitnessTOTPAllowed(ctx context.Context, realmID uuid.UUID, allowed bool) error {
	if s.witnessPolicy == nil {
		return ErrWitnessPolicyUnavailable
	}
	return s.witnessPolicy.SetDeviceWitnessTOTPAllowed(ctx, realmID, allowed)
}

// SetSessionPolicyRepository wires the session-policy store.
func (s *RealmService) SetSessionPolicyRepository(r realmSessionPolicyRepo) {
	s.sessionPolicy = r
}

// GetSessionAbsoluteTTL returns the realm's SSO session cap in seconds (nil = global default).
func (s *RealmService) GetSessionAbsoluteTTL(ctx context.Context, realmID uuid.UUID) (*int, error) {
	if s.sessionPolicy == nil {
		return nil, ErrWitnessPolicyUnavailable
	}
	return s.sessionPolicy.GetSessionAbsoluteTTLSeconds(ctx, realmID)
}

// SetSessionAbsoluteTTL validates and sets the realm's SSO session cap (nil clears it).
func (s *RealmService) SetSessionAbsoluteTTL(ctx context.Context, realmID uuid.UUID, secs *int) error {
	if s.sessionPolicy == nil {
		return ErrWitnessPolicyUnavailable
	}
	if secs != nil && (*secs < MinSessionAbsoluteTTLSeconds || *secs > MaxSessionAbsoluteTTLSeconds) {
		return ErrInvalidSessionTTL
	}
	return s.sessionPolicy.SetSessionAbsoluteTTLSeconds(ctx, realmID, secs)
}
