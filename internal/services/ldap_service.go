// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	resilient "github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const ldapAttrTitle = "title"

// ldapServiceIDPRepo defines the identity provider repository methods needed by LDAPService.
type ldapServiceIDPRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.IdentityProvider, error)
	GetByTenantAndType(ctx context.Context, tenantID uuid.UUID, providerType string) ([]*models.IdentityProvider, error)
	GetAllByType(ctx context.Context, providerType string) ([]*models.IdentityProvider, error)
}

// ldapServiceUserRepo defines the user repository methods needed by LDAPService.
type ldapServiceUserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error)
	GetByFederationID(ctx context.Context, federationType, federationID string) (*models.User, error)
	LinkFederation(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, federationType, federationID, federationSource string) error
	GetByFederationSource(ctx context.Context, federationType, federationSource string) ([]models.User, error)
	Create(ctx context.Context, user *models.User) error
	Update(ctx context.Context, user *models.User) error
	AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error
}

// ldapServiceRoleRepo defines the role repository methods needed by LDAPService.
type ldapServiceRoleRepo interface {
	GetDefaultRoles(ctx context.Context, tenantID uuid.UUID) ([]models.Role, error)
	GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error)
}

// ldapServiceRealmResolver resolves the tenant → realm mapping for user creation.
type ldapServiceRealmResolver interface {
	GetTenantRealm(ctx context.Context, tenantID uuid.UUID) (*models.Realm, error)
}

// ldapServiceSettingsRepo is a placeholder interface for the settings repository.
// No methods are currently called on it within LDAPService.
type ldapServiceSettingsRepo interface{}

// ldapServiceGroupRepo defines the group repository methods needed by LDAPService.
type ldapServiceGroupRepo interface {
	GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Group, error)
	Create(ctx context.Context, group *models.Group) error
	Update(ctx context.Context, group *models.Group) error
}

// LDAPService is an exported type.
type LDAPService struct {
	config            *config.Config
	idpRepo           ldapServiceIDPRepo
	userRepo          ldapServiceUserRepo
	roleRepo          ldapServiceRoleRepo
	settingsRepo      ldapServiceSettingsRepo
	groupRepo         ldapServiceGroupRepo
	encryptionService *crypto.EncryptionService
	realmResolver     ldapServiceRealmResolver
	auditService      *AuditService

	// dialBreaker (DDIL P3.11) sheds LDAP CONNECT attempts when the directory
	// is unreachable, so a login flood does not pile onto a dead LDAP server.
	// It gates connection establishment only — bind (credential) failures are
	// legitimate results and MUST NOT trip it (that would let a run of wrong
	// passwords disable the whole directory). nil ⇒ resilience disabled.
	dialBreaker *resilient.Breaker
}

// NewLDAPService is an exported function.
func NewLDAPService(
	cfg *config.Config,
	idpRepo ldapServiceIDPRepo,
	userRepo ldapServiceUserRepo,
	roleRepo ldapServiceRoleRepo,
) *LDAPService {
	s := &LDAPService{
		config:   cfg,
		idpRepo:  idpRepo,
		userRepo: userRepo,
		roleRepo: roleRepo,
	}
	// DDIL P3.11: a shared connect-breaker so a down directory is shed fast
	// instead of every login attempt blocking on a dead socket. Breaker-only
	// (no retry/backoff): the LDAP connect sits on the synchronous auth path,
	// where injecting backoff would add user-visible login latency; shedding is
	// the useful behaviour. Bind failures are reported to the caller and never
	// counted against this breaker.
	if cfg != nil && cfg.LDAPResilienceEnabled {
		s.dialBreaker = resilient.NewBreaker(resilient.BreakerConfig{
			FailureThreshold: cfg.LDAPBreakerFailureThreshold,
			OpenTimeout:      cfg.LDAPBreakerResetTimeout,
			OnStateChange: func(from, to resilient.State) {
				logger.Warn("LDAP connect circuit breaker state change",
					zap.String("from", from.String()), zap.String("to", to.String()))
			},
		})
	}
	return s
}

// SetSettingsRepo sets the settings repository (called after initialization)
func (s *LDAPService) SetSettingsRepo(repo ldapServiceSettingsRepo) {
	s.settingsRepo = repo
}

// SetGroupRepo sets the group repository (called after initialization)
func (s *LDAPService) SetGroupRepo(repo ldapServiceGroupRepo) {
	s.groupRepo = repo
}

// SetEncryptionService sets the encryption service for decrypting LDAP bind passwords
func (s *LDAPService) SetEncryptionService(svc *crypto.EncryptionService) {
	s.encryptionService = svc
}

// SetRealmResolver sets the realm resolver for tenant → realm mapping during user creation
func (s *LDAPService) SetRealmResolver(resolver ldapServiceRealmResolver) {
	s.realmResolver = resolver
}

// SetAuditService sets the audit service for security event logging
func (s *LDAPService) SetAuditService(svc *AuditService) {
	s.auditService = svc
}

// Connect establishes an LDAP connection with TLS/StartTLS support
func (s *LDAPService) Connect(cfg *models.LDAPConfig) (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	// Enforce TLS in production/staging environments
	if s.config.Environment == "production" || s.config.Environment == "staging" {
		if !cfg.UseTLS && !cfg.UseStartTLS {
			return nil, fmt.Errorf("LDAP connections require TLS in %s environment", s.config.Environment)
		}
		if cfg.SkipTLSVerify {
			return nil, fmt.Errorf("LDAP SkipTLSVerify is not allowed in %s environment", s.config.Environment)
		}
	}

	// Decrypt bind password if stored encrypted
	bindPassword := cfg.BindPassword
	if cfg.BindPasswordEncrypted != "" && s.encryptionService != nil {
		decrypted, err := s.encryptionService.Decrypt(cfg.BindPasswordEncrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt LDAP bind password: %w", err)
		}
		bindPassword = decrypted
	} else if bindPassword != "" && (s.config.Environment == "production" || s.config.Environment == "staging") {
		logger.Warn("SECURITY: Using plaintext LDAP bind password — migrate to encrypted storage",
			zap.String("environment", s.config.Environment),
			zap.String("provider", cfg.Host),
		)
	}

	var conn *ldap.Conn
	var err error

	// TLS Configuration.
	//
	// Floor is TLS 1.2 (ASVS V12 / RFC 9325 §3.1.1: TLS 1.0 and 1.1 are
	// deprecated by RFC 8996 and MUST NOT be negotiated). MinVersion is a
	// floor, not a pin — Go's default MaxVersion is TLS 1.3, so a modern AD
	// server negotiates 1.3 and only servers that top out at 1.2 fall back to
	// 1.2. A genuinely legacy AD (Windows Server 2012/2012 R2) that cannot do
	// 1.2 over LDAPS must opt in EXPLICITLY per-provider via AllowLegacyTLS —
	// an audited escape hatch, not a silent default downgrade. See the dated
	// SUNSET note on LDAPConfig.AllowLegacyTLS.
	minTLS := uint16(tls.VersionTLS12)
	if cfg.AllowLegacyTLS {
		minTLS = tls.VersionTLS10
		logger.Warn("SECURITY: LDAP provider using DEPRECATED TLS 1.0 floor via AllowLegacyTLS opt-in — upgrade the AD server and remove this flag (sunset 2027-01-01)",
			zap.String("provider", cfg.Host),
			zap.String("environment", s.config.Environment),
		)
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec // InsecureSkipVerify is user-configurable for LDAP TLS
		MinVersion:         minTLS,
	}
	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	} else if cfg.Host != "" {
		tlsConfig.ServerName = cfg.Host
	}

	conn, err = s.dialLDAP(address, cfg, tlsConfig)
	if err != nil {
		return nil, err
	}

	// Bind with service account
	if cfg.BindDN != "" && bindPassword != "" {
		logger.Debug("Binding to LDAP", zap.String("bind_dn", cfg.BindDN))
		if err := conn.Bind(cfg.BindDN, bindPassword); err != nil {
			conn.Close() //nolint:errcheck,gosec
			return nil, fmt.Errorf("failed to bind: %w", err)
		}
	}

	return conn, nil
}

// dialLDAP establishes a raw LDAP connection, gated by the DDIL connect-breaker
// (P3.11) when enabled. When the breaker is open the dial is shed immediately
// with ErrBreakerOpen instead of blocking on an unreachable directory. Only the
// connection attempt is gated — bind (credential) verification happens in the
// caller and never feeds this breaker.
func (s *LDAPService) dialLDAP(address string, cfg *models.LDAPConfig, tlsConfig *tls.Config) (*ldap.Conn, error) {
	if s.dialBreaker == nil {
		return s.dialLDAPOnce(address, cfg, tlsConfig)
	}
	done, err := s.dialBreaker.Allow()
	if err != nil {
		return nil, fmt.Errorf("LDAP connect to %s shed by circuit breaker: %w", address, err)
	}
	conn, dialErr := s.dialLDAPOnce(address, cfg, tlsConfig)
	done(dialErr == nil)
	return conn, dialErr
}

// dialLDAPOnce establishes a raw LDAP connection using TLS, plain TCP, or StartTLS as configured.
func (s *LDAPService) dialLDAPOnce(address string, cfg *models.LDAPConfig, tlsConfig *tls.Config) (*ldap.Conn, error) {
	if cfg.UseTLS {
		logger.Debug("Connecting to LDAP with TLS", zap.String("address", address))
		conn, err := ldap.DialURL("ldaps://"+address, ldap.DialWithTLSConfig(tlsConfig))
		if err != nil {
			return nil, fmt.Errorf("failed to connect with TLS: %w", err)
		}
		return conn, nil
	}

	logger.Debug("Connecting to LDAP", zap.String("address", address))
	conn, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	if cfg.UseStartTLS {
		logger.Debug("Upgrading connection with StartTLS")
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close() //nolint:errcheck,gosec
			return nil, fmt.Errorf("failed to start TLS: %w", err)
		}
	}
	return conn, nil
}

// TestConnection tests an LDAP connection with the provided configuration
func (s *LDAPService) TestConnection(_ context.Context, cfg *models.LDAPConfig) error {
	ldapConfig := s.applyLDAPDefaults(cfg)
	conn, err := s.Connect(ldapConfig)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	// Try a simple search to verify the configuration
	// Use ScopeBaseObject on the BaseDN to avoid size limit issues with large directories
	searchRequest := ldap.NewSearchRequest(
		ldapConfig.BaseDN,
		ldap.ScopeBaseObject, // Search only the base DN itself
		ldap.NeverDerefAliases,
		1,  // Size limit
		30, // Time limit
		false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	_, err = conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("search test failed: %w", err)
	}

	logger.Info("LDAP connection test successful", zap.String("host", ldapConfig.Host))
	return nil
}

// Authenticate authenticates a user against LDAP
func (s *LDAPService) Authenticate(ctx context.Context, _ uuid.UUID, providerID uuid.UUID, username, password string) (*models.User, error) {
	// Get identity provider configuration
	provider, err := s.idpRepo.GetByID(ctx, providerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity provider: %w", err)
	}
	if provider == nil {
		return nil, fmt.Errorf("identity provider not found")
	}
	if !provider.IsEnabled {
		return nil, fmt.Errorf("identity provider is disabled")
	}

	// Get LDAP config
	if provider.LDAPConfig == nil {
		return nil, fmt.Errorf("LDAP configuration not found")
	}
	ldapConfig := s.applyLDAPDefaults(provider.LDAPConfig)

	// Connect to LDAP
	conn, err := s.Connect(ldapConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	// Search for user
	ldapEntry, err := s.SearchUser(conn, ldapConfig, username)
	if err != nil {
		return nil, fmt.Errorf("user search failed: %w", err)
	}
	if ldapEntry == nil {
		return nil, fmt.Errorf("user not found in LDAP")
	}

	// Authenticate by binding as the user
	userDN := ldapEntry.DN
	logger.Debug("Attempting user authentication", zap.String("user_dn", userDN))

	if err := conn.Bind(userDN, password); err != nil {
		logger.Warn("LDAP authentication failed",
			zap.String("username", username),
			zap.Error(err),
		)
		return nil, fmt.Errorf("invalid credentials")
	}

	logger.Info("LDAP authentication successful",
		zap.String("username", username),
		zap.String("user_dn", userDN),
	)

	// Re-bind as service account for subsequent operations
	if ldapConfig.BindDN != "" {
		rebindPassword := ldapConfig.BindPassword
		if ldapConfig.BindPasswordEncrypted != "" && s.encryptionService != nil {
			if decrypted, err := s.encryptionService.Decrypt(ldapConfig.BindPasswordEncrypted); err == nil {
				rebindPassword = decrypted
			}
		}
		if err := conn.Bind(ldapConfig.BindDN, rebindPassword); err != nil {
			logger.Error("Failed to re-bind as service account", zap.Error(err))
		}
	}

	// Get user groups
	var groups []string
	if ldapConfig.SyncGroups {
		groups, err = s.GetUserGroups(conn, ldapConfig, userDN)
		if err != nil {
			logger.Error("Failed to get user groups", zap.Error(err))
			// Don't fail authentication if group fetch fails
			groups = []string{}
		}
	}

	// Find or create user in local database
	user, err := s.findOrCreateUser(ctx, provider, ldapEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to find or create user: %w", err)
	}

	// Map groups to roles
	if len(groups) > 0 {
		if err := s.mapGroupsToRoles(ctx, providerID, user.ID, groups); err != nil {
			logger.Error("Failed to map groups to roles", zap.Error(err))
			// Don't fail authentication if role mapping fails
		}
	}

	return user, nil
}

// SearchUser searches for a user in LDAP by username
func (s *LDAPService) SearchUser(conn *ldap.Conn, cfg *models.LDAPConfig, username string) (*ldap.Entry, error) {
	searchBase := cfg.BaseDN
	if cfg.UserSearchBase != "" {
		searchBase = cfg.UserSearchBase
	}

	// Build search filter
	filter := cfg.UserFilter
	escapedUsername := ldap.EscapeFilter(username)
	usernameAttr := cfg.UsernameAttr
	if usernameAttr == "" {
		usernameAttr = "sAMAccountName" // Default for Active Directory
	}

	switch {
	case filter == "":
		// Default filter for Active Directory
		filter = fmt.Sprintf("(&(objectClass=user)(%s=%s))", usernameAttr, escapedUsername)
	case strings.Contains(filter, "%s"):
		// Replace %s with username
		filter = strings.ReplaceAll(filter, "%s", escapedUsername)
	default:
		// Filter doesn't contain %s placeholder - combine with username filter
		// This handles filters like "(&(objectClass=user)(objectCategory=person))"
		filter = fmt.Sprintf("(&%s(%s=%s))", filter, usernameAttr, escapedUsername)
	}

	// Attributes to retrieve
	attributes := []string{
		"dn",
		cfg.UsernameAttr,
		cfg.EmailAttr,
		cfg.FirstNameAttr,
		cfg.LastNameAttr,
		cfg.DisplayNameAttr,
	}
	if cfg.PhoneAttr != "" {
		attributes = append(attributes, cfg.PhoneAttr)
	}
	if cfg.GroupAttr != "" {
		attributes = append(attributes, cfg.GroupAttr)
	}

	logger.Debug("Searching for user in LDAP",
		zap.String("search_base", searchBase),
		zap.String("filter", filter),
	)

	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,  // Size limit: expect only one user
		30, // Time limit
		false,
		filter,
		attributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, nil
	}

	return result.Entries[0], nil
}

// GetUserGroups retrieves the groups a user belongs to
func (s *LDAPService) GetUserGroups(conn *ldap.Conn, cfg *models.LDAPConfig, userDN string) ([]string, error) {
	var groups []string

	// Method 1: Get groups from user's memberOf attribute
	if cfg.GroupAttr != "" {
		searchRequest := ldap.NewSearchRequest(
			userDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			30,
			false,
			"(objectClass=*)",
			[]string{cfg.GroupAttr},
			nil,
		)

		result, err := conn.Search(searchRequest)
		if err == nil && len(result.Entries) > 0 {
			groups = result.Entries[0].GetAttributeValues(cfg.GroupAttr)
			logger.Debug("Found groups from memberOf attribute",
				zap.Int("count", len(groups)),
			)
		}
	}

	// Method 2: Search for groups that have this user as a member
	if len(groups) == 0 && cfg.GroupFilter != "" {
		searchBase := cfg.BaseDN
		if cfg.GroupSearchBase != "" {
			searchBase = cfg.GroupSearchBase
		}

		filter := strings.ReplaceAll(cfg.GroupFilter, "%s", ldap.EscapeFilter(userDN))

		searchRequest := ldap.NewSearchRequest(
			searchBase,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, // No size limit
			30,
			false,
			filter,
			[]string{"cn", "dn"},
			nil,
		)

		result, err := conn.Search(searchRequest)
		if err == nil {
			for _, entry := range result.Entries {
				groupName := entry.GetAttributeValue("cn")
				if groupName != "" {
					groups = append(groups, groupName)
				}
			}
			logger.Debug("Found groups from group search",
				zap.Int("count", len(groups)),
			)
		}
	}

	return groups, nil
}

// SyncUsers synchronizes users from LDAP to local database
func (s *LDAPService) SyncUsers(ctx context.Context, providerID uuid.UUID, fullSync bool) (*models.LDAPSyncResult, error) {
	startTime := time.Now()
	result := &models.LDAPSyncResult{
		StartedAt: startTime,
		Success:   false,
	}

	// Get identity provider
	provider, err := s.idpRepo.GetByID(ctx, providerID)
	if err != nil {
		result.Message = "Failed to get identity provider"
		result.Errors = append(result.Errors, err.Error())
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		return result, fmt.Errorf("SyncUsers: failed to get identity provider: %w", err)
	}

	if provider == nil {
		err := fmt.Errorf("identity provider not found")
		result.Message = "Identity provider not found"
		result.Errors = append(result.Errors, err.Error())
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		return result, err
	}

	// Get LDAP config
	if provider.LDAPConfig == nil {
		result.Message = "LDAP configuration not found"
		result.Errors = append(result.Errors, "LDAP configuration not found")
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		return result, fmt.Errorf("LDAP configuration not found")
	}
	ldapConfig := s.applyLDAPDefaults(provider.LDAPConfig)

	// Connect to LDAP
	conn, err := s.Connect(ldapConfig)
	if err != nil {
		result.Message = "Failed to connect to LDAP"
		result.Errors = append(result.Errors, err.Error())
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		return result, fmt.Errorf("SyncUsers: failed to connect to LDAP: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	// Search for all users
	searchBase := ldapConfig.BaseDN
	if ldapConfig.UserSearchBase != "" {
		searchBase = ldapConfig.UserSearchBase
	}

	// Use the configured user filter if available and doesn't contain %s placeholder
	// Otherwise fall back to a default filter that gets all active users
	filter := ldapConfig.UserFilter
	if filter == "" || strings.Contains(filter, "%s") {
		filter = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	}

	attributes := []string{
		"dn",
		ldapConfig.UsernameAttr,
		ldapConfig.EmailAttr,
		ldapConfig.FirstNameAttr,
		ldapConfig.LastNameAttr,
		ldapConfig.DisplayNameAttr,
	}
	if ldapConfig.PhoneAttr != "" {
		attributes = append(attributes, ldapConfig.PhoneAttr)
	}
	if ldapConfig.GroupAttr != "" {
		attributes = append(attributes, ldapConfig.GroupAttr)
	}

	logger.Info("Starting LDAP user sync",
		zap.String("provider", provider.Name),
		zap.String("search_base", searchBase),
		zap.Bool("full_sync", fullSync),
	)

	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // No size limit
		0, // No time limit
		false,
		filter,
		attributes,
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		result.Message = "LDAP search failed"
		result.Errors = append(result.Errors, err.Error())
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		return result, fmt.Errorf("SyncUsers: LDAP search failed: %w", err)
	}

	result.UsersFound = len(searchResult.Entries)
	logger.Info("Found users in LDAP", zap.Int("count", result.UsersFound))

	// Track all DNs found in LDAP for later comparison
	foundDNS := make(map[string]bool, len(searchResult.Entries))

	// Process each user
	for _, entry := range searchResult.Entries {
		username := entry.GetAttributeValue(ldapConfig.UsernameAttr)
		if username == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("User missing username attribute: %s", entry.DN))
			continue
		}

		// Track this DN as found in LDAP
		foundDNS[entry.DN] = true

		// Check if user exists BEFORE creating/updating
		existingUser, _ := s.userRepo.GetByFederationID(ctx, federationTypeLDAP, entry.DN)
		isNewUser := existingUser == nil

		// Force create during sync - always create users from LDAP
		user, err := s.findOrCreateUser(ctx, provider, entry, true)
		if err != nil {
			logger.Error("Failed to sync user",
				zap.String("username", username),
				zap.Error(err),
			)
			result.Errors = append(result.Errors, fmt.Sprintf("User %s: %v", username, err))
			continue
		}

		// Track if user was created or updated
		if isNewUser {
			result.UsersCreated++
			logger.Info("Created new user from LDAP",
				zap.String("username", username),
				zap.String("user_id", user.ID.String()),
			)
		} else {
			result.UsersUpdated++
		}

		// Sync groups if enabled
		if ldapConfig.SyncGroups {
			groups, err := s.GetUserGroups(conn, ldapConfig, entry.DN)
			if err != nil {
				logger.Error("Failed to get user groups",
					zap.String("username", username),
					zap.Error(err),
				)
			} else if len(groups) > 0 {
				if err := s.mapGroupsToRoles(ctx, providerID, user.ID, groups); err != nil {
					logger.Error("Failed to map groups to roles",
						zap.String("username", username),
						zap.Error(err),
					)
				}
			}
		}
	}

	// Full sync: disable users that are no longer in LDAP
	if fullSync {
		s.disableMissingLDAPUsers(ctx, provider, foundDNS, result)
	}

	result.Success = true
	result.Message = fmt.Sprintf("Successfully synced %d users (%d created, %d updated, %d disabled)",
		result.UsersFound, result.UsersCreated, result.UsersUpdated, result.UsersDisabled)
	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime).String()

	logger.Info("LDAP user sync completed",
		zap.Int("found", result.UsersFound),
		zap.Int("created", result.UsersCreated),
		zap.Int("updated", result.UsersUpdated),
		zap.Int("disabled", result.UsersDisabled),
		zap.String("duration", result.Duration),
	)

	return result, nil
}

// disableMissingLDAPUsers deactivates users whose federation_id (DN) was not found in LDAP.
func (s *LDAPService) disableMissingLDAPUsers(ctx context.Context, provider *models.IdentityProvider, foundDNS map[string]bool, result *models.LDAPSyncResult) {
	existingUsers, err := s.userRepo.GetByFederationSource(ctx, federationTypeLDAP, provider.Name)
	if err != nil {
		logger.Error("Failed to get existing LDAP users", zap.Error(err))
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to get existing users: %v", err))
		return
	}
	for _, user := range existingUsers {
		if user.FederationID == nil || foundDNS[*user.FederationID] {
			continue
		}
		user.IsActive = false
		if err := s.userRepo.Update(ctx, &user); err != nil {
			logger.Error("Failed to disable user", zap.String("username", user.Username), zap.Error(err))
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to disable %s: %v", user.Username, err))
		} else {
			result.UsersDisabled++
			logger.Info("Disabled user not found in LDAP",
				zap.String("username", user.Username),
				zap.String("user_id", user.ID.String()),
			)
		}
	}
}

// findOrCreateUser finds an existing user or creates a new one from LDAP entry
// If forceCreate is true, it will create users even if CreateUsers config is disabled (used for sync)
// ldapUserAttrs holds extracted LDAP entry attributes.
type ldapUserAttrs struct {
	userDN, username, email, firstName, lastName, displayName, phone, department, title string
}

func extractLDAPUserAttrs(ldapConfig *models.LDAPConfig, ldapEntry *ldap.Entry) ldapUserAttrs {
	departmentAttr := ldapConfig.DepartmentAttr
	if departmentAttr == "" {
		departmentAttr = "department"
	}
	titleAttr := ldapConfig.TitleAttr
	if titleAttr == "" {
		titleAttr = ldapAttrTitle
	}
	return ldapUserAttrs{
		userDN:      ldapEntry.DN,
		username:    ldapEntry.GetAttributeValue(ldapConfig.UsernameAttr),
		email:       ldapEntry.GetAttributeValue(ldapConfig.EmailAttr),
		firstName:   ldapEntry.GetAttributeValue(ldapConfig.FirstNameAttr),
		lastName:    ldapEntry.GetAttributeValue(ldapConfig.LastNameAttr),
		displayName: ldapEntry.GetAttributeValue(ldapConfig.DisplayNameAttr),
		phone:       ldapEntry.GetAttributeValue(ldapConfig.PhoneAttr),
		department:  ldapEntry.GetAttributeValue(departmentAttr),
		title:       ldapEntry.GetAttributeValue(titleAttr),
	}
}

func applyLDAPAttrsToUser(user *models.User, attrs ldapUserAttrs) {
	user.Email = attrs.email
	if attrs.firstName != "" {
		user.FirstName = &attrs.firstName
	}
	if attrs.lastName != "" {
		user.LastName = &attrs.lastName
	}
	if attrs.displayName != "" {
		user.DisplayName = &attrs.displayName
	}
	if attrs.phone != "" {
		user.Phone = &attrs.phone
	}
	if attrs.department != "" {
		user.Department = &attrs.department
	}
	if attrs.title != "" {
		user.Title = &attrs.title
	}
}

func (s *LDAPService) findOrCreateUser(ctx context.Context, provider *models.IdentityProvider, ldapEntry *ldap.Entry, forceCreate ...bool) (*models.User, error) {
	if provider.LDAPConfig == nil {
		return nil, fmt.Errorf("LDAP configuration not found")
	}
	ldapConfig := provider.LDAPConfig
	attrs := extractLDAPUserAttrs(ldapConfig, ldapEntry)

	user, err := s.userRepo.GetByFederationID(ctx, federationTypeLDAP, attrs.userDN)
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	fedType := federationTypeLDAP
	fedSource := provider.Name
	shouldForceCreate := len(forceCreate) > 0 && forceCreate[0]

	if user == nil && attrs.email != "" && ldapConfig.AutoLinkByEmail {
		linked, err := s.tryAutoLinkByEmail(ctx, provider, attrs, fedType, fedSource)
		if err != nil {
			return nil, err
		}
		if linked != nil {
			return linked, nil
		}
	}

	if user == nil {
		return s.createLDAPUser(ctx, provider, ldapConfig, attrs, fedType, fedSource, shouldForceCreate)
	}

	// Update existing user if enabled or forced (sync)
	if ldapConfig.UpdateUsers || shouldForceCreate {
		logger.Debug("Updating user from LDAP",
			zap.String("username", attrs.username),
			zap.String("user_id", user.ID.String()),
		)
		applyLDAPAttrsToUser(user, attrs)
		if err := s.userRepo.Update(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
	}

	return user, nil
}

// tryAutoLinkByEmail attempts to link an existing local user to LDAP by email.
func (s *LDAPService) tryAutoLinkByEmail(ctx context.Context, provider *models.IdentityProvider, attrs ldapUserAttrs, fedType, fedSource string) (*models.User, error) {
	existingByEmail, err := s.userRepo.GetByEmail(ctx, provider.TenantID, attrs.email)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing user by email: %w", err)
	}
	if existingByEmail == nil {
		return nil, nil
	}
	if existingByEmail.FederationType != nil && *existingByEmail.FederationType != "" {
		logger.Warn("Refusing to re-link already-federated user",
			zap.String("user_id", existingByEmail.ID.String()),
			zap.String("existing_federation_type", *existingByEmail.FederationType),
			zap.String("attempted_source", fedSource),
		)
		return nil, fmt.Errorf("user is already linked to a different identity provider")
	}
	logger.Info("Linking existing local user to LDAP federation",
		zap.String("user_id", existingByEmail.ID.String()),
		zap.String("dn", attrs.userDN),
	)
	if err := s.userRepo.LinkFederation(ctx, existingByEmail.ID, provider.TenantID, fedType, attrs.userDN, fedSource); err != nil {
		return nil, fmt.Errorf("failed to link existing user to LDAP: %w", err)
	}
	if s.auditService != nil {
		s.auditService.LogSecurityEvent(ctx, &SecurityAuditEvent{
			TenantID:    provider.TenantID,
			UserID:      &existingByEmail.ID,
			Category:    SecurityCategoryAuthentication,
			Severity:    SecuritySeverityHigh,
			Action:      "federation_linked",
			Description: fmt.Sprintf("Local user linked to LDAP federation source=%s", fedSource),
			Details: map[string]interface{}{
				"federation_type":   fedType,
				"federation_id":     attrs.userDN,
				"federation_source": fedSource,
				"provider_id":       provider.ID.String(),
			},
		})
	}
	existingByEmail.FederationType = &fedType
	existingByEmail.FederationID = &attrs.userDN
	existingByEmail.FederationSource = &fedSource
	return existingByEmail, nil
}

// createLDAPUser creates a new user record from an LDAP entry.
func (s *LDAPService) createLDAPUser(ctx context.Context, provider *models.IdentityProvider, ldapConfig *models.LDAPConfig, attrs ldapUserAttrs, fedType, fedSource string, shouldForceCreate bool) (*models.User, error) {
	if !ldapConfig.CreateUsers && !shouldForceCreate {
		return nil, fmt.Errorf("user %s not found and auto-creation is disabled", attrs.username)
	}
	logger.Info("Creating new user from LDAP",
		zap.String("username", attrs.username),
		zap.String("dn", attrs.userDN),
	)
	var realmID uuid.UUID
	if s.realmResolver != nil {
		realm, err := s.realmResolver.GetTenantRealm(ctx, provider.TenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve realm for tenant: %w", err)
		}
		realmID = realm.ID
	}
	user := &models.User{
		TenantID:         provider.TenantID,
		RealmID:          realmID,
		Username:         attrs.username,
		FederationType:   &fedType,
		FederationID:     &attrs.userDN,
		FederationSource: &fedSource,
		IsActive:         true,
		IsEmailVerified:  true, // LDAP users are pre-verified
	}
	applyLDAPAttrsToUser(user, attrs)
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	defaultRoles, err := s.roleRepo.GetDefaultRoles(ctx, provider.TenantID)
	if err == nil && len(defaultRoles) > 0 {
		roleIDs := make([]uuid.UUID, len(defaultRoles))
		for i, r := range defaultRoles {
			roleIDs[i] = r.ID
		}
		_ = s.userRepo.AssignRoles(ctx, user.ID, roleIDs, nil)
	}
	return user, nil
}

// mapGroupsToRoles maps LDAP groups to application roles
func (s *LDAPService) mapGroupsToRoles(ctx context.Context, providerID, userID uuid.UUID, groups []string) error {
	// Get provider to access group mappings
	provider, err := s.idpRepo.GetByID(ctx, providerID)
	if err != nil {
		return fmt.Errorf("mapGroupsToRoles: failed to get identity provider: %w", err)
	}
	if provider == nil {
		return fmt.Errorf("mapGroupsToRoles: identity provider not found")
	}

	if provider.LDAPConfig == nil {
		logger.Debug("No LDAP config found", zap.String("provider", provider.Name))
		return nil
	}
	ldapConfig := provider.LDAPConfig

	if len(ldapConfig.GroupMappings) == 0 {
		logger.Debug("No group mappings configured", zap.String("provider", provider.Name))
		return nil
	}

	// Extract CN from DN format groups (e.g., "CN=Admins,OU=Groups,DC=example,DC=com" -> "Admins")
	normalizedGroups := make([]string, 0, len(groups))
	for _, group := range groups {
		if strings.HasPrefix(strings.ToUpper(group), "CN=") {
			parts := strings.Split(group, ",")
			if len(parts) > 0 {
				cn := strings.TrimPrefix(parts[0], "CN=")
				cn = strings.TrimPrefix(cn, "cn=")
				normalizedGroups = append(normalizedGroups, cn)
			}
		} else {
			normalizedGroups = append(normalizedGroups, group)
		}
	}

	logger.Debug("Mapping LDAP groups to roles",
		zap.Int("group_count", len(normalizedGroups)),
		zap.Strings("groups", normalizedGroups),
	)

	// Find roles to assign based on group mappings
	var roleIDs []uuid.UUID
	for _, group := range normalizedGroups {
		roleName, exists := ldapConfig.GroupMappings[group]
		if !exists {
			continue
		}

		role, err := s.roleRepo.GetByName(ctx, provider.TenantID, roleName)
		if err != nil {
			logger.Error("Failed to get role",
				zap.String("role_name", roleName),
				zap.Error(err),
			)
			continue
		}

		if role != nil {
			roleIDs = append(roleIDs, role.ID)
			logger.Debug("Mapped LDAP group to role",
				zap.String("group", group),
				zap.String("role", roleName),
			)
		}
	}

	if len(roleIDs) == 0 {
		logger.Debug("No roles mapped from LDAP groups", zap.Int("group_count", len(groups)))
		return nil
	}

	// Assign roles to user
	if err := s.userRepo.AssignRoles(ctx, userID, roleIDs, nil); err != nil {
		return fmt.Errorf("failed to assign roles: %w", err)
	}

	logger.Info("Successfully mapped LDAP groups to roles",
		zap.String("user_id", userID.String()),
		zap.Int("role_count", len(roleIDs)),
	)

	return nil
}

// applyLDAPDefaults applies default values to LDAP config and returns a copy
func (s *LDAPService) applyLDAPDefaults(config *models.LDAPConfig) *models.LDAPConfig {
	// Create a copy to avoid modifying the original
	ldapConfig := *config

	// Set defaults if not specified
	if ldapConfig.Port == 0 {
		if ldapConfig.UseTLS {
			ldapConfig.Port = 636 // LDAPS
		} else {
			ldapConfig.Port = 389 // LDAP
		}
	}

	if ldapConfig.UsernameAttr == "" {
		ldapConfig.UsernameAttr = "sAMAccountName"
	}
	if ldapConfig.EmailAttr == "" {
		ldapConfig.EmailAttr = "mail"
	}
	if ldapConfig.FirstNameAttr == "" {
		ldapConfig.FirstNameAttr = "givenName"
	}
	if ldapConfig.LastNameAttr == "" {
		ldapConfig.LastNameAttr = "sn"
	}
	if ldapConfig.DisplayNameAttr == "" {
		ldapConfig.DisplayNameAttr = "displayName"
	}
	if ldapConfig.GroupAttr == "" {
		ldapConfig.GroupAttr = "memberOf"
	}

	return &ldapConfig
}

// GetActiveLDAPProviders returns all active LDAP identity providers for a tenant.
//
// Since 2026-05-21 the repository returns providers regardless of
// `is_active` (Tier-A audit memo — moves state policy out of the
// repo layer); this method now applies the inline `IsEnabled`
// filter so the method-name contract is preserved for callers
// (the LDAP-fallback paths in AuthService.Login etc. that depend on
// "only currently-enabled providers" semantics).
func (s *LDAPService) GetActiveLDAPProviders(ctx context.Context, tenantID uuid.UUID) ([]*models.IdentityProvider, error) {
	providers, err := s.idpRepo.GetByTenantAndType(ctx, tenantID, federationTypeLDAP)
	if err != nil {
		return nil, fmt.Errorf("failed to list LDAP providers: %w", err)
	}

	active := make([]*models.IdentityProvider, 0, len(providers))
	for _, p := range providers {
		if p.IsEnabled {
			active = append(active, p)
		}
	}
	return active, nil
}

// AD Employee Management Methods are in ldap_ad_operations.go
