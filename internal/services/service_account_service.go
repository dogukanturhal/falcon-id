// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// serviceAccountServiceRepo defines the repository methods needed by ServiceAccountService.
type serviceAccountServiceRepo interface {
	Create(ctx context.Context, sa *models.ServiceAccount) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ServiceAccount, error)
	GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.ServiceAccount, error)
	Update(ctx context.Context, sa *models.ServiceAccount) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateSecret(ctx context.Context, id uuid.UUID, secretHash string) error
	RevokeAllTokens(ctx context.Context, serviceAccountID uuid.UUID) error
	GetByClientID(ctx context.Context, clientID string) (*models.ServiceAccount, error)
	CreateToken(ctx context.Context, token *models.ServiceAccountToken) error
	UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error
}

// serviceAccountRoleRepo is the narrow slice of RoleRepository ServiceAccountService
// needs to resolve a service account's configured roles into the permissions they
// actually grant. This is the SAME role->permission resolution the user-login path
// uses (RoleRepository.GetRolePermissions, joined via iam_role_permissions /
// iam_permissions) — no separate/looser mechanism is invented here.
type serviceAccountRoleRepo interface {
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error)
}

// ServiceAccountService handles service account operations
type ServiceAccountService struct {
	repo     serviceAccountServiceRepo
	roleRepo serviceAccountRoleRepo
	cfg      *config.Config
}

// NewServiceAccountService is an exported function.
func NewServiceAccountService(repo serviceAccountServiceRepo, roleRepo serviceAccountRoleRepo, cfg *config.Config) *ServiceAccountService {
	return &ServiceAccountService{
		repo:     repo,
		roleRepo: roleRepo,
		cfg:      cfg,
	}
}

// resolvePermissions resolves the set of permission names granted by a service
// account's configured RoleIDs, via the repo's existing role->permission join
// (the same one the user-login path resolves through). A service account can
// only ever receive permissions its RoleIDs actually grant in the DB right now —
// never a wildcard, never a hardcoded set. Permission names are deduplicated
// across roles. An unparsable or unresolvable role ID fails the whole
// resolution (fail-closed) rather than silently minting a token with fewer
// permissions than the service account was configured for.
func (s *ServiceAccountService) resolvePermissions(ctx context.Context, roleIDs []string) ([]string, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{})
	permNames := make([]string, 0, len(roleIDs))
	for _, roleIDStr := range roleIDs {
		roleID, err := uuid.Parse(roleIDStr)
		if err != nil {
			return nil, fmt.Errorf("resolvePermissions: invalid role id %q: %w", roleIDStr, err)
		}

		perms, err := s.roleRepo.GetRolePermissions(ctx, roleID)
		if err != nil {
			return nil, fmt.Errorf("resolvePermissions: role %s: %w", roleIDStr, err)
		}

		for _, p := range perms {
			if _, ok := seen[p.Name]; ok {
				continue
			}
			seen[p.Name] = struct{}{}
			permNames = append(permNames, p.Name)
		}
	}

	return permNames, nil
}

// GenerateClientCredentials generates a new client ID and secret
func (s *ServiceAccountService) GenerateClientCredentials() (clientID, clientSecret string, err error) {
	// Generate client ID (shorter, URL-safe)
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate client ID: %w", err)
	}
	clientID = "sa_" + base64.URLEncoding.EncodeToString(idBytes)[:22]

	// Generate client secret (longer, more secure)
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate client secret: %w", err)
	}
	clientSecret = "hxs_" + base64.URLEncoding.EncodeToString(secretBytes)

	return clientID, clientSecret, nil
}

// Create creates a new service account
func (s *ServiceAccountService) Create(ctx context.Context, tenantID, userID uuid.UUID, req *models.CreateServiceAccountRequest) (*models.ServiceAccountCreatedResponse, error) {
	// Generate client credentials
	clientID, clientSecret, err := s.GenerateClientCredentials()
	if err != nil {
		return nil, fmt.Errorf("Create: GenerateClientCredentials failed: %w", err)
	}

	// Hash the client secret
	secretHash, err := crypto.HashPassword(clientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to hash client secret: %w", err)
	}

	// Default token lifetime to 60 minutes if not specified
	tokenLifetime := 60
	if req.TokenLifetimeMinutes != nil {
		tokenLifetime = *req.TokenLifetimeMinutes
	}

	sa := &models.ServiceAccount{
		TenantID:             tenantID,
		Name:                 req.Name,
		Description:          req.Description,
		ClientID:             clientID,
		ClientSecretHash:     secretHash,
		RoleIDs:              req.RoleIDs,
		AllowedIPs:           req.AllowedIPs,
		AllowedEndpoints:     req.AllowedEndpoints,
		IsActive:             true,
		TokenLifetimeMinutes: tokenLifetime,
		CreatedBy:            &userID,
	}

	if err := s.repo.Create(ctx, sa); err != nil {
		return nil, fmt.Errorf("Create: %w", err)
	}

	logger.Info("Service account created",
		zap.String("service_account_id", sa.ID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("name", sa.Name),
	)

	response := &models.ServiceAccountCreatedResponse{
		ServiceAccountResponse: *sa.ToResponse(),
		ClientSecret:           clientSecret,
	}

	return response, nil
}

// GetByID retrieves a service account by ID
func (s *ServiceAccountService) GetByID(ctx context.Context, id uuid.UUID) (*models.ServiceAccount, error) {
	return s.repo.GetByID(ctx, id)
}

// List lists all service accounts for a tenant
func (s *ServiceAccountService) List(ctx context.Context, tenantID uuid.UUID) ([]*models.ServiceAccount, error) {
	return s.repo.GetByTenantID(ctx, tenantID)
}

// Update updates a service account
func (s *ServiceAccountService) Update(ctx context.Context, tenantID, saID uuid.UUID, req *models.UpdateServiceAccountRequest) (*models.ServiceAccount, error) {
	sa, err := s.repo.GetByID(ctx, saID)
	if err != nil {
		return nil, fmt.Errorf("Update: %w", err)
	}
	if sa == nil {
		return nil, fmt.Errorf("service account not found")
	}

	// Verify tenant ownership
	if sa.TenantID != tenantID {
		return nil, fmt.Errorf("service account not found")
	}

	// Apply updates
	if req.Name != nil {
		sa.Name = *req.Name
	}
	if req.Description != nil {
		sa.Description = req.Description
	}
	if req.RoleIDs != nil {
		sa.RoleIDs = req.RoleIDs
	}
	if req.AllowedIPs != nil {
		sa.AllowedIPs = req.AllowedIPs
	}
	if req.AllowedEndpoints != nil {
		sa.AllowedEndpoints = req.AllowedEndpoints
	}
	if req.IsActive != nil {
		sa.IsActive = *req.IsActive
	}
	if req.TokenLifetimeMinutes != nil {
		sa.TokenLifetimeMinutes = *req.TokenLifetimeMinutes
	}

	if err := s.repo.Update(ctx, sa); err != nil {
		return nil, fmt.Errorf("Update: %w", err)
	}

	logger.Info("Service account updated",
		zap.String("service_account_id", sa.ID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return sa, nil
}

// Delete permanently deletes a service account
func (s *ServiceAccountService) Delete(ctx context.Context, tenantID, saID uuid.UUID) error {
	sa, err := s.repo.GetByID(ctx, saID)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if sa == nil {
		return fmt.Errorf("service account not found")
	}

	// Verify tenant ownership
	if sa.TenantID != tenantID {
		return fmt.Errorf("service account not found")
	}

	if err := s.repo.Delete(ctx, saID); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}

	logger.Info("Service account deleted",
		zap.String("service_account_id", saID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return nil
}

// RegenerateSecret generates a new client secret for a service account
func (s *ServiceAccountService) RegenerateSecret(ctx context.Context, tenantID, saID uuid.UUID) (*models.ServiceAccountCreatedResponse, error) {
	sa, err := s.repo.GetByID(ctx, saID)
	if err != nil {
		return nil, fmt.Errorf("RegenerateSecret: %w", err)
	}
	if sa == nil {
		return nil, fmt.Errorf("service account not found")
	}

	// Verify tenant ownership
	if sa.TenantID != tenantID {
		return nil, fmt.Errorf("service account not found")
	}

	// Generate new secret
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}
	clientSecret := "hxs_" + base64.URLEncoding.EncodeToString(secretBytes)

	// Hash the new secret
	secretHash, err := crypto.HashPassword(clientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to hash client secret: %w", err)
	}

	// Update the secret
	if err := s.repo.UpdateSecret(ctx, saID, secretHash); err != nil {
		return nil, fmt.Errorf("RegenerateSecret: %w", err)
	}

	// Revoke all existing tokens
	if err := s.repo.RevokeAllTokens(ctx, saID); err != nil {
		logger.Error("Failed to revoke tokens after secret regeneration",
			zap.String("service_account_id", saID.String()),
			zap.Error(err),
		)
	}

	logger.Info("Service account secret regenerated",
		zap.String("service_account_id", saID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	response := &models.ServiceAccountCreatedResponse{
		ServiceAccountResponse: *sa.ToResponse(),
		ClientSecret:           clientSecret,
	}

	return response, nil
}

// Authenticate authenticates a service account using client_credentials grant.
//
// Failure surfaces (post-2026-05-21):
//   - unknown client_id              → "authentication failed" (no audit)
//   - wrong client_secret            → "authentication failed" (no audit)
//   - client_id + secret OK, account deactivated
//                                    → "authentication failed" + structured warn
//   - IP not on allow-list           → "IP address not allowed"
//
// SECURITY INVARIANT: the deactivated-account audit signal fires ONLY
// after a successful secret-hash verification. An attacker probing
// client_ids without the matching secret gets the same generic
// "authentication failed" response whether or not the client_id maps
// to a deactivated row — no client_id-oracle leak. The audit log
// distinguishes the cases for the SOC.
func (s *ServiceAccountService) Authenticate(ctx context.Context, clientID, clientSecret, clientIP string) (*models.ServiceAccountTokenResponse, error) {
	// Look up service account by client ID
	sa, err := s.repo.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("authentication failed")
	}
	if sa == nil {
		return nil, fmt.Errorf("authentication failed")
	}

	// Verify the client secret BEFORE the state branch so a probing
	// caller without the secret cannot tell apart an unknown client_id
	// from a deactivated one.
	valid, err := crypto.VerifyPassword(clientSecret, sa.ClientSecretHash)
	if err != nil || !valid {
		return nil, fmt.Errorf("authentication failed")
	}

	// Past the hash gate — the caller has the actual client secret.
	// A deactivated-SA replay is now safe to flag for the SOC; the
	// client-facing error stays generic so the response shape is
	// identical to the no-account / wrong-secret paths.
	if !sa.IsActive {
		logger.Warn("service_account_replay.deactivated_attempted",
			zap.String("tenant_id", sa.TenantID.String()),
			zap.String("service_account_id", sa.ID.String()),
			zap.String("client_id", sa.ClientID),
			zap.String("client_ip", clientIP),
		)
		return nil, fmt.Errorf("authentication failed")
	}

	// Check IP whitelist
	if len(sa.AllowedIPs) > 0 {
		if !s.isIPAllowed(clientIP, sa.AllowedIPs) {
			return nil, fmt.Errorf("IP address not allowed")
		}
	}

	// Resolve the service account's configured roles into the permissions
	// they actually grant. Without this, platform-shared's parseUserID only
	// promotes a `scope` claim into Claims.Permissions for the
	// sub==client_id (client_credentials) shape; a service-account token has
	// sub==sa.ID != client_id, so it fell through with no permissions claim
	// at all and every RequirePermission gate rejected it.
	permissions, err := s.resolvePermissions(ctx, sa.RoleIDs)
	if err != nil {
		logger.Error("Failed to resolve service account permissions",
			zap.String("service_account_id", sa.ID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("authentication failed")
	}

	// Generate access token
	expiresAt := time.Now().Add(time.Duration(sa.TokenLifetimeMinutes) * time.Minute)

	claims := jwt.MapClaims{
		"iss":                serviceNameFalconID,
		"sub":                sa.ID.String(),
		"iat":                time.Now().Unix(),
		"nbf":                time.Now().Unix(),
		"exp":                expiresAt.Unix(),
		"tenant_id":          sa.TenantID.String(),
		"service_account_id": sa.ID.String(),
		"client_id":          sa.ClientID,
		"roles":              sa.RoleIDs,
		"permissions":        permissions,
		"type":               "service_account",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	// Store token record
	tokenRecord := &models.ServiceAccountToken{
		ServiceAccountID: sa.ID,
		TokenHash:        accessToken[:32], // Store prefix for tracking
		IPAddress:        &clientIP,
		ExpiresAt:        expiresAt,
	}
	if err := s.repo.CreateToken(ctx, tokenRecord); err != nil {
		logger.Error("Failed to store service account token record",
			zap.String("service_account_id", sa.ID.String()),
			zap.Error(err),
		)
	}

	// Update last used synchronously with a short timeout; non-fatal on error.
	updateCtx, updateCancel := context.WithTimeout(ctx, 2*time.Second)
	defer updateCancel()
	if err := s.repo.UpdateLastUsed(updateCtx, sa.ID, clientIP); err != nil {
		logger.Error("Failed to update service account last used",
			zap.String("service_account_id", sa.ID.String()),
			zap.Error(err),
		)
	}

	logger.Info("Service account authenticated",
		zap.String("service_account_id", sa.ID.String()),
		zap.String("client_id", clientID),
		zap.String("ip", clientIP),
	)

	return &models.ServiceAccountTokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   sa.TokenLifetimeMinutes * 60,
	}, nil
}

// isIPAllowed checks if the client IP is in the whitelist
func (s *ServiceAccountService) isIPAllowed(clientIP string, whitelist []string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	for _, pattern := range whitelist {
		// Try parsing as CIDR
		_, network, err := net.ParseCIDR(pattern)
		if err == nil {
			if network.Contains(ip) {
				return true
			}
			continue
		}

		// Try parsing as single IP
		patternIP := net.ParseIP(pattern)
		if patternIP != nil && ip.Equal(patternIP) {
			return true
		}
	}

	return false
}

// IsEndpointAllowed is an exported identifier.
// isEndpointAllowed checks if the endpoint is in the allowed list
func (s *ServiceAccountService) IsEndpointAllowed(endpoint string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}

	for _, pattern := range allowed {
		// Handle wildcard patterns
		if pattern == "*" {
			return true
		}

		// Handle suffix wildcards (e.g., "/api/users/*")
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(endpoint, prefix) {
				return true
			}
			continue
		}

		// Exact match
		if pattern == endpoint {
			return true
		}
	}

	return false
}

// RevokeAllTokens revokes all tokens for a service account
func (s *ServiceAccountService) RevokeAllTokens(ctx context.Context, tenantID, saID uuid.UUID) error {
	sa, err := s.repo.GetByID(ctx, saID)
	if err != nil {
		return fmt.Errorf("RevokeAllTokens: %w", err)
	}
	if sa == nil {
		return fmt.Errorf("service account not found")
	}

	// Verify tenant ownership
	if sa.TenantID != tenantID {
		return fmt.Errorf("service account not found")
	}

	if err := s.repo.RevokeAllTokens(ctx, saID); err != nil {
		return fmt.Errorf("RevokeAllTokens: %w", err)
	}

	logger.Info("All service account tokens revoked",
		zap.String("service_account_id", saID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return nil
}
