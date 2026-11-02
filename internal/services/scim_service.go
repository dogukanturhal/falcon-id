// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// scimServiceSCIMRepo defines the SCIM token repository methods needed by SCIMService.
type scimServiceSCIMRepo interface {
	Create(ctx context.Context, token *models.SCIMToken) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.SCIMToken, error)
	GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.SCIMToken, error)
	Update(ctx context.Context, token *models.SCIMToken) error
	Delete(ctx context.Context, id uuid.UUID) error
	Revoke(ctx context.Context, id uuid.UUID) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*models.SCIMToken, error)
	UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error
}

// scimServiceUserRepo defines the user repository methods needed by SCIMService.
type scimServiceUserRepo interface {
	List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]models.User, int64, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error)
	Create(ctx context.Context, user *models.User) error
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error)
	AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error
}

// scimServiceRoleRepo defines the role repository methods needed by SCIMService.
type scimServiceRoleRepo interface {
	List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]models.Role, int64, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error)
	Create(ctx context.Context, role *models.Role) error
	Update(ctx context.Context, role *models.Role) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// SCIMService handles SCIM provisioning operations
type SCIMService struct {
	scimRepo scimServiceSCIMRepo
	userRepo scimServiceUserRepo
	roleRepo scimServiceRoleRepo
	cfg      *config.Config

	accessTerminator accessTerminator
}

// SetAccessTerminator wires the single access-termination path run when SCIM
// deactivates or deletes a user.
func (s *SCIMService) SetAccessTerminator(t accessTerminator) {
	s.accessTerminator = t
}

// terminateIfDeactivated ends all access when a SCIM write flipped the user
// from active to inactive. userRepo.Update alone leaves live sessions, OAuth
// tokens and SSO cookies working.
func (s *SCIMService) terminateIfDeactivated(ctx context.Context, user *models.User, wasActive bool, reason string) {
	if !wasActive && user.IsActive && s.accessTerminator != nil {
		s.accessTerminator.ClearUserBlock(context.Background(), user.ID)
		return
	}
	if !wasActive || user.IsActive {
		return
	}
	s.terminateAccess(user, reason)
}

func (s *SCIMService) terminateAccess(user *models.User, reason string) {
	if s.accessTerminator == nil {
		return
	}
	// Detach: the SCIM request ctx may end before the fan-out completes.
	bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.accessTerminator.TerminateUserAccess(bgCtx, user.ID, user.TenantID, reason, nil); err != nil {
		logger.Error("SCIM: access termination incomplete",
			zap.String("user_id", user.ID.String()), zap.Error(err))
	}
}

// NewSCIMService creates a new SCIMService
func NewSCIMService(
	scimRepo scimServiceSCIMRepo,
	userRepo scimServiceUserRepo,
	roleRepo scimServiceRoleRepo,
	cfg *config.Config,
) *SCIMService {
	return &SCIMService{
		scimRepo: scimRepo,
		userRepo: userRepo,
		roleRepo: roleRepo,
		cfg:      cfg,
	}
}

// ==================== Token Management ====================

// CreateToken creates a new SCIM token
func (s *SCIMService) CreateToken(ctx context.Context, tenantID uuid.UUID, req *models.CreateSCIMTokenRequest, createdBy *uuid.UUID) (*models.SCIMTokenCreatedResponse, error) {
	// Generate token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	plainToken := "scim_" + base64.RawURLEncoding.EncodeToString(tokenBytes)

	// Hash the token
	hash := sha256.Sum256([]byte(plainToken))
	tokenHash := hex.EncodeToString(hash[:])

	// Parse expiration
	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("invalid expiration date format: %w", err)
		}
		expiresAt = &parsed
	}

	now := time.Now()
	token := &models.SCIMToken{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		TokenHash:   tokenHash,
		IsActive:    true,
		CreatedAt:   now,
		CreatedBy:   createdBy,
		ExpiresAt:   expiresAt,
	}

	if err := s.scimRepo.Create(ctx, token); err != nil {
		return nil, fmt.Errorf("CreateToken: %w", err)
	}

	return &models.SCIMTokenCreatedResponse{
		ID:          token.ID,
		TenantID:    token.TenantID,
		Name:        token.Name,
		Description: token.Description,
		Token:       plainToken, // Only returned at creation
		IsActive:    token.IsActive,
		CreatedAt:   token.CreatedAt,
		ExpiresAt:   token.ExpiresAt,
	}, nil
}

// GetToken retrieves a SCIM token by ID
func (s *SCIMService) GetToken(ctx context.Context, id uuid.UUID) (*models.SCIMToken, error) {
	return s.scimRepo.GetByID(ctx, id)
}

// ListTokens lists all SCIM tokens for a tenant
func (s *SCIMService) ListTokens(ctx context.Context, tenantID uuid.UUID) ([]*models.SCIMToken, error) {
	return s.scimRepo.GetByTenantID(ctx, tenantID)
}

// UpdateToken updates a SCIM token
func (s *SCIMService) UpdateToken(ctx context.Context, id uuid.UUID, req *models.UpdateSCIMTokenRequest) (*models.SCIMToken, error) {
	token, err := s.scimRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("UpdateToken: %w", err)
	}

	if req.Name != nil {
		token.Name = *req.Name
	}
	if req.Description != nil {
		token.Description = req.Description
	}
	if req.IsActive != nil {
		token.IsActive = *req.IsActive
	}

	if err := s.scimRepo.Update(ctx, token); err != nil {
		return nil, fmt.Errorf("UpdateToken: %w", err)
	}

	return token, nil
}

// DeleteToken deletes a SCIM token
func (s *SCIMService) DeleteToken(ctx context.Context, id uuid.UUID) error {
	return s.scimRepo.Delete(ctx, id)
}

// RevokeToken revokes a SCIM token
func (s *SCIMService) RevokeToken(ctx context.Context, id uuid.UUID) error {
	return s.scimRepo.Revoke(ctx, id)
}

// ValidateToken validates a SCIM token and returns the matching row
// when the token is currently usable, or an error describing the
// specific failure mode.
//
// Failure modes (post-2026-05-21):
//   - token not found             → "token not found"          (unknown hash)
//   - token revoked (!IsActive)   → "token is revoked"          + structured warn
//   - token expired               → "token is expired"          + structured warn
//
// Pre-2026-05-21 the repo's WHERE clause filtered on `is_active=true`,
// collapsing the "revoked replay attempt" path into the "unknown hash"
// path — every replay against a recently-rotated token looked
// identical to a typo'd / brute-forced hash. The repo no longer
// filters, so this method is now where the audit-trail divergence
// happens.
//
// The structured warns carry tenant_id + token_id so the SOC can
// pivot on "someone is replaying a recently-revoked token" — a strong
// signal of credential theft.
func (s *SCIMService) ValidateToken(ctx context.Context, bearerToken string) (*models.SCIMToken, error) {
	// Hash the token to look it up
	hash := sha256.Sum256([]byte(bearerToken))
	tokenHash := hex.EncodeToString(hash[:])

	token, err := s.scimRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("ValidateToken: %w", err)
	}

	if token == nil {
		return nil, fmt.Errorf("ValidateToken: token not found")
	}

	// Revoked replay — the most security-actionable signal here.
	if !token.IsActive {
		if logger.Log != nil {
			logger.Log.Warn("scim_token_replay.revoked_attempted",
				zap.String("tenant_id", token.TenantID.String()),
				zap.String("token_id", token.ID.String()),
			)
		}
		return nil, fmt.Errorf("ValidateToken: token is revoked")
	}

	// Expired replay — separate audit dimension. An attacker holding
	// an expired token is less of a "someone just leaked our key"
	// signal than a revoked replay, but still worth recording.
	if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
		if logger.Log != nil {
			logger.Log.Warn("scim_token_replay.expired_attempted",
				zap.String("tenant_id", token.TenantID.String()),
				zap.String("token_id", token.ID.String()),
				zap.Time("expired_at", *token.ExpiresAt),
			)
		}
		return nil, fmt.Errorf("ValidateToken: token is expired")
	}

	return token, nil
}

// UpdateTokenUsage updates the last used timestamp
func (s *SCIMService) UpdateTokenUsage(ctx context.Context, id uuid.UUID, ip string) {
	_ = s.scimRepo.UpdateLastUsed(ctx, id, ip)
}

// ==================== SCIM User Operations ====================

// ListUsers lists users in SCIM format
func (s *SCIMService) ListUsers(ctx context.Context, tenantID uuid.UUID, startIndex, count int, filter string) (*models.SCIMListResponse, error) {
	// Get all users for the tenant (using large page size to get all)
	userList, _, err := s.userRepo.List(ctx, tenantID, 1, 10000, "")
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Convert to pointer slice
	users := make([]*models.User, len(userList))
	for i := range userList {
		users[i] = &userList[i]
	}

	// Apply filter if provided
	filteredUsers := users
	if filter != "" {
		filteredUsers = s.filterUsers(users, filter)
	}

	// Apply pagination
	total := len(filteredUsers)
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 {
		count = 100
	}

	start := startIndex - 1 // SCIM is 1-indexed
	if start >= total {
		start = total
	}
	end := start + count
	if end > total {
		end = total
	}

	pagedUsers := filteredUsers[start:end]

	// Convert to SCIM format
	baseURL := s.getBaseURL()
	resources := make([]models.SCIMUser, 0, len(pagedUsers))
	for _, user := range pagedUsers {
		resources = append(resources, *user.ToSCIMUser(baseURL))
	}

	return &models.SCIMListResponse{
		Schemas:      []string{models.SCIMSchemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}, nil
}

// ValidateUserTenant verifies that a user belongs to the specified tenant
func (s *SCIMService) ValidateUserTenant(ctx context.Context, userID, tenantID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return fmt.Errorf("user not found")
	}
	if user.TenantID != tenantID {
		return fmt.Errorf("user not found")
	}
	return nil
}

// ValidateGroupTenant verifies that a group (role) belongs to the specified tenant
func (s *SCIMService) ValidateGroupTenant(ctx context.Context, groupID, tenantID uuid.UUID) error {
	role, err := s.roleRepo.GetByID(ctx, groupID)
	if err != nil || role == nil {
		return fmt.Errorf("group not found")
	}
	if role.TenantID != tenantID {
		return fmt.Errorf("group not found")
	}
	return nil
}

// GetUser gets a user in SCIM format
func (s *SCIMService) GetUser(ctx context.Context, userID uuid.UUID) (*models.SCIMUser, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("GetUser: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("GetUser: user not found")
	}

	return user.ToSCIMUser(s.getBaseURL()), nil
}

// CreateUser creates a user from SCIM data
func (s *SCIMService) CreateUser(ctx context.Context, tenantID uuid.UUID, scimUser *models.SCIMUser) (*models.SCIMUser, error) {
	// Extract email
	var email string
	for _, e := range scimUser.Emails {
		if e.Primary || email == "" {
			email = e.Value
		}
	}
	if email == "" && len(scimUser.Emails) > 0 {
		email = scimUser.Emails[0].Value
	}

	// Create user
	user := &models.User{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Username:  scimUser.UserName,
		Email:     email,
		IsActive:  scimUser.Active,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Set name fields
	if scimUser.Name != nil {
		if scimUser.Name.GivenName != "" {
			user.FirstName = &scimUser.Name.GivenName
		}
		if scimUser.Name.FamilyName != "" {
			user.LastName = &scimUser.Name.FamilyName
		}
	}

	// Set display name
	if scimUser.DisplayName != "" {
		user.DisplayName = &scimUser.DisplayName
	}

	// Set phone
	if len(scimUser.PhoneNumbers) > 0 {
		phone := scimUser.PhoneNumbers[0].Value
		user.Phone = &phone
	}

	// Set title
	if scimUser.Title != "" {
		user.Title = &scimUser.Title
	}

	// Set department from enterprise extension
	if scimUser.EnterpriseUser != nil && scimUser.EnterpriseUser.Department != "" {
		user.Department = &scimUser.EnterpriseUser.Department
	}

	// Set password if provided
	if scimUser.Password != "" {
		hashedPassword, err := crypto.HashPassword(scimUser.Password, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		user.PasswordHash = &hashedPassword
	}

	// Set federation type
	federationType := "scim"
	user.FederationType = &federationType

	// Create in database
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user.ToSCIMUser(s.getBaseURL()), nil
}

// UpdateUser updates a user from SCIM data
func (s *SCIMService) UpdateUser(ctx context.Context, userID uuid.UUID, scimUser *models.SCIMUser) (*models.SCIMUser, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("UpdateUser: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("UpdateUser: user not found")
	}
	wasActive := user.IsActive

	// Update fields
	if scimUser.UserName != "" {
		user.Username = scimUser.UserName
	}

	// Update email
	if len(scimUser.Emails) > 0 {
		for _, e := range scimUser.Emails {
			if e.Primary {
				user.Email = e.Value
				break
			}
		}
		if user.Email == "" {
			user.Email = scimUser.Emails[0].Value
		}
	}

	// Update name
	if scimUser.Name != nil {
		if scimUser.Name.GivenName != "" {
			user.FirstName = &scimUser.Name.GivenName
		}
		if scimUser.Name.FamilyName != "" {
			user.LastName = &scimUser.Name.FamilyName
		}
	}

	// Update display name
	if scimUser.DisplayName != "" {
		user.DisplayName = &scimUser.DisplayName
	}

	// Update phone
	if len(scimUser.PhoneNumbers) > 0 {
		phone := scimUser.PhoneNumbers[0].Value
		user.Phone = &phone
	}

	// Update title
	if scimUser.Title != "" {
		user.Title = &scimUser.Title
	}

	// Update department
	if scimUser.EnterpriseUser != nil && scimUser.EnterpriseUser.Department != "" {
		user.Department = &scimUser.EnterpriseUser.Department
	}

	// Update active status
	user.IsActive = scimUser.Active

	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}
	s.terminateIfDeactivated(ctx, user, wasActive, "scim_deactivate")

	return user.ToSCIMUser(s.getBaseURL()), nil
}

// PatchUser applies patch operations to a user
func (s *SCIMService) PatchUser(ctx context.Context, userID uuid.UUID, patchOp *models.SCIMPatchOp) (*models.SCIMUser, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("PatchUser: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("PatchUser: user not found")
	}
	wasActive := user.IsActive

	for _, op := range patchOp.Operations {
		switch strings.ToLower(op.Op) {
		case "replace":
			s.applyUserPatchReplace(user, op.Path, op.Value)
		case "add":
			s.applyUserPatchAdd(user, op.Path, op.Value)
		case "remove":
			s.applyUserPatchRemove(user, op.Path)
		}
	}

	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}
	s.terminateIfDeactivated(ctx, user, wasActive, "scim_deactivate")

	return user.ToSCIMUser(s.getBaseURL()), nil
}

// DeleteUser deletes a user
func (s *SCIMService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	user, _ := s.userRepo.GetByID(ctx, userID) // best-effort: only needed for the tenant id
	if err := s.userRepo.Delete(ctx, userID); err != nil {
		return err
	}
	if user != nil {
		s.terminateAccess(user, "scim_delete")
	}
	return nil
}

// ==================== SCIM Group Operations ====================

// ListGroups lists groups (roles) in SCIM format
func (s *SCIMService) ListGroups(ctx context.Context, tenantID uuid.UUID, startIndex, count int, filter string) (*models.SCIMListResponse, error) {
	// Get all roles for the tenant (using large page size to get all)
	roleList, _, err := s.roleRepo.List(ctx, tenantID, 1, 10000, "")
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	// Convert to pointer slice
	roles := make([]*models.Role, len(roleList))
	for i := range roleList {
		roles[i] = &roleList[i]
	}

	// Apply filter if provided
	filteredRoles := roles
	if filter != "" {
		filteredRoles = s.filterGroups(roles, filter)
	}

	// Apply pagination
	total := len(filteredRoles)
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 {
		count = 100
	}

	start := startIndex - 1
	if start >= total {
		start = total
	}
	end := start + count
	if end > total {
		end = total
	}

	pagedRoles := filteredRoles[start:end]

	// Convert to SCIM format
	baseURL := s.getBaseURL()
	resources := make([]models.SCIMGroup, 0, len(pagedRoles))
	for _, role := range pagedRoles {
		resources = append(resources, *role.ToSCIMGroup(baseURL))
	}

	return &models.SCIMListResponse{
		Schemas:      []string{models.SCIMSchemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}, nil
}

// GetGroup gets a group (role) in SCIM format
func (s *SCIMService) GetGroup(ctx context.Context, groupID uuid.UUID) (*models.SCIMGroup, error) {
	role, err := s.roleRepo.GetByID(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("GetGroup: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("GetGroup: group not found")
	}

	group := role.ToSCIMGroup(s.getBaseURL())
	// Note: Group members are not included in the basic response
	// Full member listing would require a separate query

	return group, nil
}

// CreateGroup creates a group from SCIM data
func (s *SCIMService) CreateGroup(ctx context.Context, tenantID uuid.UUID, scimGroup *models.SCIMGroup) (*models.SCIMGroup, error) {
	now := time.Now()
	role := &models.Role{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        strings.ToLower(strings.ReplaceAll(scimGroup.DisplayName, " ", "_")),
		DisplayName: scimGroup.DisplayName,
		IsSystem:    false,
		IsDefault:   false,
		Priority:    0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.roleRepo.Create(ctx, role); err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	return role.ToSCIMGroup(s.getBaseURL()), nil
}

// UpdateGroup updates a group from SCIM data
func (s *SCIMService) UpdateGroup(ctx context.Context, groupID uuid.UUID, scimGroup *models.SCIMGroup) (*models.SCIMGroup, error) {
	role, err := s.roleRepo.GetByID(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("UpdateGroup: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("UpdateGroup: group not found")
	}

	if scimGroup.DisplayName != "" {
		role.DisplayName = scimGroup.DisplayName
	}

	role.UpdatedAt = time.Now()

	if err := s.roleRepo.Update(ctx, role); err != nil {
		return nil, fmt.Errorf("failed to update group: %w", err)
	}

	return role.ToSCIMGroup(s.getBaseURL()), nil
}

// PatchGroup applies patch operations to a group
func (s *SCIMService) PatchGroup(ctx context.Context, groupID uuid.UUID, patchOp *models.SCIMPatchOp) (*models.SCIMGroup, error) {
	role, err := s.roleRepo.GetByID(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("PatchGroup: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("PatchGroup: group not found")
	}

	for _, op := range patchOp.Operations {
		switch strings.ToLower(op.Op) {
		case "replace":
			if op.Path == "displayName" {
				if str, ok := op.Value.(string); ok {
					role.DisplayName = str
				}
			}
		case "add":
			if op.Path == "members" || strings.HasPrefix(op.Path, "members") {
				s.addGroupMembers(ctx, groupID, op.Value)
			}
		case "remove":
			if strings.HasPrefix(op.Path, "members") {
				s.removeGroupMembers(ctx, groupID, op.Path)
			}
		}
	}

	role.UpdatedAt = time.Now()

	if err := s.roleRepo.Update(ctx, role); err != nil {
		return nil, fmt.Errorf("failed to update group: %w", err)
	}

	return s.GetGroup(ctx, groupID)
}

// DeleteGroup deletes a group
func (s *SCIMService) DeleteGroup(ctx context.Context, groupID uuid.UUID) error {
	return s.roleRepo.Delete(ctx, groupID)
}

// SCIM discovery, resource types, schemas, filter helpers,
// and patch operation helpers are in scim_service_discovery.go
