// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// passwordPolicyServiceRepo defines the repository methods needed by PasswordPolicyService.
type passwordPolicyServiceRepo interface {
	GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*models.PasswordPolicy, error)
	Upsert(ctx context.Context, policy *models.PasswordPolicy) error
	IsCommonPassword(ctx context.Context, passwordHash string) (bool, error)
	GetPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]models.PasswordHistory, error)
	AddPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error
}

// PasswordPolicyService is an exported type.
type PasswordPolicyService struct {
	policyRepo passwordPolicyServiceRepo
}

// NewPasswordPolicyService is an exported function.
func NewPasswordPolicyService(policyRepo passwordPolicyServiceRepo) *PasswordPolicyService {
	return &PasswordPolicyService{
		policyRepo: policyRepo,
	}
}

// GetPolicy retrieves the password policy for a tenant
func (s *PasswordPolicyService) GetPolicy(ctx context.Context, tenantID uuid.UUID) (*models.PasswordPolicy, error) {
	policy, err := s.policyRepo.GetByTenantID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get password policy: %w", err)
	}

	// Return default policy if none exists
	if policy == nil {
		return models.DefaultPasswordPolicy(tenantID), nil
	}

	return policy, nil
}

// UpdatePolicy updates or creates a password policy for a tenant
func (s *PasswordPolicyService) UpdatePolicy(ctx context.Context, tenantID uuid.UUID, req *models.PasswordPolicyRequest, userID uuid.UUID) (*models.PasswordPolicy, error) {
	// Get existing policy or create default
	policy, err := s.policyRepo.GetByTenantID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get password policy: %w", err)
	}

	if policy == nil {
		policy = models.DefaultPasswordPolicy(tenantID)
		policy.CreatedBy = &userID
	}
	policy.UpdatedBy = &userID

	if err := applyPasswordPolicyRequest(req, policy); err != nil {
		return nil, err
	}

	// Upsert the policy
	if err := s.policyRepo.Upsert(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to save password policy: %w", err)
	}

	logger.Info("Password policy updated",
		zap.String("tenant_id", tenantID.String()),
		zap.String("updated_by", userID.String()),
	)

	return policy, nil
}

// applyPasswordPolicyRequest applies all non-nil fields from the request to the policy.
func applyPasswordPolicyRequest(req *models.PasswordPolicyRequest, policy *models.PasswordPolicy) error {
	if req.MinLength != nil {
		if *req.MinLength < 6 {
			return fmt.Errorf("minimum password length cannot be less than 6")
		}
		if *req.MinLength > 128 {
			return fmt.Errorf("minimum password length cannot exceed 128")
		}
		policy.MinLength = *req.MinLength
	}
	if req.MaxLength != nil {
		if *req.MaxLength < policy.MinLength {
			return fmt.Errorf("maximum length cannot be less than minimum length")
		}
		policy.MaxLength = req.MaxLength
	}
	applyPasswordPolicyBoolFields(req, policy)
	return applyPasswordPolicyNumericFields(req, policy)
}

// applyPasswordPolicyBoolFields applies boolean fields from the request.
func applyPasswordPolicyBoolFields(req *models.PasswordPolicyRequest, policy *models.PasswordPolicy) {
	if req.RequireUppercase != nil {
		policy.RequireUppercase = *req.RequireUppercase
	}
	if req.RequireLowercase != nil {
		policy.RequireLowercase = *req.RequireLowercase
	}
	if req.RequireNumbers != nil {
		policy.RequireNumbers = *req.RequireNumbers
	}
	if req.RequireSpecial != nil {
		policy.RequireSpecial = *req.RequireSpecial
	}
	if req.DisallowUsername != nil {
		policy.DisallowUsername = *req.DisallowUsername
	}
	if req.DisallowCommonPasswords != nil {
		policy.DisallowCommonPasswords = *req.DisallowCommonPasswords
	}
	if req.RequirePasswordChangeOnFirstLogin != nil {
		policy.RequirePasswordChangeOnFirstLogin = *req.RequirePasswordChangeOnFirstLogin
	}
}

// applyPasswordPolicyNumericFields applies numeric fields from the request with validation.
func applyPasswordPolicyNumericFields(req *models.PasswordPolicyRequest, policy *models.PasswordPolicy) error {
	if req.MaxAgeDays != nil {
		if *req.MaxAgeDays < 0 {
			return fmt.Errorf("max age days cannot be negative")
		}
		policy.MaxAgeDays = *req.MaxAgeDays
	}
	if req.WarningDaysBeforeExpiry != nil {
		if *req.WarningDaysBeforeExpiry < 0 {
			return fmt.Errorf("warning days cannot be negative")
		}
		policy.WarningDaysBeforeExpiry = *req.WarningDaysBeforeExpiry
	}
	if req.HistoryCount != nil {
		if *req.HistoryCount < 0 || *req.HistoryCount > 24 {
			return fmt.Errorf("history count must be between 0 and 24")
		}
		policy.HistoryCount = *req.HistoryCount
	}
	if req.LockoutThreshold != nil {
		if *req.LockoutThreshold < 1 || *req.LockoutThreshold > 20 {
			return fmt.Errorf("lockout threshold must be between 1 and 20")
		}
		policy.LockoutThreshold = *req.LockoutThreshold
	}
	if req.LockoutDurationMinutes != nil {
		if *req.LockoutDurationMinutes < 1 || *req.LockoutDurationMinutes > 1440 {
			return fmt.Errorf("lockout duration must be between 1 and 1440 minutes")
		}
		policy.LockoutDurationMinutes = *req.LockoutDurationMinutes
	}
	if req.LockoutIncrementFactor != nil {
		if *req.LockoutIncrementFactor < 1.0 || *req.LockoutIncrementFactor > 5.0 {
			return fmt.Errorf("lockout increment factor must be between 1.0 and 5.0")
		}
		policy.LockoutIncrementFactor = *req.LockoutIncrementFactor
	}
	return nil
}

// ValidatePassword validates a password against the policy
func (s *PasswordPolicyService) ValidatePassword(ctx context.Context, tenantID uuid.UUID, password string, username string, userID *uuid.UUID) error {
	policy, err := s.GetPolicy(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("ValidatePassword: GetPolicy failed: %w", err)
	}

	return s.ValidatePasswordAgainstPolicy(ctx, password, username, userID, policy)
}

// ValidatePasswordAgainstPolicy validates a password against a specific policy
func (s *PasswordPolicyService) ValidatePasswordAgainstPolicy(ctx context.Context, password string, username string, userID *uuid.UUID, policy *models.PasswordPolicy) error {
	if len(password) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters", policy.MinLength)
	}
	if policy.MaxLength != nil && len(password) > *policy.MaxLength {
		return fmt.Errorf("password cannot exceed %d characters", *policy.MaxLength)
	}
	if err := validatePasswordComplexity(password, username, policy); err != nil {
		return err
	}
	if err := s.validatePasswordCommonAndHistory(ctx, password, userID, policy); err != nil {
		return err
	}
	return nil
}

// validatePasswordComplexity checks character type requirements and username restriction.
func validatePasswordComplexity(password, username string, policy *models.PasswordPolicy) error {
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}
	if policy.RequireUppercase && !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if policy.RequireLowercase && !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if policy.RequireNumbers && !hasDigit {
		return fmt.Errorf("password must contain at least one number")
	}
	if policy.RequireSpecial && !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}
	if policy.DisallowUsername && username != "" {
		if strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
			return fmt.Errorf("password cannot contain your username")
		}
	}
	return nil
}

// validatePasswordCommonAndHistory checks against common passwords and password history.
func (s *PasswordPolicyService) validatePasswordCommonAndHistory(ctx context.Context, password string, userID *uuid.UUID, policy *models.PasswordPolicy) error {
	if policy.DisallowCommonPasswords {
		passwordSHA := sha256.Sum256([]byte(password))
		passwordHash := hex.EncodeToString(passwordSHA[:])
		isCommon, err := s.policyRepo.IsCommonPassword(ctx, passwordHash)
		if err != nil {
			logger.Error("Failed to check common passwords", zap.Error(err))
		} else if isCommon {
			return fmt.Errorf("password is too common, please choose a different password")
		}
	}
	if userID != nil && policy.HistoryCount > 0 {
		if err := s.checkPasswordHistory(ctx, *userID, password, policy.HistoryCount); err != nil {
			return err
		}
	}
	return nil
}

// AddToPasswordHistory adds a password hash to the user's history
func (s *PasswordPolicyService) AddToPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	return s.policyRepo.AddPasswordHistory(ctx, userID, passwordHash)
}

// checkPasswordHistory verifies the new password was not used in the user's recent history.
func (s *PasswordPolicyService) checkPasswordHistory(ctx context.Context, userID uuid.UUID, password string, historyCount int) error {
	if _, err := crypto.HashPassword(password, nil); err != nil {
		return fmt.Errorf("failed to process password: %w", err)
	}
	history, err := s.policyRepo.GetPasswordHistory(ctx, userID, historyCount)
	if err != nil {
		logger.Error("Failed to get password history", zap.Error(err))
		return nil //nolint:nilerr // history check is best-effort
	}
	for _, h := range history {
		valid, verifyErr := crypto.VerifyPassword(password, h.PasswordHash)
		if verifyErr == nil && valid {
			return fmt.Errorf("password has been used recently, please choose a different password")
		}
	}
	return nil
}

// GetLockoutSettings returns the lockout configuration for a tenant
func (s *PasswordPolicyService) GetLockoutSettings(ctx context.Context, tenantID uuid.UUID) (threshold int, durationMinutes int, incrementFactor float64, err error) {
	policy, err := s.GetPolicy(ctx, tenantID)
	if err != nil {
		return 5, 30, 1.0, err // Return defaults on error
	}
	return policy.LockoutThreshold, policy.LockoutDurationMinutes, policy.LockoutIncrementFactor, nil
}
