// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// emailDomainRepo is the repository interface required by EmailDomainService.
// Keeping it unexported follows the project convention of defining repo interfaces
// at the point of use inside the service package.
type emailDomainRepo interface {
	GetVerifiedByDomain(ctx context.Context, domain string) (*models.EmailDomainRegistry, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]*models.EmailDomainRegistry, error)
	Create(ctx context.Context, entry *models.EmailDomainRegistry) error
	Verify(ctx context.Context, id uuid.UUID) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.EmailDomainRegistry, error)
	UpdateAutoEnroll(ctx context.Context, id uuid.UUID, autoEnroll bool) error
}

// EmailDomainService handles business logic for the email domain registry.
// It owns domain validation, verification-token generation, and idempotency
// for the verify operation.
type EmailDomainService struct {
	repo emailDomainRepo
}

// NewEmailDomainService constructs an EmailDomainService with the supplied repo.
func NewEmailDomainService(repo emailDomainRepo) *EmailDomainService {
	return &EmailDomainService{repo: repo}
}

// ListDomains returns all domain registrations owned by the given tenant.
func (s *EmailDomainService) ListDomains(ctx context.Context, tenantID uuid.UUID) ([]*models.EmailDomainRegistry, error) {
	entries, err := s.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	return entries, nil
}

// RegisterDomain validates and persists a new email domain registration.
// A DNS-TXT verification token is generated and stored; the caller is expected
// to surface this token to the tenant admin for out-of-band DNS configuration.
// Returns an error if the domain format is invalid or the domain is already
// claimed by a verified registration.
func (s *EmailDomainService) RegisterDomain(ctx context.Context, tenantID uuid.UUID, req *models.CreateEmailDomainRequest) (*models.EmailDomainRegistry, error) {
	domain := strings.ToLower(strings.TrimSpace(req.Domain))

	if !strings.Contains(domain, ".") || len(domain) < 3 {
		return nil, fmt.Errorf("invalid domain format: %q", domain)
	}

	// Fail fast if another verified record already claims this domain.
	existing, err := s.repo.GetVerifiedByDomain(ctx, domain)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("domain already registered to another tenant")
	}

	// Generate a 32-byte cryptographically random verification token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("register domain: generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	entry := &models.EmailDomainRegistry{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Domain:             domain,
		IsVerified:         false,
		VerificationToken:  &token,
		VerificationMethod: string(models.VerificationMethodDNSTXT),
		AutoEnroll:         req.AutoEnroll,
	}

	if err := s.repo.Create(ctx, entry); err != nil {
		return nil, fmt.Errorf("register domain: %w", err)
	}

	return entry, nil
}

// VerifyDomain marks a domain registration as verified.
// The operation is idempotent: calling it on an already-verified domain is a no-op.
func (s *EmailDomainService) VerifyDomain(ctx context.Context, domainID uuid.UUID) error {
	entry, err := s.repo.GetByID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("domain not found: %w", err)
	}

	if entry == nil {
		return fmt.Errorf("domain not found")
	}

	if entry.IsVerified {
		return nil
	}

	if err := s.repo.Verify(ctx, domainID); err != nil {
		return fmt.Errorf("verify domain: %w", err)
	}

	return nil
}

// UpdateDomain updates a domain registration's auto_enroll setting.
func (s *EmailDomainService) UpdateDomain(ctx context.Context, domainID uuid.UUID, autoEnroll bool) (*models.EmailDomainRegistry, error) {
	if err := s.repo.UpdateAutoEnroll(ctx, domainID, autoEnroll); err != nil {
		return nil, fmt.Errorf("update domain: %w", err)
	}
	return s.repo.GetByID(ctx, domainID)
}

// DeleteDomain removes a domain registration.
func (s *EmailDomainService) DeleteDomain(ctx context.Context, domainID uuid.UUID) error {
	if err := s.repo.Delete(ctx, domainID); err != nil {
		return fmt.Errorf("delete domain: %w", err)
	}
	return nil
}

// GetDomain fetches a single domain registration by its ID.
func (s *EmailDomainService) GetDomain(ctx context.Context, domainID uuid.UUID) (*models.EmailDomainRegistry, error) {
	entry, err := s.repo.GetByID(ctx, domainID)
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}
	return entry, nil
}
