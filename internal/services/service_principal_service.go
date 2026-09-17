// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// Compile-time proof that ServicePrincipalService satisfies the
// middleware.ServicePrincipalUsageRecorder interface without importing the
// middleware package (avoids a circular import).
// The interface is declared in middleware/service_auth.go; we verify structural
// compatibility here by declaring an equivalent local interface.
var _ interface {
	RecordServicePrincipalUsage(ctx context.Context, slug string, ip string, at time.Time) error
} = (*ServicePrincipalService)(nil)

// servicePrincipalRepository defines the repository interface for service principals.
type servicePrincipalRepository interface {
	Create(ctx context.Context, sp *models.ServicePrincipal) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ServicePrincipal, error)
	GetBySlug(ctx context.Context, slug string) (*models.ServicePrincipal, error)
	GetByKeyID(ctx context.Context, keyID string) (*models.ServicePrincipal, error)
	List(ctx context.Context) ([]models.ServicePrincipal, error)
	Update(ctx context.Context, sp *models.ServicePrincipal) error
	RotateKey(ctx context.Context, id uuid.UUID, publicKeyPEM, keyID string) error
	UpdateLastAuthenticated(ctx context.Context, id uuid.UUID) error
	Delete(ctx context.Context, id uuid.UUID) error
	RegisterEndpoints(ctx context.Context, spID uuid.UUID, endpoints []models.ServiceEndpoint) error
	RegisterEvents(ctx context.Context, spID uuid.UUID, events []models.ServiceEvent) error
}

// ServicePrincipalService manages service principal lifecycle.
type ServicePrincipalService struct {
	repo servicePrincipalRepository
}

// NewServicePrincipalService creates a new ServicePrincipalService.
func NewServicePrincipalService(repo servicePrincipalRepository) *ServicePrincipalService {
	return &ServicePrincipalService{repo: repo}
}

// CreateServicePrincipalResult holds the result of creating a service principal.
type CreateServicePrincipalResult struct {
	ServicePrincipal *models.ServicePrincipal
	PrivateKeyPEM    string // Returned only at creation time
}

// Create creates a new service principal with a generated RSA key pair.
func (s *ServicePrincipalService) Create(ctx context.Context, req *models.CreateServicePrincipalRequest) (*CreateServicePrincipalResult, error) {
	// Generate RSA key pair for this service
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Marshal public key to PEM
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// Compute key ID
	hash := sha256.Sum256(pubDER)
	keyID := base64.RawURLEncoding.EncodeToString(hash[:12])

	// Marshal private key to PEM (returned to caller, not stored)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	now := time.Now()
	sp := &models.ServicePrincipal{
		ID:            uuid.New(),
		ProductID:     req.ProductID,
		Name:          req.Name,
		Slug:          req.Slug,
		Description:   req.Description,
		PublicKeyPEM:  string(pubPEM),
		KeyID:         keyID,
		AllowedScopes: req.AllowedScopes,
		IPAllowlist:   req.IPAllowlist,
		Status:        provisioningStateActive,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if sp.AllowedScopes == nil {
		sp.AllowedScopes = []string{}
	}
	if sp.IPAllowlist == nil {
		sp.IPAllowlist = []string{}
	}

	if err := s.repo.Create(ctx, sp); err != nil {
		return nil, fmt.Errorf("failed to create service principal: %w", err)
	}

	logger.Info("Service principal created",
		zap.String("slug", sp.Slug),
		zap.String("key_id", sp.KeyID),
	)

	return &CreateServicePrincipalResult{
		ServicePrincipal: sp,
		PrivateKeyPEM:    string(privPEM),
	}, nil
}

// GetByID retrieves a service principal by ID.
func (s *ServicePrincipalService) GetByID(ctx context.Context, id uuid.UUID) (*models.ServicePrincipal, error) {
	return s.repo.GetByID(ctx, id)
}

// GetBySlug retrieves a service principal by slug.
func (s *ServicePrincipalService) GetBySlug(ctx context.Context, slug string) (*models.ServicePrincipal, error) {
	return s.repo.GetBySlug(ctx, slug)
}

// GetByKeyID retrieves a service principal by key ID (for JWT validation).
func (s *ServicePrincipalService) GetByKeyID(ctx context.Context, keyID string) (*models.ServicePrincipal, error) {
	return s.repo.GetByKeyID(ctx, keyID)
}

// List lists all service principals.
func (s *ServicePrincipalService) List(ctx context.Context) ([]models.ServicePrincipal, error) {
	return s.repo.List(ctx)
}

// Update updates a service principal.
func (s *ServicePrincipalService) Update(ctx context.Context, id uuid.UUID, req *models.UpdateServicePrincipalRequest) (*models.ServicePrincipal, error) {
	sp, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.Name != nil {
		sp.Name = *req.Name
	}
	if req.Description != nil {
		sp.Description = *req.Description
	}
	if req.AllowedScopes != nil {
		sp.AllowedScopes = req.AllowedScopes
	}
	if req.IPAllowlist != nil {
		sp.IPAllowlist = req.IPAllowlist
	}
	if req.Status != nil {
		sp.Status = *req.Status
	}

	if err := s.repo.Update(ctx, sp); err != nil {
		return nil, err
	}

	return sp, nil
}

// RotateKey generates a new RSA key pair for a service principal.
func (s *ServicePrincipalService) RotateKey(ctx context.Context, id uuid.UUID) (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate new RSA key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	hash := sha256.Sum256(pubDER)
	keyID := base64.RawURLEncoding.EncodeToString(hash[:12])

	if err := s.repo.RotateKey(ctx, id, string(pubPEM), keyID); err != nil {
		return "", err
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	logger.Info("Service principal key rotated",
		zap.String("id", id.String()),
		zap.String("new_key_id", keyID),
	)

	return string(privPEM), nil
}

// Delete deletes a service principal.
func (s *ServicePrincipalService) Delete(ctx context.Context, id uuid.UUID) error {
	return s.repo.Delete(ctx, id)
}

// RegisterManifest registers a service's endpoints and events.
func (s *ServicePrincipalService) RegisterManifest(ctx context.Context, spID uuid.UUID, manifest *models.RegisterServiceManifest) error {
	if err := s.repo.RegisterEndpoints(ctx, spID, manifest.Endpoints); err != nil {
		return err
	}
	if err := s.repo.RegisterEvents(ctx, spID, manifest.Events); err != nil {
		return err
	}
	return nil
}

// UpdateLastAuthenticated records the last authentication time for a service principal.
func (s *ServicePrincipalService) UpdateLastAuthenticated(ctx context.Context, id uuid.UUID) error {
	return s.repo.UpdateLastAuthenticated(ctx, id)
}

// RecordServicePrincipalUsage satisfies middleware.ServicePrincipalUsageRecorder.
// It looks up the principal by slug and then persists last_authenticated_at.
// The ip and at parameters are informational; the repository currently records
// only the timestamp (extending it to store IP is a future migration concern).
func (s *ServicePrincipalService) RecordServicePrincipalUsage(ctx context.Context, slug string, _ string, _ time.Time) error {
	sp, err := s.repo.GetBySlug(ctx, slug)
	if err != nil {
		return fmt.Errorf("RecordServicePrincipalUsage: lookup %q: %w", slug, err)
	}
	return s.repo.UpdateLastAuthenticated(ctx, sp.ID)
}
