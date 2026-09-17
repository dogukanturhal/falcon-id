// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 used only for X.509 thumbprint compatibility (RFC 4517), not for security hashing
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// spCredentialRepo defines the credential repository methods.
type spCredentialRepo interface {
	Create(ctx context.Context, cred *models.SPCredential) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.SPCredential, error)
	ListBySP(ctx context.Context, spID uuid.UUID) ([]models.SPCredential, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	CleanupExpired(ctx context.Context) (int64, error)
	DeleteBySP(ctx context.Context, spID uuid.UUID) error
	ListExpiringSoon(ctx context.Context, withinDays int) ([]models.SPCredential, error)
	RecordUsage(ctx context.Context, credID uuid.UUID) error
	ListUnused(ctx context.Context, unusedDays int) ([]models.SPCredential, error)
}

// credentialPolicyValidator validates credential expiry against policies.
type credentialPolicyValidator interface {
	ValidateCredentialExpiry(ctx context.Context, tenantID uuid.UUID, credType models.SPCredentialType, expiresAt *time.Time) error
}

// SPCredentialService manages SP credential lifecycle.
type SPCredentialService struct {
	credRepo        spCredentialRepo
	policyValidator credentialPolicyValidator
}

// NewSPCredentialService creates a new SPCredentialService.
func NewSPCredentialService(credRepo spCredentialRepo) *SPCredentialService {
	return &SPCredentialService{credRepo: credRepo}
}

// SetCredentialPolicyValidator sets the credential policy validator for expiry enforcement.
func (s *SPCredentialService) SetCredentialPolicyValidator(v credentialPolicyValidator) {
	s.policyValidator = v
}

// AddRSAKeyCredential generates an RSA keypair, stores the public key, and returns the private key (shown once).
// If a credential policy validator is configured and tenantID is non-nil, the expiry is validated.
func (s *SPCredentialService) AddRSAKeyCredential(ctx context.Context, spID uuid.UUID, expiresAt *time.Time, tenantID ...uuid.UUID) (*models.SPCredential, string, error) {
	if s.policyValidator != nil && len(tenantID) > 0 {
		if err := s.policyValidator.ValidateCredentialExpiry(ctx, tenantID[0], models.SPCredentialTypeRSAKey, expiresAt); err != nil {
			return nil, "", fmt.Errorf("SPCredentialService.AddRSAKeyCredential: policy violation: %w", err)
		}
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("SPCredentialService.AddRSAKeyCredential: keygen failed: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("SPCredentialService.AddRSAKeyCredential: marshal pubkey: %w", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	hash := sha256.Sum256(pubDER)
	keyID := base64.RawURLEncoding.EncodeToString(hash[:12])

	privPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}))

	cred := &models.SPCredential{
		ID:             uuid.New(),
		SPID:           spID,
		CredentialType: models.SPCredentialTypeRSAKey,
		KeyID:          &keyID,
		PublicKeyPEM:   &pubPEM,
		Status:         models.SPCredentialStatusActive,
		ExpiresAt:      expiresAt,
		CreatedAt:      time.Now(),
	}

	if err := s.credRepo.Create(ctx, cred); err != nil {
		return nil, "", fmt.Errorf("SPCredentialService.AddRSAKeyCredential: %w", err)
	}

	return cred, privPEM, nil
}

// AddSecretCredential generates a client secret, hashes it, and returns the plain secret (shown once).
// If a credential policy validator is configured and tenantID is non-nil, the expiry is validated.
func (s *SPCredentialService) AddSecretCredential(ctx context.Context, spID uuid.UUID, expiresAt *time.Time, tenantID ...uuid.UUID) (*models.SPCredential, string, error) {
	if s.policyValidator != nil && len(tenantID) > 0 {
		if err := s.policyValidator.ValidateCredentialExpiry(ctx, tenantID[0], models.SPCredentialTypeClientSecret, expiresAt); err != nil {
			return nil, "", fmt.Errorf("SPCredentialService.AddSecretCredential: policy violation: %w", err)
		}
	}
	// Generate random secret
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, "", fmt.Errorf("SPCredentialService.AddSecretCredential: rand failed: %w", err)
	}
	plainSecret := hex.EncodeToString(b)

	// Hash for storage
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("SPCredentialService.AddSecretCredential: hash failed: %w", err)
	}
	secretHash := string(hashBytes)

	// Display hint: last 4 chars
	hint := plainSecret[len(plainSecret)-4:]

	cred := &models.SPCredential{
		ID:             uuid.New(),
		SPID:           spID,
		CredentialType: models.SPCredentialTypeClientSecret,
		SecretHash:     &secretHash,
		DisplayHint:    &hint,
		Status:         models.SPCredentialStatusActive,
		ExpiresAt:      expiresAt,
		CreatedAt:      time.Now(),
	}

	if err := s.credRepo.Create(ctx, cred); err != nil {
		return nil, "", fmt.Errorf("SPCredentialService.AddSecretCredential: %w", err)
	}

	return cred, plainSecret, nil
}

// RevokeCredential soft-revokes a credential.
func (s *SPCredentialService) RevokeCredential(ctx context.Context, id uuid.UUID) error {
	cred, err := s.credRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("SPCredentialService.RevokeCredential: not found: %w", err)
	}
	if cred.Status != models.SPCredentialStatusActive {
		return fmt.Errorf("SPCredentialService.RevokeCredential: credential is already %s", cred.Status)
	}

	if err := s.credRepo.Revoke(ctx, id); err != nil {
		return fmt.Errorf("SPCredentialService.RevokeCredential: %w", err)
	}
	return nil
}

// ListCredentials returns active credentials for an SP.
func (s *SPCredentialService) ListCredentials(ctx context.Context, spID uuid.UUID) ([]models.SPCredential, error) {
	creds, err := s.credRepo.ListBySP(ctx, spID)
	if err != nil {
		return nil, fmt.Errorf("SPCredentialService.ListCredentials: %w", err)
	}
	return creds, nil
}

// CleanupExpired marks expired credentials. Returns count of affected rows.
func (s *SPCredentialService) CleanupExpired(ctx context.Context) (int64, error) {
	count, err := s.credRepo.CleanupExpired(ctx)
	if err != nil {
		return 0, fmt.Errorf("SPCredentialService.CleanupExpired: %w", err)
	}
	return count, nil
}

// DeleteAllForSP hard-deletes all credentials for an SP (used during SP deletion).
func (s *SPCredentialService) DeleteAllForSP(ctx context.Context, spID uuid.UUID) error {
	if err := s.credRepo.DeleteBySP(ctx, spID); err != nil {
		return fmt.Errorf("SPCredentialService.DeleteAllForSP: %w", err)
	}
	return nil
}

// CheckExpiringCredentials returns all active credentials that will expire within
// the next 30 days. Callers are expected to fire webhook notifications for each
// returned credential.
func (s *SPCredentialService) CheckExpiringCredentials(ctx context.Context) ([]models.SPCredential, error) {
	creds, err := s.credRepo.ListExpiringSoon(ctx, 30)
	if err != nil {
		return nil, fmt.Errorf("SPCredentialService.CheckExpiringCredentials: %w", err)
	}
	return creds, nil
}

// RecordUsage records the current timestamp as the last-used time for a credential.
// This should be called each time a credential is successfully authenticated.
func (s *SPCredentialService) RecordUsage(ctx context.Context, credID uuid.UUID) error {
	if err := s.credRepo.RecordUsage(ctx, credID); err != nil {
		return fmt.Errorf("SPCredentialService.RecordUsage: %w", err)
	}
	return nil
}

// ListUnusedCredentials returns all active credentials that have never been used or
// have not been used for more than unusedDays days.
func (s *SPCredentialService) ListUnusedCredentials(ctx context.Context, unusedDays int) ([]models.SPCredential, error) {
	creds, err := s.credRepo.ListUnused(ctx, unusedDays)
	if err != nil {
		return nil, fmt.Errorf("SPCredentialService.ListUnusedCredentials: %w", err)
	}
	return creds, nil
}

// AddCertificateCredential parses a PEM-encoded X.509 certificate, extracts metadata,
// and stores it as a credential. The certificate's NotAfter is used as expiry when
// no explicit expiresAt is provided. Returns the persisted credential and certificate info.
func (s *SPCredentialService) AddCertificateCredential(ctx context.Context, spID uuid.UUID, certPEM string, expiresAt *time.Time, tenantID ...uuid.UUID) (*models.SPCredential, *models.CertificateInfo, error) {
	if s.policyValidator != nil && len(tenantID) > 0 {
		if err := s.policyValidator.ValidateCredentialExpiry(ctx, tenantID[0], models.SPCredentialTypeCertificate, expiresAt); err != nil {
			return nil, nil, fmt.Errorf("SPCredentialService.AddCertificateCredential: policy violation: %w", err)
		}
	}

	// Decode the PEM block.
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("SPCredentialService.AddCertificateCredential: invalid PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("SPCredentialService.AddCertificateCredential: parse cert: %w", err)
	}

	// Compute thumbprints.
	sha1Sum := sha1.Sum(cert.Raw) //nolint:gosec // SHA-1 thumbprint for X.509 compatibility only
	sha256Sum := sha256.Sum256(cert.Raw)
	thumbSHA1 := hex.EncodeToString(sha1Sum[:])
	thumbSHA256 := hex.EncodeToString(sha256Sum[:])

	// Key ID derived from the first 12 bytes of the SHA-256 thumbprint (base64url).
	keyID := base64.RawURLEncoding.EncodeToString(sha256Sum[:12])

	subject := cert.Subject.String()
	issuer := cert.Issuer.String()
	serialNumber := cert.SerialNumber.String()

	// Fall back to the certificate's own NotAfter when no explicit expiry is set.
	effectiveExpiry := expiresAt
	if effectiveExpiry == nil {
		effectiveExpiry = &cert.NotAfter
	}

	cred := &models.SPCredential{
		ID:               uuid.New(),
		SPID:             spID,
		CredentialType:   models.SPCredentialTypeCertificate,
		KeyID:            &keyID,
		PublicKeyPEM:     &certPEM,
		Status:           models.SPCredentialStatusActive,
		ExpiresAt:        effectiveExpiry,
		CreatedAt:        time.Now(),
		ThumbprintSHA1:   &thumbSHA1,
		ThumbprintSHA256: &thumbSHA256,
		Subject:          &subject,
		Issuer:           &issuer,
		SerialNumber:     &serialNumber,
		NotBefore:        &cert.NotBefore,
	}

	if err := s.credRepo.Create(ctx, cred); err != nil {
		return nil, nil, fmt.Errorf("SPCredentialService.AddCertificateCredential: %w", err)
	}

	info := &models.CertificateInfo{
		Subject:          subject,
		Issuer:           issuer,
		SerialNumber:     serialNumber,
		ThumbprintSHA1:   thumbSHA1,
		ThumbprintSHA256: thumbSHA256,
		NotBefore:        cert.NotBefore,
		NotAfter:         cert.NotAfter,
	}

	return cred, info, nil
}

// CredentialUsageSummary holds a point-in-time usage analysis for active credentials.
type CredentialUsageSummary struct {
	TotalActive  int `json:"total_active"`
	UnusedOver30 int `json:"unused_over_30_days"`
	UnusedOver90 int `json:"unused_over_90_days"`
	NeverUsed    int `json:"never_used"`
}

// AnalyzeCredentialUsage returns a summary of active credential usage across the platform.
func (s *SPCredentialService) AnalyzeCredentialUsage(ctx context.Context) (*CredentialUsageSummary, error) {
	// Total active: reuse ListUnused with 0 days to fetch everything active, then count.
	// More precisely: fetch each threshold independently.
	all, err := s.credRepo.ListUnused(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("SPCredentialService.AnalyzeCredentialUsage: list all active: %w", err)
	}

	unused30, err := s.credRepo.ListUnused(ctx, 30)
	if err != nil {
		return nil, fmt.Errorf("SPCredentialService.AnalyzeCredentialUsage: list unused 30d: %w", err)
	}

	unused90, err := s.credRepo.ListUnused(ctx, 90)
	if err != nil {
		return nil, fmt.Errorf("SPCredentialService.AnalyzeCredentialUsage: list unused 90d: %w", err)
	}

	neverUsed := 0
	for _, c := range all {
		if c.LastUsedAt == nil {
			neverUsed++
		}
	}

	return &CredentialUsageSummary{
		TotalActive:  len(all),
		UnusedOver30: len(unused30),
		UnusedOver90: len(unused90),
		NeverUsed:    neverUsed,
	}, nil
}
