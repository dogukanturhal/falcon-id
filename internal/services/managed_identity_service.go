// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// bootstrapTokenRepository defines persistence operations for bootstrap tokens.
type bootstrapTokenRepository interface {
	CreateBootstrapToken(ctx context.Context, token *models.BootstrapToken) error
	GetBootstrapTokenByHash(ctx context.Context, hash string) (*models.BootstrapToken, error)
	ListBootstrapTokens(ctx context.Context, serviceSlug string) ([]models.BootstrapToken, error)
	DeleteBootstrapToken(ctx context.Context, id uuid.UUID) error
	IncrementBootstrapTokenUsage(ctx context.Context, id uuid.UUID) error
}

// managedSPRepository extends the base service principal repository with
// managed-identity lifecycle methods.
type managedSPRepository interface {
	servicePrincipalRepository
	UpdateHeartbeat(ctx context.Context, slug string) error
	SuspendStale(ctx context.Context, before time.Time) (int64, error)
}

// ManagedIdentityService handles the auto-provisioning lifecycle for service
// identities: bootstrap token issuance, self-registration, heartbeat tracking,
// and auto-suspend of silent services.
type ManagedIdentityService struct {
	spRepo        servicePrincipalRepository
	btRepo        bootstrapTokenRepository
	tokenEndpoint string
}

// NewManagedIdentityService creates a new ManagedIdentityService.
func NewManagedIdentityService(
	spRepo servicePrincipalRepository,
	btRepo bootstrapTokenRepository,
	tokenEndpoint string,
) *ManagedIdentityService {
	return &ManagedIdentityService{
		spRepo:        spRepo,
		btRepo:        btRepo,
		tokenEndpoint: tokenEndpoint,
	}
}

// ---------------------------------------------------------------------------
// Bootstrap token lifecycle
// ---------------------------------------------------------------------------

// CreateBootstrapToken generates a one-time token that a service can use to
// self-register.  The raw token is returned exactly once; only its hash is stored.
func (s *ManagedIdentityService) CreateBootstrapToken(
	ctx context.Context,
	req *models.CreateBootstrapTokenRequest,
	createdBy uuid.UUID,
) (*models.BootstrapToken, string, error) {
	// Generate 32 random bytes → URL-safe base64 raw token
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, "", fmt.Errorf("ManagedIdentityService.CreateBootstrapToken: rand: %w", err)
	}
	rawToken := base64.RawURLEncoding.EncodeToString(rawBytes)

	// Store the SHA-256 hex digest
	digest := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(digest[:])

	maxUses := 1
	if req.MaxUses > 0 {
		maxUses = req.MaxUses
	}

	bt := &models.BootstrapToken{
		ID:            uuid.New(),
		TokenHash:     tokenHash,
		ServiceSlug:   req.ServiceSlug,
		AllowedScopes: req.AllowedScopes,
		IPAllowlist:   req.IPAllowlist,
		MaxUses:       maxUses,
		UsedCount:     0,
		ExpiresAt:     time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour),
		CreatedBy:     createdBy,
		CreatedAt:     time.Now(),
	}
	if bt.AllowedScopes == nil {
		bt.AllowedScopes = []string{}
	}
	if bt.IPAllowlist == nil {
		bt.IPAllowlist = []string{}
	}

	if err := s.btRepo.CreateBootstrapToken(ctx, bt); err != nil {
		return nil, "", fmt.Errorf("ManagedIdentityService.CreateBootstrapToken: persist: %w", err)
	}

	logger.Info("ManagedIdentityService: bootstrap token created",
		zap.String("service_slug", req.ServiceSlug),
		zap.String("token_id", bt.ID.String()),
		zap.Time("expires_at", bt.ExpiresAt),
	)
	return bt, rawToken, nil
}

// ListBootstrapTokens returns all bootstrap tokens for the given service slug.
// Pass an empty slug to return all tokens.
func (s *ManagedIdentityService) ListBootstrapTokens(
	ctx context.Context,
	serviceSlug string,
) ([]models.BootstrapToken, error) {
	tokens, err := s.btRepo.ListBootstrapTokens(ctx, serviceSlug)
	if err != nil {
		return nil, fmt.Errorf("ManagedIdentityService.ListBootstrapTokens: %w", err)
	}
	return tokens, nil
}

// DeleteBootstrapToken removes a bootstrap token by ID.
func (s *ManagedIdentityService) DeleteBootstrapToken(ctx context.Context, id uuid.UUID) error {
	if err := s.btRepo.DeleteBootstrapToken(ctx, id); err != nil {
		return fmt.Errorf("ManagedIdentityService.DeleteBootstrapToken: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Service self-registration
// ---------------------------------------------------------------------------

// RegisterWithBootstrapToken validates a one-time bootstrap token, creates or
// updates the matching ServicePrincipal, and returns a freshly generated RSA
// private key.  The token usage count is atomically incremented on success.
func (s *ManagedIdentityService) RegisterWithBootstrapToken(
	ctx context.Context,
	req *models.BootstrapTokenRequest,
) (*models.BootstrapRegistrationResponse, error) {
	// Hash the incoming raw token
	digest := sha256.Sum256([]byte(req.BootstrapToken))
	hash := hex.EncodeToString(digest[:])

	bt, err := s.btRepo.GetBootstrapTokenByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("ManagedIdentityService.RegisterWithBootstrapToken: token not found: %w", err)
	}

	if !bt.IsValid() {
		if bt.IsExpired() {
			return nil, fmt.Errorf("ManagedIdentityService.RegisterWithBootstrapToken: token expired")
		}
		return nil, fmt.Errorf("ManagedIdentityService.RegisterWithBootstrapToken: token exhausted")
	}

	// Validate the service slug matches the token
	if bt.ServiceSlug != req.ServiceSlug {
		return nil, fmt.Errorf(
			"ManagedIdentityService.RegisterWithBootstrapToken: slug mismatch: expected %q got %q",
			bt.ServiceSlug, req.ServiceSlug,
		)
	}

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("ManagedIdentityService.RegisterWithBootstrapToken: keygen: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ManagedIdentityService.RegisterWithBootstrapToken: marshal pub: %w", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	privPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}))
	keyHash := sha256.Sum256(pubDER)
	keyID := base64.RawURLEncoding.EncodeToString(keyHash[:12])

	// Upsert the ServicePrincipal
	existing, _ := s.spRepo.GetBySlug(ctx, req.ServiceSlug)
	if existing == nil {
		now := time.Now()
		sp := &models.ServicePrincipal{
			ID:            uuid.New(),
			Name:          req.ServiceSlug,
			Slug:          req.ServiceSlug,
			Description:   fmt.Sprintf("Auto-provisioned via bootstrap token (version %s)", req.ServiceVersion),
			PublicKeyPEM:  pubPEM,
			KeyID:         keyID,
			AllowedScopes: bt.AllowedScopes,
			IPAllowlist:   bt.IPAllowlist,
			Status:        "active",
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if err := s.spRepo.Create(ctx, sp); err != nil {
			return nil, fmt.Errorf("ManagedIdentityService.RegisterWithBootstrapToken: create sp: %w", err)
		}
	} else {
		// Rotate key for existing principal
		if err := s.spRepo.RotateKey(ctx, existing.ID, pubPEM, keyID); err != nil {
			return nil, fmt.Errorf("ManagedIdentityService.RegisterWithBootstrapToken: rotate key: %w", err)
		}
	}

	// Increment usage count
	if err := s.btRepo.IncrementBootstrapTokenUsage(ctx, bt.ID); err != nil {
		// Non-fatal: log but continue
		logger.Warn("ManagedIdentityService: failed to increment token usage",
			zap.String("token_id", bt.ID.String()),
			zap.Error(err),
		)
	}

	sp, err := s.spRepo.GetBySlug(ctx, req.ServiceSlug)
	if err != nil {
		return nil, fmt.Errorf("ManagedIdentityService.RegisterWithBootstrapToken: re-fetch: %w", err)
	}

	logger.Info("ManagedIdentityService: service registered via bootstrap token",
		zap.String("service_slug", req.ServiceSlug),
		zap.String("sp_id", sp.ID.String()),
	)

	return &models.BootstrapRegistrationResponse{
		ServicePrincipalID: sp.ID,
		PrivateKeyPEM:      privPEM,
		KeyID:              keyID,
		TokenEndpoint:      s.tokenEndpoint,
		ExpiresIn:          86400 * 90, // recommend rotation within 90 days
	}, nil
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

// Heartbeat records a live signal from a managed service, updating its
// last_heartbeat_at timestamp.
func (s *ManagedIdentityService) Heartbeat(
	ctx context.Context,
	req *models.ServiceHeartbeatRequest,
) error {
	// Attempt to use the extended repo interface; fall back gracefully.
	if msr, ok := s.spRepo.(managedSPRepository); ok {
		if err := msr.UpdateHeartbeat(ctx, req.ServiceSlug); err != nil {
			return fmt.Errorf("ManagedIdentityService.Heartbeat: %w", err)
		}
		return nil
	}

	// Fallback: update last_authenticated_at via the standard interface
	sp, err := s.spRepo.GetBySlug(ctx, req.ServiceSlug)
	if err != nil {
		return fmt.Errorf("ManagedIdentityService.Heartbeat: service not found: %w", err)
	}
	if err := s.spRepo.UpdateLastAuthenticated(ctx, sp.ID); err != nil {
		return fmt.Errorf("ManagedIdentityService.Heartbeat: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Auto-suspend background job
// ---------------------------------------------------------------------------

// AutoSuspendStaleServices suspends managed services that have missed
// `missed` or more heartbeats given a per-service interval.  It is intended
// to be called by a background scheduler.
func (s *ManagedIdentityService) AutoSuspendStaleServices(ctx context.Context) (int64, error) {
	if msr, ok := s.spRepo.(managedSPRepository); ok {
		// Suspend any auto-provisioned service whose last heartbeat was more than
		// (heartbeat_interval_seconds * auto_suspend_after_missed) seconds ago.
		// We use a conservative cutoff of 5 minutes × 3 = 15 minutes as the
		// default; the DB query applies per-row thresholds.
		cutoff := time.Now().Add(-15 * time.Minute)
		suspended, err := msr.SuspendStale(ctx, cutoff)
		if err != nil {
			return 0, fmt.Errorf("ManagedIdentityService.AutoSuspendStaleServices: %w", err)
		}
		if suspended > 0 {
			logger.Info("ManagedIdentityService: suspended stale services",
				zap.Int64("count", suspended),
			)
		}
		return suspended, nil
	}
	return 0, nil
}
