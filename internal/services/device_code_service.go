// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	// deviceCodeExpiry is the RFC 8628 recommended device code lifetime.
	deviceCodeExpiry = 15 * time.Minute
	// deviceCodeInterval is the minimum polling interval in seconds.
	deviceCodeInterval = 5
	// userCodeCharset is the RFC 8628 RECOMMENDED charset (no ambiguous chars).
	userCodeCharset = "BCDFGHJKLMNPQRSTVWXZ"
	// userCodeLength is the number of characters per segment (XXXX-XXXX).
	userCodeLength = 4
)

// deviceCodeRepo narrows the repository surface used by DeviceCodeService.
type deviceCodeRepo interface {
	Create(ctx context.Context, d *models.OAuthDeviceCode) error
	GetByDeviceCode(ctx context.Context, hash string) (*models.OAuthDeviceCode, error)
	GetByUserCode(ctx context.Context, userCode string) (*models.OAuthDeviceCode, error)
	Authorize(ctx context.Context, id, userID uuid.UUID) error
	Deny(ctx context.Context, id uuid.UUID) error
	Consume(ctx context.Context, id uuid.UUID) error
	RecordPoll(ctx context.Context, id uuid.UUID) error
	ExpireOld(ctx context.Context) (int64, error)
}

// DeviceCodeService implements the OAuth 2.0 Device Authorization Grant (RFC 8628).
type DeviceCodeService struct {
	repo        deviceCodeRepo
	frontendURL string
}

// NewDeviceCodeService constructs a DeviceCodeService.
func NewDeviceCodeService(repo deviceCodeRepo, frontendURL string) *DeviceCodeService {
	return &DeviceCodeService{
		repo:        repo,
		frontendURL: frontendURL,
	}
}

// InitiateDeviceFlow creates a new device code pair and returns the RFC 8628 §3.2 response body.
func (s *DeviceCodeService) InitiateDeviceFlow(ctx context.Context, tenantID, clientID uuid.UUID, scopes []string) (*models.DeviceAuthorizationResponse, error) {
	// Generate raw device code (high-entropy opaque value)
	rawDeviceCode, err := generateDeviceCode()
	if err != nil {
		return nil, fmt.Errorf("DeviceCodeService.InitiateDeviceFlow: generate device code: %w", err)
	}

	// Store only the hash
	deviceCodeHash := hashDeviceCode(rawDeviceCode)

	// Generate human-readable user code (XXXX-XXXX)
	userCode, err := generateUserCode()
	if err != nil {
		return nil, fmt.Errorf("DeviceCodeService.InitiateDeviceFlow: generate user code: %w", err)
	}

	verificationURI := s.verificationURI(tenantID)
	verificationURIComplete := verificationURI + "?user_code=" + userCode

	expiresAt := time.Now().Add(deviceCodeExpiry)

	record := &models.OAuthDeviceCode{
		TenantID:                tenantID,
		ClientID:                clientID,
		DeviceCode:              deviceCodeHash,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: &verificationURIComplete,
		Scopes:                  scopes,
		Status:                  models.DeviceCodeStatusPending,
		IntervalSeconds:         deviceCodeInterval,
		ExpiresAt:               expiresAt,
	}

	if err := s.repo.Create(ctx, record); err != nil {
		logger.Error("DeviceCodeService.InitiateDeviceFlow: failed to persist device code", zap.Error(err))
		return nil, fmt.Errorf("failed to initiate device flow")
	}

	logger.Info("Device authorization flow initiated",
		zap.String("tenant_id", tenantID.String()),
		zap.String("client_id", clientID.String()),
	)

	return &models.DeviceAuthorizationResponse{
		DeviceCode:              rawDeviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURIComplete,
		ExpiresIn:               int64(deviceCodeExpiry.Seconds()),
		Interval:                deviceCodeInterval,
	}, nil
}

// PollDeviceCode is called by the device on the token endpoint to check authorization status.
// Returns (nil, nil) when authorization is still pending — the caller should return
// "authorization_pending" to the client.
func (s *DeviceCodeService) PollDeviceCode(ctx context.Context, rawDeviceCode string) (*models.OAuthDeviceCode, error) {
	hash := hashDeviceCode(rawDeviceCode)
	record, err := s.repo.GetByDeviceCode(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("DeviceCodeService.PollDeviceCode: %w", err)
	}
	if record == nil {
		return nil, fmt.Errorf("device code not found")
	}

	// Always record the poll attempt (for slow_down enforcement upstream if needed)
	_ = s.repo.RecordPoll(ctx, record.ID)

	if record.IsExpired() {
		return nil, fmt.Errorf("device_code expired")
	}

	return record, nil
}

// AuthorizeDevice approves the device code identified by a user code.
// Called from the browser flow after the user authenticates.
func (s *DeviceCodeService) AuthorizeDevice(ctx context.Context, userCode string, userID uuid.UUID) error {
	record, err := s.repo.GetByUserCode(ctx, userCode)
	if err != nil {
		return fmt.Errorf("DeviceCodeService.AuthorizeDevice: %w", err)
	}
	if record == nil {
		return fmt.Errorf("invalid or expired user code")
	}
	if record.IsExpired() {
		return fmt.Errorf("user code has expired")
	}

	if err := s.repo.Authorize(ctx, record.ID, userID); err != nil {
		return fmt.Errorf("DeviceCodeService.AuthorizeDevice: %w", err)
	}

	logger.Info("Device authorized by user",
		zap.String("device_code_id", record.ID.String()),
		zap.String("user_id", userID.String()),
	)
	return nil
}

// DenyDevice rejects the device code identified by a user code.
func (s *DeviceCodeService) DenyDevice(ctx context.Context, userCode string) error {
	record, err := s.repo.GetByUserCode(ctx, userCode)
	if err != nil {
		return fmt.Errorf("DeviceCodeService.DenyDevice: %w", err)
	}
	if record == nil {
		return fmt.Errorf("invalid or expired user code")
	}
	return s.repo.Deny(ctx, record.ID)
}

// ConsumeDeviceCode marks the code as consumed after a successful token issuance.
func (s *DeviceCodeService) ConsumeDeviceCode(ctx context.Context, id uuid.UUID) error {
	return s.repo.Consume(ctx, id)
}

// ExpireOldCodes is intended to be called from a background job.
func (s *DeviceCodeService) ExpireOldCodes(ctx context.Context) (int64, error) {
	return s.repo.ExpireOld(ctx)
}

// verificationURI builds the URL where the user enters their user code.
func (s *DeviceCodeService) verificationURI(_ uuid.UUID) string {
	base := s.frontendURL
	if base == "" {
		base = defaultFrontendURL
	}
	return base + "/device"
}

// ==================== helpers ====================

// generateDeviceCode returns a 32-byte cryptographically random hex string.
func generateDeviceCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashDeviceCode produces the SHA-256 hex digest stored in the database.
func hashDeviceCode(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// generateUserCode produces a human-friendly XXXX-XXXX code using the RFC 8628
// recommended character set (uppercase consonants — no ambiguous O/0/I/1).
func generateUserCode() (string, error) {
	charset := []rune(userCodeCharset)
	n := big.NewInt(int64(len(charset)))

	part := func() (string, error) {
		var sb strings.Builder
		for i := 0; i < userCodeLength; i++ {
			idx, err := rand.Int(rand.Reader, n)
			if err != nil {
				return "", err
			}
			sb.WriteRune(charset[idx.Int64()])
		}
		return sb.String(), nil
	}

	p1, err := part()
	if err != nil {
		return "", fmt.Errorf("generateUserCode: %w", err)
	}
	p2, err := part()
	if err != nil {
		return "", fmt.Errorf("generateUserCode: %w", err)
	}
	return p1 + "-" + p2, nil
}
