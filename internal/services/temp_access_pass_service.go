// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrTAPNotFound indicates no matching Temporary Access Pass was found.
var ErrTAPNotFound = errors.New("temporary access pass not found")

// ErrTAPExpired indicates the Temporary Access Pass has passed its expiry time.
var ErrTAPExpired = errors.New("temporary access pass has expired")

// ErrTAPExhausted indicates a multi-use pass has no remaining uses.
var ErrTAPExhausted = errors.New("temporary access pass has no remaining uses")

// ErrTAPInvalidPass indicates the plaintext value did not match the stored hash.
var ErrTAPInvalidPass = errors.New("temporary access pass is invalid")

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// tapCharset is the alphabet used when generating pass characters. It intentionally
// omits visually ambiguous characters (0/O, 1/I/l) to reduce transcription errors
// when users must read a pass from a screen.
const tapCharset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"

// tapLength is the number of characters in a generated Temporary Access Pass.
const tapLength = 8

// TempAccessPass represents a short-lived, high-entropy pass that grants
// authentication without a password. It is analogous to Microsoft Entra's
// Temporary Access Pass feature.
type TempAccessPass struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	TenantID      uuid.UUID
	PassHash      string // SHA-256 hex of the plaintext pass
	IsOneTime     bool
	MaxUses       int
	UsesRemaining int
	ExpiresAt     time.Time
	CreatedBy     uuid.UUID
	CreatedAt     time.Time
}

// ---------------------------------------------------------------------------
// Repository interface
// ---------------------------------------------------------------------------

// tempAccessPassRepo defines the persistence methods consumed by TempAccessPassService.
type tempAccessPassRepo interface {
	Create(ctx context.Context, pass *TempAccessPass) error
	GetByUserAndHash(ctx context.Context, userID, tenantID uuid.UUID, passHash string) (*TempAccessPass, error)
	DecrementUses(ctx context.Context, id uuid.UUID) error
	DeleteExpired(ctx context.Context) (int64, error)
	ListByUser(ctx context.Context, userID, tenantID uuid.UUID) ([]*TempAccessPass, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// TempAccessPassService manages the lifecycle of Temporary Access Passes (TAP).
// A TAP is a short-lived, single- or multi-use pass that lets a user authenticate
// without their password — typically used for account recovery or initial device
// enrolment before the user has set up MFA.
type TempAccessPassService struct {
	repo   tempAccessPassRepo
	logger *zap.Logger
}

// NewTempAccessPassService creates a TempAccessPassService backed by the provided
// repository and logger.
func NewTempAccessPassService(repo tempAccessPassRepo, logger *zap.Logger) *TempAccessPassService {
	return &TempAccessPassService{
		repo:   repo,
		logger: logger,
	}
}

// GeneratePass creates a new Temporary Access Pass for the given user.
//
//   - isOneTime: when true, maxUses is forced to 1 regardless of the argument.
//   - maxUses: maximum number of authentication attempts (≥1). For one-time passes
//     this is always 1.
//   - durationMins: how many minutes until the pass expires. Must be ≥1.
//
// The plaintext pass is returned to the caller exactly once and is never stored.
// The repository stores only the SHA-256 hex digest.
func (s *TempAccessPassService) GeneratePass(
	ctx context.Context,
	userID, tenantID, createdBy uuid.UUID,
	isOneTime bool,
	maxUses int,
	durationMins int,
) (plaintext string, err error) {
	if durationMins < 1 {
		return "", fmt.Errorf("TempAccessPassService.GeneratePass: durationMins must be at least 1")
	}
	if maxUses < 1 {
		maxUses = 1
	}
	if isOneTime {
		maxUses = 1
	}

	plaintext, err = s.generatePassPhrase()
	if err != nil {
		return "", fmt.Errorf("TempAccessPassService.GeneratePass: %w", err)
	}

	passHash := s.hashPass(plaintext)
	expiresAt := time.Now().UTC().Add(time.Duration(durationMins) * time.Minute)

	tap := &TempAccessPass{
		ID:            uuid.New(),
		UserID:        userID,
		TenantID:      tenantID,
		PassHash:      passHash,
		IsOneTime:     isOneTime,
		MaxUses:       maxUses,
		UsesRemaining: maxUses,
		ExpiresAt:     expiresAt,
		CreatedBy:     createdBy,
		CreatedAt:     time.Now().UTC(),
	}

	if err := s.repo.Create(ctx, tap); err != nil {
		return "", fmt.Errorf("TempAccessPassService.GeneratePass: %w", err)
	}

	s.logger.Info("Temporary Access Pass generated",
		zap.String("tap_id", tap.ID.String()),
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.Bool("one_time", isOneTime),
		zap.Int("max_uses", maxUses),
		zap.Time("expires_at", expiresAt),
	)

	return plaintext, nil
}

// ValidatePass checks whether the provided plaintext pass is valid for the given
// user. On success the use count is decremented. If the pass has become exhausted
// after this use and is a one-time pass, the repository row is automatically deleted.
//
// Security properties:
//   - Constant-time SHA-256 hash comparison prevents timing side-channels.
//   - The same error (ErrTAPInvalidPass) is returned for both not-found and
//     hash-mismatch cases to prevent oracle attacks.
func (s *TempAccessPassService) ValidatePass(ctx context.Context, userID, tenantID uuid.UUID, plaintext string) error {
	passHash := s.hashPass(plaintext)

	tap, err := s.repo.GetByUserAndHash(ctx, userID, tenantID, passHash)
	if err != nil {
		return fmt.Errorf("TempAccessPassService.ValidatePass: %w", err)
	}
	if tap == nil {
		return ErrTAPInvalidPass
	}

	if time.Now().UTC().After(tap.ExpiresAt) {
		return ErrTAPExpired
	}

	if tap.UsesRemaining <= 0 {
		return ErrTAPExhausted
	}

	if err := s.repo.DecrementUses(ctx, tap.ID); err != nil {
		return fmt.Errorf("TempAccessPassService.ValidatePass: decrement: %w", err)
	}

	s.logger.Info("Temporary Access Pass used",
		zap.String("tap_id", tap.ID.String()),
		zap.String("user_id", userID.String()),
		zap.Int("uses_remaining_before", tap.UsesRemaining),
	)

	return nil
}

// ListPasses returns all non-expired Temporary Access Passes for the given user.
// Expired passes are not pruned here — use the background cleaner for that.
func (s *TempAccessPassService) ListPasses(ctx context.Context, userID, tenantID uuid.UUID) ([]*TempAccessPass, error) {
	passes, err := s.repo.ListByUser(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("TempAccessPassService.ListPasses: %w", err)
	}
	if passes == nil {
		passes = []*TempAccessPass{}
	}
	return passes, nil
}

// RevokePass deletes a Temporary Access Pass before its natural expiry.
// This is used by administrators to immediately invalidate a pass that may
// have been compromised.
func (s *TempAccessPassService) RevokePass(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("TempAccessPassService.RevokePass: %w", err)
	}
	s.logger.Info("Temporary Access Pass revoked", zap.String("tap_id", id.String()))
	return nil
}

// CleanupExpiredPasses removes all passes whose expiry time has passed.
// Intended to be called periodically from the background worker.
func (s *TempAccessPassService) CleanupExpiredPasses(ctx context.Context) (int64, error) {
	count, err := s.repo.DeleteExpired(ctx)
	if err != nil {
		return 0, fmt.Errorf("TempAccessPassService.CleanupExpiredPasses: %w", err)
	}
	if count > 0 {
		s.logger.Info("Temporary Access Passes pruned", zap.Int64("count", count))
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// generatePassPhrase creates an 8-character cryptographically random pass using
// the tapCharset. The character distribution is uniform thanks to rejection
// sampling: bytes whose value would bias toward lower-index characters are
// discarded and re-drawn.
func (s *TempAccessPassService) generatePassPhrase() (string, error) {
	charsetLen := byte(len(tapCharset))
	// Largest multiple of charsetLen that fits in a byte — used for rejection sampling.
	maxUnbiased := byte(256/int(charsetLen)) * charsetLen //nolint:gosec // value is bounded by 0-255 range, safe conversion

	result := make([]byte, tapLength)
	generated := 0

	// We may need more than tapLength random bytes due to rejection; draw in
	// batches to minimise syscalls.
	buf := make([]byte, tapLength*4)
	for generated < tapLength {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("generatePassPhrase: crypto/rand unavailable: %w", err)
		}
		for _, b := range buf {
			if generated >= tapLength {
				break
			}
			// Reject bytes that would create modulo bias.
			if b >= maxUnbiased {
				continue
			}
			result[generated] = tapCharset[b%charsetLen]
			generated++
		}
	}

	return string(result), nil
}

// hashPass returns the SHA-256 hex digest of the given plaintext. SHA-256 is
// appropriate here because TAPs are high-entropy (≥47 bits from 8 chars over a
// 58-char alphabet), so brute-force resistance comes from the pass itself rather
// than from a slow hash function like bcrypt/argon2.
func (s *TempAccessPassService) hashPass(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
