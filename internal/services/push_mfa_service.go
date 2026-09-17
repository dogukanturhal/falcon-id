// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// PushChallengeDefaultTTL is the window within which the user must respond to
// a push notification before the challenge is considered expired.
const PushChallengeDefaultTTL = 5 * time.Minute

// PushWaitPollInterval is the sleep duration between status-checks inside
// WaitForResponse.
const PushWaitPollInterval = 500 * time.Millisecond

// --- Push provider interface and stubs ---

// PushProvider is the abstraction over FCM and APNs delivery. Real
// implementations are injected at runtime; the stubs below log the payload so
// that the service can be exercised without credentials.
type PushProvider interface {
	// SendPush delivers a push notification to the given device token.
	// title and body are the human-readable strings shown by the OS.
	// data contains arbitrary key-value metadata (e.g. challenge_id).
	SendPush(ctx context.Context, deviceToken, title, body string, data map[string]string) error
}

// FCMPushProvider is a stub for Firebase Cloud Messaging (Android).
// Replace with the official firebase-admin-go SDK once FCM credentials
// are provisioned.
type FCMPushProvider struct {
	log *zap.Logger
}

// NewFCMPushProvider constructs the FCM stub.
func NewFCMPushProvider() *FCMPushProvider {
	return &FCMPushProvider{log: logger.Log}
}

// SendPush logs the push payload. Wire a real FCM client here when ready.
func (p *FCMPushProvider) SendPush(_ context.Context, deviceToken, title, body string, data map[string]string) error {
	p.log.Info("FCM push (stub — no credentials configured)",
		zap.String("device_token_prefix", truncate(deviceToken, 16)),
		zap.String("title", title),
		zap.String("body", body),
		zap.Any("data", data),
	)
	return nil
}

// APNsPushProvider is a stub for Apple Push Notification service (iOS).
// Replace with the sideshow/apns2 or buger/apns2 library once APNs
// credentials (p8 key + key-id + team-id) are provisioned.
type APNsPushProvider struct {
	log *zap.Logger
}

// NewAPNsPushProvider constructs the APNs stub.
func NewAPNsPushProvider() *APNsPushProvider {
	return &APNsPushProvider{log: logger.Log}
}

// SendPush logs the push payload. Wire a real APNs client here when ready.
func (p *APNsPushProvider) SendPush(_ context.Context, deviceToken, title, body string, data map[string]string) error {
	p.log.Info("APNs push (stub — no credentials configured)",
		zap.String("device_token_prefix", truncate(deviceToken, 16)),
		zap.String("title", title),
		zap.String("body", body),
		zap.Any("data", data),
	)
	return nil
}

// --- Service ---

// PushMFAService manages authenticator-device registration and push-based MFA
// pushMFAUserRepo is the narrow user-repository surface PushMFAService
// needs to denormalize the per-user mfa_enabled flag when a device is
// registered. Mirrors webauthn_service.go's webAuthnUserLookup pattern;
// the dependency is kept minimal so tests don't have to construct a
// full UserRepository.
//
// nil-safe via SetUserRepo: when unset (test harness, boot before the
// user repo exists) RegisterDevice still persists the device but skips
// the flag update with a warn log. The iam_push_mfa_devices row stays
// authoritative.
type pushMFAUserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
}

// challenges. It mirrors the Auth0 / Okta / Microsoft Authenticator model
// where a dedicated mobile app receives push notifications and the user
// approves or denies the login attempt.
type PushMFAService struct {
	cfg          *config.Config
	repo         *repositories.PushMFARepository
	userRepo     pushMFAUserRepo
	encSvc       *crypto.EncryptionService
	fcmProvider  PushProvider
	apnsProvider PushProvider
	log          *zap.Logger
}

// SetUserRepo wires the user repository so RegisterDevice can flip the
// user.mfa_enabled summary flag once a push device is registered.
// Called from cmd/handlers.go after both services exist. nil-safe.
func (s *PushMFAService) SetUserRepo(repo pushMFAUserRepo) {
	s.userRepo = repo
}

// NewPushMFAService creates a PushMFAService.
//
// encryptionKey must match Config.EncryptionKey — it is used to encrypt push
// tokens at rest (AES-GCM via the shared crypto package).
func NewPushMFAService(
	cfg *config.Config,
	repo *repositories.PushMFARepository,
	encryptionKey string,
) (*PushMFAService, error) {
	encSvc, err := crypto.NewEncryptionService(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("PushMFAService: invalid encryption key: %w", err)
	}
	return &PushMFAService{
		cfg:          cfg,
		repo:         repo,
		encSvc:       encSvc,
		fcmProvider:  NewFCMPushProvider(),
		apnsProvider: NewAPNsPushProvider(),
		log:          logger.Log,
	}, nil
}

// SetFCMProvider replaces the FCM push provider (for testing or real impl).
func (s *PushMFAService) SetFCMProvider(p PushProvider) {
	s.fcmProvider = p
}

// SetAPNsProvider replaces the APNs push provider (for testing or real impl).
func (s *PushMFAService) SetAPNsProvider(p PushProvider) {
	s.apnsProvider = p
}

// --- Device management ---

// RegisterDevice registers a new authenticator device for the user.
// The raw push token is encrypted before being written to the database.
func (s *PushMFAService) RegisterDevice(
	ctx context.Context,
	userID uuid.UUID,
	deviceName, platform, pushToken, publicKey string,
) (*models.PushMFADevice, error) {
	if platform != "ios" && platform != "android" {
		return nil, errors.New("platform must be 'ios' or 'android'")
	}

	encryptedToken, err := s.encSvc.Encrypt(pushToken)
	if err != nil {
		return nil, fmt.Errorf("PushMFAService.RegisterDevice: encrypt token: %w", err)
	}

	dev := &models.PushMFADevice{
		ID:                 uuid.New(),
		UserID:             userID,
		DeviceName:         deviceName,
		Platform:           platform,
		PushTokenEncrypted: encryptedToken,
		PublicKey:          publicKey,
	}

	if err := s.repo.CreateDevice(ctx, dev); err != nil {
		return nil, fmt.Errorf("PushMFAService.RegisterDevice: %w", err)
	}

	// Denormalize: flip the user's mfa_enabled summary flag so the
	// OAuth /authorize ACR step-up gate recognises this user has at
	// least one factor. Best-effort — the device row in
	// iam_push_mfa_devices is the authoritative state; a failure here
	// is logged but doesn't roll back the registration. Mirrors
	// webauthn_service.go FinishRegistration and the TOTP / email
	// enrollment paths (mfa_service.go:190,344,478,
	// mfa_enrollment_service.go:356).
	if s.userRepo != nil {
		if user, getErr := s.userRepo.GetByID(ctx, userID); getErr == nil && user != nil && !user.MFAEnabled {
			user.MFAEnabled = true
			if updErr := s.userRepo.Update(ctx, user); updErr != nil {
				s.log.Warn("Push MFA device persisted but failed to set user.mfa_enabled",
					zap.String("user_id", userID.String()),
					zap.Error(updErr),
				)
			}
		}
	}

	s.log.Info("Push MFA device registered",
		zap.String("user_id", userID.String()),
		zap.String("device_id", dev.ID.String()),
		zap.String("platform", platform),
	)
	return dev, nil
}

// UnregisterDevice removes the device from the user's account.
// Returns an error if the device is not found or does not belong to the user.
func (s *PushMFAService) UnregisterDevice(ctx context.Context, deviceID, userID uuid.UUID) error {
	deleted, err := s.repo.DeleteDevice(ctx, deviceID, userID)
	if err != nil {
		return fmt.Errorf("PushMFAService.UnregisterDevice: %w", err)
	}
	if !deleted {
		return errors.New("device not found")
	}
	s.log.Info("Push MFA device unregistered",
		zap.String("user_id", userID.String()),
		zap.String("device_id", deviceID.String()),
	)
	return nil
}

// ListDevices returns all push-MFA devices registered by the user.
func (s *PushMFAService) ListDevices(ctx context.Context, userID uuid.UUID) ([]*models.PushMFADevice, error) {
	devices, err := s.repo.ListDevicesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("PushMFAService.ListDevices: %w", err)
	}
	return devices, nil
}

// --- Challenge flow ---

// SendPushChallenge creates a challenge record and fires a push notification to
// all registered devices belonging to the user. At least one active device must
// be registered; otherwise an error is returned.
//
// ipAddress, userAgent, and geoLocation are optional context values shown to
// the user inside the authenticator app ("someone is trying to log in from…").
func (s *PushMFAService) SendPushChallenge(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	ipAddress, userAgent, geoLocation string,
) (*models.PushMFAChallenge, error) {
	devices, err := s.repo.ListDevicesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("PushMFAService.SendPushChallenge: list devices: %w", err)
	}
	if len(devices) == 0 {
		return nil, errors.New("no push MFA devices registered for this user")
	}

	challenge := &models.PushMFAChallenge{
		ID:          uuid.New(),
		UserID:      userID,
		TenantID:    tenantID,
		Status:      models.PushChallengeStatusPending,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		GeoLocation: geoLocation,
		ExpiresAt:   time.Now().Add(PushChallengeDefaultTTL),
	}

	// Associate the challenge with the most-recently-used device (best-effort).
	challenge.DeviceID = &devices[0].ID

	if err := s.repo.CreateChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("PushMFAService.SendPushChallenge: create challenge: %w", err)
	}

	data := map[string]string{
		"challenge_id": challenge.ID.String(),
		"ip_address":   ipAddress,
		"geo_location": geoLocation,
	}
	title := "Login request"
	body := fmt.Sprintf("A sign-in attempt from %s. Approve or deny?", orDefault(geoLocation, ipAddress, "an unknown location"))

	// Deliver to every device — the first response wins.
	for _, dev := range devices {
		rawToken, decErr := s.encSvc.Decrypt(dev.PushTokenEncrypted)
		if decErr != nil {
			s.log.Warn("Push MFA: failed to decrypt push token, skipping device",
				zap.String("device_id", dev.ID.String()),
				zap.Error(decErr),
			)
			continue
		}
		provider := s.providerFor(dev.Platform)
		if pushErr := provider.SendPush(ctx, rawToken, title, body, data); pushErr != nil {
			s.log.Warn("Push MFA: push delivery failed for device",
				zap.String("device_id", dev.ID.String()),
				zap.String("platform", dev.Platform),
				zap.Error(pushErr),
			)
		}
	}

	s.log.Info("Push MFA challenge created",
		zap.String("challenge_id", challenge.ID.String()),
		zap.String("user_id", userID.String()),
		zap.Int("device_count", len(devices)),
	)
	return challenge, nil
}

// RespondToChallenge records the user's approval or denial of the challenge.
// signature is optional; when present it is stored alongside the response for
// future cryptographic audit purposes (not validated here — wire end-to-end
// signature verification once the mobile SDK is stable).
func (s *PushMFAService) RespondToChallenge(ctx context.Context, challengeID uuid.UUID, approved bool, _ string) error {
	// Ensure the challenge is still pending and not expired.
	if err := s.repo.ExpireChallenge(ctx, challengeID); err != nil {
		s.log.Warn("Push MFA: expiry sweep failed", zap.String("challenge_id", challengeID.String()), zap.Error(err))
	}

	challenge, err := s.repo.GetChallengeByID(ctx, challengeID)
	if err != nil {
		return fmt.Errorf("PushMFAService.RespondToChallenge: %w", err)
	}
	if challenge == nil {
		return errors.New("challenge not found")
	}
	if challenge.Status != models.PushChallengeStatusPending {
		return fmt.Errorf("challenge already resolved (status: %s)", challenge.Status)
	}

	newStatus := models.PushChallengeStatusApproved
	if !approved {
		newStatus = models.PushChallengeStatusDenied
	}

	if err := s.repo.UpdateChallengeStatus(ctx, challengeID, newStatus); err != nil {
		return fmt.Errorf("PushMFAService.RespondToChallenge: update status: %w", err)
	}

	// Touch the device's last_used_at so staleness detection stays accurate.
	if challenge.DeviceID != nil {
		if touchErr := s.repo.TouchDevice(ctx, *challenge.DeviceID); touchErr != nil {
			s.log.Warn("Push MFA: failed to touch device",
				zap.String("device_id", challenge.DeviceID.String()),
				zap.Error(touchErr),
			)
		}
	}

	s.log.Info("Push MFA challenge responded",
		zap.String("challenge_id", challengeID.String()),
		zap.String("user_id", challenge.UserID.String()),
		zap.String("status", string(newStatus)),
	)
	return nil
}

// GetChallengeStatus returns the current status of a challenge without blocking.
// It expires stale challenges on read to keep status accurate.
func (s *PushMFAService) GetChallengeStatus(ctx context.Context, challengeID uuid.UUID) (*models.PushMFAChallenge, error) {
	// Best-effort expiry sweep before returning status.
	if err := s.repo.ExpireChallenge(ctx, challengeID); err != nil {
		s.log.Warn("Push MFA: expiry sweep failed",
			zap.String("challenge_id", challengeID.String()),
			zap.Error(err),
		)
	}

	challenge, err := s.repo.GetChallengeByID(ctx, challengeID)
	if err != nil {
		return nil, fmt.Errorf("PushMFAService.GetChallengeStatus: %w", err)
	}
	if challenge == nil {
		return nil, errors.New("challenge not found")
	}
	return challenge, nil
}

// WaitForResponse long-polls until the challenge is resolved or the context
// deadline/cancellation fires. It returns the final challenge state.
//
// This is suitable for server-sent long-poll patterns (e.g. a login page that
// keeps the request open until the user responds on their phone). Callers
// should set a context deadline that matches the challenge TTL.
func (s *PushMFAService) WaitForResponse(ctx context.Context, challengeID uuid.UUID, timeout time.Duration) (*models.PushMFAChallenge, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(PushWaitPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case now := <-ticker.C:
			if now.After(deadline) {
				// Mark as expired and return final state.
				_ = s.repo.ExpireChallenge(ctx, challengeID)
				return s.GetChallengeStatus(ctx, challengeID)
			}

			challenge, err := s.GetChallengeStatus(ctx, challengeID)
			if err != nil {
				return nil, err
			}
			if challenge.Status != models.PushChallengeStatusPending {
				return challenge, nil
			}
		}
	}
}

// --- internal helpers ---

// providerFor returns the appropriate PushProvider for a device platform.
func (s *PushMFAService) providerFor(platform string) PushProvider {
	if platform == "ios" {
		return s.apnsProvider
	}
	return s.fcmProvider
}

// truncate returns the first n runes of s.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

// orDefault returns the first non-empty string from the list.
func orDefault(candidates ...string) string {
	for _, c := range candidates {
		if c != "" {
			return c
		}
	}
	return authMethodUnknown
}
