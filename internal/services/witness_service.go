// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// witness_service.go — server-side state and policy for the ZTNA Path B
// enrollment witness (ADR 0043 §3.c.0), both methods:
//
//   - passkey: begin persists {device_uuid, ek_pubkey_hash, state} keyed by
//     the WebAuthn ceremony session; finish reads the stored values back and
//     ignores whatever the request body claims.
//   - totp (authenticator-app fallback): a Redis challenge, attempt caps, a
//     per-user failure lockout and the shared TOTP replay claim. Only users
//     with NO passkey may use it, only when the realm policy and the env kill
//     switch allow it, and only once the TOTP factor is >24h old.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	witnessChallengeTTL      = 120 * time.Second
	witnessBindingTTL        = 5 * time.Minute
	witnessMaxChallengeTries = 3
	witnessMaxUserFailures   = 5
	witnessFailureWindow     = 15 * time.Minute
	witnessLockDuration      = 15 * time.Minute
	// witnessMinTOTPAge is how old the TOTP factor must be before it may
	// vouch for a device: an attacker who just hijacked a session cannot
	// enrol their own authenticator and immediately witness a device.
	witnessMinTOTPAge = 24 * time.Hour

	witnessKeyBinding   = "witness:pk:"
	witnessKeyChallenge = "witness:totp:ch:"
	witnessKeyTries     = "witness:totp:tries:"
	witnessKeyFail      = "witness:totp:fail:"
	witnessKeyLock      = "witness:totp:lock:"
)

var (
	witnessEKHashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	witnessCodeRE   = regexp.MustCompile(`^[0-9]{6}$`)
	witnessStateMax = 64
)

// Witness error codes returned in WitnessError.Code (stable API strings).
const (
	WitnessErrNotPlatformAdmin = "witness_platform_admin_required"
	WitnessErrDisabled         = "witness_totp_disabled"
	WitnessErrPolicyOff        = "witness_totp_policy_off"
	WitnessErrHasPasskey       = "witness_passkey_required"
	WitnessErrNoTOTP           = "witness_totp_not_enrolled"
	WitnessErrTOTPTooNew       = "witness_totp_too_new"
	WitnessErrBadRequest       = "witness_invalid_request"
	WitnessErrExpired          = "witness_challenge_expired"
	WitnessErrCodeInvalid      = "witness_code_invalid"
	WitnessErrExhausted        = "witness_attempts_exhausted"
	WitnessErrLocked           = "witness_locked"
	WitnessErrUnavailable      = "witness_unavailable"
)

// WitnessError is a refusal with a stable code and an HTTP status.
type WitnessError struct {
	Code              string
	Status            int
	Message           string
	RemainingAttempts int
}

func (e *WitnessError) Error() string { return e.Code + ": " + e.Message }

func witnessErr(status int, code, msg string) *WitnessError {
	return &WitnessError{Code: code, Status: status, Message: msg}
}

// WitnessBinding is what begin persists server-side. The finish step trusts
// only this, never the request.
type WitnessBinding struct {
	UserID       uuid.UUID `json:"user_id"`
	SessionID    string    `json:"session_id,omitempty"`
	DeviceUUID   string    `json:"device_uuid"`
	EKPubkeyHash string    `json:"ek_pubkey_hash"`
	State        string    `json:"state,omitempty"`
}

type witnessChallenge struct {
	ID string `json:"id"`
	WitnessBinding
}

// ── dependencies (narrow, for tests) ─────────────────────────────────────────

type witnessUserReader interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetMFATOTPEnabledAt(ctx context.Context, id uuid.UUID) (*time.Time, error)
}

type witnessPasskeyCounter interface {
	CountActiveByUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error)
}

type witnessPolicyReader interface {
	DeviceWitnessTOTPAllowed(ctx context.Context, tenantID uuid.UUID) (bool, error)
}

type witnessMFAVerifier interface {
	VerifyMFACodeForMethod(ctx context.Context, userID uuid.UUID, code, method string) (bool, error)
	ClaimTOTP(ctx context.Context, userID uuid.UUID, code string) (bool, error)
}

type witnessMinter interface {
	MintWitnessJWS(p WitnessMintParams) (*WitnessJWS, error)
}

type witnessAuditor interface {
	LogUserAction(ctx context.Context, tenantID uuid.UUID, actorID, targetUserID *uuid.UUID, action string, success bool, details map[string]interface{})
}

// WitnessService implements the witness state machine. Safe for concurrent use.
type WitnessService struct {
	rdb      redis.Cmdable
	users    witnessUserReader
	passkeys witnessPasskeyCounter
	policy   witnessPolicyReader
	mfa      witnessMFAVerifier
	minter   witnessMinter
	audit    witnessAuditor
	notifier *SecurityNotificationService
	// totpEnabled is the FALCON_WITNESS_TOTP_ENABLED kill switch.
	totpEnabled bool
	now         func() time.Time
	log         *zap.Logger
}

// WitnessServiceDeps groups the constructor inputs.
type WitnessServiceDeps struct {
	Redis       redis.Cmdable
	Users       witnessUserReader
	Passkeys    witnessPasskeyCounter
	Policy      witnessPolicyReader
	MFA         witnessMFAVerifier
	Minter      witnessMinter
	Audit       witnessAuditor
	Notifier    *SecurityNotificationService
	TOTPEnabled bool
	Logger      *zap.Logger
}

// NewWitnessService builds the service.
func NewWitnessService(d WitnessServiceDeps) *WitnessService {
	log := d.Logger
	if log == nil {
		log = zap.NewNop()
	}
	return &WitnessService{
		rdb: d.Redis, users: d.Users, passkeys: d.Passkeys, policy: d.Policy,
		mfa: d.MFA, minter: d.Minter, audit: d.Audit, notifier: d.Notifier,
		totpEnabled: d.TOTPEnabled, now: time.Now, log: log,
	}
}

// ValidateBinding checks the begin-request fields shared by both methods.
func ValidateWitnessBinding(deviceUUID, ekHash, state string) error {
	if _, err := uuid.Parse(deviceUUID); err != nil {
		return witnessErr(400, WitnessErrBadRequest, "device_uuid must be a valid UUID")
	}
	if !witnessEKHashRE.MatchString(ekHash) {
		return witnessErr(400, WitnessErrBadRequest, "ek_pubkey_hash must be 64 lowercase hex characters")
	}
	if len(state) > witnessStateMax {
		return witnessErr(400, WitnessErrBadRequest, "state must be at most 64 characters")
	}
	return nil
}

// ── passkey binding ──────────────────────────────────────────────────────────

// SavePasskeyBinding persists the begin-time values under the WebAuthn
// ceremony session id.
func (s *WitnessService) SavePasskeyBinding(ctx context.Context, waSessionID string, b WitnessBinding) error {
	if s == nil || s.rdb == nil {
		return witnessErr(503, WitnessErrUnavailable, "witness state store unavailable")
	}
	raw, _ := json.Marshal(b)
	if err := s.rdb.Set(ctx, witnessKeyBinding+waSessionID, raw, witnessBindingTTL).Err(); err != nil {
		return witnessErr(503, WitnessErrUnavailable, "witness state store unavailable")
	}
	return nil
}

// TakePasskeyBinding atomically reads and deletes the binding (single use).
// It must belong to userID.
func (s *WitnessService) TakePasskeyBinding(ctx context.Context, waSessionID string, userID uuid.UUID) (*WitnessBinding, error) {
	if s == nil || s.rdb == nil {
		return nil, witnessErr(503, WitnessErrUnavailable, "witness state store unavailable")
	}
	raw, err := s.rdb.GetDel(ctx, witnessKeyBinding+waSessionID).Result()
	if errors.Is(err, redis.Nil) {
		return nil, witnessErr(410, WitnessErrExpired, "witness session expired or already used; start again")
	}
	if err != nil {
		return nil, witnessErr(503, WitnessErrUnavailable, "witness state store unavailable")
	}
	var b WitnessBinding
	if json.Unmarshal([]byte(raw), &b) != nil || b.UserID != userID {
		return nil, witnessErr(410, WitnessErrExpired, "witness session expired or already used; start again")
	}
	return &b, nil
}

// ── TOTP ─────────────────────────────────────────────────────────────────────

// WitnessTOTPStatus tells the witness page which methods to offer.
type WitnessTOTPStatus struct {
	HasPasskey  bool `json:"has_passkey"`
	HasTOTP     bool `json:"has_totp"`
	TOTPAllowed bool `json:"totp_allowed"` // kill switch AND realm policy
}

// Status computes what the witness page may offer. Best-effort: any lookup
// failure degrades to the safest answer (no TOTP offered).
func (s *WitnessService) Status(ctx context.Context, u *models.CurrentUser) WitnessTOTPStatus {
	var st WitnessTOTPStatus
	if s == nil || u == nil {
		return st
	}
	// Fail safe: a lookup error is treated as "has a passkey" (no TOTP offered).
	n, err := s.passkeys.CountActiveByUser(ctx, u.ID, u.TenantID)
	st.HasPasskey = err != nil || n > 0
	if user, err := s.users.GetByID(ctx, u.ID); err == nil && user != nil {
		st.HasTOTP = user.MFAEnabled && user.MFATOTPEnabled
	}
	if s.totpEnabled {
		if ok, err := s.policy.DeviceWitnessTOTPAllowed(ctx, u.TenantID); err == nil {
			st.TOTPAllowed = ok
		}
	}
	return st
}

// eligible enforces every refusal rule of the TOTP method. Called at begin
// and again at finish (policy or factor state may change in between).
func (s *WitnessService) eligible(ctx context.Context, u *models.CurrentUser) *WitnessError {
	if !u.IsPlatformAdmin || u.TenantID.String() != models.HexxlockInternalTenantID {
		return witnessErr(403, WitnessErrNotPlatformAdmin, "platform admin required")
	}
	if !s.totpEnabled {
		return witnessErr(403, WitnessErrDisabled, "authenticator-app witness is not enabled")
	}
	allowed, err := s.policy.DeviceWitnessTOTPAllowed(ctx, u.TenantID)
	if err != nil {
		return witnessErr(503, WitnessErrUnavailable, "witness policy unavailable")
	}
	if !allowed {
		return witnessErr(403, WitnessErrPolicyOff, "authenticator-app witness is disabled by realm policy")
	}
	n, err := s.passkeys.CountActiveByUser(ctx, u.ID, u.TenantID)
	if err != nil {
		return witnessErr(503, WitnessErrUnavailable, "passkey lookup unavailable")
	}
	if n > 0 {
		return witnessErr(403, WitnessErrHasPasskey, "this account has a passkey; use the passkey to witness the device")
	}
	user, err := s.users.GetByID(ctx, u.ID)
	if err != nil || user == nil {
		return witnessErr(503, WitnessErrUnavailable, "user lookup unavailable")
	}
	if !user.MFAEnabled || !user.MFATOTPEnabled {
		return witnessErr(403, WitnessErrNoTOTP, "set up an authenticator app on your account page first")
	}
	at, err := s.users.GetMFATOTPEnabledAt(ctx, u.ID)
	if err != nil {
		return witnessErr(503, WitnessErrUnavailable, "user lookup unavailable")
	}
	// NULL (legacy rows enrolled before the column existed) counts as old enough.
	if at != nil && s.now().Sub(*at) < witnessMinTOTPAge {
		return witnessErr(403, WitnessErrTOTPTooNew, "the authenticator app was enrolled less than 24 hours ago")
	}
	return nil
}

func (s *WitnessService) locked(ctx context.Context, userID uuid.UUID) (bool, error) {
	n, err := s.rdb.Exists(ctx, witnessKeyLock+userID.String()).Result()
	return n > 0, err
}

// BeginTOTP validates eligibility and the binding, then stores a single-use
// 120s challenge. sessionID is the caller's login session.
func (s *WitnessService) BeginTOTP(ctx context.Context, u *models.CurrentUser, sessionID, deviceUUID, ekHash, state string) (challengeID string, expiresIn time.Duration, err error) {
	if s == nil || s.rdb == nil {
		return "", 0, witnessErr(503, WitnessErrUnavailable, "witness unavailable")
	}
	if werr := s.eligible(ctx, u); werr != nil {
		return "", 0, werr
	}
	if err := ValidateWitnessBinding(deviceUUID, ekHash, state); err != nil {
		return "", 0, err
	}
	lk, lerr := s.locked(ctx, u.ID)
	if lerr != nil {
		return "", 0, witnessErr(503, WitnessErrUnavailable, "witness state store unavailable")
	}
	if lk {
		return "", 0, witnessErr(429, WitnessErrLocked, "too many failed attempts; try again later")
	}
	var idb [16]byte
	if _, rerr := rand.Read(idb[:]); rerr != nil {
		return "", 0, witnessErr(500, WitnessErrUnavailable, "entropy unavailable")
	}
	id := hex.EncodeToString(idb[:])
	raw, _ := json.Marshal(witnessChallenge{ID: id, WitnessBinding: WitnessBinding{
		UserID: u.ID, SessionID: sessionID, DeviceUUID: deviceUUID, EKPubkeyHash: ekHash, State: state,
	}})
	if serr := s.rdb.Set(ctx, witnessKeyChallenge+id, raw, witnessChallengeTTL).Err(); serr != nil {
		return "", 0, witnessErr(503, WitnessErrUnavailable, "witness state store unavailable")
	}
	return id, witnessChallengeTTL, nil
}

// FinishTOTPResult is the successful outcome of FinishTOTP.
type FinishTOTPResult struct {
	JWS   *WitnessJWS
	State string
}

// FinishTOTP verifies the code against the challenge and mints the OTP witness.
// ip/ua feed the notification email and audit event.
func (s *WitnessService) FinishTOTP(ctx context.Context, u *models.CurrentUser, sessionID, challengeID, code, ip, ua string) (*FinishTOTPResult, error) {
	if s == nil || s.rdb == nil {
		return nil, witnessErr(503, WitnessErrUnavailable, "witness unavailable")
	}
	if !witnessIDRE.MatchString(challengeID) {
		return nil, witnessErr(410, WitnessErrExpired, "challenge expired or already used; start again")
	}
	raw, err := s.rdb.Get(ctx, witnessKeyChallenge+challengeID).Result()
	if errors.Is(err, redis.Nil) {
		return nil, witnessErr(410, WitnessErrExpired, "challenge expired or already used; start again")
	}
	if err != nil {
		return nil, witnessErr(503, WitnessErrUnavailable, "witness state store unavailable")
	}
	var ch witnessChallenge
	if json.Unmarshal([]byte(raw), &ch) != nil || ch.UserID != u.ID || ch.SessionID != sessionID {
		// Another user's / session's challenge: indistinguishable from absent.
		return nil, witnessErr(410, WitnessErrExpired, "challenge expired or already used; start again")
	}
	if lk, lerr := s.locked(ctx, u.ID); lerr != nil {
		return nil, witnessErr(503, WitnessErrUnavailable, "witness state store unavailable")
	} else if lk {
		return nil, witnessErr(429, WitnessErrLocked, "too many failed attempts; try again later")
	}
	if werr := s.eligible(ctx, u); werr != nil {
		s.rdb.Del(ctx, witnessKeyChallenge+challengeID)
		return nil, werr
	}

	// Per-challenge attempt cap, atomic via INCR.
	triesKey := witnessKeyTries + challengeID
	tries, err := s.rdb.Incr(ctx, triesKey).Result()
	if err != nil {
		return nil, witnessErr(503, WitnessErrUnavailable, "witness state store unavailable")
	}
	if tries == 1 {
		s.rdb.Expire(ctx, triesKey, witnessChallengeTTL)
	}
	if tries > witnessMaxChallengeTries {
		s.rdb.Del(ctx, witnessKeyChallenge+challengeID)
		return nil, witnessErr(429, WitnessErrExhausted, "too many attempts for this challenge; start again")
	}

	ok := false
	if witnessCodeRE.MatchString(code) { // 6 digits only: never a backup code
		var verr error
		ok, verr = s.mfa.VerifyMFACodeForMethod(ctx, u.ID, code, "totp")
		if verr != nil {
			return nil, witnessErr(503, WitnessErrUnavailable, "verification unavailable")
		}
		if ok {
			fresh, cerr := s.mfa.ClaimTOTP(ctx, u.ID, code)
			if cerr != nil {
				return nil, witnessErr(503, WitnessErrUnavailable, "verification unavailable")
			}
			ok = fresh // already used (login/step-up/witness) -> reject
		}
	}
	if !ok {
		return nil, s.recordFailure(ctx, u, challengeID, int(tries), ip, ua)
	}

	// Single use: whoever deletes the challenge wins.
	if n, derr := s.rdb.Del(ctx, witnessKeyChallenge+challengeID).Result(); derr != nil || n == 0 {
		return nil, witnessErr(410, WitnessErrExpired, "challenge expired or already used; start again")
	}
	s.rdb.Del(ctx, witnessKeyTries+challengeID, witnessKeyFail+u.ID.String())

	jws, merr := s.minter.MintWitnessJWS(WitnessMintParams{
		AdminSub: u.ID.String(), DeviceUUID: ch.DeviceUUID, EKPubkeyHash: ch.EKPubkeyHash, Method: WitnessMethodOTP,
	})
	if merr != nil {
		if errors.Is(merr, ErrNoSigningKey) {
			return nil, witnessErr(503, WitnessErrUnavailable, "signing key not available")
		}
		return nil, witnessErr(500, WitnessErrUnavailable, "failed to mint witness")
	}
	s.afterSuccess(ctx, u, ch.DeviceUUID, ch.EKPubkeyHash, ip, ua)
	return &FinishTOTPResult{JWS: jws, State: ch.State}, nil
}

var witnessIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// recordFailure bumps the per-user failure counter and locks at the cap.
func (s *WitnessService) recordFailure(ctx context.Context, u *models.CurrentUser, challengeID string, tries int, ip, ua string) error {
	failKey := witnessKeyFail + u.ID.String()
	fails, err := s.rdb.Incr(ctx, failKey).Result()
	if err == nil && fails == 1 {
		s.rdb.Expire(ctx, failKey, witnessFailureWindow)
	}
	if err == nil && fails >= witnessMaxUserFailures {
		s.rdb.Set(ctx, witnessKeyLock+u.ID.String(), "1", witnessLockDuration)
		s.rdb.Del(ctx, witnessKeyChallenge+challengeID, failKey)
		s.alertLocked(ctx, u, ip, ua)
		return witnessErr(429, WitnessErrLocked, "too many failed attempts; try again later")
	}
	remaining := witnessMaxChallengeTries - tries
	if remaining <= 0 {
		s.rdb.Del(ctx, witnessKeyChallenge+challengeID)
		return witnessErr(429, WitnessErrExhausted, "too many attempts for this challenge; start again")
	}
	e := witnessErr(401, WitnessErrCodeInvalid, "invalid code")
	e.RemainingAttempts = remaining
	return e
}

func (s *WitnessService) alertLocked(ctx context.Context, u *models.CurrentUser, ip, ua string) {
	uid := u.ID
	if s.audit != nil {
		s.audit.LogUserAction(ctx, u.TenantID, &uid, &uid, "device_witness.totp.locked", false,
			map[string]interface{}{"ip": ip, "lock_minutes": int(witnessLockDuration.Minutes())})
	}
	if s.notifier == nil {
		return
	}
	if user, err := s.users.GetByID(ctx, u.ID); err == nil && user != nil {
		unlock := s.now().Add(witnessLockDuration)
		s.notifier.NotifyAccountLocked(ctx, user, "repeated failed authenticator-app codes while witnessing a device enrollment", &unlock, witnessEventContext(ip, ua))
	}
}

func (s *WitnessService) afterSuccess(ctx context.Context, u *models.CurrentUser, deviceUUID, ekHash, ip, ua string) {
	uid := u.ID
	if s.audit != nil {
		s.audit.LogUserAction(ctx, u.TenantID, &uid, &uid, "device_witness.totp.minted", true,
			map[string]interface{}{"device_uuid": deviceUUID, "ek_pubkey_hash": ekHash, "ip": ip, "method": WitnessMethodOTP})
	}
	if s.notifier == nil {
		return
	}
	if user, err := s.users.GetByID(ctx, u.ID); err == nil && user != nil {
		s.notifier.NotifyDeviceEnrolledViaAuthenticator(ctx, user, deviceUUID, witnessEventContext(ip, ua))
	}
}

func witnessEventContext(ip, ua string) securityEventContext {
	return securityEventContext{Timestamp: time.Now(), IPAddress: ip, DeviceLabel: parseDeviceLabel(ua), UserAgent: ua}
}
