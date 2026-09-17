// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// webAuthnRepo defines the persistence contract for WebAuthn credentials.
// Defined as an interface (not a concrete type) so tests can swap in mocks.
type webAuthnRepo interface {
	Create(ctx context.Context, cred *models.WebAuthnCredential) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.WebAuthnCredential, error)
	GetByCredentialID(ctx context.Context, credentialID []byte) (*models.WebAuthnCredential, error)
	ListByUser(ctx context.Context, userID, tenantID uuid.UUID) ([]models.WebAuthnCredential, error)
	CountActiveByUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error)
	ListDiscoverableByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.WebAuthnCredential, error)
	UpdateSignCount(ctx context.Context, id uuid.UUID, signCount uint32) error
	UpdateLastUsedAt(ctx context.Context, id uuid.UUID) error
	Delete(ctx context.Context, id uuid.UUID) error
	Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID) error
	SetCloneWarning(ctx context.Context, id uuid.UUID) error
}

// webAuthnSessionStorage is the contract for persisting *webauthn.SessionData
// across the begin/finish round-trip. Production wiring uses Redis via
// WebAuthnSessionCache; tests can supply an in-memory implementation.
type webAuthnSessionStorage interface {
	Save(ctx context.Context, sessionID string, data *webauthn.SessionData) error
	Take(ctx context.Context, sessionID string) (*webauthn.SessionData, error)
}

// webAuthnUserLookup resolves a user record by ID. Required by
// FinishAuthentication when the user is not yet authenticated (the standard
// login flow has already collected user_id by then; the conditional/
// discoverable flow uses a different code path).
type webAuthnUserLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	// Update is invoked from FinishRegistration to denormalize the
	// per-user mfa_enabled flag once a WebAuthn credential is
	// persisted. Without this, /oauth/authorize's ACR step-up gate
	// (oauth_provider_handler.go:511-513) routes passkey-only users
	// to /auth/mfa/enrollment instead of /challenge despite their
	// having a phishing-resistant factor — mfa_enabled stays false
	// because nothing was flipping it. Matches the TOTP / email
	// enrollment flow that sets user.MFAEnabled=true + Update().
	Update(ctx context.Context, user *models.User) error
}

// WebAuthnSubject is the narrow identity surface the registration/auth
// ceremonies need from the caller: the persistent user ID + tenant, plus
// the Username/Email used to build the W3C user handle and display name.
//
// Why a dedicated type (vs. *models.User):
//
//   - The handler-side `currentUserToWebAuthnSubject` (webauthn_handler.go)
//     builds this struct from the JWT-derived *models.CurrentUser and
//     carries ONLY 4 fields. The full *models.User has ~30. A previous
//     regression (2026-05-23) passed a partial *models.User from JWT
//     context into `userRepo.Update`, which is a write-all-columns SQL
//     UPDATE, wiping every column not set on the inbound struct.
//   - Narrowing the parameter type at the registration boundary makes
//     it structurally impossible to pass this synthetic struct to
//     `userRepo.Update` by signature — the Go type system rejects the
//     mismatch at compile time. Defense in depth on top of the SQL
//     CASE-WHEN guard in user_repository.go:Update.
//   - The MFA enrollment flow that loads a FULL user from
//     `userRepo.GetByID` builds a WebAuthnSubject at the call site
//     (mfa_enrollment_service.go) — explicit narrowing keeps the
//     contract uniform.
type WebAuthnSubject struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	Username string
	Email    string
}

// WebAuthnService wraps go-webauthn (v0.17+) to provide FIDO2 / WebAuthn
// passkey lifecycle management for Falcon-ID.
//
// Cryptographic verification, attestation parsing, sign-count anomaly
// detection, and replay-resistance are all delegated to the upstream
// library. This service's responsibilities are:
//
//  1. Build the W3C-shaped challenge payload from a persistent user ID.
//  2. Persist the library's *webauthn.SessionData server-side so that the
//     finish step verifies against the original challenge — not whatever
//     the client claims.
//  3. Apply tenant-level attestation policy (AAGUID allowlist, max creds
//     per user, synced-passkey block) BEFORE handing off to the library.
//  4. Hard-reject any credential whose sign-count regressed (W3C §6.1.3
//     declares this evidence of cloning) and emit a CAEP signal so active
//     sessions are re-evaluated.
type WebAuthnService struct {
	repo         webAuthnRepo
	users        webAuthnUserLookup
	sessions     webAuthnSessionStorage
	auditService *AuditService
	caeService   *CAEService
	// caepEmitter is the OpenID CAEP 1.0 transmitter — distinct from
	// caeService (in-process pub/sub). On a successful
	// FinishRegistration we emit credential-change
	// (credential_type=fido2-platform, change_type=create) so every
	// SSF receiver knows a new strong factor was bound. nil-safe.
	caepEmitter *CAEPEmitter
	logger      *zap.Logger
	wa          *webauthn.WebAuthn
}

// SetCAEPEmitter wires the OpenID CAEP 1.0 transmitter into
// WebAuthnService. Safe to call with nil.
func (s *WebAuthnService) SetCAEPEmitter(em *CAEPEmitter) {
	s.caepEmitter = em
}

// WebAuthnConfig wires the relying-party identity to the service.
//
//   - RPID is the eTLD+1 root (e.g. "hexxlock.com"). It is immutable per
//     credential — every previously-registered passkey is bound to this
//     value. Changing RPID after credentials exist invalidates all of them.
//   - RPDisplayName is shown by the authenticator UI during ceremony prompts.
//   - RPOrigins MUST cover every host running the login or accounts UI
//     (e.g. "https://accounts.hexxlock.com", "https://id.hexxlock.com").
//     Subdomains of RPID are not auto-trusted; they must be listed.
type WebAuthnConfig struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

// NewWebAuthnService constructs the service. It returns an error when the
// supplied WebAuthn config is invalid (e.g. RPID is not a valid domain or
// RPOrigins is empty) so misconfigurations surface at boot rather than the
// first ceremony.
func NewWebAuthnService(
	repo *repositories.WebAuthnRepository,
	users webAuthnUserLookup,
	sessions webAuthnSessionStorage,
	auditService *AuditService,
	caeService *CAEService,
	logger *zap.Logger,
	cfg WebAuthnConfig,
) (*WebAuthnService, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// UV=required is the AAL3 baseline per NIST SP 800-63B-4 §5.1.7.
			// Authenticators that cannot enforce user verification (older
			// platform authenticators without biometric) will reject the
			// ceremony — the user falls back to TOTP / email-OTP. This is
			// intentional: tier-1 means upgrade path, not breakage.
			UserVerification: protocol.VerificationRequired,
			// ResidentKey=required ensures discoverable credentials so
			// usernameless / conditional-UI passkey login works without a
			// prior username step.
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
		},
		// Conveyance=none keeps attestation light by default; tenants that
		// require attestation enforcement use AttestationPolicy.RequireAttestation
		// (checked before persistence below).
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.New: %w", err)
	}
	return &WebAuthnService{
		repo:         repo,
		users:        users,
		sessions:     sessions,
		auditService: auditService,
		caeService:   caeService,
		logger:       logger,
		wa:           wa,
	}, nil
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// RegistrationChallenge is what the begin endpoint returns to the browser.
// It carries the standard W3C PublicKeyCredentialCreationOptions plus an
// opaque ceremony ID the client echoes back on finish so the server can
// look up the SessionData (which carries the challenge to verify).
type RegistrationChallenge struct {
	PublicKey *protocol.CredentialCreation `json:"publicKey"`
	SessionID string                       `json:"wa_session_id"`
}

// AuthenticationChallenge is the assertion-side analogue of
// RegistrationChallenge.
type AuthenticationChallenge struct {
	PublicKey *protocol.CredentialAssertion `json:"publicKey"`
	SessionID string                        `json:"wa_session_id"`
}

// BeginRegistration generates a PublicKeyCredentialCreationOptions payload
// and persists the SessionData server-side. The returned RegistrationChallenge
// is JSON-shaped for direct consumption by @simplewebauthn/browser or the
// raw navigator.credentials.create() API.
//
// Takes a `*WebAuthnSubject` (not `*models.User`) by design — see the
// type doc for the rationale.
func (s *WebAuthnService) BeginRegistration(
	ctx context.Context,
	subject *WebAuthnSubject,
	friendlyName string,
) (*RegistrationChallenge, error) {
	// Pull existing creds so the library can populate exclusionList — this
	// prevents the user from registering the same authenticator twice.
	existing, err := s.repo.ListByUser(ctx, subject.ID, subject.TenantID)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginRegistration: list existing: %w", err)
	}
	// Build a thin *models.User scoped to library wrapping. Never escapes
	// this function; never reaches userRepo.Update.
	user := &models.User{
		ID:       subject.ID,
		TenantID: subject.TenantID,
		Username: subject.Username,
		Email:    subject.Email,
	}
	wu := newWebAuthnUser(user, existing, true /* activeOnly */)

	exclusions := make([]protocol.CredentialDescriptor, 0, len(wu.WebAuthnCredentials()))
	for _, c := range wu.WebAuthnCredentials() {
		exclusions = append(exclusions, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.ID,
		})
	}

	creation, sessionData, err := s.wa.BeginRegistration(wu, webauthn.WithExclusions(exclusions))
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginRegistration: library: %w", err)
	}

	sessionID, err := NewSessionID()
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginRegistration: session id: %w", err)
	}
	if err := s.sessions.Save(ctx, sessionID, sessionData); err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginRegistration: persist session: %w", err)
	}

	s.logger.Info("WebAuthn registration ceremony started",
		zap.String("user_id", subject.ID.String()),
		zap.String("tenant_id", subject.TenantID.String()),
		zap.String("friendly_name", friendlyName),
	)

	return &RegistrationChallenge{
		PublicKey: creation,
		SessionID: sessionID,
	}, nil
}

// FinishRegistration verifies the authenticator response against the stored
// SessionData and persists the resulting credential. Tenant policy is
// applied BEFORE persistence so that a violating credential never lands in
// the DB.
//
// Takes a `*WebAuthnSubject` (not `*models.User`) by design — see the
// type doc for the rationale.
func (s *WebAuthnService) FinishRegistration(
	ctx context.Context,
	subject *WebAuthnSubject,
	sessionID, friendlyName string,
	policy models.AttestationPolicy,
	r *http.Request,
) (*models.WebAuthnCredential, error) {
	sessionData, err := s.sessions.Take(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.FinishRegistration: load session: %w", err)
	}

	existing, err := s.repo.ListByUser(ctx, subject.ID, subject.TenantID)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.FinishRegistration: list existing: %w", err)
	}
	// Build a thin *models.User scoped to library wrapping. Never escapes
	// this function; never reaches userRepo.Update (the MFA flip below
	// uses GetByID to load the FULL row first).
	user := &models.User{
		ID:       subject.ID,
		TenantID: subject.TenantID,
		Username: subject.Username,
		Email:    subject.Email,
	}
	wu := newWebAuthnUser(user, existing, true)

	libCred, err := s.wa.FinishRegistration(wu, *sessionData, r)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.FinishRegistration: verify: %w", err)
	}

	if err := s.applyAttestationPolicy(libCred, policy, len(existing)); err != nil {
		return nil, err
	}

	cred := fromLibraryCredential(libCred, subject.ID, subject.TenantID, friendlyName)
	if err := s.repo.Create(ctx, cred); err != nil {
		return nil, fmt.Errorf("WebAuthnService.FinishRegistration: persist: %w", err)
	}

	// Denormalize: flip the user's mfa_enabled summary flag so the
	// OAuth /authorize ACR step-up gate recognises this user has at
	// least one factor and routes them to /auth/mfa/challenge (not
	// /enrollment). Best-effort — the credential is already persisted
	// and serves as the authoritative state; a failure here is logged
	// but doesn't roll back the registration.
	//
	// MUST re-fetch the full user row via GetByID before calling Update —
	// the WebAuthnSubject parameter carries only ID/TenantID/Username/Email,
	// and userRepo.Update writes all columns. A partial-struct Update
	// would wipe Email/EmailHash/IsActive/IsEmailVerified/PasswordHash/etc.
	// SQL-level CASE-WHEN guard in user_repository.go:Update is the
	// belt-and-suspenders backup; this caller-side re-fetch is the
	// primary defense + matches the push_mfa_service.go:195-200 pattern.
	// Live regression (2026-05-23): the prior partial-struct call wiped
	// the row and locked the user out via the discover-flow
	// "Restricted access" branch.
	fullUser, getErr := s.users.GetByID(ctx, subject.ID)
	if getErr != nil || fullUser == nil {
		s.logger.Warn("WebAuthn credential persisted but failed to reload user for mfa_enabled flip",
			zap.String("user_id", subject.ID.String()),
			zap.Error(getErr),
		)
	} else if !fullUser.MFAEnabled {
		fullUser.MFAEnabled = true
		if updErr := s.users.Update(ctx, fullUser); updErr != nil {
			s.logger.Warn("WebAuthn credential persisted but failed to set user.mfa_enabled",
				zap.String("user_id", subject.ID.String()),
				zap.Error(updErr),
			)
		}
	}

	s.logger.Info("WebAuthn credential registered",
		zap.String("credential_id", cred.ID.String()),
		zap.String("user_id", subject.ID.String()),
		zap.String("tenant_id", subject.TenantID.String()),
		zap.String("friendly_name", friendlyName),
		zap.Bool("backup_eligible", cred.BackupEligible),
		zap.Bool("is_discoverable", cred.IsDiscoverable),
	)

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, subject.TenantID, &subject.ID, nil, "webauthn_credential_registered", true, map[string]interface{}{
			"credential_id":   cred.ID.String(),
			"friendly_name":   friendlyName,
			"backup_eligible": cred.BackupEligible,
			"is_discoverable": cred.IsDiscoverable,
		})
	}

	// CAEP 1.0 credential-change SET — push to every SSF receiver so
	// they know a new fido2-platform factor was bound. Background
	// goroutine so the ceremony response isn't gated on receiver
	// reachability.
	if s.caepEmitter != nil && subject.TenantID != uuid.Nil {
		go func(tid, uid uuid.UUID) { //nolint:gosec // goroutine must outlive request ctx
			_ = s.caepEmitter.EmitCredentialChange(
				context.Background(),
				tid, uid,
				"fido2-platform",
				"create",
				"webauthn_enrollment",
			)
		}(subject.TenantID, subject.ID)
	}

	return cred, nil
}

// applyAttestationPolicy enforces tenant-level constraints on a freshly
// minted *webauthn.Credential. Returns an error to short-circuit
// persistence when the credential violates any rule.
func (s *WebAuthnService) applyAttestationPolicy(libCred *webauthn.Credential, policy models.AttestationPolicy, currentCount int) error {
	if policy.RequireAttestation && (libCred.AttestationType == "" || libCred.AttestationType == metadataNone) {
		return errors.New("WebAuthnService: tenant policy requires a verifiable attestation statement")
	}
	if policy.BlockSyncedPasskeys && libCred.Flags.BackupEligible {
		return errors.New("WebAuthnService: tenant policy blocks backup-eligible (synced) credentials")
	}
	if len(policy.AllowedAAGUIDs) > 0 {
		aaguidHex := hex.EncodeToString(libCred.Authenticator.AAGUID)
		if !containsAAGUID(policy.AllowedAAGUIDs, aaguidHex) {
			return fmt.Errorf("WebAuthnService: authenticator AAGUID %s is not in the tenant allowlist", aaguidHex)
		}
	}
	if policy.MaxCredentialsPerUser > 0 && currentCount >= policy.MaxCredentialsPerUser {
		return fmt.Errorf("WebAuthnService: user has reached the maximum of %d credentials allowed by tenant policy", policy.MaxCredentialsPerUser)
	}
	return nil
}

// metadataNone is the protocol-level "none" attestation marker.
const metadataNone = "none"

// ---------------------------------------------------------------------------
// Standard authentication (username-first)
// ---------------------------------------------------------------------------

// BeginAuthentication issues a credential-assertion challenge for a known
// user. allowedCredentials is populated from the user's active credentials
// so the browser can hint to the authenticator which key to use.
func (s *WebAuthnService) BeginAuthentication(
	ctx context.Context,
	userID, tenantID uuid.UUID,
) (*AuthenticationChallenge, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginAuthentication: user lookup: %w", err)
	}
	if user == nil {
		return nil, errors.New("WebAuthnService.BeginAuthentication: user not found")
	}
	dbCreds, err := s.repo.ListByUser(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginAuthentication: list creds: %w", err)
	}
	wu := newWebAuthnUser(user, dbCreds, true)
	if len(wu.WebAuthnCredentials()) == 0 {
		return nil, errors.New("WebAuthnService.BeginAuthentication: no active credentials registered")
	}

	assertion, sessionData, err := s.wa.BeginLogin(wu)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginAuthentication: library: %w", err)
	}

	sessionID, err := NewSessionID()
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginAuthentication: session id: %w", err)
	}
	if err := s.sessions.Save(ctx, sessionID, sessionData); err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginAuthentication: persist session: %w", err)
	}

	return &AuthenticationChallenge{
		PublicKey: assertion,
		SessionID: sessionID,
	}, nil
}

// FinishAuthentication verifies the assertion. On success it returns the
// matched WebAuthnCredential and the *models.User who owns it, with a
// hard-reject + clone signal emitted on any sign-count anomaly.
func (s *WebAuthnService) FinishAuthentication(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	sessionID string,
	r *http.Request,
) (*models.WebAuthnCredential, *models.User, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("WebAuthnService.FinishAuthentication: user lookup: %w", err)
	}
	if user == nil {
		return nil, nil, errors.New("WebAuthnService.FinishAuthentication: user not found")
	}
	dbCreds, err := s.repo.ListByUser(ctx, userID, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("WebAuthnService.FinishAuthentication: list creds: %w", err)
	}
	wu := newWebAuthnUser(user, dbCreds, true)

	sessionData, err := s.sessions.Take(ctx, sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("WebAuthnService.FinishAuthentication: load session: %w", err)
	}

	libCred, err := s.wa.FinishLogin(wu, *sessionData, r)
	if err != nil {
		return nil, nil, fmt.Errorf("WebAuthnService.FinishAuthentication: verify: %w", err)
	}

	dbCred, err := s.completeAuthentication(ctx, libCred, tenantID)
	if err != nil {
		return nil, nil, err
	}
	return dbCred, user, nil
}

// ---------------------------------------------------------------------------
// Conditional / discoverable authentication (passkey autofill)
// ---------------------------------------------------------------------------

// BeginConditionalLogin issues a discoverable-credential assertion challenge.
// No allowedCredentials are advertised — the authenticator chooses from its
// resident keys when the user activates the autofill UI.
func (s *WebAuthnService) BeginConditionalLogin(
	ctx context.Context,
	tenantID uuid.UUID,
) (*AuthenticationChallenge, error) {
	// Sanity-check: tenant must have at least one discoverable credential
	// before we hand out a challenge.
	creds, err := s.repo.ListDiscoverableByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginConditionalLogin: list discoverable: %w", err)
	}
	if len(creds) == 0 {
		return nil, errors.New("WebAuthnService.BeginConditionalLogin: no discoverable credentials in tenant")
	}

	assertion, sessionData, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginConditionalLogin: library: %w", err)
	}

	sessionID, err := NewSessionID()
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginConditionalLogin: session id: %w", err)
	}
	if err := s.sessions.Save(ctx, sessionID, sessionData); err != nil {
		return nil, fmt.Errorf("WebAuthnService.BeginConditionalLogin: persist session: %w", err)
	}
	return &AuthenticationChallenge{
		PublicKey: assertion,
		SessionID: sessionID,
	}, nil
}

// FinishConditionalLogin completes the discoverable-credential ceremony.
// The library invokes the DiscoverableUserHandler with rawID + userHandle;
// we use those to resolve the credential row + owner before delegating
// verification to the library.
func (s *WebAuthnService) FinishConditionalLogin(
	ctx context.Context,
	tenantID uuid.UUID,
	sessionID string,
	r *http.Request,
) (*models.WebAuthnCredential, *models.User, error) {
	sessionData, err := s.sessions.Take(ctx, sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("WebAuthnService.FinishConditionalLogin: load session: %w", err)
	}

	var resolvedUser *models.User

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		userID, parseErr := uuid.FromBytes(userHandle)
		if parseErr != nil {
			return nil, fmt.Errorf("WebAuthnService.FinishConditionalLogin: invalid user handle: %w", parseErr)
		}
		u, err := s.users.GetByID(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("WebAuthnService.FinishConditionalLogin: user lookup: %w", err)
		}
		if u == nil {
			return nil, errors.New("WebAuthnService.FinishConditionalLogin: user not found")
		}
		if u.TenantID != tenantID {
			return nil, errors.New("WebAuthnService.FinishConditionalLogin: user does not belong to tenant")
		}
		dbCreds, err := s.repo.ListByUser(ctx, userID, tenantID)
		if err != nil {
			return nil, fmt.Errorf("WebAuthnService.FinishConditionalLogin: list creds: %w", err)
		}
		var match *models.WebAuthnCredential
		for i := range dbCreds {
			c := &dbCreds[i]
			if c.IsActive() && bytesEqual(c.CredentialID, rawID) {
				match = c
				break
			}
		}
		if match == nil {
			return nil, errors.New("WebAuthnService.FinishConditionalLogin: credential not found or inactive")
		}
		resolvedUser = u
		return newWebAuthnUser(u, dbCreds, true), nil
	}

	parsed, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		return nil, nil, fmt.Errorf("WebAuthnService.FinishConditionalLogin: parse: %w", err)
	}

	libCred, err := s.wa.ValidateDiscoverableLogin(handler, *sessionData, parsed)
	if err != nil {
		return nil, nil, fmt.Errorf("WebAuthnService.FinishConditionalLogin: verify: %w", err)
	}
	if resolvedUser == nil {
		return nil, nil, errors.New("WebAuthnService.FinishConditionalLogin: handler did not resolve user")
	}

	dbCred, err := s.completeAuthentication(ctx, libCred, tenantID)
	if err != nil {
		return nil, nil, err
	}
	return dbCred, resolvedUser, nil
}

// ---------------------------------------------------------------------------
// Sign-count enforcement & post-verification finalisation
// ---------------------------------------------------------------------------

// completeAuthentication runs the post-verification path that's identical
// for both standard and conditional flows: hard-reject sign-count
// regression, persist the new sign count, audit-log success, return the
// updated row.
//
// The library's [Credential.Authenticator.CloneWarning] field is set when a
// regression is detected, but the library does NOT short-circuit the
// verification itself — it leaves the policy decision to the RP. W3C
// WebAuthn §6.1.3 is explicit: "If less than or equal to the stored value,
// the Relying Party SHOULD treat this as a signal that the authenticator
// may be cloned." We treat it as a hard error AND emit a CAEP signal so
// existing sessions on the affected user/tenant are revoked downstream.
func (s *WebAuthnService) completeAuthentication(
	ctx context.Context,
	libCred *webauthn.Credential,
	tenantID uuid.UUID,
) (*models.WebAuthnCredential, error) {
	dbCred, err := s.repo.GetByCredentialID(ctx, libCred.ID)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.completeAuthentication: lookup: %w", err)
	}
	if dbCred == nil {
		return nil, errors.New("WebAuthnService.completeAuthentication: credential not found post-verify")
	}

	if libCred.Authenticator.CloneWarning {
		if err := s.repo.SetCloneWarning(ctx, dbCred.ID); err != nil {
			s.logger.Error("WebAuthn: failed to persist clone warning",
				zap.String("credential_id", dbCred.ID.String()),
				zap.Error(err),
			)
		}
		if err := s.repo.Revoke(ctx, dbCred.ID, dbCred.UserID); err != nil {
			s.logger.Error("WebAuthn: failed to auto-revoke cloned credential",
				zap.String("credential_id", dbCred.ID.String()),
				zap.Error(err),
			)
		}
		s.emitCloneCompromiseEvent(ctx, dbCred, tenantID)
		s.logger.Warn("WebAuthn sign-count regression — credential auto-revoked",
			zap.String("credential_id", dbCred.ID.String()),
			zap.String("user_id", dbCred.UserID.String()),
			zap.Uint32("stored_count", dbCred.SignCount),
			zap.Uint32("received_count", libCred.Authenticator.SignCount),
		)
		return nil, errors.New("WebAuthnService.completeAuthentication: sign-count regression — credential revoked")
	}

	if err := s.repo.UpdateSignCount(ctx, dbCred.ID, libCred.Authenticator.SignCount); err != nil {
		return nil, fmt.Errorf("WebAuthnService.completeAuthentication: update sign count: %w", err)
	}
	dbCred.SignCount = libCred.Authenticator.SignCount
	now := time.Now().UTC()
	dbCred.LastUsedAt = &now

	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, &dbCred.UserID, nil, "webauthn_authentication", true, map[string]interface{}{
			"credential_id": dbCred.ID.String(),
		})
	}

	return dbCred, nil
}

// emitCloneCompromiseEvent fans a CAEP credential_compromised event so any
// active session bearing the affected credential is revoked downstream.
// Best-effort: failures are logged-only because the credential has already
// been auto-revoked above and a session-revocation event is recoverable.
func (s *WebAuthnService) emitCloneCompromiseEvent(ctx context.Context, dbCred *models.WebAuthnCredential, tenantID uuid.UUID) {
	if s.caeService == nil {
		return
	}
	if err := s.caeService.OnCredentialCompromised(ctx, dbCred.UserID, tenantID, dbCred.ID); err != nil {
		s.logger.Error("WebAuthn: failed to emit CAEP credential_compromised",
			zap.String("credential_id", dbCred.ID.String()),
			zap.Error(err),
		)
	}
}

// ---------------------------------------------------------------------------
// Credential management
// ---------------------------------------------------------------------------

// ListCredentials returns all WebAuthn credentials registered by the given
// user within the given tenant, including revoked / expired entries so the
// security UI can display full history.
func (s *WebAuthnService) ListCredentials(ctx context.Context, userID, tenantID uuid.UUID) ([]models.WebAuthnCredential, error) {
	creds, err := s.repo.ListByUser(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnService.ListCredentials: %w", err)
	}
	return creds, nil
}

// DeleteCredential removes a credential after verifying ownership.
func (s *WebAuthnService) DeleteCredential(ctx context.Context, credID, userID, tenantID uuid.UUID) error {
	creds, err := s.repo.ListByUser(ctx, userID, tenantID)
	if err != nil {
		return fmt.Errorf("WebAuthnService.DeleteCredential: list: %w", err)
	}
	found := false
	for i := range creds {
		if creds[i].ID == credID {
			found = true
			break
		}
	}
	if !found {
		return errors.New("WebAuthnService.DeleteCredential: credential not found for user")
	}
	if err := s.repo.Delete(ctx, credID); err != nil {
		return fmt.Errorf("WebAuthnService.DeleteCredential: delete: %w", err)
	}
	s.logger.Info("WebAuthn credential deleted",
		zap.String("credential_id", credID.String()),
		zap.String("user_id", userID.String()),
	)
	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, &userID, nil, "webauthn_credential_deleted", true, map[string]interface{}{
			"credential_id": credID.String(),
		})
	}
	if s.caepEmitter != nil && tenantID != uuid.Nil {
		go func(tid, uid uuid.UUID) { //nolint:gosec // outlives request ctx
			_ = s.caepEmitter.EmitCredentialChange(
				context.Background(),
				tid, uid,
				"fido2-platform",
				"delete",
				"user_self_service_delete",
			)
		}(tenantID, userID)
	}
	return nil
}

// AdminRevokeCredential marks a credential revoked on behalf of an admin.
// Unlike Delete, the row is preserved for audit purposes and subsequent
// authentications fail because IsActive() returns false.
func (s *WebAuthnService) AdminRevokeCredential(ctx context.Context, credID, adminID, tenantID uuid.UUID) error {
	if err := s.repo.Revoke(ctx, credID, adminID); err != nil {
		return fmt.Errorf("WebAuthnService.AdminRevokeCredential: revoke: %w", err)
	}
	s.logger.Warn("WebAuthn credential revoked by admin",
		zap.String("credential_id", credID.String()),
		zap.String("admin_id", adminID.String()),
		zap.String("tenant_id", tenantID.String()),
	)
	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, &adminID, nil, "webauthn_credential_revoked", true, map[string]interface{}{
			"credential_id": credID.String(),
			"revoked_by":    adminID.String(),
		})
	}
	// AdminRevokeCredential is initiated_by=admin; the CAEP receiver
	// can branch on this vs the user-initiated delete above for IR
	// scoring. We don't have the affected user ID at this entry-point
	// (only credID + adminID), so we resolve via the row before
	// emitting. Lookup failure → log + skip, since the revoke already
	// succeeded.
	if s.caepEmitter != nil && tenantID != uuid.Nil {
		if cred, lookupErr := s.repo.GetByID(ctx, credID); lookupErr == nil && cred != nil {
			go func(tid, uid uuid.UUID) { //nolint:gosec // outlives request ctx
				_ = s.caepEmitter.EmitCredentialChange(
					context.Background(),
					tid, uid,
					"fido2-platform",
					"revoke",
					"admin_revoked",
				)
			}(tenantID, cred.UserID)
		} else {
			s.logger.Warn("AdminRevokeCredential: skip CAEP emit; cred lookup failed after revoke",
				zap.String("credential_id", credID.String()),
				zap.Error(lookupErr),
			)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// containsAAGUID reports whether aaguidHex matches any entry in the allowlist.
// Comparison is case-insensitive and tolerates the two common formats
// (raw 32-char hex vs hyphen-separated UUID).
func containsAAGUID(allowlist []string, aaguidHex string) bool {
	if len(aaguidHex) == 32 {
		aaguidHex = aaguidHex[0:8] + "-" +
			aaguidHex[8:12] + "-" +
			aaguidHex[12:16] + "-" +
			aaguidHex[16:20] + "-" +
			aaguidHex[20:]
	}
	for _, allowed := range allowlist {
		if equalFoldASCII(allowed, aaguidHex) {
			return true
		}
	}
	return false
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
