// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/metrics"
)

// OAuthClientReader is the minimal interface for fetching OAuth clients needed
// by the back-channel logout service.
type OAuthClientReader interface {
	// GetByID returns an OAuth client by its client_id string.
	GetByID(ctx context.Context, clientID string) (*OAuthClientRecord, error)
}

const serviceNameFalconID = "falcon-id"

// OAuthClientLister lists all OAuth clients that have a backchannel logout URI
// configured for a given tenant.
type OAuthClientLister interface {
	GetClientsWithBackchannelLogout(ctx context.Context, tenantID uuid.UUID) ([]OAuthClientRecord, error)
}

// TokenSigner signs JWTs for logout tokens.
type TokenSigner interface {
	SignLogoutToken(claims jwt.Claims) (string, error)
}

// OAuthClientRecord holds the fields required by back-channel logout.
type OAuthClientRecord struct {
	ClientID                   string
	BackchannelLogoutURI       string
	BackchannelSessionRequired bool
}

// SessionInvalidator is the minimal interface the backchannel service needs to
// remove server-side sessions on logout.
type SessionInvalidator interface {
	InvalidateByUserID(ctx context.Context, userID uuid.UUID, exceptSessionID string) error
}

// BackchannelLogoutConfig holds operational settings for back-channel
// logout fan-out at the writer layer. Delivery-side knobs (HTTP
// timeout, retry budget, concurrency) live on
// BackchannelLogoutDrainerConfig — the drainer owns delivery, this
// service owns enqueue.
//
// As of feat/tier1-bcl-outbox-drainer the writer no longer performs
// HTTP delivery directly; the only knob remaining at this layer is
// kept for future use (e.g., per-call timeout caps on enqueue) but
// the struct is preserved so downstream callers don't break.
type BackchannelLogoutConfig struct{}

// DefaultBackchannelLogoutConfig returns conservative production defaults.
//
// The legacy BACKCHANNEL_LOGOUT_ENDPOINTS env-var-driven static-endpoint
// path was removed in `feat/tier1-slo-restoration` once the canonical
// DB-seeded path was restored via cmd/oauth_client_slo_bootstrap.go.
// Static URIs in env are an anti-pattern for tier-1 multi-RP estates:
// they bypass tenant scoping, can't be validated against the OAuth
// client list, and create silent dual-source-of-truth between env and
// iam_oauth_clients.
//
// The legacy in-memory retry knobs (HTTPTimeout, MaxRetries,
// MaxConcurrency) moved to BackchannelLogoutDrainerConfig — see
// internal/services/backchannel_logout_drainer.go.
func DefaultBackchannelLogoutConfig() BackchannelLogoutConfig {
	return BackchannelLogoutConfig{}
}

// backchannelLogoutClaims are the JWT claims for an OIDC back-channel logout token.
// Per spec (§2.4) the token MUST contain iss, sub, aud, iat, jti, and the
// "events" claim; it MUST NOT contain a nonce.
type backchannelLogoutClaims struct {
	jwt.RegisteredClaims
	// Events is the required OIDC logout event claim.
	Events map[string]interface{} `json:"events"`
	// Sid is included only when BackchannelSessionRequired is set on the client.
	Sid string `json:"sid,omitempty"`
}

// OAuthLogoutOutboxEnqueuer is the minimal interface
// BackchannelLogoutService needs from the outbox repository to write
// rows. Defined here so the service can be unit-tested without a
// real *repositories.OAuthLogoutOutboxRepository.
type OAuthLogoutOutboxEnqueuer interface {
	Insert(ctx context.Context, tx repositories.DBTX, row *repositories.OAuthLogoutOutboxRow) error
}

// BCLAuditPublisher is the minimal interface for emitting structured
// audit events from the BCL pipeline to the integration-bus / NATS /
// audit-archiver chain. Defined here so the service can be unit-
// tested without a real *IntegrationBusPublisher.
type BCLAuditPublisher interface {
	PublishEvent(ctx context.Context, tenantID, eventType string, payload interface{}) error
}

// BCLAuditPayload is the canonical audit-event payload emitted by
// every BCL pipeline state transition. Lands in the audit-archive
// MinIO bucket via the existing audit-archiver NATS pipeline (see
// operational notes); 7-year WORM
// retention per operational notes.
//
// Field shape mirrors what an auditor needs to reconstruct a Sign Out
// cascade after the fact: who logged out (Sub), from which session
// (Sid), to which RP did we attempt delivery (RPClientID), did it
// succeed (Outcome), and how many attempts (AttemptCount).
type BCLAuditPayload struct {
	EventType     string `json:"event_type"` // bcl_enqueued | bcl_delivered | bcl_dead
	RPClientID    string `json:"rp_client_id"`
	Sub           string `json:"sub,omitempty"`
	Sid           string `json:"sid,omitempty"`
	JTI           string `json:"jti"`
	Outcome       string `json:"outcome"` // queued | sent | dead
	AttemptCount  int    `json:"attempt_count,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	TimestampUnix int64  `json:"timestamp_unix"`
}

// Canonical event_type strings emitted on the integration-bus topic
// `example.iam.bcl.*`. Receivers (audit-archiver) route by these.
const (
	BCLEventTypeEnqueued  = "example.iam.bcl.enqueued"
	BCLEventTypeDelivered = "example.iam.bcl.delivered"
	BCLEventTypeDead      = "example.iam.bcl.dead"
)

// BackchannelLogoutService enqueues OIDC back-channel logout tokens
// into iam_oauth_logout_outbox when a user session is terminated.
// HTTP delivery is owned by BackchannelLogoutDrainer (separate
// goroutine, persistent retry, advisory-lock-serialized).
//
// This service implements the WRITER side of the transactional
// outbox pattern: NotifyLogout signs one logout_token per RP
// registered for the user's tenant and INSERTs an outbox row per
// token. The drainer picks up pending rows on its tick.
//
// The legacy in-memory delivery loop (deliverToClient) was removed in
// feat/tier1-bcl-outbox-drainer because pod restart mid-fan-out lost
// every in-flight delivery; the outbox restores at-least-once
// delivery with bounded staleness.
type BackchannelLogoutService struct {
	clients      OAuthClientReader
	sessions     SessionInvalidator
	clientLister OAuthClientLister
	tokenSigner  TokenSigner
	outbox       OAuthLogoutOutboxEnqueuer
	receiverCfg  *BackchannelLogoutReceiverConfig
	jwksCache    *receiverJWKSCache // lazy-init on first Receive()
	auditPub     BCLAuditPublisher
	cfg          BackchannelLogoutConfig
	logger       *zap.Logger
}

// NewBackchannelLogoutService constructs a BackchannelLogoutService.
// clients and sessions may be nil; the service degrades gracefully (logs and
// returns nil) when dependencies are absent so startup is never blocked.
func NewBackchannelLogoutService(
	clients OAuthClientReader,
	sessions SessionInvalidator,
	cfg BackchannelLogoutConfig,
	logger *zap.Logger,
) *BackchannelLogoutService {
	return &BackchannelLogoutService{
		clients:  clients,
		sessions: sessions,
		cfg:      cfg,
		logger:   logger,
	}
}

// SetClientLister injects the OAuthClientLister dependency after construction.
func (s *BackchannelLogoutService) SetClientLister(lister OAuthClientLister) {
	s.clientLister = lister
}

// SetTokenSigner injects the TokenSigner dependency after construction.
func (s *BackchannelLogoutService) SetTokenSigner(signer TokenSigner) {
	s.tokenSigner = signer
}

// SetOutboxEnqueuer injects the outbox writer dependency after construction.
// Production wires *repositories.OAuthLogoutOutboxRepository here.
func (s *BackchannelLogoutService) SetOutboxEnqueuer(outbox OAuthLogoutOutboxEnqueuer) {
	s.outbox = outbox
}

// SetAuditPublisher wires the integration-bus publisher used to emit
// structured BCL audit events. Optional: when nil, audit emission is
// a no-op and only the Prometheus counters + structured zap logs
// carry the diagnostic trail. Audit events land in the WORM
// audit-archive MinIO bucket with 7yr object-lock retention via the
// existing audit-archiver NATS pipeline.
func (s *BackchannelLogoutService) SetAuditPublisher(pub BCLAuditPublisher) {
	s.auditPub = pub
}

// emitAuditEvent fires a structured audit event in a detached
// goroutine. context.Background() is used (not the request ctx)
// because the audit emission must complete even if the request that
// triggered it has long since returned to the user.
//
// All errors are logged but never propagated — audit publishing is
// strictly best-effort; the BCL pipeline succeeds regardless.
func (s *BackchannelLogoutService) emitAuditEvent(tenantID, eventType string, payload BCLAuditPayload) {
	if s.auditPub == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.auditPub.PublishEvent(ctx, tenantID, eventType, payload); err != nil {
			s.logger.Warn("BackchannelLogout: failed to publish audit event",
				zap.String("event_type", eventType),
				zap.String("rp_client_id", payload.RPClientID),
				zap.String("jti", payload.JTI),
				zap.Error(err),
			)
		}
	}()
}

// NotifyLogout sends a back-channel logout token to every OAuth client
// registered for tenantID that has a backchannel_logout_uri. It is
// best-effort: individual delivery failures are logged but never propagated to
// the caller so the overall logout is never blocked.
//
// The tenantID parameter restricts the fan-out to clients belonging to the
// user's own tenant.
func (s *BackchannelLogoutService) NotifyLogout(ctx context.Context, userID uuid.UUID, sessionID string, tenantID uuid.UUID) error {
	if s.tokenSigner == nil {
		s.logger.Debug("BackchannelLogout.NotifyLogout: token signer not wired, skipping")
		return nil
	}

	if s.clientLister == nil {
		// No lister wired — fan-out is not possible. This branch is hit
		// during early bootstrap and in tests; production dependency
		// injection always wires the lister via SetClientLister.
		s.logger.Debug("BackchannelLogout.NotifyLogout: client lister not wired, skipping")
		return nil
	}

	clients, err := s.clientLister.GetClientsWithBackchannelLogout(ctx, tenantID)
	if err != nil {
		s.logger.Error("BackchannelLogout.NotifyLogout: failed to list clients",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		// Best-effort: do not block the user-driven Sign Out on a transient
		// DB read failure. The next Sign Out will retry the lookup; the
		// session is already invalidated locally so subsequent requests
		// from the user's browser are blocked even if BCL never fires.
		return nil
	}

	metrics.OAuthBCLFanOutSize.Observe(float64(len(clients)))

	if len(clients) == 0 {
		// REGRESSION SIGNAL: a Sign Out reached the OP-side fan-out path
		// but no RPs are registered. After the 2026-05-10 SLO seed
		// restoration (cmd/oauth_client_slo_bootstrap.go), the platform
		// tenant MUST have at minimum svc-talon and svc-accounts as
		// fan-out targets. Zero-clients on the platform tenant means
		// either a fresh-initdb wiped the seed (replay
		// `bootstrapOAuthClientSLOSeed` on next pod restart fixes it)
		// or a tenant has genuinely zero first-party RPs (legitimate
		// for non-platform tenants but worth surfacing). See
		// docs/audits/2026-05-10-slo-bcl-fcl-regression.md.
		metrics.OAuthBCLNoClients.WithLabelValues(tenantID.String()).Inc()
		s.logger.Warn("BackchannelLogout.NotifyLogout: zero RPs registered for tenant — Sign Out will not propagate",
			zap.String("user_id", userID.String()),
			zap.String("session_id", sessionID),
			zap.String("tenant_id", tenantID.String()),
		)
		return nil
	}

	if s.outbox == nil {
		s.logger.Warn("BackchannelLogout.NotifyLogout: outbox enqueuer not wired, dropping fan-out",
			zap.String("tenant_id", tenantID.String()),
			zap.Int("dropped_client_count", len(clients)),
		)
		return nil
	}

	s.logger.Info("BackchannelLogout.NotifyLogout: enqueuing logout tokens",
		zap.String("user_id", userID.String()),
		zap.String("session_id", sessionID),
		zap.String("tenant_id", tenantID.String()),
		zap.Int("client_count", len(clients)),
	)

	// One outbox row per RP. Per-row errors are logged but never block
	// subsequent rows — the user-driven Sign Out has already completed
	// and we don't want to lose 9 of 10 enqueues because one INSERT
	// failed.
	subStr := userID.String()
	sidStr := sessionID
	for _, client := range clients {
		if err := s.enqueueOne(ctx, tenantID.String(), &subStr, &sidStr, client); err != nil {
			// Errors here are diagnostic — outbox.Insert already logs
			// transient DB failures via the repo. We still log here so
			// the per-RP context is preserved.
			s.logger.Error("BackchannelLogout.NotifyLogout: enqueue failed",
				zap.String("client_id", client.ClientID),
				zap.Error(err),
			)
			metrics.OAuthBCLDeliveries.WithLabelValues(client.ClientID, "enqueue_error").Inc()
		}
	}

	return nil
}

// enqueueOne signs one logout_token JWT and writes it into the outbox.
// Caller-supplied sub and sid pointers are stored on the row for ops
// queries (the JWT itself is the authoritative carrier).
func (s *BackchannelLogoutService) enqueueOne(ctx context.Context, tenantID string, sub, sid *string, client OAuthClientRecord) error {
	jti := uuid.New().String()
	logoutToken, err := s.buildLogoutToken(jti, derefOrEmpty(sub), derefOrEmpty(sid), client.ClientID, client.BackchannelSessionRequired)
	if err != nil {
		metrics.OAuthBCLDeliveries.WithLabelValues(client.ClientID, "build_error").Inc()
		return fmt.Errorf("sign logout_token: %w", err)
	}

	row := &repositories.OAuthLogoutOutboxRow{
		ID:             uuid.New(),
		RPClientID:     client.ClientID,
		LogoutTokenJTI: jti,
		Sub:            sub,
		Sid:            sid,
		TargetURI:      client.BackchannelLogoutURI,
		Payload:        logoutToken,
		Status:         repositories.OAuthLogoutOutboxPending,
		AttemptCount:   0,
		NextRetryAt:    time.Now().UTC(),
		CreatedAt:      time.Now().UTC(),
	}

	// Pass nil tx so Insert runs on the pool directly. The full
	// transactional-outbox semantics (INSERT in same tx as session
	// commit) is a follow-up — the auth_service.Logout call site is
	// best-effort async today, so we degrade to "enqueue immediately
	// after termination" rather than holding a tx around the entire
	// Logout. Future MR can plumb the tx through if we move to
	// synchronous Logout.
	if err := s.outbox.Insert(ctx, nil, row); err != nil {
		if errors.Is(err, repositories.ErrOutboxDuplicateJTI) {
			// Concurrent NotifyLogout with the same jti — treat as
			// success.
			return nil
		}
		return fmt.Errorf("outbox insert: %w", err)
	}

	// F1: emit a structured audit event for every successful enqueue.
	// Lands in the WORM audit-archive bucket via the integration-bus →
	// NATS → audit-archiver pipeline. 7-year retention per
	// operational notes.
	s.emitAuditEvent(tenantID, BCLEventTypeEnqueued, BCLAuditPayload{
		EventType:     "bcl_enqueued",
		RPClientID:    client.ClientID,
		Sub:           derefOrEmpty(sub),
		Sid:           derefOrEmpty(sid),
		JTI:           jti,
		Outcome:       "queued",
		AttemptCount:  0,
		TimestampUnix: time.Now().UTC().Unix(),
	})
	return nil
}

// buildLogoutToken constructs a signed JWT logout token per OpenID
// Connect Back-Channel Logout 1.0 §2.4. The caller supplies the jti
// so the writer can stash it on the outbox row; the token deliberately
// omits the nonce claim as required by the spec.
func (s *BackchannelLogoutService) buildLogoutToken(jti, userID, sessionID, clientID string, includeSessionID bool) (string, error) {
	issuer := os.Getenv("JWT_ISSUER")
	if issuer == "" {
		issuer = serviceNameFalconID
	}

	now := time.Now().UTC()
	claims := backchannelLogoutClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{clientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
			ID:        jti,
		},
		Events: map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": struct{}{},
		},
	}

	if includeSessionID && sessionID != "" {
		claims.Sid = sessionID
	}

	return s.tokenSigner.SignLogoutToken(claims)
}

// derefOrEmpty returns the string value or "" if the pointer is nil.
func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ErrBackchannelReceiverDisabled is returned by Receive when the
// service is not configured with any trusted upstream IdP. In
// HexxLock's current topology Falcon-ID is the OP, not an RP, so the
// /api/v1/oauth/backchannel-logout receive endpoint is dormant. The
// previous implementation used ParseUnverified — which would have
// allowed any unauthenticated party that could reach the endpoint to
// trigger arbitrary user-session invalidation by forging a JWT. This
// error closes that attack surface; operators enable receipt by
// setting FALCON_BCL_RECEIVER_TRUSTED_ISSUERS + FALCON_BCL_RECEIVER_AUDIENCE
// (see SetReceiverConfig).
var ErrBackchannelReceiverDisabled = errors.New(
	"backchannel logout receiver is disabled (no trusted issuers configured)")

// BackchannelLogoutReceiverConfig holds the set of upstream IdPs
// whose logout_token JWTs this service is willing to accept, and
// the audience claim Falcon-ID expects in those tokens.
//
// Both fields are required to enable the Receive() path. Empty
// TrustedIssuers means the receiver is disabled (returns
// ErrBackchannelReceiverDisabled on every call).
type BackchannelLogoutReceiverConfig struct {
	// TrustedIssuers is the allow-list of upstream OP issuer URLs.
	// A token's `iss` claim MUST exactly match one of these for the
	// JWKS to be fetched. Wildcards / prefix-matches are NOT
	// supported — explicit-only allow-list per defense-in-depth.
	TrustedIssuers []string

	// Audience is Falcon-ID's expected `aud` claim value (typically
	// our own client_id at the upstream IdP).
	Audience string

	// MaxSkew is the iat-clock-skew tolerance window. Default 60s
	// matches Talon's receiver and the spec's recommended range.
	MaxSkew time.Duration

	// JWKSCacheTTL bounds how long a fetched JWKS document is
	// considered fresh. Default 1h. Lower for high-rotation IdPs.
	JWKSCacheTTL time.Duration
}

// SetReceiverConfig wires the receiver's trusted-issuer allow-list
// and audience expectation. Without this call (or with an empty
// TrustedIssuers slice), Receive returns ErrBackchannelReceiverDisabled.
func (s *BackchannelLogoutService) SetReceiverConfig(cfg BackchannelLogoutReceiverConfig) {
	if cfg.MaxSkew == 0 {
		cfg.MaxSkew = 60 * time.Second
	}
	if cfg.JWKSCacheTTL == 0 {
		cfg.JWKSCacheTTL = 1 * time.Hour
	}
	s.receiverCfg = &cfg
}

// Receive validates an incoming back-channel logout token from an
// upstream IdP per OIDC Back-Channel Logout 1.0 §2.6:
//
//   - JWKS-verified signature (from the iss-keyed cached JWKS).
//   - iss in the configured TrustedIssuers allow-list.
//   - aud equals the configured Audience.
//   - iat within MaxSkew of now.
//   - exp within reasonable bounds (≤ now + 5min).
//   - sub OR sid present (at least one).
//   - events claim contains the spec-§2.4 backchannel-logout URN.
//   - nonce claim ABSENT (spec §2.4 forbids it).
//
// Returns ErrBackchannelReceiverDisabled if no trusted issuers are
// configured — protects against the previous-implementation
// vulnerability where ParseUnverified accepted any unsigned JWT.
//
// HexxLock's current topology has Falcon-ID as the OP, not an RP,
// so this path is dormant in production. Configure trusted issuers
// only when integrating with an external upstream IdP (e.g.,
// federated SSO with another organisation's OP).
func (s *BackchannelLogoutService) Receive(ctx context.Context, logoutToken string) (string, error) {
	if logoutToken == "" {
		return "", fmt.Errorf("backchannel logout: empty logout_token")
	}

	if s.receiverCfg == nil || len(s.receiverCfg.TrustedIssuers) == 0 {
		s.logger.Warn("BackchannelLogout.Receive: rejected — receiver disabled (no trusted issuers configured)")
		return "", ErrBackchannelReceiverDisabled
	}
	if s.receiverCfg.Audience == "" {
		s.logger.Error("BackchannelLogout.Receive: rejected — Audience config required when TrustedIssuers is set")
		return "", errors.New("backchannel logout: receiver Audience must be configured")
	}

	// Full §2.6 verification pipeline lives in
	// backchannel_logout_receiver.go (F2 of the 2026-05-10 tier-1 SLO
	// restoration plan). Returns the validated `sub` claim on success.
	sub, err := s.receiveJWKSVerify(ctx, logoutToken)
	if err != nil {
		s.logger.Warn("BackchannelLogout.Receive: token validation failed",
			zap.Strings("trusted_issuers", s.receiverCfg.TrustedIssuers),
			zap.Error(err),
		)
		return "", fmt.Errorf("backchannel logout: %w", err)
	}

	s.logger.Info("BackchannelLogout.Receive: token validated successfully",
		zap.String("sub", sub),
	)
	return sub, nil
}

