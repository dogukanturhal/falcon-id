// SPDX-License-Identifier: AGPL-3.0-or-later

// caep_emitter.go — real implementation of SSFEventEmitter that signs
// CAEP 1.0 / SSF 1.0 Security Event Tokens and pushes them to
// subscribed stream receivers per RFC 8935.
//
// Replaces the NoOpSSFEmitter for production deployments. The NoOp
// remains as the default test wiring; cmd/services.go flips to this
// implementation when the Falcon-ID issuer + KeyManager + SSFService
// are all initialized.
//
// Architecture (verified against tier-1 research 2026-06-04):
//
//   - Stream subscription persistence reuses the existing SSFService
//     + SSFRepository — no parallel registry.
//
//   - Signing reuses pkg/keys.KeyManager.ActiveKey() (RS256, ≥2048-bit
//     per CAEP Interop Profile 1.0 MUST).
//
//   - Event-type URN constants come from internal/models/ssf.go
//     (SSFEventType) — single source of truth for the wire shape.
//
//   - Subject identifier uses SSFSubjectIssuerSub (iss + sub) per RFC
//     9493; iss = Falcon-ID issuer URL, sub = uuid.UUID.String().
//
//   - Push delivery is synchronous best-effort in Phase 1: on receiver
//     5xx we log + count + drop the SET for this receiver but continue
//     iterating over the rest of the subscribed streams. The PG-backed
//     outbox + drainer pattern (mirrored on backchannel_logout_drainer.
//     go) lands in Phase 2 alongside RFC 8936 poll delivery.
//
//   - Paused / disabled streams are skipped at the EventsRequested
//     filter step — both `paused` AND `disabled` short-circuit before
//     delivery (only `enabled` streams receive).
package services

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// CAEPSigningKeyProvider is the slice of pkg/keys.KeyManager the
// emitter needs. Defined here so unit tests can stub it without
// spinning the real KeyManager + database.
type CAEPSigningKeyProvider interface {
	ActiveKey() (crypto.Signer, string, error)
}

// CAEPEmitterConfig wires the emitter. Loaded from cmd/services.go
// when CAEP transmitter is enabled in deployment.
type CAEPEmitterConfig struct {
	// Issuer is the Falcon-ID iss claim populated on every SET.
	// Typical: "https://id.example.com/".
	Issuer string

	// HTTPClient is the transport for push delivery. Defaults to a
	// 5s-timeout client per RFC 8935 best practice — receivers are
	// expected to ACK fast; the outbox drainer (Phase 2) absorbs the
	// rest.
	HTTPClient *http.Client
}

// CAEPEmitter delivers SETs to subscribed streams via RFC 8935 push.
// Implements SSFEventEmitter + adds the CAEP session-revoked and
// credential-change emit methods.
type CAEPEmitter struct {
	cfg     CAEPEmitterConfig
	streams SSFRepository
	keys    CAEPSigningKeyProvider
	logger  *zap.Logger

	// outbox is the optional CAEP transactional outbox. When set,
	// emit() ENQUEUES rows to iam_caep_event_outbox instead of
	// performing a sync HTTP push. Delivery becomes the responsibility
	// of CAEPOutboxDrainer (Phase 6 ZTNA program). When nil the legacy
	// best-effort sync path is used.
	outbox CAEPOutboxWriter
}

// CAEPOutboxWriter is the narrow interface the emitter needs to write
// to the CAEP transactional outbox. Implemented by
// *repositories.CAEPEventOutboxRepository today; a stub is supplied in
// tests.
type CAEPOutboxWriter interface {
	Insert(ctx context.Context, tx repositories.DBTX, row *repositories.CAEPEventOutboxRow) error
}

// SetOutbox wires the outbox writer. nil reverts to sync delivery.
// Safe to call after construction (boot-time wiring in
// cmd/services.go).
func (e *CAEPEmitter) SetOutbox(w CAEPOutboxWriter) {
	e.outbox = w
}

// NewCAEPEmitter constructs the emitter. Issuer + streams + keys are
// required; nil-checks happen at construction so the boot path fails
// fast rather than the first emit.
func NewCAEPEmitter(cfg CAEPEmitterConfig, streams SSFRepository, keys CAEPSigningKeyProvider, logger *zap.Logger) (*CAEPEmitter, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("caep: Issuer is required")
	}
	if streams == nil {
		return nil, errors.New("caep: SSFRepository is required")
	}
	if keys == nil {
		return nil, errors.New("caep: KeyManager is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &CAEPEmitter{
		cfg:     cfg,
		streams: streams,
		keys:    keys,
		logger:  logger,
	}, nil
}

// EmitAccountCreated implements the existing SSFEventEmitter interface.
// Phase 1 ships the same logging behavior as NoOpSSFEmitter — the
// production wire-up for account-created lands in a follow-up MR
// once the event-type URN is registered in models.SSFEventType
// (currently the model only ships CAEP + RISC URNs; account-created
// is a custom event-class that needs its own URN registration).
func (e *CAEPEmitter) EmitAccountCreated(ctx context.Context, evt AccountCreatedEvent) error {
	e.logger.Info("CAEP: account-created (logged only; URN not yet registered)",
		zap.String("user_id", evt.UserID.String()),
		zap.String("tenant_id", evt.TenantID.String()),
		zap.String("account_type", evt.AccountType),
	)
	return nil
}

// EmitSessionRevoked emits a CAEP §3.1 session-revoked event for the
// given userID across all enabled streams (tenant-scoped) that
// subscribe to the event. Returns the count of streams successfully
// delivered to.
//
// Failure semantics: receiver 5xx → log + skip; signing failure →
// abort (signing failure is unrecoverable, retrying every stream
// would just re-fail).
func (e *CAEPEmitter) EmitSessionRevoked(ctx context.Context, tenantID, userID uuid.UUID, reason string) int {
	payload := map[string]interface{}{
		"subject": models.SSFSubject{
			Format:  models.SSFSubjectIssuerSub,
			Issuer:  e.cfg.Issuer,
			Subject: userID.String(),
		},
		"event_timestamp":   time.Now().Unix(),
		"initiating_entity": "user",
	}
	if reason != "" {
		payload["reason_admin"] = map[string]string{"en": reason}
	}
	return e.emit(ctx, tenantID, userID, models.CAEPSessionRevoked, payload)
}

// EmitCredentialChange emits a CAEP §3.2 credential-change event.
// credentialType MUST be one of the CAEP 1.0 values
// (password, fido2-platform, etc.). changeType MUST be one of
// create|revoke|update|delete per CAEP §3.2.
func (e *CAEPEmitter) EmitCredentialChange(ctx context.Context, tenantID, userID uuid.UUID, credentialType, changeType, reason string) int {
	payload := map[string]interface{}{
		"subject": models.SSFSubject{
			Format:  models.SSFSubjectIssuerSub,
			Issuer:  e.cfg.Issuer,
			Subject: userID.String(),
		},
		"credential_type":   credentialType,
		"change_type":       changeType,
		"event_timestamp":   time.Now().Unix(),
		"initiating_entity": "user",
	}
	if reason != "" {
		payload["reason_admin"] = map[string]string{"en": reason}
	}
	return e.emit(ctx, tenantID, userID, models.CAEPCredentialChange, payload)
}

func (e *CAEPEmitter) emit(ctx context.Context, tenantID, userID uuid.UUID, eventType models.SSFEventType, payload map[string]interface{}) int {
	streams, err := e.streams.ListStreams(ctx, tenantID)
	if err != nil {
		e.logger.Error("caep: ListStreams failed",
			zap.String("tenant", tenantID.String()),
			zap.String("event_type", string(eventType)),
			zap.Error(err))
		return 0
	}
	if len(streams) == 0 {
		return 0
	}
	signer, kid, err := e.keys.ActiveKey()
	if err != nil {
		e.logger.Error("caep: ActiveKey failed",
			zap.String("event_type", string(eventType)),
			zap.Error(err))
		return 0
	}

	delivered := 0
	for _, s := range streams {
		if !shouldDeliverToStream(s, eventType) {
			continue
		}
		// Outbox path (Phase 6 ZTNA — at-least-once delivery): enqueue
		// a row keyed on the stream, drainer (caep_outbox_drainer.go)
		// signs + delivers + handles retries. We still call signSET
		// for streams using DeliveryMethod=push when outbox is nil to
		// preserve Phase 1 sync behaviour.
		if e.outbox != nil {
			payloadJSON, mErr := json.Marshal(payload)
			if mErr != nil {
				e.logger.Error("caep: marshal payload failed; SET dropped",
					zap.String("stream", s.ID.String()),
					zap.String("event_type", string(eventType)),
					zap.Error(mErr))
				continue
			}
			targetURI := ""
			if s.PushEndpointURL != nil {
				targetURI = *s.PushEndpointURL
			}
			if targetURI == "" {
				e.logger.Warn("caep: stream has no push endpoint; outbox enqueue skipped",
					zap.String("stream", s.ID.String()))
				continue
			}
			row := &repositories.CAEPEventOutboxRow{
				StreamID:      s.ID,
				EventType:     string(eventType),
				SubjectFormat: string(models.SSFSubjectIssuerSub),
				SubjectIss:    e.cfg.Issuer,
				SubjectSub:    userID.String(),
				EventData:     payloadJSON,
				TargetURI:     targetURI,
			}
			if iErr := e.outbox.Insert(ctx, nil, row); iErr != nil {
				if errors.Is(iErr, repositories.ErrCAEPOutboxStreamGone) {
					// Stream was deleted between ListStreams and Insert
					// — benign race. Skip silently.
					continue
				}
				e.logger.Error("caep: outbox insert failed",
					zap.String("stream", s.ID.String()),
					zap.String("event_type", string(eventType)),
					zap.Error(iErr))
				continue
			}
			delivered++
			continue
		}

		// Legacy sync path (Phase 1 wave 2). Kept for canaries +
		// fallback when outbox is nil.
		setJWT, err := e.signSET(s, eventType, payload, signer, kid, userID)
		if err != nil {
			e.logger.Error("caep: signSET failed",
				zap.String("stream", s.ID.String()),
				zap.Error(err))
			continue
		}
		if err := e.deliver(ctx, s, setJWT); err != nil {
			e.logger.Warn("caep: deliver failed; SET dropped (Phase 6 outbox would retry)",
				zap.String("stream", s.ID.String()),
				zap.String("event_type", string(eventType)),
				zap.Error(err))
			continue
		}
		delivered++
	}
	return delivered
}

func shouldDeliverToStream(s *models.SSFStream, eventType models.SSFEventType) bool {
	if s.Status != models.SSFStreamEnabled {
		return false
	}
	if s.IsInbound {
		// IsInbound = Falcon-ID acts as a receiver; never deliver to
		// inbound streams.
		return false
	}
	if s.DeliveryMethod != models.SSFDeliveryPush {
		// Phase 1 ships push only — poll subscriptions are a Phase 2
		// outbox feature.
		return false
	}
	if len(s.EventsRequested) == 0 {
		return true
	}
	for _, et := range s.EventsRequested {
		if et == eventType {
			return true
		}
	}
	return false
}

func (e *CAEPEmitter) signSET(s *models.SSFStream, eventType models.SSFEventType, payload map[string]interface{}, signer crypto.Signer, kid string, userID uuid.UUID) (string, error) {
	// Audience is []string in the SSFStream model — RFC 8417 permits
	// either a single string or array. We emit the array form when
	// the stream has >1 audience entry; otherwise collapse to string
	// for receiver compatibility (some receivers reject single-element
	// arrays).
	var aud interface{}
	switch len(s.Audience) {
	case 0:
		return "", errors.New("stream has empty Audience")
	case 1:
		aud = s.Audience[0]
	default:
		aud = s.Audience
	}

	claims := jwt.MapClaims{
		"iss": e.cfg.Issuer,
		"aud": aud,
		"iat": time.Now().Unix(),
		"jti": uuid.NewString(),
		"events": map[string]interface{}{
			string(eventType): payload,
		},
		"sub_id": models.SSFSubject{
			Format:  models.SSFSubjectIssuerSub,
			Issuer:  e.cfg.Issuer,
			Subject: userID.String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	token.Header["typ"] = "secevent+jwt"
	return token.SignedString(signer)
}

func (e *CAEPEmitter) deliver(ctx context.Context, s *models.SSFStream, setJWT string) error {
	if s.PushEndpointURL == nil || *s.PushEndpointURL == "" {
		return errors.New("stream has nil PushEndpointURL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *s.PushEndpointURL, bytes.NewReader([]byte(setJWT)))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// RFC 8935 §4.1: 202 Accepted on success. Some receivers return
	// 200; we accept any 2xx.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("receiver returned %d", resp.StatusCode)
	}
	return nil
}

// MarshalSubject is exposed for downstream packages that need to
// canonicalize a subject identifier consistently with what the
// emitter writes into SETs. Returns the JSON-encoded SSFSubject in
// iss_sub format.
func (e *CAEPEmitter) MarshalSubject(userID uuid.UUID) ([]byte, error) {
	return json.Marshal(models.SSFSubject{
		Format:  models.SSFSubjectIssuerSub,
		Issuer:  e.cfg.Issuer,
		Subject: userID.String(),
	})
}
