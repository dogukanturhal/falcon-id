// SPDX-License-Identifier: AGPL-3.0-or-later

package entitlementsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	sharedconfig "github.com/dogukanturhal/platform-shared/config"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/scram"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	// Subject is the single topic this consumer reads.
	Subject = "example.tenant.modules.sync"

	// ConsumerGroup is the durable Kafka consumer group for this
	// consumer. MUST NOT be reused by any other consumer, including
	// tenantprojection's "falcon-id-tenant-projection" — see
	// kafkauser-falcon-id-entitlements-sync.yaml in <gitops-bootstrap-repo>.
	ConsumerGroup = "falcon-id-entitlements-sync"

	// DLQTopic is shared with tenantprojection's DLQ; x-original-topic
	// distinguishes origin.
	DLQTopic = "example.tenant.dlq"

	// maxRetries mirrors tenantprojection's retry budget: linear back-off,
	// 100ms x attempt, total <= 1.5s before giving up and going to DLQ.
	maxRetries = 5
)

// Envelope is the wire format: {"type": "...", "data": <payload>, "timestamp": "..."}.
type Envelope struct {
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
}

// modulePayload is one module entry inside a snapshot.
type modulePayload struct {
	ModuleCode     string     `json:"module_code"`
	Status         string     `json:"status"`
	Seats          *int       `json:"seats,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	EverTrialed    bool       `json:"ever_trialed"`
	EverSubscribed bool       `json:"ever_subscribed"`
	Source         *string    `json:"source,omitempty"`
	TierCode       *string    `json:"tier_code,omitempty"`
	// ReadOnly: grace-only write block; absent = false (full access).
	ReadOnly bool `json:"read_only"`
}

// snapshotPayload decodes the `data` field of a example.tenant.modules.sync
// event: a FULL per-tenant snapshot, not a delta.
//
// Full-snapshot contract: the producer (tenant-management) is expected to
// include every module it considers in-scope for the tenant, using
// status="expired" for a module the tenant no longer has -- never by
// omitting it. This consumer deliberately does NOT infer "absent from this
// snapshot = expired" by diffing against the existing DB rows, because
// that would require a read-modify-write per snapshot and would silently
// expire a module if the producer ever sends a partial/malformed payload.
// Trusting the producer's explicit status list keeps this consumer a pure
// per-module idempotent upsert, consistent with
// services.TenantEntitlementService.PutSnapshot's single-purpose contract.
type snapshotPayload struct {
	TenantID     uuid.UUID       `json:"tenant_id"`
	EventVersion int64           `json:"event_version"`
	Modules      []modulePayload `json:"modules"`
	Flags        map[string]bool `json:"flags,omitempty"`
	// Limits: integer plan limits (migration 0020), -1 = unlimited.
	Limits map[string]int64 `json:"limits,omitempty"`
}

// entitlementService abstracts services.TenantEntitlementService for the
// consumer.
type entitlementService interface {
	PutSnapshot(ctx context.Context, e *models.ModuleEntitlement) error
	PutFlagsSnapshot(ctx context.Context, f *models.TenantEntitlementFlags) error
}

// SubscriberConfig holds Kafka connectivity + consumer group configuration.
type SubscriberConfig struct {
	Brokers  []string
	GroupID  string
	SASLCfg  sharedconfig.KafkaSASLConfig
	DLQTopic string
}

// Subscriber consumes example.tenant.modules.sync and applies snapshots via
// entitlementService.
type Subscriber struct {
	cfg     SubscriberConfig
	svc     entitlementService
	metrics *Metrics
	log     *zap.SugaredLogger

	reader    *kafka.Reader
	dlqWriter *kafka.Writer
	wg        sync.WaitGroup
	cancel    context.CancelFunc
}

// NewSubscriber wires a subscriber. If cfg.GroupID is empty, ConsumerGroup
// is used as the default.
func NewSubscriber(cfg SubscriberConfig, svc entitlementService, metrics *Metrics, log *zap.SugaredLogger) *Subscriber {
	if cfg.GroupID == "" {
		cfg.GroupID = ConsumerGroup
	}
	if cfg.DLQTopic == "" {
		cfg.DLQTopic = DLQTopic
	}

	s := &Subscriber{
		cfg:     cfg,
		svc:     svc,
		metrics: metrics,
		log:     log,
	}

	if len(cfg.Brokers) > 0 && cfg.DLQTopic != "" {
		w := &kafka.Writer{
			Addr:         kafka.TCP(cfg.Brokers...),
			Topic:        cfg.DLQTopic,
			Balancer:     &kafka.Hash{},
			BatchTimeout: 10 * time.Millisecond,
			RequiredAcks: kafka.RequireAll,
		}
		if cfg.SASLCfg.SASLEnabled || cfg.SASLCfg.TLSEnabled {
			transport, err := buildKafkaTransport(cfg.SASLCfg)
			if err != nil && log != nil {
				log.Warnw("entitlementsync subscriber: DLQ transport build failed; DLQ disabled", "error", err)
			} else if err == nil {
				w.Transport = transport
			}
		}
		s.dlqWriter = w
	}

	return s
}

// Run starts the read loop and blocks until ctx is canceled. Returns nil
// immediately when no brokers are configured (Kafka-disabled mode).
func (s *Subscriber) Run(ctx context.Context) error {
	if len(s.cfg.Brokers) == 0 {
		if s.log != nil {
			s.log.Warn("entitlementsync subscriber: KAFKA_BROKERS empty, entitlement sync disabled")
		}
		return nil
	}

	subCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	r, err := s.newReader()
	if err != nil {
		cancel()
		return fmt.Errorf("entitlementsync subscriber: newReader: %w", err)
	}
	s.reader = r
	s.wg.Add(1)
	go s.consume(subCtx)
	if s.log != nil {
		s.log.Infow("entitlementsync subscriber: subscribed", "subject", Subject, "group", s.cfg.GroupID)
	}

	<-subCtx.Done()
	return nil
}

// Stop cancels the subscriber context, closes the reader, and waits for
// in-flight handlers to complete.
func (s *Subscriber) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.reader != nil {
		if err := s.reader.Close(); err != nil && s.log != nil {
			s.log.Warnw("entitlementsync subscriber: close reader", "error", err)
		}
	}
	s.wg.Wait()
	if s.dlqWriter != nil {
		if err := s.dlqWriter.Close(); err != nil && s.log != nil {
			s.log.Warnw("entitlementsync subscriber: close DLQ writer", "error", err)
		}
	}
	if s.log != nil {
		s.log.Info("entitlementsync subscriber: stopped")
	}
}

func (s *Subscriber) newReader() (*kafka.Reader, error) {
	rc := kafka.ReaderConfig{
		Brokers:     s.cfg.Brokers,
		GroupID:     s.cfg.GroupID,
		Topic:       Subject,
		MinBytes:    1,
		MaxBytes:    10e6,
		MaxWait:     1 * time.Second,
		StartOffset: kafka.FirstOffset,
	}
	if s.cfg.SASLCfg.SASLEnabled || s.cfg.SASLCfg.TLSEnabled {
		d, err := buildKafkaDialer(s.cfg.SASLCfg)
		if err != nil {
			return nil, fmt.Errorf("newReader: %w", err)
		}
		rc.Dialer = d
	}
	return kafka.NewReader(rc), nil
}

func (s *Subscriber) consume(ctx context.Context) {
	defer s.wg.Done()

	tracer := otel.Tracer("falcon-id/entitlementsync")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := s.reader.ReadMessage(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return
			}
			if s.log != nil {
				s.log.Warnw("entitlementsync subscriber: read error", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}

		msgCtx, msgCancel := context.WithTimeout(context.Background(), 30*time.Second)
		msgCtx, span := tracer.Start(msgCtx, "entitlementsync.handleEvent",
			trace.WithAttributes(
				attribute.String("kafka.subject", Subject),
				attribute.Int64("kafka.offset", msg.Offset),
				attribute.Int("kafka.partition", msg.Partition),
			),
		)

		s.handleMessage(msgCtx, msg)

		span.End()
		msgCancel()
	}
}

func (s *Subscriber) handleMessage(ctx context.Context, msg kafka.Message) {
	firstAttemptAt := time.Now().UTC()

	var env Envelope
	if err := json.Unmarshal(msg.Value, &env); err != nil {
		if s.log != nil {
			s.log.Warnw("entitlementsync subscriber: bad envelope", "offset", msg.Offset, "error", err)
		}
		s.sendToDLQ(ctx, msg, firstAttemptAt, fmt.Errorf("bad envelope: %w", err))
		return
	}

	var payload snapshotPayload
	if err := json.Unmarshal(env.Data, &payload); err != nil {
		if s.log != nil {
			s.log.Warnw("entitlementsync subscriber: bad snapshot payload", "offset", msg.Offset, "error", err)
		}
		s.sendToDLQ(ctx, msg, firstAttemptAt, fmt.Errorf("bad snapshot payload: %w", err))
		return
	}
	if payload.TenantID == uuid.Nil {
		s.sendToDLQ(ctx, msg, firstAttemptAt, fmt.Errorf("snapshot missing tenant_id (offset=%d)", msg.Offset))
		return
	}
	if err := models.ValidateEntitlementLimits(payload.Limits); err != nil {
		// Terminal (retrying cannot fix the payload): DLQ, never a partial apply.
		s.sendToDLQ(ctx, msg, firstAttemptAt, fmt.Errorf("bad snapshot limits: %w", err))
		return
	}

	eventAt := env.Timestamp
	if eventAt.IsZero() {
		eventAt = time.Now().UTC()
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := s.applySnapshot(ctx, payload, eventAt); err != nil {
			lastErr = err
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			}
			continue
		}
		s.metrics.ObserveLag(eventAt)
		return
	}

	s.sendToDLQ(ctx, msg, firstAttemptAt, lastErr)
}

// applySnapshot upserts every module row plus the flags row from one
// snapshot event, sharing the single per-tenant event_version across all
// of them (the product roadmap §4.1: "event version / updated_at monotonic").
// Each individual PutSnapshot/PutFlagsSnapshot call is independently
// idempotent (see services.TenantEntitlementService), so a partial
// failure partway through a snapshot with N modules is safe to retry in
// full -- already-applied rows simply no-op on the version guard.
func (s *Subscriber) applySnapshot(ctx context.Context, payload snapshotPayload, eventAt time.Time) error {
	for _, mp := range payload.Modules {
		status := models.ModuleEntitlementStatus(mp.Status)
		if !status.IsValid() {
			// Reject the unknown status rather than silently persisting
			// it (fail-closed extends to "reject the unknown" -- see
			// models.ModuleEntitlementStatus.IsValid doc comment). This
			// counts as a permanent decode-level failure for THIS module,
			// but must not block the rest of the snapshot, so we log and
			// skip rather than aborting the whole batch.
			if s.log != nil {
				s.log.Warnw("entitlementsync subscriber: unknown module status, skipping module",
					"tenant_id", payload.TenantID, "module_code", mp.ModuleCode, "status", mp.Status)
			}
			s.metrics.IncSkipped()
			continue
		}

		entitlement := &models.ModuleEntitlement{
			TenantID:        payload.TenantID,
			ModuleCode:      mp.ModuleCode,
			Status:          status,
			Seats:           mp.Seats,
			ExpiresAt:       mp.ExpiresAt,
			EverTrialed:     mp.EverTrialed,
			EverSubscribed:  mp.EverSubscribed,
			Source:          mp.Source,
			TierCode:        mp.TierCode,
			ReadOnly:        mp.ReadOnly,
			EventVersion:    payload.EventVersion,
			SourceUpdatedAt: eventAt,
		}
		if err := s.svc.PutSnapshot(ctx, entitlement); err != nil {
			return fmt.Errorf("PutSnapshot module=%s: %w", mp.ModuleCode, err)
		}
		s.metrics.IncOK()
	}

	if payload.Flags != nil || payload.Limits != nil {
		flags := &models.TenantEntitlementFlags{
			TenantID:        payload.TenantID,
			Flags:           payload.Flags,
			Limits:          payload.Limits,
			EventVersion:    payload.EventVersion,
			SourceUpdatedAt: eventAt,
		}
		if err := s.svc.PutFlagsSnapshot(ctx, flags); err != nil {
			return fmt.Errorf("PutFlagsSnapshot: %w", err)
		}
	}

	return nil
}

// sendToDLQ publishes a terminally-failed message to the DLQ topic with
// contextual headers so operators can triage and replay. Mirrors
// tenantprojection.TenantSubscriber.sendToDLQ.
func (s *Subscriber) sendToDLQ(ctx context.Context, msg kafka.Message, firstAttemptAt time.Time, terminalErr error) {
	if s.dlqWriter == nil {
		if s.log != nil {
			s.log.Errorw("entitlementsync subscriber: terminal failure, DLQ disabled, dropping",
				"offset", msg.Offset, "error", terminalErr)
		}
		s.metrics.IncFailed()
		return
	}

	headers := []kafka.Header{
		{Key: "x-original-topic", Value: []byte(Subject)},
		{Key: "x-consumer-group", Value: []byte(ConsumerGroup)},
		{Key: "x-retry-count", Value: []byte(strconv.Itoa(maxRetries))},
		{Key: "x-first-attempt-at", Value: []byte(firstAttemptAt.Format(time.RFC3339Nano))},
		{Key: "x-final-error", Value: []byte(terminalErr.Error())},
	}
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, carrier)
	if tp := carrier["traceparent"]; tp != "" {
		headers = append(headers, kafka.Header{Key: "traceparent", Value: []byte(tp)})
	}

	pubCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dlqMsg := kafka.Message{
		Key:     msg.Key,
		Value:   msg.Value,
		Headers: headers,
		Time:    time.Now().UTC(),
	}

	if err := s.dlqWriter.WriteMessages(pubCtx, dlqMsg); err != nil {
		if s.log != nil {
			s.log.Errorw("entitlementsync subscriber: DLQ publish FAILED — payload LOST",
				"offset", msg.Offset, "terminal_error", terminalErr, "dlq_error", err)
		}
		s.metrics.IncFailed()
		return
	}

	if s.log != nil {
		s.log.Warnw("entitlementsync subscriber: terminal failure, sent to DLQ",
			"offset", msg.Offset, "dlq_topic", s.cfg.DLQTopic, "error", terminalErr)
	}
	s.metrics.IncDLQ()
}

// buildKafkaDialer builds a SASL/SCRAM dialer for the reader path.
// Duplicated from internal/tenantprojection rather than shared, matching
// this codebase's existing per-package convention (see
// tenantprojection/subscriber.go's identical helper) — small enough that a
// shared package would add more indirection than it saves.
func buildKafkaDialer(saslCfg sharedconfig.KafkaSASLConfig) (*kafka.Dialer, error) {
	d := &kafka.Dialer{DualStack: true}

	if saslCfg.SASLEnabled {
		algo, err := scramAlgo(saslCfg.SASLMechanism)
		if err != nil {
			return nil, err
		}
		mech, err := scram.Mechanism(algo, saslCfg.SASLUsername, saslCfg.SASLPassword)
		if err != nil {
			return nil, fmt.Errorf("create SCRAM mechanism: %w", err)
		}
		d.SASLMechanism = mech
	}
	if saslCfg.TLSEnabled {
		tlsCfg, err := saslCfg.NewTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("build TLS config: %w", err)
		}
		d.TLS = tlsCfg
	}
	return d, nil
}

// buildKafkaTransport builds a SASL/SCRAM transport for the DLQ writer path.
func buildKafkaTransport(saslCfg sharedconfig.KafkaSASLConfig) (*kafka.Transport, error) {
	t := &kafka.Transport{}

	if saslCfg.SASLEnabled {
		algo, err := scramAlgo(saslCfg.SASLMechanism)
		if err != nil {
			return nil, err
		}
		mech, err := scram.Mechanism(algo, saslCfg.SASLUsername, saslCfg.SASLPassword)
		if err != nil {
			return nil, fmt.Errorf("create SCRAM mechanism: %w", err)
		}
		t.SASL = mech
	}
	if saslCfg.TLSEnabled {
		tlsCfg, err := saslCfg.NewTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("build TLS config: %w", err)
		}
		t.TLS = tlsCfg
	}
	return t, nil
}

func scramAlgo(mechanism string) (scram.Algorithm, error) {
	switch mechanism {
	case "SCRAM-SHA-256":
		return scram.SHA256, nil
	case "SCRAM-SHA-512":
		return scram.SHA512, nil
	default:
		return scram.SHA512, fmt.Errorf("unsupported SASL mechanism: %s (supported: SCRAM-SHA-256, SCRAM-SHA-512)", mechanism)
	}
}
