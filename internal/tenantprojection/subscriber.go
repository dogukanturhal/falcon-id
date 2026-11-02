// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantprojection

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
)

// Topic constants consumed by this subscriber.
const (
	SubjectTenantCreated = "example.tenant.created"
	SubjectTenantUpdated = "example.tenant.updated"
	SubjectTenantDeleted = "example.tenant.deleted"

	// ConsumerGroup is the durable Kafka consumer group for falcon-id's
	// reverse projection. MUST NOT be reused by any other consumer
	// (especially not by quota-service-projection which owns its own offsets).
	ConsumerGroup = "falcon-id-tenant-projection"

	// DLQTopic is the dead-letter topic provisioned by <gitops-bootstrap-repo>!709.
	// Shared with the quota-service forward projection so DLQ tooling is
	// consolidated; the x-original-topic header identifies the originating consumer.
	DLQTopic = "example.tenant.dlq"

	// maxRetries is the in-process retry budget per message before DLQ publish.
	// Linear back-off: 100 ms × attempt → total ≤ 1.5 s before giving up.
	maxRetries = 5
)

// TenantSubjects returns the canonical topic list consumed by this subscriber.
func TenantSubjects() []string {
	return []string{SubjectTenantCreated, SubjectTenantUpdated, SubjectTenantDeleted}
}

// Envelope is the wire format produced by tenant-management's outbox relay:
//
//	{"type": "<topic>", "data": <payload>, "timestamp": "<RFC3339>"}
//
// `data` is left as a RawMessage so we can re-decode based on `type`.
type Envelope struct {
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
}

// tenantPayload decodes the `data` field for created + updated events.
// Partial decode — unknown fields are ignored so producer schema additions
// do not break the consumer.
type tenantPayload struct {
	ID             uuid.UUID       `json:"id"`
	Plan           string          `json:"plan"`
	Type           string          `json:"type"` // tenant tier / TenantType
	Status         string          `json:"subscription_status"`
	PlatformStatus string          `json:"status"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
}

func tenantProjectionStatus(payload tenantPayload) string {
	if payload.Status != "" {
		return payload.Status
	}
	// PlatformService's paid recovery uses the canonical iam_status DTO.
	// Do not replace a real status with an empty legacy subscription field.
	return payload.PlatformStatus
}

// tenantDeletePayload decodes the `data` field for delete events.
// tenant-management ships {"id": <uuid>} only (not the full tenant struct).
type tenantDeletePayload struct {
	ID uuid.UUID `json:"id"`
}

// SubscriberConfig holds Kafka connectivity + consumer group configuration.
type SubscriberConfig struct {
	Brokers  []string
	GroupID  string
	SASLCfg  sharedconfig.KafkaSASLConfig
	DLQTopic string
}

// TenantSubscriber consumes tenant.{created,updated,deleted} from Kafka and
// applies UPDATE-only patches to iam_tenants via Repository.
//
// One *kafka.Reader per subject — three goroutines share the same durable
// consumer group. Kafka tracks per-partition offsets; each goroutine commits
// only after the repository call succeeds.
type TenantSubscriber struct {
	trialReadyHook func(context.Context, uuid.UUID) error
	cfg            SubscriberConfig
	repo           *Repository
	metrics        *Metrics
	log            *zap.SugaredLogger

	readers   []*kafka.Reader
	dlqWriter *kafka.Writer
	wg        sync.WaitGroup
	cancel    context.CancelFunc
}

func (s *TenantSubscriber) SetTrialReadyHook(hook func(context.Context, uuid.UUID) error) {
	s.trialReadyHook = hook
}

// NewTenantSubscriber wires a subscriber. If cfg.GroupID is empty,
// ConsumerGroup is used as the default.
func NewTenantSubscriber(cfg SubscriberConfig, repo *Repository, metrics *Metrics, log *zap.SugaredLogger) *TenantSubscriber {
	if cfg.GroupID == "" {
		cfg.GroupID = ConsumerGroup
	}
	if cfg.DLQTopic == "" {
		cfg.DLQTopic = DLQTopic
	}

	s := &TenantSubscriber{
		cfg:     cfg,
		repo:    repo,
		metrics: metrics,
		log:     log,
		readers: make([]*kafka.Reader, 0, 3),
	}

	// Pre-build the DLQ writer so the hot path never allocates.
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
				log.Warnw("tenantprojection subscriber: DLQ transport build failed; DLQ disabled", "error", err)
			} else if err == nil {
				w.Transport = transport
			}
		}
		s.dlqWriter = w
	}

	return s
}

// Run starts one goroutine per topic and blocks until ctx is canceled.
// Returns nil immediately when no brokers are configured (Kafka-disabled mode:
// the service serves API traffic with a potentially stale iam_tenants).
func (s *TenantSubscriber) Run(ctx context.Context) error {
	if len(s.cfg.Brokers) == 0 {
		if s.log != nil {
			s.log.Warn("tenantprojection subscriber: KAFKA_BROKERS empty, projection disabled")
		}
		return nil
	}

	subCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	for _, subject := range TenantSubjects() {
		r, err := s.newReader(subject)
		if err != nil {
			cancel()
			return fmt.Errorf("tenantprojection subscriber: newReader %s: %w", subject, err)
		}
		s.readers = append(s.readers, r)
		s.wg.Add(1)
		go s.consumeSubject(subCtx, r, subject) //nolint:errcheck // goroutine; errors are logged internally
		if s.log != nil {
			s.log.Infow("tenantprojection subscriber: subscribed",
				"subject", subject,
				"group", s.cfg.GroupID,
			)
		}
	}

	<-subCtx.Done()
	return nil
}

// Stop cancels the subscriber context, closes all readers, and waits for
// in-flight handlers to complete.
func (s *TenantSubscriber) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	for _, r := range s.readers {
		if err := r.Close(); err != nil && s.log != nil {
			s.log.Warnw("tenantprojection subscriber: close reader", "error", err)
		}
	}
	s.wg.Wait()
	if s.dlqWriter != nil {
		if err := s.dlqWriter.Close(); err != nil && s.log != nil {
			s.log.Warnw("tenantprojection subscriber: close DLQ writer", "error", err)
		}
	}
	if s.log != nil {
		s.log.Info("tenantprojection subscriber: stopped")
	}
}

// newReader builds a kafka.Reader for a single subject.
func (s *TenantSubscriber) newReader(subject string) (*kafka.Reader, error) {
	rc := kafka.ReaderConfig{
		Brokers:     s.cfg.Brokers,
		GroupID:     s.cfg.GroupID,
		Topic:       subject,
		MinBytes:    1,
		MaxBytes:    10e6, // 10 MB safety cap
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

// consumeSubject is the per-topic read loop. One goroutine per Reader.
func (s *TenantSubscriber) consumeSubject(ctx context.Context, r *kafka.Reader, subject string) {
	defer s.wg.Done()

	tracer := otel.Tracer("falcon-id/tenantprojection")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := r.ReadMessage(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return
			}
			if s.log != nil {
				s.log.Warnw("tenantprojection subscriber: read error", "subject", subject, "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}

		// Derive a fresh context for the handler so a parent cancel (shutdown)
		// doesn't abort an in-flight UPDATE mid-flight.
		msgCtx, msgCancel := context.WithTimeout(context.Background(), 30*time.Second)
		msgCtx, span := tracer.Start(msgCtx, "tenantprojection.handleEvent",
			trace.WithAttributes(
				attribute.String("kafka.subject", subject),
				attribute.Int64("kafka.offset", msg.Offset),
				attribute.Int("kafka.partition", msg.Partition),
			),
		)

		s.handleMessage(msgCtx, subject, msg)

		span.End()
		msgCancel()
	}
}

// handleMessage parses the envelope, dispatches per type, and manages the
// retry / metric / DLQ lifecycle.
func (s *TenantSubscriber) handleMessage(ctx context.Context, subject string, msg kafka.Message) {
	firstAttemptAt := time.Now().UTC()

	var env Envelope
	if err := json.Unmarshal(msg.Value, &env); err != nil {
		// Unparseable envelope: skip the retry loop, go straight to DLQ.
		if s.log != nil {
			s.log.Warnw("tenantprojection subscriber: bad envelope",
				"subject", subject, "offset", msg.Offset, "error", err)
		}
		s.sendToDLQ(ctx, subject, msg, firstAttemptAt, fmt.Errorf("bad envelope: %w", err))
		return
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := s.dispatch(ctx, subject, env, msg.Offset); err != nil {
			lastErr = err
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			}
			continue
		}
		// Success: lag observation is done inside dispatch.
		return
	}

	// Exhausted retries.
	s.sendToDLQ(ctx, subject, msg, firstAttemptAt, lastErr)
}

// dispatch routes the envelope to the appropriate repository call.
func (s *TenantSubscriber) dispatch(ctx context.Context, subject string, env Envelope, offset int64) error {
	eventType := env.Type
	if eventType == "" {
		eventType = subject
	}

	switch eventType {
	case SubjectTenantCreated, SubjectTenantUpdated:
		var p tenantPayload
		if err := json.Unmarshal(env.Data, &p); err != nil {
			return fmt.Errorf("decode tenant payload: %w", err)
		}
		if p.ID == uuid.Nil {
			return fmt.Errorf("envelope missing tenant id (offset=%d)", offset)
		}
		if tenantProjectionStatus(p) == "" {
			return fmt.Errorf("tenant payload missing lifecycle status")
		}
		if string(p.Metadata) == "null" {
			p.Metadata = nil
		}
		// Phase 3.2 (ADR 0029): wire payload still carries plan + type for
		// producer-side backward compatibility, but the consumer no longer
		// copies them into TenantEvent — iam_tenants.plan / iam_tenants.type
		// were physically dropped by the GitOps repository !699.
		evt := TenantEvent{
			ID:        p.ID,
			Status:    tenantProjectionStatus(p),
			Metadata:  p.Metadata,
			EventTime: env.Timestamp,
		}
		if evt.EventTime.IsZero() {
			// Defensive: if producer omitted timestamp, treat as "now" so
			// the updated_at guard doesn't silently skip all events.
			s.log.Warnw("tenantprojection subscriber: envelope missing timestamp, using current time",
				"subject", subject, "offset", offset, "tenant_id", p.ID)
			evt.EventTime = time.Now().UTC()
		}
		result, err := s.repo.ApplyTenantUpsert(ctx, evt)
		if err != nil {
			return fmt.Errorf("ApplyTenantUpsert: %w", err)
		}
		s.handleResult(result, subject, evt.EventTime, p.ID)
		var metadata map[string]any
		if len(p.Metadata) > 0 {
			_ = json.Unmarshal(p.Metadata, &metadata)
		}
		if result != UpsertResultOrphan && tenantProjectionStatus(p) == "trial" && metadata["signup_trial_started"] == true && s.trialReadyHook != nil {
			// Runs on replay too: projection may have committed before the
			// product callback failed. The callback verifies current source
			// eligibility and is idempotent, including for stale events.
			if err := s.trialReadyHook(ctx, p.ID); err != nil {
				return fmt.Errorf("confirmed trial product: %w", err)
			}
		}

	case SubjectTenantDeleted:
		var d tenantDeletePayload
		if err := json.Unmarshal(env.Data, &d); err != nil {
			return fmt.Errorf("decode tenant delete payload: %w", err)
		}
		if d.ID == uuid.Nil {
			return fmt.Errorf("delete envelope missing tenant id (offset=%d)", offset)
		}
		result, err := s.repo.ApplyTenantDelete(ctx, d.ID)
		if err != nil {
			return fmt.Errorf("ApplyTenantDelete: %w", err)
		}
		s.handleResult(result, subject, env.Timestamp, d.ID)

	default:
		// Unknown type: log and skip — do not retry (no point), do not DLQ
		// (operator can't act on it). Count as skipped.
		if s.log != nil {
			s.log.Warnw("tenantprojection subscriber: unknown event type",
				"type", eventType, "offset", offset)
		}
		s.metrics.IncSkipped(subject)
	}
	return nil
}

// handleResult logs and metrics-records the outcome of a repository call.
func (s *TenantSubscriber) handleResult(result UpsertResult, subject string, eventAt time.Time, tenantID uuid.UUID) {
	switch result {
	case UpsertResultApplied:
		s.metrics.IncOK(subject)
		s.metrics.ObserveLag(subject, eventAt)
		if s.log != nil {
			s.log.Debugw("tenantprojection subscriber: applied",
				"subject", subject, "tenant_id", tenantID)
		}
	case UpsertResultSkipped:
		s.metrics.IncSkipped(subject)
		if s.log != nil {
			s.log.Debugw("tenantprojection subscriber: skipped stale event",
				"subject", subject, "tenant_id", tenantID)
		}
	case UpsertResultOrphan:
		s.metrics.IncOrphan(subject)
		if s.log != nil {
			s.log.Warnw("tenantprojection subscriber: orphan event — tenant_id not in iam_tenants",
				"subject", subject, "tenant_id", tenantID,
				"hint", "signup adapter may not have run yet; if persistent, check signup flow",
			)
		}
	}
}

// sendToDLQ publishes a terminally-failed message to the DLQ topic with
// contextual headers so operators can triage and replay.
func (s *TenantSubscriber) sendToDLQ(ctx context.Context, subject string, msg kafka.Message, firstAttemptAt time.Time, terminalErr error) {
	if s.dlqWriter == nil {
		// DLQ disabled (test / no-config mode). Log loudly and count as failed.
		if s.log != nil {
			s.log.Errorw("tenantprojection subscriber: terminal failure, DLQ disabled, dropping",
				"subject", subject, "offset", msg.Offset, "error", terminalErr)
		}
		s.metrics.IncFailed(subject)
		return
	}

	headers := []kafka.Header{
		{Key: "x-original-topic", Value: []byte(subject)},
		{Key: "x-consumer-group", Value: []byte(ConsumerGroup)},
		{Key: "x-retry-count", Value: []byte(strconv.Itoa(maxRetries))},
		{Key: "x-first-attempt-at", Value: []byte(firstAttemptAt.Format(time.RFC3339Nano))},
		{Key: "x-final-error", Value: []byte(terminalErr.Error())},
	}
	// Propagate W3C trace context so the DLQ record links back to the failing span.
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
			s.log.Errorw("tenantprojection subscriber: DLQ publish FAILED — payload LOST",
				"subject", subject, "offset", msg.Offset,
				"terminal_error", terminalErr, "dlq_error", err)
		}
		s.metrics.IncFailed(subject)
		return
	}

	if s.log != nil {
		s.log.Warnw("tenantprojection subscriber: terminal failure, sent to DLQ",
			"subject", subject, "offset", msg.Offset,
			"dlq_topic", s.cfg.DLQTopic, "error", terminalErr)
	}
	s.metrics.IncDLQ(subject)
}

// buildKafkaDialer builds a SASL/SCRAM dialer for the reader path.
// Mirrors the pattern in platform-commerce/services/quota-service.
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
