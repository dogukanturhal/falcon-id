// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantstatus

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
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/scram"
	"go.uber.org/zap"
)

const (
	// Subject is the single topic this consumer reads.
	Subject = "example.tenant.status"

	// ConsumerGroup MUST NOT be shared with any other consumer; see
	// kafkauser-falcon-id-tenant-status.yaml in <gitops-bootstrap-repo>.
	ConsumerGroup = "falcon-id-tenant-status"

	// DLQTopic is shared with the other tenant consumers; x-original-topic
	// identifies the origin.
	DLQTopic = "example.tenant.dlq"

	maxRetries = 5
)

// Envelope is the wire format {"type","tenant_id","data","timestamp"}.
type Envelope struct {
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
}

// snapshotPayload is the `data` field: a FULL per-tenant status snapshot.
type snapshotPayload struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	EventVersion int64     `json:"event_version"`
	Status       string    `json:"status"`
	Reason       string    `json:"reason,omitempty"`
	AccessScope  string    `json:"access_scope,omitempty"`
}

type applier interface {
	Apply(ctx context.Context, evt Event) (Result, error)
}

// permanentError marks a failure that retrying cannot fix (goes to the DLQ).
type permanentError struct{ err error }

func (p permanentError) Error() string { return p.err.Error() }
func (p permanentError) Unwrap() error { return p.err }

// Consumer applies decoded events to the repository and keeps the gate's cache
// coherent. It is transport-agnostic so ordering/idempotency can be tested
// without Kafka.
type Consumer struct {
	repo    applier
	gate    *Gate
	metrics *Metrics
	log     *zap.SugaredLogger
}

// NewConsumer wires the event handler. gate may be nil.
func NewConsumer(repo applier, gate *Gate, metrics *Metrics, log *zap.SugaredLogger) *Consumer {
	return &Consumer{repo: repo, gate: gate, metrics: metrics, log: log}
}

// Handle decodes and applies one raw message value. A nil return means the
// message is fully dealt with (applied, stale-skipped, or deliberately
// rejected). A permanentError means "send to DLQ"; any other error is retryable.
func (c *Consumer) Handle(ctx context.Context, value []byte) error {
	var env Envelope
	if err := json.Unmarshal(value, &env); err != nil {
		return permanentError{fmt.Errorf("bad envelope: %w", err)}
	}
	var p snapshotPayload
	if err := json.Unmarshal(env.Data, &p); err != nil {
		return permanentError{fmt.Errorf("bad status payload: %w", err)}
	}
	if p.TenantID == uuid.Nil {
		return permanentError{errors.New("status event missing tenant_id")}
	}
	if p.Status == "" {
		return permanentError{errors.New("status event missing status")}
	}
	at := env.Timestamp
	if at.IsZero() {
		at = time.Now().UTC()
	}
	res, err := c.repo.Apply(ctx, Event{
		TenantID: p.TenantID, Status: p.Status, Reason: p.Reason,
		AccessScope:  p.AccessScope,
		EventVersion: p.EventVersion, EventTime: at,
	})
	switch {
	case errors.Is(err, ErrProtectedTenant):
		c.metrics.inc("rejected")
		if c.log != nil {
			c.log.Errorw("tenantstatus: refusing to suspend protected tenant", "tenant_id", p.TenantID)
		}
		return nil
	case err != nil:
		return err
	}
	c.gate.Invalidate(p.TenantID)
	if res == ResultApplied {
		c.metrics.inc("applied")
		if (Event{Status: p.Status, Reason: p.Reason, AccessScope: p.AccessScope}).Suspended() && c.log != nil {
			c.log.Warnw("tenantstatus: tenant suspended; sessions and tokens revoked", "tenant_id", p.TenantID, "event_version", p.EventVersion)
		}
	} else {
		c.metrics.inc("skipped")
	}
	c.metrics.ObserveLag(at)
	return nil
}

// SubscriberConfig holds Kafka connectivity + consumer group configuration.
type SubscriberConfig struct {
	Brokers  []string
	GroupID  string
	SASLCfg  sharedconfig.KafkaSASLConfig
	DLQTopic string
}

// Subscriber reads example.tenant.status and feeds the Consumer.
type Subscriber struct {
	cfg      SubscriberConfig
	consumer *Consumer
	metrics  *Metrics
	log      *zap.SugaredLogger

	reader    *kafka.Reader
	dlqWriter *kafka.Writer
	wg        sync.WaitGroup
	cancel    context.CancelFunc
}

// NewSubscriber wires a subscriber.
func NewSubscriber(cfg SubscriberConfig, consumer *Consumer, metrics *Metrics, log *zap.SugaredLogger) *Subscriber {
	if cfg.GroupID == "" {
		cfg.GroupID = ConsumerGroup
	}
	if cfg.DLQTopic == "" {
		cfg.DLQTopic = DLQTopic
	}
	s := &Subscriber{cfg: cfg, consumer: consumer, metrics: metrics, log: log}
	if len(cfg.Brokers) > 0 {
		w := &kafka.Writer{
			Addr: kafka.TCP(cfg.Brokers...), Topic: cfg.DLQTopic, Balancer: &kafka.Hash{},
			BatchTimeout: 10 * time.Millisecond, RequiredAcks: kafka.RequireAll,
		}
		if cfg.SASLCfg.SASLEnabled || cfg.SASLCfg.TLSEnabled {
			if t, err := buildKafkaTransport(cfg.SASLCfg); err != nil {
				log.Warnw("tenantstatus subscriber: DLQ transport build failed; DLQ disabled", "error", err)
			} else {
				w.Transport = t
				s.dlqWriter = w
			}
		} else {
			s.dlqWriter = w
		}
	}
	return s
}

// Run starts the read loop and blocks until ctx is canceled. Returns nil
// immediately when no brokers are configured.
func (s *Subscriber) Run(ctx context.Context) error {
	if len(s.cfg.Brokers) == 0 {
		s.log.Warn("tenantstatus subscriber: KAFKA_BROKERS empty, tenant suspension sync disabled")
		return nil
	}
	subCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	rc := kafka.ReaderConfig{
		Brokers: s.cfg.Brokers, GroupID: s.cfg.GroupID, Topic: Subject,
		MinBytes: 1, MaxBytes: 10e6, MaxWait: time.Second, StartOffset: kafka.FirstOffset,
	}
	if s.cfg.SASLCfg.SASLEnabled || s.cfg.SASLCfg.TLSEnabled {
		d, err := buildKafkaDialer(s.cfg.SASLCfg)
		if err != nil {
			cancel()
			return fmt.Errorf("tenantstatus subscriber: dialer: %w", err)
		}
		rc.Dialer = d
	}
	s.reader = kafka.NewReader(rc)
	s.wg.Add(1)
	go s.consume(subCtx)
	s.log.Infow("tenantstatus subscriber: subscribed", "subject", Subject, "group", s.cfg.GroupID)
	<-subCtx.Done()
	return nil
}

// Stop cancels the context, closes the reader and waits for in-flight handlers.
func (s *Subscriber) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.reader != nil {
		_ = s.reader.Close()
	}
	s.wg.Wait()
	if s.dlqWriter != nil {
		_ = s.dlqWriter.Close()
	}
}

func (s *Subscriber) consume(ctx context.Context) {
	defer s.wg.Done()
	for {
		msg, err := s.reader.ReadMessage(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return
			}
			s.log.Warnw("tenantstatus subscriber: read error", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		msgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		s.handle(msgCtx, msg)
		cancel()
	}
}

func (s *Subscriber) handle(ctx context.Context, msg kafka.Message) {
	first := time.Now().UTC()
	var last error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := s.consumer.Handle(ctx, msg.Value)
		if err == nil {
			return
		}
		last = err
		var perm permanentError
		if errors.As(err, &perm) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
		}
	}
	s.sendToDLQ(ctx, msg, first, last)
}

func (s *Subscriber) sendToDLQ(ctx context.Context, msg kafka.Message, first time.Time, terminal error) {
	if s.dlqWriter == nil {
		s.log.Errorw("tenantstatus subscriber: terminal failure, DLQ disabled, dropping", "offset", msg.Offset, "error", terminal)
		s.metrics.inc("failed")
		return
	}
	pubCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := s.dlqWriter.WriteMessages(pubCtx, kafka.Message{
		Key: msg.Key, Value: msg.Value, Time: time.Now().UTC(),
		Headers: []kafka.Header{
			{Key: "x-original-topic", Value: []byte(Subject)},
			{Key: "x-consumer-group", Value: []byte(ConsumerGroup)},
			{Key: "x-retry-count", Value: []byte(strconv.Itoa(maxRetries))},
			{Key: "x-first-attempt-at", Value: []byte(first.Format(time.RFC3339Nano))},
			{Key: "x-final-error", Value: []byte(terminal.Error())},
		},
	})
	if err != nil {
		s.log.Errorw("tenantstatus subscriber: DLQ publish FAILED -- payload LOST", "offset", msg.Offset, "terminal_error", terminal, "dlq_error", err)
		s.metrics.inc("failed")
		return
	}
	s.log.Warnw("tenantstatus subscriber: terminal failure, sent to DLQ", "offset", msg.Offset, "error", terminal)
	s.metrics.inc("dlq")
}

func buildKafkaDialer(c sharedconfig.KafkaSASLConfig) (*kafka.Dialer, error) {
	d := &kafka.Dialer{DualStack: true}
	if c.SASLEnabled {
		mech, err := saslMechanism(c)
		if err != nil {
			return nil, err
		}
		d.SASLMechanism = mech
	}
	if c.TLSEnabled {
		tlsCfg, err := c.NewTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("build TLS config: %w", err)
		}
		d.TLS = tlsCfg
	}
	return d, nil
}

func buildKafkaTransport(c sharedconfig.KafkaSASLConfig) (*kafka.Transport, error) {
	t := &kafka.Transport{}
	if c.SASLEnabled {
		mech, err := saslMechanism(c)
		if err != nil {
			return nil, err
		}
		t.SASL = mech
	}
	if c.TLSEnabled {
		tlsCfg, err := c.NewTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("build TLS config: %w", err)
		}
		t.TLS = tlsCfg
	}
	return t, nil
}

func saslMechanism(c sharedconfig.KafkaSASLConfig) (sasl.Mechanism, error) {
	var algo scram.Algorithm
	switch c.SASLMechanism {
	case "SCRAM-SHA-256":
		algo = scram.SHA256
	case "SCRAM-SHA-512":
		algo = scram.SHA512
	default:
		return nil, fmt.Errorf("unsupported SASL mechanism: %s (supported: SCRAM-SHA-256, SCRAM-SHA-512)", c.SASLMechanism)
	}
	mech, err := scram.Mechanism(algo, c.SASLUsername, c.SASLPassword)
	if err != nil {
		return nil, fmt.Errorf("create SCRAM mechanism: %w", err)
	}
	return mech, nil
}
