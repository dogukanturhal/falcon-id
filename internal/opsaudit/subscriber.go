// SPDX-License-Identifier: AGPL-3.0-or-later

package opsaudit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	sharedconfig "github.com/dogukanturhal/platform-shared/config"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/scram"
	"go.uber.org/zap"
)

const (
	// ConsumerGroup MUST NOT be shared with any other consumer.
	ConsumerGroup = "falcon-id-ops-audit"
	// DLQTopic receives events that cannot be stored.
	DLQTopic = Topic + ".dlq"

	maxRetries = 5
)

// SubscriberConfig holds Kafka connectivity + consumer group configuration.
type SubscriberConfig struct {
	Brokers []string
	GroupID string
	SASLCfg sharedconfig.KafkaSASLConfig
}

// Subscriber reads platform.ops-audit.v1 and feeds the Consumer.
type Subscriber struct {
	cfg      SubscriberConfig
	consumer *Consumer
	log      *zap.SugaredLogger

	reader    *kafka.Reader
	dlqWriter *kafka.Writer
	wg        sync.WaitGroup
	cancel    context.CancelFunc
}

// NewSubscriber wires a subscriber.
func NewSubscriber(cfg SubscriberConfig, consumer *Consumer, log *zap.SugaredLogger) *Subscriber {
	if cfg.GroupID == "" {
		cfg.GroupID = ConsumerGroup
	}
	s := &Subscriber{cfg: cfg, consumer: consumer, log: log}
	if len(cfg.Brokers) > 0 {
		w := &kafka.Writer{
			Addr: kafka.TCP(cfg.Brokers...), Topic: DLQTopic, Balancer: &kafka.Hash{},
			BatchTimeout: 10 * time.Millisecond, RequiredAcks: kafka.RequireAll,
		}
		if cfg.SASLCfg.SASLEnabled || cfg.SASLCfg.TLSEnabled {
			t, err := buildTransport(cfg.SASLCfg)
			if err != nil {
				log.Warnw("opsaudit subscriber: DLQ transport build failed; DLQ disabled", "error", err)
				return s
			}
			w.Transport = t
		}
		s.dlqWriter = w
	}
	return s
}

// Run starts the read loop and blocks until ctx is canceled. Returns nil
// immediately when no brokers are configured.
func (s *Subscriber) Run(ctx context.Context) error {
	if len(s.cfg.Brokers) == 0 {
		s.log.Warn("opsaudit subscriber: KAFKA_BROKERS empty, operator audit consumer disabled")
		return nil
	}
	subCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	rc := kafka.ReaderConfig{
		Brokers: s.cfg.Brokers, GroupID: s.cfg.GroupID, Topic: Topic,
		MinBytes: 1, MaxBytes: 10e6, MaxWait: time.Second, StartOffset: kafka.FirstOffset,
	}
	if s.cfg.SASLCfg.SASLEnabled || s.cfg.SASLCfg.TLSEnabled {
		d, err := buildDialer(s.cfg.SASLCfg)
		if err != nil {
			cancel()
			return fmt.Errorf("opsaudit subscriber: dialer: %w", err)
		}
		rc.Dialer = d
	}
	s.reader = kafka.NewReader(rc)
	s.wg.Add(1)
	go s.consume(subCtx)
	s.log.Infow("opsaudit subscriber: subscribed", "topic", Topic, "group", s.cfg.GroupID)
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
			s.log.Warnw("opsaudit subscriber: read error", "error", err)
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
	s.sendToDLQ(msg, first, last)
}

func (s *Subscriber) sendToDLQ(msg kafka.Message, first time.Time, terminal error) {
	if s.dlqWriter == nil {
		s.log.Errorw("opsaudit subscriber: terminal failure, DLQ disabled, AUDIT EVENT DROPPED", "offset", msg.Offset, "error", terminal)
		return
	}
	pubCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := s.dlqWriter.WriteMessages(pubCtx, kafka.Message{
		Key: msg.Key, Value: msg.Value, Time: time.Now().UTC(),
		Headers: []kafka.Header{
			{Key: "x-original-topic", Value: []byte(Topic)},
			{Key: "x-consumer-group", Value: []byte(s.cfg.GroupID)},
			{Key: "x-retry-count", Value: []byte(strconv.Itoa(maxRetries))},
			{Key: "x-first-attempt-at", Value: []byte(first.Format(time.RFC3339Nano))},
			{Key: "x-final-error", Value: []byte(terminal.Error())},
		},
	})
	if err != nil {
		s.log.Errorw("opsaudit subscriber: DLQ publish FAILED -- AUDIT EVENT LOST", "offset", msg.Offset, "terminal_error", terminal, "dlq_error", err)
		return
	}
	s.log.Warnw("opsaudit subscriber: terminal failure, sent to DLQ", "offset", msg.Offset, "error", terminal)
}

func buildDialer(c sharedconfig.KafkaSASLConfig) (*kafka.Dialer, error) {
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

func buildTransport(c sharedconfig.KafkaSASLConfig) (*kafka.Transport, error) {
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
