// SPDX-License-Identifier: AGPL-3.0-or-later

// Package iamevents publishes falcon-id user lifecycle events
// (example.iam.user.created / .updated / .status-changed) straight to Kafka.
//
// Consumer: example-business HR (IamUserEventConsumer, group business-hr-iam-sync),
// which keeps employee contact data and IAM links in step with the identity
// provider. The topics and this service's Write ACLs are pre-created in
// <gitops-bootstrap-repo> (addons/base/kafka-cluster/manifests); falcon-id holds no
// Create ACL, so only the names in Topics may be written (anything else is
// rejected locally instead of failing on the broker).
//
// Wire format matches the business IntegrationEventEnvelope
// (Shared/Outbox/IntegrationEventEnvelope.cs) and its Kafka headers
// ("tenant-id", "event-type"), so the business KafkaConsumer reads it like any
// other platform event. Message key = user id, which keeps every event for one
// user on one partition (in order).
package iamevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	sharedconfig "github.com/dogukanturhal/platform-shared/config"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/scram"
	"go.uber.org/zap"
)

// Event names (4-segment, hyphenated; must equal the KafkaTopic names).
const (
	UserCreated       = "example.iam.user.created"
	UserUpdated       = "example.iam.user.updated"
	UserStatusChanged = "example.iam.user.status-changed"
)

// Topics is the closed set of topics this publisher may write.
var Topics = []string{UserCreated, UserUpdated, UserStatusChanged}

// ErrUnknownEventType is returned for an event type outside Topics.
var ErrUnknownEventType = errors.New("iamevents: event type has no pre-created topic")

// Envelope is the JSON value of every message.
type Envelope struct {
	EventID       uuid.UUID       `json:"event_id"`
	EventType     string          `json:"event_type"`
	TenantID      string          `json:"tenant_id"`
	OccurredAt    time.Time       `json:"occurred_at"`
	AggregateType string          `json:"aggregate_type"`
	AggregateID   string          `json:"aggregate_id"`
	Payload       json.RawMessage `json:"payload"`
}

// messageWriter is the subset of *kafka.Writer the publisher needs (test seam).
type messageWriter interface {
	WriteMessages(ctx context.Context, msgs ...kafka.Message) error
	Close() error
}

// Publisher writes IAM user events to Kafka. Safe for concurrent use.
type Publisher struct {
	w   messageWriter
	log *zap.Logger
	now func() time.Time
}

// NewPublisher builds a publisher for the given brokers. SASL/TLS follow the
// shared KAFKA_SASL_* settings (same credentials as falcon-id's consumers).
func NewPublisher(brokers []string, saslCfg sharedconfig.KafkaSASLConfig, log *zap.Logger) (*Publisher, error) {
	if len(brokers) == 0 {
		return nil, errors.New("iamevents: no Kafka brokers configured")
	}
	w := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Balancer:     &kafka.Hash{},
		BatchTimeout: 10 * time.Millisecond,
		RequiredAcks: kafka.RequireAll,
		// Topics are pre-created by <gitops-bootstrap-repo>; never auto-create.
		AllowAutoTopicCreation: false,
	}
	if saslCfg.SASLEnabled || saslCfg.TLSEnabled {
		transport, err := buildTransport(saslCfg)
		if err != nil {
			return nil, fmt.Errorf("iamevents: kafka transport: %w", err)
		}
		w.Transport = transport
	}
	return newPublisher(w, log), nil
}

func newPublisher(w messageWriter, log *zap.Logger) *Publisher {
	if log == nil {
		log = zap.NewNop()
	}
	return &Publisher{w: w, log: log, now: time.Now}
}

// PublishEvent writes one event. tenantID must be a UUID; payload is any
// JSON-serialisable value and must carry "user_id" (used as aggregate id/key).
func (p *Publisher) PublishEvent(ctx context.Context, tenantID, eventType string, payload interface{}) error {
	if !isKnown(eventType) {
		return fmt.Errorf("%w: %s", ErrUnknownEventType, eventType)
	}
	if _, err := uuid.Parse(tenantID); err != nil {
		return fmt.Errorf("iamevents: invalid tenant id: %w", err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("iamevents: marshal payload: %w", err)
	}
	var ids struct {
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(raw, &ids); err != nil || ids.UserID == "" {
		return errors.New("iamevents: payload has no user_id")
	}
	env := Envelope{
		EventID:       uuid.New(),
		EventType:     eventType,
		TenantID:      tenantID,
		OccurredAt:    p.now().UTC(),
		AggregateType: "iam_user",
		AggregateID:   ids.UserID,
		Payload:       raw,
	}
	value, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("iamevents: marshal envelope: %w", err)
	}
	msg := kafka.Message{
		Topic: eventType,
		Key:   []byte(ids.UserID),
		Value: value,
		Headers: []kafka.Header{
			{Key: "tenant-id", Value: []byte(tenantID)},
			{Key: "event-type", Value: []byte(eventType)},
			{Key: "event-id", Value: []byte(env.EventID.String())},
		},
	}
	if err := p.w.WriteMessages(ctx, msg); err != nil {
		return fmt.Errorf("iamevents: write %s: %w", eventType, err)
	}
	p.log.Debug("iam user event published",
		zap.String("event_type", eventType),
		zap.String("event_id", env.EventID.String()),
		zap.String("tenant_id", tenantID))
	return nil
}

// Close flushes and closes the underlying writer.
func (p *Publisher) Close() error { return p.w.Close() }

func isKnown(eventType string) bool {
	for _, t := range Topics {
		if t == eventType {
			return true
		}
	}
	return false
}

func buildTransport(saslCfg sharedconfig.KafkaSASLConfig) (*kafka.Transport, error) {
	t := &kafka.Transport{}
	if saslCfg.SASLEnabled {
		algo := scram.SHA512
		switch saslCfg.SASLMechanism {
		case "SCRAM-SHA-256":
			algo = scram.SHA256
		case "SCRAM-SHA-512", "":
		default:
			return nil, fmt.Errorf("unsupported SASL mechanism: %s", saslCfg.SASLMechanism)
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
