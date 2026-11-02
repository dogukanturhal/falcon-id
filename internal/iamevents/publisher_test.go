// SPDX-License-Identifier: AGPL-3.0-or-later

package iamevents

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
)

type fakeWriter struct {
	msgs []kafka.Message
	err  error
}

func (f *fakeWriter) WriteMessages(_ context.Context, msgs ...kafka.Message) error {
	if f.err != nil {
		return f.err
	}
	f.msgs = append(f.msgs, msgs...)
	return nil
}
func (f *fakeWriter) Close() error { return nil }

const tenant = "7f9c2b1e-3c1d-4e55-9a1b-2b5f2c9e0a11"
const user = "0c4d6a1e-1111-4a22-8b33-444455556666"

func TestPublishEvent_EnvelopeHeadersKey(t *testing.T) {
	fw := &fakeWriter{}
	p := newPublisher(fw, nil)
	p.now = func() time.Time { return time.Date(2026, 10, 5, 9, 0, 0, 0, time.FixedZone("TRT", 3*3600)) }

	payload := map[string]any{"user_id": user, "tenant_id": tenant, "email": "a@b.test", "is_active": true, "source": "iam"}
	if err := p.PublishEvent(context.Background(), tenant, UserCreated, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(fw.msgs) != 1 {
		t.Fatalf("want 1 message, got %d", len(fw.msgs))
	}
	m := fw.msgs[0]
	if m.Topic != UserCreated || string(m.Key) != user {
		t.Fatalf("topic/key = %q/%q", m.Topic, m.Key)
	}
	h := map[string]string{}
	for _, x := range m.Headers {
		h[x.Key] = string(x.Value)
	}
	if h["tenant-id"] != tenant || h["event-type"] != UserCreated || h["event-id"] == "" {
		t.Fatalf("headers = %v", h)
	}
	var env Envelope
	if err := json.Unmarshal(m.Value, &env); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if env.EventType != UserCreated || env.TenantID != tenant || env.AggregateID != user || env.AggregateType != "iam_user" {
		t.Fatalf("envelope = %+v", env)
	}
	if env.OccurredAt.Location() != time.UTC || env.OccurredAt.Hour() != 6 {
		t.Fatalf("occurred_at not UTC: %v", env.OccurredAt)
	}
	if env.EventID.String() != h["event-id"] {
		t.Fatal("event-id header must equal envelope event_id")
	}
	var back map[string]any
	if err := json.Unmarshal(env.Payload, &back); err != nil || back["email"] != "a@b.test" {
		t.Fatalf("payload round-trip: %v %v", back, err)
	}
}

func TestPublishEvent_Rejections(t *testing.T) {
	p := newPublisher(&fakeWriter{}, nil)
	ctx := context.Background()
	if err := p.PublishEvent(ctx, tenant, "example.iam.user.admin_soft_deleted", map[string]any{"user_id": user}); !errors.Is(err, ErrUnknownEventType) {
		t.Fatalf("unknown event type: %v", err)
	}
	if err := p.PublishEvent(ctx, "not-a-uuid", UserUpdated, map[string]any{"user_id": user}); err == nil {
		t.Fatal("invalid tenant must fail")
	}
	if err := p.PublishEvent(ctx, tenant, UserUpdated, map[string]any{"email": "x"}); err == nil {
		t.Fatal("missing user_id must fail")
	}
}

func TestPublishEvent_WriterError(t *testing.T) {
	p := newPublisher(&fakeWriter{err: errors.New("broker down")}, nil)
	if err := p.PublishEvent(context.Background(), tenant, UserStatusChanged, map[string]any{"user_id": user}); err == nil {
		t.Fatal("writer error must propagate")
	}
}

func TestTopicsAreFourSegmentHyphenated(t *testing.T) {
	for _, topic := range Topics {
		segs := 0
		for _, c := range topic {
			if c == '.' {
				segs++
			}
			if c == '_' {
				t.Fatalf("%s: underscore not allowed", topic)
			}
		}
		if segs != 3 {
			t.Fatalf("%s: want 4 segments", topic)
		}
	}
}
