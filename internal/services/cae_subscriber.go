// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// SSEClient represents a single connected SSE consumer. Callers receive an
// *SSEClient from CAERedisSubscriber.Subscribe and read CAEP event frames from
// its Events() channel.
type SSEClient struct {
	id          uuid.UUID
	tenantID    uuid.UUID
	eventFilter map[CAEEventType]struct{} // nil means accept all types
	send        chan []byte
}

// Events returns a receive-only channel that yields pre-serialised SSE frames.
// The channel is closed when the client is removed from the subscriber (i.e.
// after the cleanup function returned by Subscribe is called).
func (c *SSEClient) Events() <-chan []byte {
	return c.send
}

// CAERedisSubscriber subscribes to a Redis pub/sub channel and fans events
// out to all registered SSE clients for the relevant tenant.
//
// The subscriber is designed to be long-lived: it runs until the provided
// context is cancelled (typically on graceful shutdown) and handles Redis
// reconnection internally.
type CAERedisSubscriber struct {
	redisClient redis.UniversalClient
	logger      *zap.Logger

	mu      sync.RWMutex
	clients map[uuid.UUID]*SSEClient // keyed by client.id

	// channelPrefix is the Redis pub/sub channel prefix.
	// Full channel name: "<channelPrefix>:<tenant_id>"
	channelPrefix string
}

// NewCAERedisSubscriber constructs a CAERedisSubscriber.
// redisClient must already be connected; the caller owns its lifecycle.
func NewCAERedisSubscriber(redisClient redis.UniversalClient, logger *zap.Logger) *CAERedisSubscriber {
	return &CAERedisSubscriber{
		redisClient:   redisClient,
		clients:       make(map[uuid.UUID]*SSEClient),
		channelPrefix: "caep:events",
		logger:        logger,
	}
}

// Subscribe registers a new SSE client and returns the client handle and a
// cleanup function that the caller MUST invoke when the HTTP connection closes.
//
// eventTypes filters which CAEEventType values are delivered; passing nil
// means all types are forwarded.
func (s *CAERedisSubscriber) Subscribe(
	tenantID uuid.UUID,
	eventTypes []CAEEventType,
) (*SSEClient, func()) {
	client := &SSEClient{
		id:       uuid.New(),
		tenantID: tenantID,
		send:     make(chan []byte, 64), // buffer prevents slow-consumer stalls
	}

	if len(eventTypes) > 0 {
		client.eventFilter = make(map[CAEEventType]struct{}, len(eventTypes))
		for _, et := range eventTypes {
			client.eventFilter[et] = struct{}{}
		}
	}

	s.mu.Lock()
	s.clients[client.id] = client
	s.mu.Unlock()

	s.logger.Debug("CAE SSE client registered",
		zap.String("client_id", client.id.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.Int("filter_count", len(eventTypes)),
	)

	cleanup := func() {
		s.mu.Lock()
		delete(s.clients, client.id)
		s.mu.Unlock()
		close(client.send)

		s.logger.Debug("CAE SSE client removed",
			zap.String("client_id", client.id.String()),
			zap.String("tenant_id", tenantID.String()),
		)
	}

	return client, cleanup
}

// BroadcastToTenant delivers an event to all SSE clients registered for
// tenantID whose event filter admits the event type.
// Clients with a full send channel receive a warning log and the frame is
// dropped — SSE reconnection + history catch-up handles recovery.
func (s *CAERedisSubscriber) BroadcastToTenant(tenantID uuid.UUID, event CAEEvent) {
	frame := BuildSSEFrame(event)

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		if client.tenantID != tenantID {
			continue
		}

		// Apply per-client event type filter.
		if client.eventFilter != nil {
			if _, ok := client.eventFilter[event.Type]; !ok {
				continue
			}
		}

		select {
		case client.send <- frame:
		default:
			// The consumer is not keeping up; drop the frame rather than
			// blocking the broadcast loop.
			s.logger.Warn("CAE SSE client send buffer full; dropping frame",
				zap.String("client_id", client.id.String()),
				zap.String("event_type", string(event.Type)),
			)
		}
	}
}

// Run subscribes to all tenant channels using a Redis PSUBSCRIBE pattern and
// forwards received messages to registered SSE clients. It blocks until ctx
// is cancelled. Redis reconnection is handled by go-redis internally.
func (s *CAERedisSubscriber) Run(ctx context.Context) {
	pattern := s.channelPrefix + ":*"

	pubsub := s.redisClient.PSubscribe(ctx, pattern)
	defer func() { _ = pubsub.Close() }()

	s.logger.Info("CAE Redis subscriber started", zap.String("pattern", pattern))

	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("CAE Redis subscriber shutting down")
			return

		case msg, ok := <-ch:
			if !ok {
				// Channel was closed (Redis disconnect). go-redis re-subscribes
				// automatically; wait briefly before the next iteration to avoid
				// a tight spin during outages.
				s.logger.Warn("CAE Redis pub/sub channel closed; waiting for reconnect")
				select {
				case <-ctx.Done():
					return
				case <-time.After(500 * time.Millisecond):
				}
				continue
			}

			s.handleMessage(msg)
		}
	}
}

// handleMessage decodes a Redis pub/sub message and delivers the event to
// matching SSE clients.
func (s *CAERedisSubscriber) handleMessage(msg *redis.Message) {
	var event CAEEvent
	if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
		s.logger.Error("CAE subscriber: failed to unmarshal event",
			zap.String("channel", msg.Channel),
			zap.Error(err),
		)
		return
	}

	s.BroadcastToTenant(event.TenantID, event)
}

// BuildSSEFrame serialises a CAEEvent into a complete SSE frame.
// The id field is the event timestamp in Unix nanoseconds so that a
// reconnecting client can supply Last-Event-ID for precise catch-up.
// Exported so that cae_handler.go can reuse the same format during replay.
func BuildSSEFrame(event CAEEvent) []byte {
	data, _ := json.Marshal(event)
	frame := fmt.Sprintf(
		"id:%d\nevent:%s\ndata:%s\n\n",
		event.Timestamp.UnixNano(),
		string(event.Type),
		string(data),
	)
	return []byte(frame)
}
