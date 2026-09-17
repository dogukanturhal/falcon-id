// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PermissionChange represents a permission change from SpiceDB Watch API
type PermissionChange struct {
	Operation    string // "TOUCH", "DELETE"
	ResourceType string // "user", "tenant", "role", etc.
	ResourceID   string // Resource identifier
	Relation     string // "member", "admin", "viewer", etc.
	SubjectType  string // "user", "group", etc.
	SubjectID    string // Subject identifier
	Timestamp    time.Time
}

// ChangeHandler is a function that processes permission changes
type ChangeHandler func(ctx context.Context, change PermissionChange) error

// WatchService streams permission changes from SpiceDB and invalidates caches
type WatchService struct {
	client   *authzed.Client
	redis    *redis.Client
	logger   *zap.Logger
	handlers []ChangeHandler
	stopCh   chan struct{}
	stopOnce sync.Once
	mu       sync.RWMutex

	// Reconnection configuration
	reconnectDelay    time.Duration
	maxReconnectDelay time.Duration
}

// WatchConfig holds configuration for the Watch service
type WatchConfig struct {
	// Optional object types to watch (empty = watch all)
	ObjectTypes []string

	// Reconnection settings
	ReconnectDelay    time.Duration // Initial reconnect delay
	MaxReconnectDelay time.Duration // Max reconnect delay (exponential backoff)
}

// DefaultWatchConfig returns default watch configuration
func DefaultWatchConfig() *WatchConfig {
	return &WatchConfig{
		ObjectTypes:       []string{}, // Watch all types
		ReconnectDelay:    1 * time.Second,
		MaxReconnectDelay: 30 * time.Second,
	}
}

// NewWatchService creates a new SpiceDB Watch service
func NewWatchService(client *authzed.Client, redisClient *redis.Client, logger *zap.Logger, cfg *WatchConfig) *WatchService {
	if cfg == nil {
		cfg = DefaultWatchConfig()
	}

	return &WatchService{
		client:            client,
		redis:             redisClient,
		logger:            logger,
		handlers:          make([]ChangeHandler, 0),
		stopCh:            make(chan struct{}),
		reconnectDelay:    cfg.ReconnectDelay,
		maxReconnectDelay: cfg.MaxReconnectDelay,
	}
}

// RegisterHandler registers a change handler
func (w *WatchService) RegisterHandler(handler ChangeHandler) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.handlers = append(w.handlers, handler)
}

// RegisterCacheInvalidationHandler registers a handler that invalidates permission cache
func (w *WatchService) RegisterCacheInvalidationHandler() {
	w.RegisterHandler(func(ctx context.Context, change PermissionChange) error {
		// Extract tenant and user from subject ID (format: "tenantID:userID")
		parts := strings.Split(change.SubjectID, ":")
		if len(parts) != 2 {
			w.logger.Warn("Invalid subject ID format for cache invalidation",
				zap.String("subject_id", change.SubjectID),
			)
			return nil
		}

		tenantIDStr, userIDStr := parts[0], parts[1]

		// Validate UUIDs
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			w.logger.Warn("Invalid tenant UUID in subject ID",
				zap.String("tenant_id", tenantIDStr),
				zap.Error(err),
			)
			return nil
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			w.logger.Warn("Invalid user UUID in subject ID",
				zap.String("user_id", userIDStr),
				zap.Error(err),
			)
			return nil
		}

		// Invalidate user's permission cache
		// Pattern: hexxlock:authz:{tenantID}:{userID}:*
		pattern := fmt.Sprintf("hexxlock:authz:%s:%s:*", tenantID, userID)

		// Use SCAN to find all matching keys (safer than KEYS in production)
		iter := w.redis.Scan(ctx, 0, pattern, 100).Iterator()
		keysToDelete := make([]string, 0)

		for iter.Next(ctx) {
			keysToDelete = append(keysToDelete, iter.Val())
		}

		if err := iter.Err(); err != nil {
			w.logger.Error("Failed to scan Redis keys for invalidation",
				zap.Error(err),
				zap.String("pattern", pattern),
			)
			return fmt.Errorf("RegisterCacheInvalidationHandler: %w", err)
		}

		// Delete keys in batch if any found
		if len(keysToDelete) > 0 {
			if err := w.redis.Del(ctx, keysToDelete...).Err(); err != nil {
				w.logger.Error("Failed to delete cache keys",
					zap.Error(err),
					zap.Int("key_count", len(keysToDelete)),
				)
				return fmt.Errorf("RegisterCacheInvalidationHandler: %w", err)
			}

			w.logger.Info("Invalidated permission cache keys",
				zap.String("tenant_id", tenantIDStr),
				zap.String("user_id", userIDStr),
				zap.Int("key_count", len(keysToDelete)),
			)
		}

		// Publish invalidation event to Redis pub/sub
		message := map[string]interface{}{
			"type":      "watch_update",
			"tenant_id": tenantID.String(),
			"user_id":   userID.String(),
			"operation": change.Operation,
			"resource":  change.ResourceType,
			"relation":  change.Relation,
			"timestamp": change.Timestamp.Format(time.RFC3339),
		}

		// Publish to hexxlock:permission:invalidate channel
		if err := w.redis.Publish(ctx, "hexxlock:permission:invalidate", message).Err(); err != nil {
			w.logger.Warn("Failed to publish invalidation event",
				zap.Error(err),
			)
			// Don't return error - cache invalidation succeeded even if pub/sub failed
		}

		return nil
	})
}

// RegisterUserNotificationHandler registers a handler that publishes
// per-user permission change events to a Redis Pub/Sub channel.
// Each subject of type "user" gets a message published to
// "hexxlock:permissions:<userID>" so SSE connections can relay it to
// the browser in real time.
func (w *WatchService) RegisterUserNotificationHandler() {
	w.RegisterHandler(func(ctx context.Context, change PermissionChange) error {
		if change.SubjectType != spicedbObjectTypeUser {
			return nil
		}

		userID := extractUserID(change.SubjectID)
		if userID == "" {
			return nil
		}

		channel := fmt.Sprintf("hexxlock:permissions:%s", userID)
		msg := fmt.Sprintf(
			`{"type":"permission_changed","user_id":"%s","resource":"%s","relation":"%s","operation":"%s","timestamp":"%s"}`,
			userID,
			change.ResourceType,
			change.Relation,
			change.Operation,
			change.Timestamp.Format(time.RFC3339),
		)

		if err := w.redis.Publish(ctx, channel, msg).Err(); err != nil {
			w.logger.Warn("Failed to publish user permission notification",
				zap.String("user_id", userID),
				zap.String("channel", channel),
				zap.Error(err),
			)
			// Non-fatal: cache invalidation already succeeded via
			// RegisterCacheInvalidationHandler; SSE delivery is best-effort.
			return nil
		}

		w.logger.Debug("Published user permission notification",
			zap.String("user_id", userID),
			zap.String("channel", channel),
			zap.String("operation", change.Operation),
		)

		return nil
	})
}

// extractUserID derives the plain user ID from a tenant-scoped subject ID.
// SpiceDB subject IDs are formatted as "<tenantID>/<userID>" (tenant-scoped)
// or, in legacy format, "<tenantID>:<userID>".  When no separator is found
// the raw string is returned as-is (single-component ID).
func extractUserID(subjectID string) string {
	// Prefer slash separator (canonical tenant-scoped format in this codebase)
	if parts := strings.SplitN(subjectID, "/", 2); len(parts) == 2 {
		return parts[1]
	}
	// Fall back to colon separator
	if parts := strings.SplitN(subjectID, ":", 2); len(parts) == 2 {
		return parts[1]
	}
	return subjectID
}

// Start begins watching for permission changes
func (w *WatchService) Start(ctx context.Context) error {
	w.logger.Info("Starting SpiceDB Watch service")

	currentDelay := w.reconnectDelay

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("SpiceDB Watch service stopped by context")
			return ctx.Err()
		case <-w.stopCh:
			w.logger.Info("SpiceDB Watch service stopped")
			return nil
		default:
			// Attempt to connect and stream
			err := w.streamChanges(ctx)
			if err != nil {
				// If the Watch API is not available (Unimplemented), stop retrying.
				// This is a permanent error — enable --datastore-watch-enabled on SpiceDB.
				if isGRPCCode(err, codes.Unimplemented) {
					w.logger.Warn("SpiceDB Watch API not enabled, disabling watch service. "+
						"Enable with --datastore-watch-enabled=true on SpiceDB server",
						zap.Error(err))
					return nil
				}

				w.logger.Error("SpiceDB Watch stream error, reconnecting",
					zap.Error(err),
					zap.Duration("delay", currentDelay),
				)

				// Wait before reconnecting (exponential backoff)
				select {
				case <-time.After(currentDelay):
					// Double the delay for next attempt (exponential backoff)
					currentDelay *= 2
					if currentDelay > w.maxReconnectDelay {
						currentDelay = w.maxReconnectDelay
					}
				case <-ctx.Done():
					return ctx.Err()
				case <-w.stopCh:
					return nil
				}
			} else {
				// Successfully reconnected, reset delay
				currentDelay = w.reconnectDelay
			}
		}
	}
}

// streamChanges maintains a Watch stream and processes changes
func (w *WatchService) streamChanges(ctx context.Context) error {
	// Create watch request
	req := &v1.WatchRequest{
		OptionalObjectTypes: []string{}, // Watch all types
	}

	// Establish watch stream
	stream, err := w.client.Watch(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create watch stream: %w", err)
	}

	w.logger.Info("SpiceDB Watch stream established")

	// Process updates from the stream
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.stopCh:
			return nil
		default:
			// Receive next update
			resp, err := stream.Recv()
			if err != nil {
				return fmt.Errorf("watch stream receive error: %w", err)
			}

			// Process all updates in the response
			for _, update := range resp.Updates {
				change := w.convertToChange(update)
				w.notifyHandlers(ctx, change)
			}
		}
	}
}

// convertToChange converts a SpiceDB relationship update to a PermissionChange
func (w *WatchService) convertToChange(update *v1.RelationshipUpdate) PermissionChange {
	change := PermissionChange{
		Timestamp: time.Now(),
	}

	// Determine operation
	switch update.Operation {
	case v1.RelationshipUpdate_OPERATION_TOUCH:
		change.Operation = "TOUCH"
	case v1.RelationshipUpdate_OPERATION_DELETE:
		change.Operation = "DELETE"
	default:
		change.Operation = "UNKNOWN"
	}

	// Extract relationship details
	if update.Relationship != nil {
		if update.Relationship.Resource != nil {
			change.ResourceType = update.Relationship.Resource.ObjectType
			change.ResourceID = update.Relationship.Resource.ObjectId
		}

		change.Relation = update.Relationship.Relation

		if update.Relationship.Subject != nil && update.Relationship.Subject.Object != nil {
			change.SubjectType = update.Relationship.Subject.Object.ObjectType
			change.SubjectID = update.Relationship.Subject.Object.ObjectId
		}
	}

	return change
}

// notifyHandlers notifies all registered handlers about a permission change
func (w *WatchService) notifyHandlers(ctx context.Context, change PermissionChange) {
	w.mu.RLock()
	handlers := make([]ChangeHandler, len(w.handlers))
	copy(handlers, w.handlers)
	w.mu.RUnlock()

	for i, handler := range handlers {
		if err := handler(ctx, change); err != nil {
			w.logger.Error("Handler failed to process permission change",
				zap.Int("handler_index", i),
				zap.Error(err),
				zap.String("operation", change.Operation),
				zap.String("resource", change.ResourceType),
				zap.String("subject", change.SubjectID),
			)
		}
	}
}

// Stop stops the watch service
func (w *WatchService) Stop() {
	w.stopOnce.Do(func() { close(w.stopCh) })
}

// isGRPCCode checks if any error in the chain is a gRPC error with the given code.
func isGRPCCode(err error, code codes.Code) bool {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if s, ok := status.FromError(e); ok && s.Code() == code {
			return true
		}
	}
	return false
}
