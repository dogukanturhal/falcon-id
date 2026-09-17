// SPDX-License-Identifier: AGPL-3.0-or-later

package provisioners

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

// KafkaResourceProvisioner provisions Kafka topics for tenant product instances.
//
// Topic naming convention: "example.{tenant_slug}.{resource_name}"
//
// Config keys read from ResourceProvisionRequest.Config:
//   - "partitions"      int – number of partitions (default: 3)
//   - "retention_hours" int – message retention in hours (default: 168 = 7 days)
//
// When Kafka brokers are unreachable, Provision returns a simulated result
// so the provisioning saga is not blocked in local development.
type KafkaResourceProvisioner struct {
	brokers []string
	log     *zap.SugaredLogger
}

// NewKafkaResourceProvisioner creates a KafkaResourceProvisioner.
// brokers is the list of Kafka broker addresses (e.g. ["kafka:9092"]).
func NewKafkaResourceProvisioner(brokers []string, log *zap.SugaredLogger) *KafkaResourceProvisioner {
	return &KafkaResourceProvisioner{
		brokers: brokers,
		log:     log,
	}
}

// ResourceType satisfies ResourceProvisioner.
func (p *KafkaResourceProvisioner) ResourceType() string { return "kafka_topic" }

// Provision creates a Kafka topic for the tenant.
func (p *KafkaResourceProvisioner) Provision(ctx context.Context, req ResourceProvisionRequest) (*ResourceProvisionResult, error) {
	partitions := intFromConfig(req.Config, "partitions", 3)
	retentionHours := intFromConfig(req.Config, "retention_hours", 168)
	topicName := buildKafkaTopicName(req.TenantSlug, req.ResourceName)

	if len(p.brokers) == 0 {
		p.log.Warnw("KafkaResourceProvisioner: no brokers configured, using simulated result",
			"topic", topicName,
		)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"topic_name":      topicName,
			"partitions":      partitions,
			"retention_hours": retentionHours,
		}), nil
	}

	conn, err := p.dialLeader(ctx)
	if err != nil {
		p.log.Warnw("KafkaResourceProvisioner: broker unavailable, using simulated result",
			"brokers", p.brokers,
			"topic", topicName,
			"error", err,
		)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"topic_name":      topicName,
			"partitions":      partitions,
			"retention_hours": retentionHours,
		}), nil
	}
	defer func() { _ = conn.Close() }()

	retentionMS := int64(retentionHours) * int64(time.Hour/time.Millisecond)
	topicCfg := kafka.TopicConfig{
		Topic:             topicName,
		NumPartitions:     partitions,
		ReplicationFactor: p.replicationFactor(),
		ConfigEntries: []kafka.ConfigEntry{
			{
				ConfigName:  "retention.ms",
				ConfigValue: fmt.Sprintf("%d", retentionMS),
			},
		},
	}

	err = conn.CreateTopics(topicCfg)
	if err != nil {
		// "Topic already exists" is not an error for idempotency.
		if isKafkaTopicExists(err) {
			p.log.Infow("KafkaResourceProvisioner: topic already exists, skipping creation",
				"topic", topicName,
			)
		} else {
			p.log.Warnw("KafkaResourceProvisioner: failed to create topic, using simulated result",
				"topic", topicName,
				"error", err,
			)
			return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
				"topic_name":      topicName,
				"partitions":      partitions,
				"retention_hours": retentionHours,
			}), nil
		}
	}

	p.log.Infow("KafkaResourceProvisioner: topic provisioned",
		"topic", topicName,
		"partitions", partitions,
		"retention_hours", retentionHours,
	)

	return &ResourceProvisionResult{
		Status: "active",
		ProvisionedConfig: map[string]interface{}{
			"topic_name":      topicName,
			"partitions":      partitions,
			"retention_hours": retentionHours,
		},
	}, nil
}

// Deprovision deletes a Kafka topic.
func (p *KafkaResourceProvisioner) Deprovision(ctx context.Context, req ResourceDeprovisionRequest) error {
	topicName := stringFromConfig(req.ProvisionedConfig, "topic_name", "")
	if topicName == "" {
		p.log.Warnw("KafkaResourceProvisioner.Deprovision: no topic_name in provisioned config, skipping",
			"tenant_slug", req.TenantSlug,
		)
		return nil
	}

	if len(p.brokers) == 0 {
		p.log.Warnw("KafkaResourceProvisioner.Deprovision: no brokers configured, skipping topic deletion",
			"topic", topicName,
		)
		return nil
	}

	conn, err := p.dialLeader(ctx)
	if err != nil {
		p.log.Warnw("KafkaResourceProvisioner.Deprovision: broker unavailable, skipping (non-fatal)",
			"topic", topicName,
			"error", err,
		)
		return nil
	}
	defer func() { _ = conn.Close() }()

	if err := conn.DeleteTopics(topicName); err != nil {
		if isKafkaTopicNotFound(err) {
			// Already gone — treat as success.
			return nil
		}
		p.log.Warnw("KafkaResourceProvisioner.Deprovision: failed to delete topic (non-fatal)",
			"topic", topicName,
			"error", err,
		)
		return nil
	}

	p.log.Infow("KafkaResourceProvisioner.Deprovision: topic deleted",
		"topic", topicName,
	)
	return nil
}

// HealthCheck verifies that the topic exists by reading its metadata.
func (p *KafkaResourceProvisioner) HealthCheck(ctx context.Context, req ResourceHealthCheckRequest) (*ResourceHealthResult, error) {
	topicName := stringFromConfig(req.ProvisionedConfig, "topic_name", "")
	if topicName == "" {
		return &ResourceHealthResult{Healthy: false, Message: "no topic_name in provisioned config"}, nil
	}

	if len(p.brokers) == 0 {
		return &ResourceHealthResult{Healthy: false, Message: "no Kafka brokers configured"}, nil
	}

	conn, err := p.dialLeader(ctx)
	if err != nil {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("Kafka broker unavailable: %v", err),
		}, nil
	}
	defer func() { _ = conn.Close() }()

	partitions, err := conn.ReadPartitions(topicName)
	if err != nil {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("topic %q not readable: %v", topicName, err),
		}, nil
	}

	return &ResourceHealthResult{
		Healthy: true,
		Message: fmt.Sprintf("topic %q has %d partition(s)", topicName, len(partitions)),
	}, nil
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// buildKafkaTopicName constructs the canonical topic name for a tenant resource.
func buildKafkaTopicName(tenantSlug, resourceName string) string {
	return fmt.Sprintf("example.%s.%s", tenantSlug, resourceName)
}

// dialLeader opens a TCP connection to the first available Kafka broker.
// The context deadline is honoured via a net.Dialer.
func (p *KafkaResourceProvisioner) dialLeader(ctx context.Context) (*kafka.Conn, error) {
	dialer := &kafka.Dialer{
		Timeout:   10 * time.Second,
		DualStack: true,
		DialFunc: func(ctx2 context.Context, network, address string) (net.Conn, error) {
			nd := &net.Dialer{Timeout: 10 * time.Second}
			return nd.DialContext(ctx2, network, address)
		},
	}

	var lastErr error
	for _, broker := range p.brokers {
		conn, err := dialer.DialContext(ctx, "tcp", broker)
		if err != nil {
			lastErr = err
			continue
		}
		return conn, nil
	}
	return nil, fmt.Errorf("all Kafka brokers unreachable: %w", lastErr)
}

// replicationFactor returns a sensible replication factor based on the number
// of configured brokers (capped at 3).
func (p *KafkaResourceProvisioner) replicationFactor() int {
	n := len(p.brokers)
	if n <= 0 {
		return 1
	}
	if n > 3 {
		return 3
	}
	return n
}

// isKafkaTopicExists returns true when the error message indicates the topic
// already exists (TOPIC_ALREADY_EXISTS Kafka error code).
func isKafkaTopicExists(err error) bool {
	if err == nil {
		return false
	}
	return containsAny(err.Error(),
		"TopicExistsException",
		"TOPIC_ALREADY_EXISTS",
		"topic already exists",
	)
}

// isKafkaTopicNotFound returns true when the error indicates the topic is gone.
func isKafkaTopicNotFound(err error) bool {
	if err == nil {
		return false
	}
	return containsAny(err.Error(),
		"UNKNOWN_TOPIC_OR_PARTITION",
		"topic not found",
		"UnknownTopicOrPartition",
	)
}

// containsAny returns true if s contains any of the given substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 {
			idx := 0
			for idx < len(s) {
				if len(s)-idx < len(sub) {
					break
				}
				if s[idx:idx+len(sub)] == sub {
					return true
				}
				idx++
			}
		}
	}
	return false
}
