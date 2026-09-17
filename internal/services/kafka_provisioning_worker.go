// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
)

// TopicSubscriptionActivated is an exported identifier.
// Kafka is an exported identifier.
// Kafka is an exported identifier.
// Kafka topic for subscription activation events.
const TopicSubscriptionActivated = "example.tenant.subscription.activated"

// KafkaProvisioningWorkerConfig holds Kafka configuration.
type KafkaProvisioningWorkerConfig struct {
	Brokers []string
	GroupID string
	Topic   string
}

// KafkaProvisioningWorker consumes subscription activation events from Kafka
// and triggers product provisioning via the ProvisioningConsumer.
type KafkaProvisioningWorker struct {
	cfg      KafkaProvisioningWorkerConfig
	consumer *ProvisioningConsumer
	reader   *kafka.Reader
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	// Deduplication: track processed event IDs to handle at-least-once delivery.
	processedEvents sync.Map
}

// NewKafkaProvisioningWorker creates a new Kafka worker.
func NewKafkaProvisioningWorker(cfg KafkaProvisioningWorkerConfig, consumer *ProvisioningConsumer) *KafkaProvisioningWorker {
	ctx, cancel := context.WithCancel(context.Background())

	if cfg.Topic == "" {
		cfg.Topic = TopicSubscriptionActivated
	}

	return &KafkaProvisioningWorker{
		cfg:      cfg,
		consumer: consumer,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start begins consuming subscription activation events from Kafka.
func (w *KafkaProvisioningWorker) Start() error {
	if len(w.cfg.Brokers) == 0 {
		log.Println("[KafkaProvisioningWorker] Kafka brokers not configured, skipping")
		return nil
	}

	w.reader = kafka.NewReader(kafka.ReaderConfig{
		Brokers:     w.cfg.Brokers,
		GroupID:     w.cfg.GroupID,
		Topic:       w.cfg.Topic,
		MinBytes:    10e3,
		MaxBytes:    10e6,
		StartOffset: kafka.LastOffset,
	})

	w.wg.Add(1)
	go w.consumeLoop()

	w.wg.Add(1)
	go w.cleanProcessedEvents()

	log.Printf("[KafkaProvisioningWorker] Started consuming from topic %s", w.cfg.Topic)
	return nil
}

// Stop gracefully shuts down the worker.
func (w *KafkaProvisioningWorker) Stop() {
	w.cancel()
	if w.reader != nil {
		_ = w.reader.Close()
	}
	w.wg.Wait()
	log.Println("[KafkaProvisioningWorker] Stopped")
}

func (w *KafkaProvisioningWorker) consumeLoop() {
	defer w.wg.Done()

	for {
		msg, err := w.reader.ReadMessage(w.ctx)
		if err != nil {
			if w.ctx.Err() != nil {
				return // context cancelled, shutting down
			}
			log.Printf("[KafkaProvisioningWorker] Read error: %v", err)
			continue
		}

		w.handleMessage(msg)
	}
}

func (w *KafkaProvisioningWorker) handleMessage(msg kafka.Message) {
	// Deduplication: use the message key + offset as event ID.
	eventKey := fmt.Sprintf("%s:%d:%d", msg.Topic, msg.Partition, msg.Offset)
	if _, loaded := w.processedEvents.LoadOrStore(eventKey, time.Now()); loaded {
		log.Printf("[KafkaProvisioningWorker] Duplicate event %s, skipping", eventKey)
		return
	}

	event, err := ParseSubscriptionActivatedEvent(msg.Value)
	if err != nil {
		log.Printf("[KafkaProvisioningWorker] Failed to parse event: %v", err)
		return
	}

	log.Printf("[KafkaProvisioningWorker] Processing subscription.activated for tenant %s", event.TenantID)

	if err := w.consumer.HandleSubscriptionActivated(w.ctx, *event); err != nil {
		log.Printf("[KafkaProvisioningWorker] Failed to handle activation for tenant %s: %v",
			event.TenantID, err)
		// Don't remove from processedEvents — let the dedup window expire
		// and allow reprocessing on next delivery if needed.
	}
}

func (w *KafkaProvisioningWorker) cleanProcessedEvents() {
	defer w.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-1 * time.Hour)
			w.processedEvents.Range(func(key, value interface{}) bool {
				if ts, ok := value.(time.Time); ok && ts.Before(cutoff) {
					w.processedEvents.Delete(key)
				}
				return true
			})
		}
	}
}

// ParseKafkaMessage is a convenience function for parsing a raw Kafka message
// into a SubscriptionActivatedEvent. Useful for testing.
func ParseKafkaMessage(data []byte) (*SubscriptionActivatedEvent, error) {
	var raw struct {
		TenantID  string  `json:"tenant_id"`
		ProductID *string `json:"product_id,omitempty"`
		Timestamp string  `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal kafka message: %w", err)
	}

	return ParseSubscriptionActivatedEvent(data)
}
