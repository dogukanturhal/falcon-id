// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"strconv"

	"github.com/dogukanturhal/falcon-id/internal/iamevents"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	sharedconfig "github.com/dogukanturhal/platform-shared/config"
	"go.uber.org/zap"
)

// wireIAMUserEventPublisher connects UserService to Kafka so user create /
// update / status changes reach example-business HR (IamUserEventConsumer).
// Topics example.iam.user.{created,updated,status-changed} and the Write ACLs
// for falcon-id's SASL principal live in <gitops-bootstrap-repo>. Disabled when
// KAFKA_BROKERS is empty (dev) or IAM_USER_EVENTS_ENABLED=false.
func wireIAMUserEventPublisher(cfg *config.Config, userService *services.UserService) {
	if enabled, err := strconv.ParseBool(envOr("IAM_USER_EVENTS_ENABLED", "true")); err == nil && !enabled {
		logger.Info("IAM user lifecycle events disabled (IAM_USER_EVENTS_ENABLED=false)")
		return
	}
	brokers := splitCSV(cfg.KafkaBrokers)
	if len(brokers) == 0 {
		logger.Warn("IAM user lifecycle events disabled: KAFKA_BROKERS empty (HR employee sync will not receive user changes)")
		return
	}
	pub, err := iamevents.NewPublisher(brokers, sharedconfig.LoadKafkaSASLConfig(), logger.Log)
	if err != nil {
		logger.Error("IAM user lifecycle events disabled: publisher init failed", zap.Error(err))
		return
	}
	userService.SetIntegrationBusPublisher(pub)
	logger.Info("IAM user lifecycle events wired to Kafka", zap.Strings("topics", iamevents.Topics))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
