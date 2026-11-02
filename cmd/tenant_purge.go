// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/tenantpurge"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	sharedconfig "github.com/dogukanturhal/platform-shared/config"
	serviceauth "github.com/dogukanturhal/platform-shared/service-auth"
)

// startTenantPurge starts falcon-id's tenant purge saga participant
// (internal/tenantpurge) when TENANT_PURGE_PARTICIPANT_ENABLED=true. A
// misconfigured participant fails startup. The returned func stops the consumer.
func startTenantPurge(infra *Infrastructure) func() {
	if !tenantpurge.Enabled() {
		return func() {}
	}
	if infra.DB == nil || infra.DB.Pool == nil {
		logger.Fatal("tenant purge participant needs the main database")
	}
	if infra.SpiceDBClient == nil {
		logger.Fatal("tenant purge participant needs the SpiceDB client")
	}
	opts := tenantpurge.Options{
		Pool:    infra.DB.Pool,
		SpiceDB: tenantpurge.NewSpiceDBCleaner(infra.SpiceDBClient.AuthzedClient()),
		Brokers: splitCSV(infra.Config.KafkaBrokers),
		SASL:    sharedconfig.LoadKafkaSASLConfig(),
		Logger:  logger.Log,
	}
	if infra.ControlPlaneDB != nil {
		opts.ControlPool = infra.ControlPlaneDB.Pool
	}
	purge, err := tenantpurge.New(opts)
	if err != nil {
		logger.Fatal("tenant purge participant init failed", zap.Error(err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if rerr := purge.Run(ctx); rerr != nil {
			logger.Error("tenant purge participant stopped", zap.Error(rerr))
		}
	}()
	logger.Info("Tenant purge participant started", zap.String("group", tenantpurge.ServiceName+"-tenant-purge"))
	return func() {
		cancel()
		<-done
	}
}

// tenantPurgePlanner adapts the tenant-management client to the handler's port.
type tenantPurgePlanner struct{ c *tenantpurge.TMClient }

func (p tenantPurgePlanner) StartPlan(ctx context.Context, tenantID uuid.UUID, reason, actor string, actorID *uuid.UUID) (handlers.TenantPurgeRun, error) {
	run, err := p.c.StartPlan(ctx, tenantID, reason, actor, actorID)
	return handlers.TenantPurgeRun{RunID: run.RunID, State: run.State}, err
}

// buildTenantPurgePlanner returns the planner DeleteTenant uses, or nil (the
// endpoint then answers 501) when the tenant-management URL or the service
// credentials are missing. The scope platform:tenants:admin must be granted to
// svc-falcon-id (the GitOps repository serviceclientclaim-falcon-id.yaml).
func buildTenantPurgePlanner(cfg *config.Config, log *zap.Logger) handlers.TenantPurgePlanner {
	if strings.TrimSpace(cfg.TenantManagementInternalURL) == "" ||
		cfg.ServiceClientID == "" || cfg.ServiceClientSecret == "" || cfg.IAMServiceURL == "" {
		log.Warn("tenant purge endpoint disabled: tenant-management URL or outbound OAuth credentials missing")
		return nil
	}
	httpClient, err := serviceauth.NewIAMHTTPClient(serviceauth.IAMHTTPClientConfig{
		IAMURL:       cfg.IAMServiceURL,
		ClientID:     cfg.ServiceClientID,
		ClientSecret: cfg.ServiceClientSecret,
		Scope:        tenantpurge.TMScope,
	})
	if err != nil {
		log.Error("tenant purge endpoint disabled: NewIAMHTTPClient failed", zap.Error(err))
		return nil
	}
	if httpClient.Timeout == 0 {
		httpClient.Timeout = 15 * time.Second
	}
	return tenantPurgePlanner{c: tenantpurge.NewTMClient(cfg.TenantManagementInternalURL, httpClient)}
}
