// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"regexp"

	serviceauth "github.com/dogukanturhal/platform-shared/service-auth"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/internal/tenantstatus"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// pepperVersionRE matches the hash_alg DB CHECK (^hmac-sha256:v[0-9]+$).
var pepperVersionRE = regexp.MustCompile(`^v[0-9]+$`)

// buildTenantAPIKeyService wires the WO#20 tenant API key service. It returns
// nil unless DEVELOPER_KEYS_ENABLED is on; with the flag on but a dependency
// missing (SpiceDB, pepper, business URL / S2S credentials) it logs and also
// returns nil, so the routes answer 503 instead of issuing half-working keys.
func buildTenantAPIKeyService(
	cfg *config.Config,
	infra *Infrastructure,
	repos *Repositories,
	audit *services.AuditService,
	minter *services.OAuthProviderService,
	gate *tenantstatus.Gate,
	log *zap.Logger,
) *services.TenantAPIKeyService {
	if !cfg.DeveloperKeysEnabled {
		return nil
	}
	if infra.SpiceDBClient == nil {
		log.Error("developer API keys disabled: SpiceDB client unavailable")
		return nil
	}
	peppers, current := cfg.DeveloperKeyPeppers()
	if !pepperVersionRE.MatchString(current) {
		log.Error("developer API keys disabled: invalid pepper version name", zap.String("pepper_version", current))
		return nil
	}
	for v := range peppers {
		if !pepperVersionRE.MatchString(v) {
			log.Error("developer API keys disabled: invalid pepper version name", zap.String("pepper_version", v))
			return nil
		}
	}
	if peppers[current] == "" {
		log.Error("developer API keys disabled: no pepper configured for the current version",
			zap.String("pepper_version", current))
		return nil
	}
	if cfg.BusinessInternalURL == "" || cfg.ServiceClientID == "" || cfg.ServiceClientSecret == "" || cfg.IAMServiceURL == "" {
		log.Error("developer API keys disabled: business URL or S2S credentials missing",
			zap.Bool("have_business_url", cfg.BusinessInternalURL != ""),
			zap.Bool("have_client_id", cfg.ServiceClientID != ""),
			zap.Bool("have_client_secret", cfg.ServiceClientSecret != ""),
		)
		return nil
	}
	httpClient, err := serviceauth.NewIAMHTTPClient(serviceauth.IAMHTTPClientConfig{
		IAMURL:       cfg.IAMServiceURL,
		ClientID:     cfg.ServiceClientID,
		ClientSecret: cfg.ServiceClientSecret,
		Scope:        services.BusinessAPIKeyScope,
	})
	if err != nil {
		log.Error("developer API keys disabled: NewIAMHTTPClient failed", zap.Error(err))
		return nil
	}
	deps := services.TenantAPIKeyDeps{
		Repo:         repos.APIKey,
		Roles:        repos.Role,
		UserRoles:    repos.User,
		SpiceDB:      infra.SpiceDBClient,
		Companies:    services.NewBusinessAPIKeyClient(cfg.BusinessInternalURL, httpClient),
		Audit:        audit,
		Entitlements: repos.ModuleEntitlement,
		Minter:       minter,
		Suspension:   gate,
	}
	if infra.RedisClient != nil {
		deps.AuditDedupe = infra.RedisClient
	}
	return services.NewTenantAPIKeyService(cfg, deps)
}
