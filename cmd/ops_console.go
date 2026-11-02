// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/operatorauth"

	"github.com/dogukanturhal/falcon-id/internal/opsaudit"
	"github.com/dogukanturhal/falcon-id/internal/opsconsole"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// initOpsConsole builds the staff-console operator surface. It returns nil
// (routes not mounted) unless the operator token exchange is configured
// (OPS_OPERATOR_EXCHANGE_CLIENT_IDS) and SpiceDB is available: without them no
// operator assertion can exist, so the surface would be dead weight.
//
// The assertion is verified against falcon-id's own JWKS / issuer (the
// platform-shared operatorauth.Verifier, same as every other service).
// OPS_OPERATOR_JWKS_URL overrides the default loopback URL.
func initOpsConsole(services *Services, repos *Repositories, infra *Infrastructure) *opsconsole.Console {
	cfg := infra.Config
	if len(cfg.OpsOperatorExchangeClientIDs) == 0 || infra.SpiceDBClient == nil || services.OAuthProvider == nil {
		return nil
	}
	jwks := strings.TrimSpace(os.Getenv("OPS_OPERATOR_JWKS_URL"))
	if jwks == "" {
		jwks = "http://127.0.0.1:" + cfg.ServicePort + "/.well-known/jwks.json"
	}
	verifier, err := operatorauth.NewVerifier(operatorauth.Config{JWKSURL: jwks, Issuer: services.OAuthProvider.Issuer()})
	if err != nil {
		logger.Log.Error("ops console disabled: operator verifier", zap.Error(err))
		return nil
	}
	deps := opsconsole.Deps{
		DB:                infra.DB.Pool,
		Verifier:          verifier,
		Audit:             opsaudit.NewConsumer(infra.DB.Pool),
		Log:               logger.Log,
		Users:             repos.User,
		Sessions:          repos.Session,
		PlatformAuthority: repos.PlatformAuthority,
		Authority:         services.PlatformAuth,
		JITRepo:           repos.PlatformElevation,
		JIT:               services.PlatformJIT,
		Spice:             infra.SpiceDBClient,
		Signer:            services.OAuthProvider,
		KillSessions: func(ctx context.Context, userID uuid.UUID, reason string) error {
			active, _ := repos.Session.GetActiveSessions(ctx, userID)
			if err := repos.Session.EndAllUserSessions(ctx, userID, reason); err != nil {
				return err
			}
			if err := services.Token.RevokeAllUserOAuthTokens(ctx, userID, reason); err != nil {
				return err
			}
			if infra.TokenBlacklist != nil {
				for _, s := range active {
					_ = infra.TokenBlacklist.BlacklistSession(ctx, s.ID, reason, 24*time.Hour)
				}
				_ = infra.TokenBlacklist.BlacklistUserTokens(ctx, userID, reason, 24*time.Hour)
			}
			return nil
		},
	}
	if infra.RateLimiter != nil {
		deps.Limiter = infra.RateLimiter
	}
	logger.Log.Info("ops console operator surface enabled", zap.String("jwks_url", jwks))
	return opsconsole.New(deps)
}
