// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// security_adapters.go contains thin adapter types that bridge the concrete
// repository and cache types wired in infrastructure.go to the narrow interfaces
// required by BackchannelLogoutService.
//
// Each adapter is fewer than 20 lines and intentionally has no business logic —
// the sole purpose is structural type adaptation.

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ─── BackchannelLogoutService adapters ───────────────────────────────────────

// oauthClientReaderAdapter bridges *repositories.OAuthClientRepository to the
// services.OAuthClientReader interface required by BackchannelLogoutService.
type oauthClientReaderAdapter struct {
	repo *repositories.OAuthClientRepository
}

// GetByID satisfies OAuthClientReader: fetches the OAuth client by its client_id
// string and maps the relevant fields to OAuthClientRecord.
func (a *oauthClientReaderAdapter) GetByID(ctx context.Context, clientID string) (*services.OAuthClientRecord, error) {
	client, err := a.repo.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("oauthClientReaderAdapter.GetByID: %w", err)
	}
	// BackchannelLogoutURI is a *string in the model; dereference safely.
	logoutURI := ""
	if client.BackchannelLogoutURI != nil {
		logoutURI = *client.BackchannelLogoutURI
	}
	return &services.OAuthClientRecord{
		ClientID:                   client.ClientID,
		BackchannelLogoutURI:       logoutURI,
		BackchannelSessionRequired: client.BackchannelLogoutSessionRequired,
	}, nil
}

// sessionInvalidatorAdapter bridges *repositories.SessionRepository to the
// services.SessionInvalidator interface required by BackchannelLogoutService.
type sessionInvalidatorAdapter struct {
	repo *repositories.SessionRepository
}

// InvalidateByUserID satisfies SessionInvalidator: ends all active sessions for
// the given user, except the session identified by exceptSessionID (which may be
// empty to end all sessions unconditionally).
func (a *sessionInvalidatorAdapter) InvalidateByUserID(ctx context.Context, userID uuid.UUID, exceptSessionID string) error {
	if exceptSessionID != "" {
		exceptUUID, err := uuid.Parse(exceptSessionID)
		if err != nil {
			// Cannot parse — fall back to ending all sessions.
			return a.repo.EndAllUserSessions(ctx, userID, "backchannel_logout")
		}
		return a.repo.EndAllUserSessionsExcept(ctx, userID, exceptUUID, "backchannel_logout")
	}
	return a.repo.EndAllUserSessions(ctx, userID, "backchannel_logout")
}

// oauthClientListerAdapter bridges *repositories.OAuthClientRepository to the
// services.OAuthClientLister interface required by BackchannelLogoutService.
type oauthClientListerAdapter struct {
	repo *repositories.OAuthClientRepository
}

// GetClientsWithBackchannelLogout satisfies OAuthClientLister: fetches all
// active OAuth clients for tenantID that have a backchannel_logout_uri
// configured, and maps each model to an OAuthClientRecord.
func (a *oauthClientListerAdapter) GetClientsWithBackchannelLogout(ctx context.Context, tenantID uuid.UUID) ([]services.OAuthClientRecord, error) {
	clients, err := a.repo.GetClientsWithBackchannelLogout(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("oauthClientListerAdapter.GetClientsWithBackchannelLogout: %w", err)
	}

	records := make([]services.OAuthClientRecord, 0, len(clients))
	for _, c := range clients {
		logoutURI := ""
		if c.BackchannelLogoutURI != nil {
			logoutURI = *c.BackchannelLogoutURI
		}
		records = append(records, services.OAuthClientRecord{
			ClientID:                   c.ClientID,
			BackchannelLogoutURI:       logoutURI,
			BackchannelSessionRequired: c.BackchannelLogoutSessionRequired,
		})
	}
	return records, nil
}

// ─── FrontchannelLogoutService adapter ───────────────────────────────────────

// frontchannelLogoutListerAdapter bridges *repositories.OAuthClientRepository
// to the services.FrontchannelLogoutLister interface required by
// FrontchannelLogoutService. Mirrors oauthClientListerAdapter for BCL.
type frontchannelLogoutListerAdapter struct {
	repo *repositories.OAuthClientRepository
}

// GetClientsWithFrontchannelLogout satisfies FrontchannelLogoutLister: fetches
// all active OAuth clients for tenantID that have a frontchannel_logout_uri
// configured and maps each model to a FrontchannelLogoutClient.
func (a *frontchannelLogoutListerAdapter) GetClientsWithFrontchannelLogout(ctx context.Context, tenantID uuid.UUID) ([]services.FrontchannelLogoutClient, error) {
	clients, err := a.repo.GetClientsWithFrontchannelLogout(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("frontchannelLogoutListerAdapter.GetClientsWithFrontchannelLogout: %w", err)
	}

	records := make([]services.FrontchannelLogoutClient, 0, len(clients))
	for _, c := range clients {
		uri := ""
		if c.FrontchannelLogoutURI != nil {
			uri = *c.FrontchannelLogoutURI
		}
		records = append(records, services.FrontchannelLogoutClient{
			ClientID:              c.ClientID,
			FrontchannelLogoutURI: uri,
			SessionRequired:       c.FrontchannelLogoutSessionRequired,
		})
	}
	return records, nil
}

// tokenSignerAdapter bridges *services.TokenService to the services.TokenSigner
// interface required by BackchannelLogoutService. TokenService.SignLogoutToken
// accepts jwt.Claims from golang-jwt/jwt/v5, which is the same type used by
// the TokenSigner interface.
type tokenSignerAdapter struct {
	tokenService *services.TokenService
}

// SignLogoutToken satisfies TokenSigner by delegating to TokenService.SignLogoutToken.
func (a *tokenSignerAdapter) SignLogoutToken(claims jwt.Claims) (string, error) {
	return a.tokenService.SignLogoutToken(claims)
}
