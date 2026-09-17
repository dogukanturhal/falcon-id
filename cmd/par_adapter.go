// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"

	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

// redisPARStoreAdapter adapts redis.PARStore to satisfy the services.PARStore interface.
// It translates between the two PAREntry struct types to avoid an import cycle between
// pkg/redis and internal/services.
type redisPARStoreAdapter struct {
	store *redis.PARStore
}

var _ services.PARStore = (*redisPARStoreAdapter)(nil)

func newRedisPARStoreAdapter(store *redis.PARStore) *redisPARStoreAdapter {
	return &redisPARStoreAdapter{store: store}
}

func (a *redisPARStoreAdapter) SetPAR(ctx context.Context, entry *services.PAREntry) error {
	return a.store.SetPAR(ctx, &redis.PAREntry{
		Reference:           entry.Reference,
		ClientID:            entry.ClientID,
		ResponseType:        entry.ResponseType,
		RedirectURI:         entry.RedirectURI,
		Scope:               entry.Scope,
		State:               entry.State,
		Nonce:               entry.Nonce,
		CodeChallenge:       entry.CodeChallenge,
		CodeChallengeMethod: entry.CodeChallengeMethod,
		Display:             entry.Display,
		Prompt:              entry.Prompt,
		AcrValues:           entry.AcrValues,
		MaxAge:              entry.MaxAge,
		LoginHint:           entry.LoginHint,
		LoginContext:        entry.LoginContext,
		ExpiresAt:           entry.ExpiresAt,
	})
}

func (a *redisPARStoreAdapter) GetPAR(ctx context.Context, reference string) (*services.PAREntry, error) {
	e, err := a.store.GetPAR(ctx, reference)
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, nil
	}
	return &services.PAREntry{
		Reference:           e.Reference,
		ClientID:            e.ClientID,
		ResponseType:        e.ResponseType,
		RedirectURI:         e.RedirectURI,
		Scope:               e.Scope,
		State:               e.State,
		Nonce:               e.Nonce,
		CodeChallenge:       e.CodeChallenge,
		CodeChallengeMethod: e.CodeChallengeMethod,
		Display:             e.Display,
		Prompt:              e.Prompt,
		AcrValues:           e.AcrValues,
		MaxAge:              e.MaxAge,
		LoginHint:           e.LoginHint,
		LoginContext:        e.LoginContext,
		ExpiresAt:           e.ExpiresAt,
	}, nil
}

func (a *redisPARStoreAdapter) DeletePAR(ctx context.Context, reference string) error {
	return a.store.DeletePAR(ctx, reference)
}
