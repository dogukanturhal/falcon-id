// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// Tenant suspension enforcement (R1-GAPS row 27): refresh is denied with the
// stable `tenant_suspended` error, resume re-enables it, and the gate is
// consulted by token validation. The Postgres-backed revocation/ordering tests
// live in internal/tenantstatus.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

type fakeSuspensionChecker struct{ suspended atomic.Bool }

func (f *fakeSuspensionChecker) IsSuspended(context.Context, uuid.UUID) bool {
	return f.suspended.Load()
}

func TestRefreshTokens_TenantSuspended_DeniedThenResumeReenables(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)
	checker := &fakeSuspensionChecker{}
	svc.SetTenantSuspensionChecker(checker)

	client := activeConfidentialBFFClient("rotate")
	plaintext := "inbound-refresh-token-plaintext-suspension"
	hash := svc.hashSecret(plaintext)
	id := uuid.New()
	family := id
	repo.addToken(hash, &models.OAuthToken{
		ID: id, TenantID: client.TenantID, ClientID: client.ID, TokenType: "access_token",
		Token: "x", Scopes: []string{"openid"}, RefreshToken: &hash, TokenFamilyID: &family,
		ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now().Add(-time.Minute), UpdatedAt: time.Now().Add(-time.Minute),
	})

	checker.suspended.Store(true)
	resp, err := svc.RefreshTokens(context.Background(), client, plaintext, "")
	require.ErrorIs(t, err, ErrTenantSuspended)
	assert.Nil(t, resp)
	assert.Equal(t, "tenant_suspended", err.Error(), "wire code is the stable error message")
	assert.Empty(t, repo.consumedTokenIDs, "a denied refresh must not consume the token")
	assert.Empty(t, repo.revokedFamilies, "a denied refresh must not trip reuse detection")

	// Resume: the very same token works again.
	checker.suspended.Store(false)
	resp, err = svc.RefreshTokens(context.Background(), client, plaintext, "")
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestCheckTenantNotSuspended_NilCheckerAllows(t *testing.T) {
	require.NoError(t, checkTenantNotSuspended(context.Background(), nil, uuid.New()))
	c := &fakeSuspensionChecker{}
	require.NoError(t, checkTenantNotSuspended(context.Background(), c, uuid.New()))
	c.suspended.Store(true)
	require.ErrorIs(t, checkTenantNotSuspended(context.Background(), c, uuid.New()), ErrTenantSuspended)
}

func TestGenerateAccessToken_TenantSuspended_Denied(t *testing.T) {
	svc := NewTokenService(&config.Config{}, nil, nil)
	checker := &fakeSuspensionChecker{}
	checker.suspended.Store(true)
	svc.SetTenantSuspensionChecker(checker)

	tok, err := svc.GenerateAccessToken(context.Background(), &models.User{ID: uuid.New(), TenantID: uuid.New()}, uuid.New(), nil, nil)
	require.ErrorIs(t, err, ErrTenantSuspended)
	assert.Empty(t, tok)
}
