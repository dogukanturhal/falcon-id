// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// These tests lock the 2026-07-21 OAuth migration-gap remediation (Fix B):
// a token-generation / refresh-token-write failure must NOT permanently burn
// the authorization code. ExchangeAuthorizationCode wraps the mark-used CAS and
// the token-row INSERT in one transaction and commits only after token
// generation fully succeeds, so a downstream failure rolls the mark-used back
// and the client can retry the SAME code. Single-use is still enforced by the
// CAS under a concurrent double-exchange.

// ---------------------------------------------------------------------------
// Stateful fake: models the single auth code + a real commit/rollback tx
// ---------------------------------------------------------------------------

// txExchangeFakeRepo is a STATEFUL fake of oauthProviderServiceClientRepo. It
// embeds noopOAuthClientRepo for the methods the exchange path never touches and
// overrides GetAuthorizationCode + BeginTx to model, in memory, the exact
// semantics the real repository gets from Postgres:
//
//   - GetAuthorizationCode is an MVCC reader: it returns the last COMMITTED
//     is_used state and never blocks on an in-flight writer.
//   - MarkAuthorizationCodeUsedCAS takes a row-level write lock (rowLock) held
//     until the transaction ends, so a concurrent CAS serialises behind it and
//     only observes the committed flip.
//   - The mark-used is applied to committed state ONLY on Commit; Rollback
//     discards it, leaving the code usable.
type txExchangeFakeRepo struct {
	*noopOAuthClientRepo

	stateMu sync.Mutex                     // guards code.IsUsed committed state (MVCC snapshot)
	rowLock sync.Mutex                     // "row write-lock" held across a tx from CAS to Commit/Rollback
	code    *models.OAuthAuthorizationCode // the single authorization code

	failCreate  atomic.Bool  // when true, CreateOAuthToken fails (models the migration-0009 write failure)
	createCalls atomic.Int32 // number of token-row INSERT attempts
}

func (f *txExchangeFakeRepo) codeUsed() bool {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	return f.code.IsUsed
}

func (f *txExchangeFakeRepo) GetAuthorizationCode(_ context.Context, _ string) (*models.OAuthAuthorizationCode, error) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	cp := *f.code // copy so the caller's early IsUsed read reflects committed state
	return &cp, nil
}

func (f *txExchangeFakeRepo) BeginTx(_ context.Context) (repositories.OAuthClientTx, error) {
	return &txExchangeFakeTx{repo: f}, nil
}

// txExchangeFakeTx is the transaction handle returned by BeginTx.
type txExchangeFakeTx struct {
	repo     *txExchangeFakeRepo
	staged   bool // this tx won the CAS and intends to set is_used on commit
	holdsRow bool // this tx currently holds repo.rowLock
}

func (t *txExchangeFakeTx) MarkAuthorizationCodeUsedCAS(_ context.Context, _ uuid.UUID) (bool, error) {
	t.repo.rowLock.Lock() // serialise writers; released on Commit/Rollback
	t.holdsRow = true

	if t.repo.codeUsed() {
		// Already consumed by a committed tx → release the lock and report a
		// lost CAS (RowsAffected == 0 in the real UPDATE ... WHERE is_used=false).
		t.repo.rowLock.Unlock()
		t.holdsRow = false
		return false, nil
	}
	t.staged = true
	return true, nil
}

func (t *txExchangeFakeTx) CreateOAuthToken(_ context.Context, _ *models.OAuthToken) error {
	t.repo.createCalls.Add(1)
	if t.repo.failCreate.Load() {
		return errors.New("simulated refresh-token write failure: token_family_id column missing (migration 0009 gap)")
	}
	return nil
}

func (t *txExchangeFakeTx) LockRefreshRecovery(_ context.Context, _, _ uuid.UUID) (repositories.RefreshRecoveryOutcome, error) {
	return repositories.RefreshRecoveryOK, nil
}

func (t *txExchangeFakeTx) SetTokenReplacedBy(_ context.Context, _, _ uuid.UUID) error { return nil }
func (t *txExchangeFakeTx) RepointTokenReplacedBy(_ context.Context, _, _, _ uuid.UUID) error { return nil }

func (t *txExchangeFakeTx) Commit(_ context.Context) error {
	if t.staged {
		t.repo.stateMu.Lock()
		t.repo.code.IsUsed = true
		t.repo.stateMu.Unlock()
	}
	t.release()
	return nil
}

func (t *txExchangeFakeTx) Rollback(_ context.Context) error {
	// staged flip is simply never applied to committed state
	t.release()
	return nil
}

func (t *txExchangeFakeTx) release() {
	if t.holdsRow {
		t.repo.rowLock.Unlock()
		t.holdsRow = false
	}
}

// newTxExchangeFixture wires an OAuthProviderService over the stateful fake and
// returns everything ExchangeAuthorizationCode needs (client, redirect, code).
func newTxExchangeFixture(t *testing.T) (*OAuthProviderService, *txExchangeFakeRepo, *models.OAuthClient, string, string) {
	t.Helper()

	user := subjectUser()
	client := &models.OAuthClient{
		ID:                   uuid.New(),
		TenantID:             uuid.New(),
		ClientID:             "tx-exchange-client",
		GrantTypes:           []string{"authorization_code", "refresh_token"},
		ResponseTypes:        []string{"code"},
		Scopes:               []string{"openid"},
		AccessTokenLifetime:  300,
		RefreshTokenLifetime: 3600,
		IDTokenLifetime:      300,
		IsActive:             true,
		IsConfidential:       true,
		IsFirstParty:         true,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	redirectURI := "https://rp.example.com/callback"

	repo := &txExchangeFakeRepo{
		noopOAuthClientRepo: &noopOAuthClientRepo{},
		code: &models.OAuthAuthorizationCode{
			ID:          uuid.New(),
			TenantID:    client.TenantID,
			ClientID:    client.ID,
			UserID:      user.ID,
			RedirectURI: redirectURI,
			Scopes:      []string{"openid"},
			IsUsed:      false,
			ExpiresAt:   time.Now().Add(10 * time.Minute),
			CreatedAt:   time.Now(),
		},
	}

	svc := newTestOAuthProviderService(t, repo, &fixedUserRepo{user: user})
	return svc, repo, client, redirectURI, "opaque-authorization-code"
}

// TestExchangeAuthorizationCode_TokenGenFailureDoesNotBurnCode is THE Fix B
// regression: when the token/refresh-token persistence fails, the exchange
// returns an error but the authorization code stays unused, and a subsequent
// exchange of the SAME code succeeds.
func TestExchangeAuthorizationCode_TokenGenFailureDoesNotBurnCode(t *testing.T) {
	ctx := context.Background()
	svc, repo, client, redirectURI, code := newTxExchangeFixture(t)

	// First exchange: force the refresh-token write to fail.
	repo.failCreate.Store(true)
	resp, err := svc.ExchangeAuthorizationCode(ctx, client, code, redirectURI, "", "")
	require.Error(t, err, "exchange must fail when the token row cannot be persisted")
	require.Nil(t, resp)
	assert.Equal(t, int32(1), repo.createCalls.Load(),
		"the failure must have occurred at the token-row INSERT (mark-used already ran)")
	assert.False(t, repo.codeUsed(),
		"BUG GUARD: a token-gen failure must roll back the mark-used so the code is NOT burned")

	// Second exchange of the SAME code now succeeds — the client simply retried.
	repo.failCreate.Store(false)
	resp, err = svc.ExchangeAuthorizationCode(ctx, client, code, redirectURI, "", "")
	require.NoError(t, err, "the code must still be redeemable after the transient failure")
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken, "a successful retry must return an access token")
	assert.NotEmpty(t, resp.RefreshToken)
	assert.True(t, repo.codeUsed(), "a committed exchange must consume the code")

	// Third exchange is now correctly rejected as already-used (single-use).
	resp, err = svc.ExchangeAuthorizationCode(ctx, client, code, redirectURI, "", "")
	require.Error(t, err)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "already been used")
}

// TestExchangeAuthorizationCode_ConcurrentDoubleExchangeSingleUse asserts the
// single-use invariant survives the transactional path: two concurrent
// exchanges of the same live code yield exactly one success and mint exactly
// one token.
func TestExchangeAuthorizationCode_ConcurrentDoubleExchangeSingleUse(t *testing.T) {
	ctx := context.Background()
	svc, repo, client, redirectURI, code := newTxExchangeFixture(t)
	repo.failCreate.Store(false)

	const racers = 2
	var wg sync.WaitGroup
	var successes atomic.Int32
	errs := make([]error, racers)

	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func(idx int) {
			defer wg.Done()
			resp, err := svc.ExchangeAuthorizationCode(ctx, client, code, redirectURI, "", "")
			if err == nil && resp != nil {
				successes.Add(1)
			}
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	assert.Equal(t, int32(1), successes.Load(),
		"exactly one concurrent exchange of a single-use code must succeed")
	assert.Equal(t, int32(1), repo.createCalls.Load(),
		"exactly one token row must be minted for a single-use code")
	assert.True(t, repo.codeUsed(), "the winning exchange must consume the code")

	var lost int
	for _, err := range errs {
		if err != nil {
			lost++
			assert.Contains(t, err.Error(), "already been used")
		}
	}
	assert.Equal(t, racers-1, lost, "every loser must be rejected as already-used")
}
