// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// Tests for the per-client refresh_token_rotation_policy branch in
// RefreshTokens (migration v0.232.242).
//
// Scope:
//   - Default "rotate" → inbound refresh_token revoked; new refresh
//     issued (different from the inbound).
//   - "reuse"          → inbound refresh_token NOT revoked; same
//     plaintext returned alongside a freshly-minted access_token.
//   - Empty policy on the client struct → defaults to "rotate"
//     (defensive: stale callers / pre-migration rows shouldn't
//     silently fall through to reuse).
//
// Out of scope:
//   - Database-level CHECK constraint behavior (covered by the SQL
//     migration; this layer trusts the constraint).
//   - DPoP / IP-change / amr-preservation paths — covered by the
//     existing RefreshTokens tests.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// rotationPolicyTestRepo is a hand-rolled stub satisfying
// oauthProviderServiceClientRepo. It records RevokeOAuthToken /
// CreateOAuthToken calls so tests can assert on the rotate-vs-reuse
// side effects without touching a real database.
//
// Implements only the methods exercised by RefreshTokens; everything
// else delegates to the noop pattern used by the rest of this package's
// tests.
type rotationPolicyTestRepo struct {
	noopOAuthClientRepo

	mu               sync.Mutex
	tokenByHash      map[string]*models.OAuthToken
	tokenByID        map[uuid.UUID]*models.OAuthToken
	revokedHashes    []string
	consumedTokenIDs []uuid.UUID
	revokedFamilies  []uuid.UUID
	createdTokenRows []*models.OAuthToken
}

func newRotationPolicyTestRepo() *rotationPolicyTestRepo {
	return &rotationPolicyTestRepo{
		tokenByHash: map[string]*models.OAuthToken{},
		tokenByID:   map[uuid.UUID]*models.OAuthToken{},
	}
}

func (r *rotationPolicyTestRepo) addToken(hash string, tok *models.OAuthToken) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokenByHash[hash] = tok
	r.tokenByID[tok.ID] = tok
}

// ConsumeRefreshToken models the repository's atomic compare-and-swap: under a
// single mutex it flips is_revoked true → but ONLY when currently false, and
// reports whether THIS caller won. This is the in-memory analogue of the
// Postgres `UPDATE ... WHERE id=$1 AND is_revoked=false` and gives the
// concurrent-redemption test real, race-safe atomicity.
func (r *rotationPolicyTestRepo) ConsumeRefreshToken(_ context.Context, tokenID uuid.UUID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tok, ok := r.tokenByID[tokenID]
	if !ok || tok.IsRevoked {
		return false, nil
	}
	tok.IsRevoked = true
	now := time.Now()
	tok.RevokedAt = &now // mirror the repo's `revoked_at = now` for grace-window checks
	rsn := "rotated"     // mirror the repo's `revoke_reason = 'rotated'`
	tok.RevokeReason = &rsn
	r.consumedTokenIDs = append(r.consumedTokenIDs, tokenID)
	return true, nil
}

// RevokeRefreshTokenFamily records the revoked family id and revokes every
// still-live row sharing it, mirroring the repository's family-wide UPDATE.
func (r *rotationPolicyTestRepo) RevokeRefreshTokenFamily(_ context.Context, familyID uuid.UUID) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revokedFamilies = append(r.revokedFamilies, familyID)
	var n int64
	for _, tok := range r.tokenByID {
		if tok.TokenFamilyID != nil && *tok.TokenFamilyID == familyID && !tok.IsRevoked {
			tok.IsRevoked = true
			n++
		}
	}
	return n, nil
}

func (r *rotationPolicyTestRepo) GetOAuthTokenByHash(_ context.Context, tokenHash string) (*models.OAuthToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tok, ok := r.tokenByHash[tokenHash]; ok {
		// Return a copy so the caller can't mutate the stored row
		// underneath subsequent assertions.
		cp := *tok
		return &cp, nil
	}
	return nil, assertFail("token not found in test repo")
}

func (r *rotationPolicyTestRepo) RevokeOAuthToken(_ context.Context, tokenHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revokedHashes = append(r.revokedHashes, tokenHash)
	if tok, ok := r.tokenByHash[tokenHash]; ok {
		tok.IsRevoked = true
	}
	return nil
}

func (r *rotationPolicyTestRepo) CreateOAuthToken(_ context.Context, tok *models.OAuthToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *tok
	r.createdTokenRows = append(r.createdTokenRows, &cp)
	return nil
}

// assertFail is a sentinel error used by the stub repo so test failures
// surface a meaningful message rather than a nil-pointer panic.
type assertFailErr string

func (e assertFailErr) Error() string { return string(e) }

func assertFail(msg string) error { return assertFailErr(msg) }

func newRefreshPolicyTestService(t *testing.T, repo *rotationPolicyTestRepo) *OAuthProviderService {
	t.Helper()
	svc, err := NewOAuthProviderService(
		repo,
		&noopUserRepo{},
		&config.Config{
			JWTSecret:   "test-secret-for-refresh-policy-tests",
			ServicePort: "8080",
		},
	)
	require.NoError(t, err)
	return svc
}

// activeConfidentialBFFClient is a confidential first-party client
// shaped like the six svc-*-bff clients (the seed targets in migration
// 242). Tests vary the RefreshTokenRotationPolicy field to exercise
// each branch.
func activeConfidentialBFFClient(policy string) *models.OAuthClient {
	now := time.Now()
	return &models.OAuthClient{
		ID:                         uuid.New(),
		TenantID:                   uuid.New(),
		ClientID:                   "svc-falcon-admin-bff",
		Name:                       "Falcon Admin BFF",
		GrantTypes:                 []string{"refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		Scopes:                     []string{"openid", "profile", "offline_access"},
		AccessTokenLifetime:        300,
		RefreshTokenLifetime:       3600,
		IsConfidential:             true,
		IsFirstParty:               true,
		IsActive:                   true,
		RefreshTokenRotationPolicy: policy,
		CreatedAt:                  now,
		UpdatedAt:                  now,
	}
}

func TestRefreshTokens_RotatePolicy_RevokesOldAndIssuesFreshRefresh(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)

	client := activeConfidentialBFFClient("rotate")
	inboundPlaintext := "inbound-refresh-token-plaintext-rotate-case"
	inboundHash := svc.hashSecret(inboundPlaintext)
	inboundID := uuid.New()
	familyID := inboundID // root token: family == id

	// Seed the inbound token row that GetOAuthTokenByHash will find.
	repo.addToken(inboundHash, &models.OAuthToken{
		ID:            inboundID,
		TenantID:      client.TenantID,
		ClientID:      client.ID,
		TokenType:     "access_token",
		Token:         "irrelevant-access-token-hash",
		Scopes:        []string{"openid", "profile"},
		RefreshToken:  &inboundHash,
		IsRevoked:     false,
		TokenFamilyID: &familyID,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		CreatedAt:     time.Now().Add(-1 * time.Minute),
		UpdatedAt:     time.Now().Add(-1 * time.Minute),
	})

	resp, err := svc.RefreshTokens(context.Background(), client, inboundPlaintext, "")
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Canonical rotate semantics: inbound atomically consumed exactly once,
	// no family revoke (a clean rotation is not a reuse), refresh differs.
	assert.Equal(t, []uuid.UUID{inboundID}, repo.consumedTokenIDs,
		"rotate policy must atomically consume the inbound refresh token exactly once")
	assert.Empty(t, repo.revokedFamilies,
		"a clean rotation must NOT revoke the token family")
	assert.NotEmpty(t, resp.RefreshToken)
	assert.NotEqual(t, inboundPlaintext, resp.RefreshToken,
		"rotate policy must issue a fresh refresh_token plaintext")
	assert.NotEmpty(t, resp.AccessToken)
}

func TestRefreshTokens_ReusePolicy_KeepsOldAndReturnsSameRefresh(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)

	client := activeConfidentialBFFClient("reuse")
	inboundPlaintext := "inbound-refresh-token-plaintext-reuse-case"
	inboundHash := svc.hashSecret(inboundPlaintext)

	repo.addToken(inboundHash, &models.OAuthToken{
		ID:           uuid.New(),
		TenantID:     client.TenantID,
		ClientID:     client.ID,
		TokenType:    "access_token",
		Token:        "irrelevant-access-token-hash",
		Scopes:       []string{"openid", "profile"},
		RefreshToken: &inboundHash,
		IsRevoked:    false,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now().Add(-1 * time.Minute),
		UpdatedAt:    time.Now().Add(-1 * time.Minute),
	})

	resp, err := svc.RefreshTokens(context.Background(), client, inboundPlaintext, "")
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Duende BFF / OAuth 2.1 first-party-app semantics:
	//   - the inbound refresh_token MUST NOT be revoked
	//   - the response's refresh_token MUST equal the inbound plaintext
	//   - a fresh access_token is still minted (the whole reason to call
	//     the refresh endpoint)
	assert.Empty(t, repo.revokedHashes,
		"reuse policy must NOT revoke the inbound refresh token")
	assert.Equal(t, inboundPlaintext, resp.RefreshToken,
		"reuse policy must return the SAME refresh_token the caller already holds")
	assert.NotEmpty(t, resp.AccessToken)

	// The new access-token row's refresh_token column must record the
	// SAME hash as the inbound row's, so future RevokeOAuthToken
	// `WHERE refresh_token=$1` cascades cleanly across all reuse rows.
	require.Len(t, repo.createdTokenRows, 1)
	row := repo.createdTokenRows[0]
	require.NotNil(t, row.RefreshToken)
	assert.Equal(t, inboundHash, *row.RefreshToken,
		"reuse must record the inbound refresh hash on the new access-token row")
}

func TestRefreshTokens_EmptyPolicy_DefaultsToRotate(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)

	client := activeConfidentialBFFClient("") // empty — should behave as "rotate"
	inboundPlaintext := "inbound-refresh-token-plaintext-empty-case"
	inboundHash := svc.hashSecret(inboundPlaintext)
	inboundID := uuid.New()
	familyID := inboundID

	repo.addToken(inboundHash, &models.OAuthToken{
		ID:            inboundID,
		TenantID:      client.TenantID,
		ClientID:      client.ID,
		TokenType:     "access_token",
		Token:         "irrelevant-access-token-hash",
		Scopes:        []string{"openid", "profile"},
		RefreshToken:  &inboundHash,
		IsRevoked:     false,
		TokenFamilyID: &familyID,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		CreatedAt:     time.Now().Add(-1 * time.Minute),
		UpdatedAt:     time.Now().Add(-1 * time.Minute),
	})

	resp, err := svc.RefreshTokens(context.Background(), client, inboundPlaintext, "")
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Anything other than the exact string "reuse" must take the
	// canonical rotate path. This is the defensive default — pre-
	// migration rows (NULL → COALESCE 'rotate') and stale callers
	// that pass an empty string should not silently bypass rotation.
	assert.Equal(t, []uuid.UUID{inboundID}, repo.consumedTokenIDs,
		"empty policy must default to rotate (atomically consume inbound)")
	assert.NotEqual(t, inboundPlaintext, resp.RefreshToken,
		"empty policy must default to rotate (fresh refresh_token)")
}

// TestRefreshTokens_WithReuseRefreshTokenContextHelper exercises the
// public context helper directly so other call sites (a future
// service-layer caller wanting to opt in without going through the
// per-client policy column) can rely on the contract.
func TestRefreshTokens_WithReuseRefreshTokenContextHelper(t *testing.T) {
	ctx := context.Background()
	assert.Empty(t, reuseRefreshTokenFromContext(ctx),
		"bare ctx must return empty plaintext")

	ctx2 := WithReuseRefreshToken(ctx, "")
	assert.Empty(t, reuseRefreshTokenFromContext(ctx2),
		"empty input must short-circuit (no-op derived ctx)")

	ctx3 := WithReuseRefreshToken(ctx, "the-plaintext")
	assert.Equal(t, "the-plaintext", reuseRefreshTokenFromContext(ctx3))
}
