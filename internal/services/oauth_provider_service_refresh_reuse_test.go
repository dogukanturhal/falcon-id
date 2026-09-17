// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// Focused tests for the RFC 9700 §4.14 refresh-token reuse-detection path in
// RefreshTokens. These are security-correctness-critical, so they live apart
// from the rotate-vs-reuse policy tests and prove the three properties the
// fix must guarantee:
//
//   (a) rotation works — a live refresh token rotates and is atomically
//       consumed exactly once (covered end-to-end here + in the policy tests).
//   (b) reuse of a rotated (older-generation, revoked) token revokes the
//       ENTIRE token family AND emits the CAEP token-theft signal.
//   (c) concurrent redemption of the SAME live token is race-safe: exactly
//       one winner, every loser fails closed with invalid_grant, and the
//       family is NOT revoked (a benign race is not a theft).

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// wireCAERecorder attaches a CAEService backed by a recordingPublisher (from
// oauth_provider_service_ip_change_test.go) so tests can assert on emitted
// security events.
func wireCAERecorder(t *testing.T, svc *OAuthProviderService) *recordingPublisher {
	t.Helper()
	pub := &recordingPublisher{}
	svc.SetCAEService(NewCAEService(pub, zap.NewNop()))
	return pub
}

// lastCAEEvent decodes the most recent published CAE event, or fails.
func lastCAEEvent(t *testing.T, pub *recordingPublisher) CAEEvent {
	t.Helper()
	raw := pub.lastMessage()
	require.NotNil(t, raw, "expected a CAE event to have been published")
	var ev CAEEvent
	require.NoError(t, json.Unmarshal(raw, &ev))
	return ev
}

// (a) A clean rotation atomically consumes the inbound token exactly once and
// never touches the family. (Complements the policy-layer rotate test with an
// explicit family + no-reuse assertion.)
func TestRefreshTokens_Reuse_CleanRotationConsumesOnceNoFamilyRevoke(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)
	pub := wireCAERecorder(t, svc)

	client := activeConfidentialBFFClient("rotate")
	plaintext := "clean-rotation-refresh-plaintext"
	hash := svc.hashSecret(plaintext)
	id := uuid.New()
	fam := id
	uid := uuid.New()
	repo.addToken(hash, &models.OAuthToken{
		ID:            id,
		TenantID:      client.TenantID,
		ClientID:      client.ID,
		UserID:        &uid,
		TokenType:     "access_token",
		Token:         "irrelevant",
		Scopes:        []string{"openid"},
		RefreshToken:  &hash,
		IsRevoked:     false,
		TokenFamilyID: &fam,
		ExpiresAt:     time.Now().Add(time.Hour),
	})

	resp, err := svc.RefreshTokens(context.Background(), client, plaintext, "")
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, []uuid.UUID{id}, repo.consumedTokenIDs, "inbound consumed exactly once")
	assert.Empty(t, repo.revokedFamilies, "clean rotation must not revoke the family")
	assert.Equal(t, 0, pub.calls(), "clean rotation must not emit a CAEP theft signal")
}

// (b) Replaying a rotated (older-generation, revoked-outside-grace) refresh
// token revokes the WHOLE family and emits the CAEP token-theft signal.
func TestRefreshTokens_Reuse_RevokesFamilyAndEmitsCAEPTheftSignal(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)
	pub := wireCAERecorder(t, svc)

	client := activeConfidentialBFFClient("rotate")
	userID := uuid.New()
	familyID := uuid.New()
	sessionID := uuid.New()

	// The replayed (stolen) token: already revoked WELL outside the grace
	// window, so it is unambiguously an older-generation replay, not a race.
	stolenPlaintext := "stolen-older-generation-refresh-plaintext"
	stolenHash := svc.hashSecret(stolenPlaintext)
	revokedLongAgo := time.Now().Add(-1 * time.Hour)
	repo.addToken(stolenHash, &models.OAuthToken{
		ID:            uuid.New(),
		TenantID:      client.TenantID,
		ClientID:      client.ID,
		UserID:        &userID,
		TokenType:     "access_token",
		Token:         "stolen-access-hash",
		Scopes:        []string{"openid"},
		RefreshToken:  &stolenHash,
		IsRevoked:     true,
		RevokedAt:     &revokedLongAgo,
		TokenFamilyID: &familyID,
		IdpSessionID:  &sessionID,
		ExpiresAt:     time.Now().Add(time.Hour),
	})

	// A still-live sibling in the SAME family (the current legitimate token).
	// Family revocation must sweep it too.
	liveSiblingHash := svc.hashSecret("live-sibling-refresh-plaintext")
	repo.addToken(liveSiblingHash, &models.OAuthToken{
		ID:            uuid.New(),
		TenantID:      client.TenantID,
		ClientID:      client.ID,
		UserID:        &userID,
		TokenType:     "access_token",
		Token:         "live-sibling-access-hash",
		Scopes:        []string{"openid"},
		RefreshToken:  &liveSiblingHash,
		IsRevoked:     false,
		TokenFamilyID: &familyID,
		ExpiresAt:     time.Now().Add(time.Hour),
	})

	resp, err := svc.RefreshTokens(context.Background(), client, stolenPlaintext, "")
	require.Error(t, err)
	require.Nil(t, resp)
	assert.True(t, strings.HasPrefix(err.Error(), "invalid_grant:"),
		"reuse must be rejected as invalid_grant, got %q", err.Error())

	// Family revoked (theft metric AuthTokenReuseDetected is incremented as a
	// side effect inside handleRefreshTokenReuse; the family revoke + CAEP
	// signal below are the deterministic, load-bearing proofs of that path).
	assert.Equal(t, []uuid.UUID{familyID}, repo.revokedFamilies,
		"reuse must revoke exactly the compromised family")
	sibling := repo.tokenByHash[liveSiblingHash]
	assert.True(t, sibling.IsRevoked, "the live sibling in the family must be revoked")

	// CAEP theft signal emitted with the right shape.
	require.Equal(t, 1, pub.calls(), "exactly one CAEP theft signal must be emitted")
	ev := lastCAEEvent(t, pub)
	assert.Equal(t, CAERefreshTokenReuse, ev.Type)
	assert.Equal(t, userID, ev.UserID)
	assert.Equal(t, familyID.String(), ev.Metadata["family_id"])
	assert.Equal(t, sessionID.String(), ev.Metadata["session_id"])
}

// (c) N goroutines redeem the SAME live refresh token concurrently. The atomic
// CAS must let exactly one win; every loser fails closed with invalid_grant;
// the family is NOT revoked and NO theft signal fires (benign race, not theft).
func TestRefreshTokens_Reuse_ConcurrentRedemptionIsRaceSafe(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)
	pub := wireCAERecorder(t, svc)

	client := activeConfidentialBFFClient("rotate")
	plaintext := "concurrent-redemption-refresh-plaintext"
	hash := svc.hashSecret(plaintext)
	id := uuid.New()
	fam := id
	uid := uuid.New()
	repo.addToken(hash, &models.OAuthToken{
		ID:            id,
		TenantID:      client.TenantID,
		ClientID:      client.ID,
		UserID:        &uid,
		TokenType:     "access_token",
		Token:         "irrelevant",
		Scopes:        []string{"openid"},
		RefreshToken:  &hash,
		IsRevoked:     false,
		TokenFamilyID: &fam,
		ExpiresAt:     time.Now().Add(time.Hour),
	})

	const n = 24
	var (
		wg       sync.WaitGroup
		start    = make(chan struct{})
		wins     int64
		invalids int64
	)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start // maximise contention: release all goroutines at once
			resp, err := svc.RefreshTokens(context.Background(), client, plaintext, "")
			switch {
			case err == nil && resp != nil:
				atomic.AddInt64(&wins, 1)
			case err != nil && strings.HasPrefix(err.Error(), "invalid_grant:"):
				atomic.AddInt64(&invalids, 1)
			default:
				t.Errorf("unexpected outcome: resp=%v err=%v", resp, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), wins, "exactly one concurrent redemption may win")
	assert.Equal(t, int64(n-1), invalids, "every loser must fail closed with invalid_grant")
	assert.Len(t, repo.consumedTokenIDs, 1, "the token must be atomically consumed exactly once")
	assert.Empty(t, repo.revokedFamilies, "a benign concurrent race must NOT revoke the family")
	assert.Equal(t, 0, pub.calls(), "a benign concurrent race must NOT emit a CAEP theft signal")
}
