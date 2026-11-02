// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// Logout scope vs refresh-token reuse detection. Only a token consumed by
// rotation (revoke_reason = 'rotated') can be a stolen-copy replay; a token
// revoked by logout / session end / legacy NULL reason is a plain ended
// session and must never trip the family revoke or the CAEP theft signal.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// addRevokedRefresh stores a revoked refresh token with the given reason
// (nil = legacy NULL) revoked revokedAgo in the past.
func addRevokedRefresh(svc *OAuthProviderService, repo *rotationPolicyTestRepo, client *models.OAuthClient, userID, familyID uuid.UUID, plaintext string, reason *string, revokedAgo time.Duration) {
	hash := svc.hashSecret(plaintext)
	revokedAt := time.Now().Add(-revokedAgo)
	repo.addToken(hash, &models.OAuthToken{
		ID:            uuid.New(),
		TenantID:      client.TenantID,
		ClientID:      client.ID,
		UserID:        &userID,
		TokenType:     "access_token",
		Token:         "access-" + plaintext,
		Scopes:        []string{"openid"},
		RefreshToken:  &hash,
		IsRevoked:     true,
		RevokedAt:     &revokedAt,
		RevokeReason:  reason,
		TokenFamilyID: &familyID,
		ExpiresAt:     time.Now().Add(time.Hour),
	})
}

// Logout on device A (per-device scope) revokes only A's tokens; device B's
// refresh token is untouched, so B refreshes normally with no CAE event.
func TestRefreshTokens_PerDeviceLogout_OtherDeviceStillValid(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)
	pub := wireCAERecorder(t, svc)

	client := activeConfidentialBFFClient("rotate")
	userID := uuid.New()
	svc.userRepo = &bindingUserRepo{user: &models.User{ID: userID, TenantID: client.TenantID, IsActive: true}}

	// Device A: revoked by its own logout (session_ended).
	famA := uuid.New()
	ended := "session_ended"
	addRevokedRefresh(svc, repo, client, userID, famA, "device-a-refresh", &ended, time.Minute)

	// Device B: live token in a different family.
	plainB := "device-b-refresh"
	hashB := svc.hashSecret(plainB)
	idB := uuid.New()
	famB := uuid.New()
	repo.addToken(hashB, &models.OAuthToken{
		ID: idB, TenantID: client.TenantID, ClientID: client.ID, UserID: &userID,
		TokenType: "access_token", Token: "access-b", Scopes: []string{"openid"},
		RefreshToken: &hashB, TokenFamilyID: &famB, ExpiresAt: time.Now().Add(time.Hour),
	})

	resp, err := svc.RefreshTokens(context.Background(), client, plainB, "")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, []uuid.UUID{idB}, repo.consumedTokenIDs)
	assert.Empty(t, repo.revokedFamilies)
	assert.Equal(t, 0, pub.calls(), "no CAE event when another device refreshes after a per-device logout")
}

// Logout everywhere, then a refresh from any device: "session has ended",
// no family revoke, no CAE event. Also covers legacy rows with NULL reason.
func TestRefreshTokens_LogoutEverywhere_SessionEndedNoCAE(t *testing.T) {
	logout := "logout"
	for name, reason := range map[string]*string{"logout": &logout, "legacy_null": nil} {
		t.Run(name, func(t *testing.T) {
			repo := newRotationPolicyTestRepo()
			svc := newRefreshPolicyTestService(t, repo)
			pub := wireCAERecorder(t, svc)

			client := activeConfidentialBFFClient("rotate")
			userID := uuid.New()
			svc.userRepo = &bindingUserRepo{user: &models.User{ID: userID, TenantID: client.TenantID, IsActive: true}}
			fam := uuid.New()
			// Outside the grace window, the exact shape that used to be misread as theft.
			addRevokedRefresh(svc, repo, client, userID, fam, "other-device-refresh", reason, time.Hour)

			resp, err := svc.RefreshTokens(context.Background(), client, "other-device-refresh", "")
			require.Error(t, err)
			require.Nil(t, resp)
			assert.True(t, strings.HasPrefix(err.Error(), "invalid_grant:"))
			assert.Contains(t, err.Error(), "session has ended")
			assert.Empty(t, repo.revokedFamilies, "an ended session is not theft")
			assert.Equal(t, 0, pub.calls(), "no CAE event for an ended session")
		})
	}
}

// A rotated token replayed after the 5 minute recovery window is still theft.
func TestRefreshTokens_RotatedReplayAfterFiveMinutes_StillTheft(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)
	pub := wireCAERecorder(t, svc)

	client := activeConfidentialBFFClient("rotate")
	userID := uuid.New()
	svc.userRepo = &bindingUserRepo{user: &models.User{ID: userID, TenantID: client.TenantID, IsActive: true}}
	fam := uuid.New()
	rotated := "rotated"
	addRevokedRefresh(svc, repo, client, userID, fam, "old-rotated-refresh", &rotated, 6*time.Minute)

	_, err := svc.RefreshTokens(context.Background(), client, "old-rotated-refresh", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
	assert.NotContains(t, err.Error(), "session has ended")
	assert.Equal(t, []uuid.UUID{fam}, repo.revokedFamilies, "a late rotated replay revokes the family")
	assert.Equal(t, 1, pub.calls(), "a late rotated replay emits the CAEP theft signal")
}

// A rotated token replayed inside the grace window is a benign race and is
// reported as refresh_race (the BFF retries instead of treating it as final).
func TestRefreshTokens_GraceWindowRace_ReportsRefreshRace(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)
	pub := wireCAERecorder(t, svc)

	client := activeConfidentialBFFClient("rotate")
	userID := uuid.New()
	svc.userRepo = &bindingUserRepo{user: &models.User{ID: userID, TenantID: client.TenantID, IsActive: true}}
	fam := uuid.New()
	rotated := "rotated"
	addRevokedRefresh(svc, repo, client, userID, fam, "just-rotated-refresh", &rotated, time.Second)

	_, err := svc.RefreshTokens(context.Background(), client, "just-rotated-refresh", "")
	require.Error(t, err)
	assert.Equal(t, "invalid_grant: refresh_race", err.Error())
	assert.Empty(t, repo.revokedFamilies)
	assert.Equal(t, 0, pub.calls())
}
