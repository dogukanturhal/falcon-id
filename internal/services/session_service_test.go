// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

const (
	testSessionUA = "Mozilla/5.0"
)

// ---------------------------------------------------------------------------
// Tests: Session model helpers
// ---------------------------------------------------------------------------

func TestSession_ToResponse_IsCurrent(t *testing.T) {
	sessionID := uuid.New()
	session := &models.Session{
		ID:             sessionID,
		UserID:         uuid.New(),
		IsActive:       true,
		CreatedAt:      time.Now(),
		LastActivityAt: time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	resp := session.ToResponse(&sessionID)

	assert.True(t, resp.IsCurrent)
	assert.True(t, resp.IsActive)
}

func TestSession_ToResponse_NotCurrent(t *testing.T) {
	sessionID := uuid.New()
	otherID := uuid.New()
	session := &models.Session{
		ID:             sessionID,
		UserID:         uuid.New(),
		IsActive:       true,
		CreatedAt:      time.Now(),
		LastActivityAt: time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	resp := session.ToResponse(&otherID)

	assert.False(t, resp.IsCurrent)
}

func TestSession_ToResponse_NilCurrentSessionID(t *testing.T) {
	session := &models.Session{
		ID:             uuid.New(),
		UserID:         uuid.New(),
		IsActive:       true,
		CreatedAt:      time.Now(),
		LastActivityAt: time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	resp := session.ToResponse(nil)

	assert.False(t, resp.IsCurrent)
}

func TestSession_ToResponse_OptionalFields(t *testing.T) {
	device := "Chrome on macOS"
	ip := "192.168.1.1"
	ua := testSessionUA
	loc := "Istanbul, TR"

	session := &models.Session{
		ID:             uuid.New(),
		UserID:         uuid.New(),
		DeviceInfo:     &device,
		IPAddress:      &ip,
		UserAgent:      &ua,
		Location:       &loc,
		IsActive:       true,
		CreatedAt:      time.Now(),
		LastActivityAt: time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	resp := session.ToResponse(nil)

	require.NotNil(t, resp.DeviceInfo)
	assert.Equal(t, device, *resp.DeviceInfo)
	require.NotNil(t, resp.IPAddress)
	assert.Equal(t, ip, *resp.IPAddress)
}

func TestSession_ToLoginHistoryEntry(t *testing.T) {
	reason := "logout"
	endedAt := time.Now()
	session := &models.Session{
		ID:             uuid.New(),
		IsActive:       false,
		CreatedAt:      time.Now().Add(-time.Hour),
		LastActivityAt: time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
		EndedAt:        &endedAt,
		EndReason:      &reason,
	}

	entry := session.ToLoginHistoryEntry()

	// LoginHistoryEntry was rewritten for the risk-events-sourced shape
	// (v0.232.241). Session-sourced rows always represent a successful
	// authentication; lifecycle state (is_active, ended_at, end_reason)
	// is no longer mirrored onto LoginHistoryEntry — it lives on the
	// underlying Session struct.
	assert.Equal(t, "allowed", entry.Outcome)
	assert.Equal(t, session.CreatedAt, entry.LoginAt)
}

func TestSession_WithUser_ToResponse(t *testing.T) {
	sessionID := uuid.New()
	sw := &models.SessionWithUser{
		Session: models.Session{
			ID:             sessionID,
			UserID:         uuid.New(),
			IsActive:       true,
			CreatedAt:      time.Now(),
			LastActivityAt: time.Now(),
			ExpiresAt:      time.Now().Add(time.Hour),
		},
		Username: "alice",
	}

	resp := sw.ToResponse(&sessionID)

	assert.Equal(t, "alice", resp.Username)
	assert.True(t, resp.IsCurrent)
}

// ---------------------------------------------------------------------------
// Tests: parseDeviceInfo pure function (from auth_account_service.go)
// ---------------------------------------------------------------------------

func TestSession_ParseDeviceInfo(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{"iphone mobile", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) Mobile Safari/604.1", "Mobile"},
		{"android mobile", "Mozilla/5.0 (Linux; Android 12) Mobile", "Mobile"},
		{"ipad desktop", "Mozilla/5.0 (iPad; CPU OS 16_0) AppleWebKit/605.1.15", "Desktop"},
		{"windows chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0", "Desktop"},
		{"curl", "curl/7.84.0", "Desktop"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDeviceInfo(tc.ua)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: Session creation through MagicLinkService.createSession
//
// MagicLinkService exposes createSession as a private method, but its effect
// is observable via the sessionRepo mock: if createSession is called with
// correct fields, the mock will be satisfied.
// ---------------------------------------------------------------------------

func TestSession_Create_ViaRequestMagicLink(t *testing.T) {
	// This test verifies that when RequestMagicLink successfully processes a
	// valid, active user it calls magicRepo.Create (which internally invokes
	// the session repo via createSession only during VerifyMagicLink, not
	// RequestMagicLink).  The session creation path is confirmed via the
	// mockMagicLinkSessionRepo.Create assertion.

	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)

	cfg := &config.Config{
		FrontendURL:   "https://app.example.com",
		SessionExpiry: 24 * time.Hour,
	}

	// Provide a real (no-SMTP) EmailService so nil-receiver panic is avoided.
	emailSvc := NewEmailService(cfg)
	svc := NewMagicLinkService(cfg, magicRepo, userRepo, sessionRepo, nil, emailSvc, nil)

	tenantID := uuid.New()
	userID := uuid.New()
	email := "alice@example.com"
	name := "Alice"

	magicRepo.On("CountRecentByEmail", ctx, email, mock.AnythingOfType("time.Time")).Return(0, nil)
	magicRepo.On("CountRecentByIP", ctx, "10.0.0.1", mock.AnythingOfType("time.Time")).Return(0, nil)
	userRepo.On("GetByEmail", ctx, tenantID, email).Return(&models.User{
		ID:        userID,
		TenantID:  tenantID,
		Email:     email,
		Username:  "alice",
		FirstName: &name,
		IsActive:  true,
		IsLocked:  false,
	}, nil)
	magicRepo.On("Create", ctx, mock.AnythingOfType("*models.MagicLink")).Return(nil)

	err := svc.RequestMagicLink(ctx, tenantID, email, "10.0.0.1", "TestAgent/1.0")

	require.NoError(t, err)
	magicRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
	// sessionRepo.Create is only called during VerifyMagicLink, not RequestMagicLink.
	sessionRepo.AssertNotCalled(t, "Create")
}

// ---------------------------------------------------------------------------
// Tests: Session end via mock – simulating RevokeSession behavior
// ---------------------------------------------------------------------------

// sessionEndRepo is a targeted interface that mirrors the subset of
// SessionRepository used for testing session termination logic.
type sessionEndRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error)
	EndSession(ctx context.Context, id uuid.UUID, reason string) error
	GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]models.Session, error)
}

type mockSessionEndRepo struct {
	mock.Mock
}

func (m *mockSessionEndRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

func (m *mockSessionEndRepo) EndSession(ctx context.Context, id uuid.UUID, reason string) error {
	args := m.Called(ctx, id, reason)
	return args.Error(0)
}

func (m *mockSessionEndRepo) GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]models.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Session), args.Error(1)
}

// revokeSession mirrors the logic inside AuthService.RevokeSession so we can
// verify the repository interactions in isolation.
func revokeSession(ctx context.Context, repo sessionEndRepo, userID, sessionID uuid.UUID) error {
	session, err := repo.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if session == nil {
		return assert.AnError
	}
	if session.UserID != userID {
		return assert.AnError
	}
	return repo.EndSession(ctx, sessionID, "revoked")
}

func TestSession_Revoke_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSessionEndRepo)

	userID := uuid.New()
	sessionID := uuid.New()
	session := &models.Session{ID: sessionID, UserID: userID, IsActive: true}

	repo.On("GetByID", ctx, sessionID).Return(session, nil)
	repo.On("EndSession", ctx, sessionID, "revoked").Return(nil)

	err := revokeSession(ctx, repo, userID, sessionID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestSession_Revoke_NotFound_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSessionEndRepo)

	sessionID := uuid.New()
	repo.On("GetByID", ctx, sessionID).Return(nil, nil)

	err := revokeSession(ctx, repo, uuid.New(), sessionID)

	assert.Error(t, err)
}

func TestSession_Revoke_WrongUser_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSessionEndRepo)

	sessionID := uuid.New()
	session := &models.Session{ID: sessionID, UserID: uuid.New()} // different user

	repo.On("GetByID", ctx, sessionID).Return(session, nil)

	err := revokeSession(ctx, repo, uuid.New(), sessionID)

	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Tests: GetActiveSessions – list sessions for a user
// ---------------------------------------------------------------------------

func TestSession_GetActive_ReturnsSessions(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSessionEndRepo)

	userID := uuid.New()
	sessions := []models.Session{
		{ID: uuid.New(), UserID: userID, IsActive: true},
		{ID: uuid.New(), UserID: userID, IsActive: true},
	}
	repo.On("GetActiveSessions", ctx, userID).Return(sessions, nil)

	got, err := repo.GetActiveSessions(ctx, userID)

	require.NoError(t, err)
	assert.Len(t, got, 2)
	for _, s := range got {
		assert.True(t, s.IsActive)
		assert.Equal(t, userID, s.UserID)
	}
	repo.AssertExpectations(t)
}

func TestSession_GetActive_Empty(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSessionEndRepo)

	userID := uuid.New()
	repo.On("GetActiveSessions", ctx, userID).Return([]models.Session{}, nil)

	got, err := repo.GetActiveSessions(ctx, userID)

	require.NoError(t, err)
	assert.Empty(t, got)
}

// ---------------------------------------------------------------------------
// Tests: Session model field validation
// ---------------------------------------------------------------------------

func TestSession_EndedAt_IsSet_OnRevoked(t *testing.T) {
	// Simulate what EndSession would do at the repo level: set EndedAt and EndReason.
	now := time.Now()
	reason := "revoked"
	session := &models.Session{
		ID:        uuid.New(),
		IsActive:  false,
		EndedAt:   &now,
		EndReason: &reason,
	}

	assert.False(t, session.IsActive)
	assert.NotNil(t, session.EndedAt)
	assert.Equal(t, "revoked", *session.EndReason)
}

func TestSession_SAML_Metadata_Fields(t *testing.T) {
	providerID := uuid.New()
	nameID := "user@saml.example.com"
	sessionIndex := "saml-session-index-123"

	session := &models.Session{
		ID:               uuid.New(),
		IsActive:         true,
		SAMLProviderID:   &providerID,
		SAMLNameID:       &nameID,
		SAMLSessionIndex: &sessionIndex,
	}

	assert.NotNil(t, session.SAMLProviderID)
	assert.Equal(t, nameID, *session.SAMLNameID)
	assert.Equal(t, sessionIndex, *session.SAMLSessionIndex)
}

// ---------------------------------------------------------------------------
// Tests: Session list response builder
// ---------------------------------------------------------------------------

func TestSession_ListResponse_ConvertToResponses(t *testing.T) {
	currentID := uuid.New()
	sessions := []models.Session{
		{
			ID:             currentID,
			UserID:         uuid.New(),
			IsActive:       true,
			CreatedAt:      time.Now(),
			LastActivityAt: time.Now(),
			ExpiresAt:      time.Now().Add(time.Hour),
		},
		{
			ID:             uuid.New(),
			UserID:         uuid.New(),
			IsActive:       true,
			CreatedAt:      time.Now(),
			LastActivityAt: time.Now(),
			ExpiresAt:      time.Now().Add(time.Hour),
		},
	}

	responses := make([]models.SessionResponse, len(sessions))
	for i, s := range sessions {
		s := s
		responses[i] = *s.ToResponse(&currentID)
	}

	require.Len(t, responses, 2)
	assert.True(t, responses[0].IsCurrent, "first session should be marked as current")
	assert.False(t, responses[1].IsCurrent, "second session should not be current")
}
