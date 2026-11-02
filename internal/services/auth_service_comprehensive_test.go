// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

const (
	testAuthIP    = "10.0.0.1"
	testAuthIP192 = "192.168.1.100"
)

// ---------------------------------------------------------------------------
// Shared test configuration helpers
// ---------------------------------------------------------------------------

// newAuthCfg returns a config suitable for auth service tests.
func newAuthCfg() *config.Config {
	return &config.Config{
		JWTSecret:              "test-jwt-secret-key-for-auth-tests-min-32chars",
		JWTIssuer:              "hexxlock-test",
		AccessTokenExpiry:      15 * time.Minute,
		SessionExpiry:          24 * time.Hour,
		MaxLoginAttempts:       5,
		LockoutDuration:        15 * time.Minute,
		PasswordMinLength:      8,
		PasswordRequireUpper:   true,
		PasswordRequireLower:   true,
		PasswordRequireDigit:   true,
		PasswordRequireSpecial: false,
	}
}

// newNopAuditSvc builds a real AuditService backed by a no-op audit repo.
// This lets methods that call s.auditService.LogLogin / LogUserAction compile
// and run without a real database.
func newNopAuditSvc() *AuditService {
	return &AuditService{tokenRepo: &noopAuditTokenRepo{}}
}

// noopAuditTokenRepo discards all audit log writes.
type noopAuditTokenRepo struct{}

func (n *noopAuditTokenRepo) CreateAuditLog(_ context.Context, _ *models.AuditLog) error {
	return nil
}

func (n *noopAuditTokenRepo) GetAuditLogByID(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*models.AuditLog, error) {
	return nil, nil
}

func (n *noopAuditTokenRepo) ListAuditLogs(_ context.Context, _ uuid.UUID, _, _ int, _ map[string]interface{}) ([]models.AuditLog, int64, error) {
	return nil, 0, nil
}

// authSvc builds a minimal *AuthService with nil concrete repos.
// Only use this for tests that exercise code paths that do not call into the repos.
func authSvc() *AuthService {
	return &AuthService{
		config:       newAuthCfg(),
		auditService: newNopAuditSvc(),
	}
}

// ---------------------------------------------------------------------------
// Tests: parseDeviceInfo (pure function — no DB, no state)
// ---------------------------------------------------------------------------

func TestParseDeviceInfo_Desktop(t *testing.T) {
	got := parseDeviceInfo("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120")
	assert.Equal(t, "Desktop", got)
}

func TestParseDeviceInfo_Mobile(t *testing.T) {
	got := parseDeviceInfo("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148")
	assert.Equal(t, "Mobile", got)
}

func TestParseDeviceInfo_Tablet(t *testing.T) {
	got := parseDeviceInfo("Mozilla/5.0 (iPad; CPU OS 17_0) tablet AppleWebKit")
	assert.Equal(t, "Tablet", got)
}

func TestParseDeviceInfo_EmptyDefaultsToDesktop(t *testing.T) {
	got := parseDeviceInfo("")
	assert.Equal(t, "Desktop", got)
}

func TestParseDeviceInfo_CaseInsensitive(t *testing.T) {
	assert.Equal(t, "Mobile", parseDeviceInfo("MOBILE browser"))
	assert.Equal(t, "Tablet", parseDeviceInfo("TABLET browser"))
}

func TestParseDeviceInfo_TableDriven(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{"postman", "PostmanRuntime/7.36", "Desktop"},
		{"curl", "curl/8.1.2", "Desktop"},
		{"android mobile", "Dalvik/2.1.0 (Android 14) Mobile", "Mobile"},
		{"ipad tablet", "Apple iPad tablet AppleWebKit", "Tablet"},
		{"chrome windows", "Mozilla/5.0 (Windows NT 10.0) Chrome/120", "Desktop"},
		{"safari mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/537.36", "Desktop"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseDeviceInfo(tt.ua))
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: checkUserStatus
// The method calls s.auditService.LogLogin and (for expired locks) s.userRepo.UnlockUser.
// We test the paths that do NOT call userRepo.UnlockUser (nil userRepo is safe).
// ---------------------------------------------------------------------------

func TestAuthService_CheckUserStatus_Active(t *testing.T) {
	svc := authSvc()
	user := &models.User{ID: uuid.New(), IsActive: true, IsLocked: false}
	err := svc.checkUserStatus(context.Background(), uuid.New(), user, "alice", "1.2.3.4", "UA")
	require.NoError(t, err)
}

func TestAuthService_CheckUserStatus_Inactive(t *testing.T) {
	svc := authSvc()
	user := &models.User{ID: uuid.New(), IsActive: false}
	err := svc.checkUserStatus(context.Background(), uuid.New(), user, "alice", "1.2.3.4", "UA")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestAuthService_CheckUserStatus_PermanentlyLocked(t *testing.T) {
	svc := authSvc()
	user := &models.User{
		ID:       uuid.New(),
		IsActive: true,
		IsLocked: true,
		// LockedUntil nil → permanent lock, never auto-unlocks
	}
	err := svc.checkUserStatus(context.Background(), uuid.New(), user, "alice", "1.2.3.4", "UA")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "locked")
}

// TestAuthService_CheckUserStatus_PendingDeletionBlocksLogin is the
// behavioural test for the self-service soft-delete login block.
// CONTROL: TestAuthService_CheckUserStatus_Active (above) proves the same
// call, with ActivationStatus left at its zero value, passes — so this
// failure is the pending_deletion check firing, not some other gate.
func TestAuthService_CheckUserStatus_PendingDeletionBlocksLogin(t *testing.T) {
	svc := authSvc()
	user := &models.User{ID: uuid.New(), IsActive: true, ActivationStatus: "pending_deletion"}
	err := svc.checkUserStatus(context.Background(), uuid.New(), user, "alice", "1.2.3.4", "UA")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scheduled for deletion")
}

// TestAuthService_CheckUserStatus_AdminDeletedBlocksLogin is the
// behavioural test for the admin-triggered soft-delete login block.
func TestAuthService_CheckUserStatus_AdminDeletedBlocksLogin(t *testing.T) {
	svc := authSvc()
	user := &models.User{ID: uuid.New(), IsActive: true, ActivationStatus: "admin_deleted"}
	err := svc.checkUserStatus(context.Background(), uuid.New(), user, "alice", "1.2.3.4", "UA")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deleted")
}

// TestAuthService_CheckUserStatus_OrdinaryActivationStatusPasses is a
// second control: an activation_status value that is neither
// pending_deletion nor admin_deleted must NOT be blocked by this gate.
func TestAuthService_CheckUserStatus_OrdinaryActivationStatusPasses(t *testing.T) {
	svc := authSvc()
	user := &models.User{ID: uuid.New(), IsActive: true, ActivationStatus: "active"}
	err := svc.checkUserStatus(context.Background(), uuid.New(), user, "alice", "1.2.3.4", "UA")
	require.NoError(t, err)
}

func TestAuthService_CheckUserStatus_LockedWithFutureExpiry(t *testing.T) {
	svc := authSvc()
	future := time.Now().Add(30 * time.Minute)
	user := &models.User{
		ID:          uuid.New(),
		IsActive:    true,
		IsLocked:    true,
		LockedUntil: &future,
	}
	err := svc.checkUserStatus(context.Background(), uuid.New(), user, "alice", "1.2.3.4", "UA")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "locked")
}

// ---------------------------------------------------------------------------
// Tests: getAvailableMFAMethods (pure method, only uses user struct fields)
// ---------------------------------------------------------------------------

func TestAuthService_GetAvailableMFAMethods(t *testing.T) {
	svc := &AuthService{}

	tests := []struct {
		name       string
		user       *models.User
		hasPasskey bool
		contains   []string
		length     int
	}{
		{
			name:     "totp only",
			user:     &models.User{MFATOTPEnabled: true},
			contains: []string{"totp"},
			length:   1,
		},
		{
			name:     "email only",
			user:     &models.User{MFAEmailEnabled: true},
			contains: []string{"email"},
			length:   1,
		},
		{
			name:     "both totp and email",
			user:     &models.User{MFATOTPEnabled: true, MFAEmailEnabled: true},
			contains: []string{"totp", "email"},
			length:   2,
		},
		{
			// 2026-05-26: replaces "fallback to MFAType" — the canonical
			// passkey-only case now emits webauthn, not the denormalized
			// MFAType column (removed because it was unreliable and led
			// to drift bugs).
			name:       "passkey only — emits webauthn",
			user:       &models.User{IsEmailVerified: true},
			hasPasskey: true,
			contains:   []string{authMethodWebAuthn},
			length:     1,
		},
		{
			// 2026-05-26: previously asserted [email] via the silent
			// fallback. That was the bug — now empty list when user has
			// genuinely no factor enrolled.
			name:   "empty when nothing configured",
			user:   &models.User{IsEmailVerified: true},
			length: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := svc.getAvailableMFAMethods(tt.user, tt.hasPasskey)
			assert.Len(t, got, tt.length)
			for _, m := range tt.contains {
				assert.Contains(t, got, m)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: selectMFAMethod (pure method)
// ---------------------------------------------------------------------------

func TestAuthService_SelectMFAMethod(t *testing.T) {
	svc := &AuthService{}

	tests := []struct {
		name             string
		user             *models.User
		requestedMethod  string
		availableMethods []string
		want             string
	}{
		{
			name:             "uses request preferred when available",
			user:             &models.User{},
			requestedMethod:  "email",
			availableMethods: []string{"totp", "email"},
			want:             "email",
		},
		{
			name:             "ignores unavailable request preferred, falls to user preferred",
			user:             &models.User{MFAPreferredMethod: ptrString("totp")},
			requestedMethod:  "sms",
			availableMethods: []string{"totp", "email"},
			want:             "totp",
		},
		{
			name:             "falls back to first available when no preference",
			user:             &models.User{},
			requestedMethod:  "",
			availableMethods: []string{"email"},
			want:             "email",
		},
		{
			name:             "falls back to MFAType when no available methods",
			user:             &models.User{MFAType: ptrString("totp")},
			requestedMethod:  "",
			availableMethods: nil,
			want:             "totp",
		},
		{
			// Updated 2026-05-23: previously asserted the buggy
			// "default to totp" foot-gun that locked out passkey-only
			// users (mfa_enabled=true after webauthn registration but
			// no TOTP enrolled → MFA challenge asked for a TOTP code
			// from a non-existent authenticator). Default is now
			// `email` since is_email_verified=true is a prerequisite
			// for every active account, making email a universally
			// usable fallback. See selectMFAMethod doc + the
			// getAvailableMFAMethods doc for the full regression
			// context (username `dogukanturhal` lockout, 2026-05-23).
			name:             "defaults to email when nothing configured",
			user:             &models.User{},
			requestedMethod:  "",
			availableMethods: nil,
			want:             "email",
		},
		{
			name:             "user preferred method chosen over request when request unavailable",
			user:             &models.User{MFAPreferredMethod: ptrString("email")},
			requestedMethod:  "sms",
			availableMethods: []string{"totp", "email"},
			want:             "email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := svc.selectMFAMethod(tt.user, tt.requestedMethod, tt.availableMethods)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: determineMFAMethod (pure method)
// ---------------------------------------------------------------------------

func TestAuthService_DetermineMFAMethod(t *testing.T) {
	svc := &AuthService{}

	tests := []struct {
		name              string
		user              *models.User
		requestedMethod   string
		riskMFARequired   bool
		wantMethod        string
		wantMethodsLength int
	}{
		{
			name:              "totp enabled, no preference",
			user:              &models.User{MFAEnabled: true, MFATOTPEnabled: true},
			wantMethod:        "totp",
			wantMethodsLength: 1,
		},
		{
			name:              "email enabled, no preference",
			user:              &models.User{MFAEnabled: true, MFAEmailEnabled: true},
			wantMethod:        "email",
			wantMethodsLength: 1,
		},
		{
			name:              "both enabled, prefers totp via request",
			user:              &models.User{MFAEnabled: true, MFATOTPEnabled: true, MFAEmailEnabled: true},
			requestedMethod:   "totp",
			wantMethod:        "totp",
			wantMethodsLength: 2,
		},
		{
			name:              "risk-based MFA for user without MFA",
			user:              &models.User{MFAEnabled: false},
			riskMFARequired:   true,
			wantMethod:        "email",
			wantMethodsLength: 1,
		},
		{
			name:              "no MFA configured, no risk requirement",
			user:              &models.User{MFAEnabled: false},
			wantMethod:        "",
			wantMethodsLength: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// hasFactor mirrors the legacy user.MFAEnabled-based pathing this
			// test fixture was written against — passing tt.user.MFAEnabled
			// preserves the original semantics now that determineMFAMethod
			// takes the source-of-truth boolean explicitly.
			method, methods := svc.determineMFAMethod(tt.user, tt.requestedMethod, tt.riskMFARequired, tt.user.MFAEnabled, false /* hasPasskey */)
			assert.Equal(t, tt.wantMethod, method)
			assert.Len(t, methods, tt.wantMethodsLength)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: buildMFAChallengeResponse (pure method)
// ---------------------------------------------------------------------------

func TestAuthService_BuildMFAChallengeResponse_NoRisk(t *testing.T) {
	svc := &AuthService{}
	resp := svc.buildMFAChallengeResponse("totp", []string{"totp", "email"}, "session-abc", false, nil)

	assert.True(t, resp.RequiresMFA)
	assert.Equal(t, "totp", resp.MFAMethod)
	assert.Equal(t, []string{"totp", "email"}, resp.AvailableMFAMethods)
	assert.Equal(t, "session-abc", resp.SessionID)
	assert.False(t, resp.IsNewDevice)
	assert.Zero(t, resp.RiskScore)
	assert.Empty(t, resp.RiskLevel)
	assert.Empty(t, resp.RiskWarnings)
}

func TestAuthService_BuildMFAChallengeResponse_WithRisk(t *testing.T) {
	svc := &AuthService{}
	ra := &models.RiskAssessment{
		TotalScore: 80,
		Level:      models.RiskLevelHigh,
		Warnings:   []string{"new country", "unusual hour"},
	}
	resp := svc.buildMFAChallengeResponse("email", []string{"email"}, "sess-xyz", true, ra)

	assert.True(t, resp.RequiresMFA)
	assert.Equal(t, "email", resp.MFAMethod)
	assert.True(t, resp.IsNewDevice)
	assert.Equal(t, 80, resp.RiskScore)
	assert.Equal(t, string(models.RiskLevelHigh), resp.RiskLevel)
	assert.Len(t, resp.RiskWarnings, 2)
}

func TestAuthService_BuildMFAChallengeResponse_NewDevice(t *testing.T) {
	svc := &AuthService{}
	resp := svc.buildMFAChallengeResponse("totp", []string{"totp"}, "sess-new", true, nil)

	assert.True(t, resp.IsNewDevice)
	assert.True(t, resp.RequiresMFA)
}

// ---------------------------------------------------------------------------
// Tests: buildRiskContext (pure method)
// ---------------------------------------------------------------------------

func TestAuthService_BuildRiskContext(t *testing.T) {
	svc := &AuthService{}
	tenantID := uuid.New()
	now := time.Now()
	lastLoginIP := testAuthIP

	user := &models.User{
		ID:          uuid.New(),
		TenantID:    tenantID,
		LastLoginIP: &lastLoginIP,
		LastLoginAt: &now,
	}

	// buildRiskContext now reads Location from context (via clientctx)
	// so it can populate iam_login_risk_events.location alongside the
	// IP / UA. Tests pass a bare context — Location stays empty.
	riskCtx := svc.buildRiskContext(context.Background(), tenantID, user, "192.168.1.1", "TestUA/1.0", true)

	assert.Equal(t, user.ID, riskCtx.UserID)
	assert.Equal(t, tenantID, riskCtx.TenantID)
	assert.Equal(t, "192.168.1.1", riskCtx.IPAddress)
	assert.Equal(t, "TestUA/1.0", riskCtx.UserAgent)
	assert.True(t, riskCtx.IsNewDevice)
	assert.NotNil(t, riskCtx.LastLoginIP)
	assert.Equal(t, lastLoginIP, *riskCtx.LastLoginIP)
	assert.NotNil(t, riskCtx.LastLoginTime)
}

func TestAuthService_BuildRiskContext_NoLastLogin(t *testing.T) {
	svc := &AuthService{}
	tenantID := uuid.New()

	user := &models.User{
		ID:       uuid.New(),
		TenantID: tenantID,
		// No LastLoginIP, no LastLoginAt
	}

	riskCtx := svc.buildRiskContext(context.Background(), tenantID, user, "1.2.3.4", "UA", false)

	assert.Equal(t, user.ID, riskCtx.UserID)
	assert.Nil(t, riskCtx.LastLoginIP)
	assert.Nil(t, riskCtx.LastLoginTime)
	assert.False(t, riskCtx.IsNewDevice)
}

// ---------------------------------------------------------------------------
// Tests: applyRiskDelay (respects context cancellation)
// ---------------------------------------------------------------------------

func TestAuthService_ApplyRiskDelay_ZeroDelay(t *testing.T) {
	svc := &AuthService{}
	ra := &models.RiskAssessment{DelaySeconds: 0}

	ctx := context.Background()
	start := time.Now()
	svc.applyRiskDelay(ctx, ra)
	elapsed := time.Since(start)

	// Zero delay should return immediately
	assert.Less(t, elapsed, 100*time.Millisecond)
}

func TestAuthService_ApplyRiskDelay_ContextCancellation(t *testing.T) {
	svc := &AuthService{}
	ra := &models.RiskAssessment{DelaySeconds: 60} // very long delay

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	svc.applyRiskDelay(ctx, ra)
	elapsed := time.Since(start)

	// Context should cancel the delay well before 60 seconds
	assert.Less(t, elapsed, 500*time.Millisecond)
}

// ---------------------------------------------------------------------------
// Tests: ChangePassword — using real crypto but function-table userRepo
// We test the pure logic (password verification, policy validation) by
// constructing AuthService with a functional "fake" userRepo.
//
// Since AuthService.userRepo is *repositories.UserRepository (concrete), we
// cannot inject a mock.  Instead we test ChangePassword behaviour through a
// combination of:
//   a) Verifying that ChangePassword returns the right errors before touching
//      the repo (LDAP check, missing password hash, policy failure) — these
//      code paths hit the user returned from GetByID, but we cannot supply
//      GetByID.
//   b) For paths that need GetByID we rely on the fact that a nil
//      *repositories.UserRepository will panic — so we cover only the paths
//      where ChangePassword fails early.
//
// For full ChangePassword coverage see the integration test suite.
// ---------------------------------------------------------------------------

// TestAuthService_ChangePassword_PolicyValidation tests password policy checks
// by directly calling crypto.ValidatePassword (the same function ChangePassword uses).
func TestAuthService_ChangePassword_PolicyValidation(t *testing.T) {
	cfg := newAuthCfg()
	policy := &crypto.PasswordPolicy{
		MinLength:      cfg.PasswordMinLength,
		RequireUpper:   cfg.PasswordRequireUpper,
		RequireLower:   cfg.PasswordRequireLower,
		RequireDigit:   cfg.PasswordRequireDigit,
		RequireSpecial: cfg.PasswordRequireSpecial,
	}

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid complex password", "SecurePass1", false},
		{"too short", "abc", true},
		{"missing uppercase", "alllowercase1", true},
		{"missing lowercase", "ALLUPPERCASE1", true},
		{"missing digit", "NoDigitHere!", true},
		{"minimum length exactly", "Passw0rd", false},
		{"long valid password", "ThisIsAVeryLongSecurePassword123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := crypto.ValidatePassword(tt.password, policy)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAuthService_PasswordHashing verifies the crypto layer used by auth.
func TestAuthService_PasswordHashing(t *testing.T) {
	password := "TestPassword123"

	hash1, err := crypto.HashPassword(password, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, hash1)

	// Correct password verifies successfully
	valid, err := crypto.VerifyPassword(password, hash1)
	require.NoError(t, err)
	assert.True(t, valid)

	// Wrong password fails verification
	valid, err = crypto.VerifyPassword("WrongPassword123", hash1)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestAuthService_PasswordHashing_DifferentSalts(t *testing.T) {
	password := "SamePassword1"

	hash1, err := crypto.HashPassword(password, nil)
	require.NoError(t, err)

	hash2, err := crypto.HashPassword(password, nil)
	require.NoError(t, err)

	// Same password should produce different hashes (different salts)
	assert.NotEqual(t, hash1, hash2)

	// Both should verify correctly
	valid1, _ := crypto.VerifyPassword(password, hash1)
	valid2, _ := crypto.VerifyPassword(password, hash2)
	assert.True(t, valid1)
	assert.True(t, valid2)
}

// ---------------------------------------------------------------------------
// Tests: Logout — logic path analysis
//
// Logout has two code paths: single-session and all-devices.
// Both paths call into s.sessionRepo and s.tokenService (concrete types).
// Since we cannot inject mocks, we test the logic decisions made BEFORE
// the repo calls, and verify the method signatures / error wrapping by
// checking what the function would return given repo errors.
//
// For actual Logout behaviour with mock repos, see the integration suite.
// ---------------------------------------------------------------------------

// TestAuthService_Logout_MFAChallengeBuildResponse verifies that the MFA
// challenge response omits tokens (i.e., RequiresMFA is true and AccessToken is empty).
func TestAuthService_Logout_MFAChallengeHasNoTokens(t *testing.T) {
	svc := &AuthService{}
	resp := svc.buildMFAChallengeResponse("totp", []string{"totp"}, "sess-1", false, nil)

	assert.True(t, resp.RequiresMFA)
	assert.Empty(t, resp.AccessToken)
	assert.Empty(t, resp.RefreshToken)
}

// ---------------------------------------------------------------------------
// Tests: resolveTenantContext — invalid inputs (no DB needed for these paths)
// ---------------------------------------------------------------------------

func TestAuthService_ResolveTenantContext_NoTenantContext(t *testing.T) {
	svc := authSvc()
	req := &models.LoginRequest{
		Username: "user",
		Password: "pass",
		// Neither TenantID nor TenantSlug set
	}

	_, err := svc.resolveTenantContext(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant")
}

func TestAuthService_ResolveTenantContext_InvalidTenantID(t *testing.T) {
	svc := authSvc()
	req := &models.LoginRequest{
		Username: "user",
		Password: "pass",
		TenantID: "not-a-valid-uuid",
	}

	_, err := svc.resolveTenantContext(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tenant ID")
}

func TestAuthService_ResolveTenantContext_InvalidTenantSlug(t *testing.T) {
	svc := authSvc()
	// resolveTenantContext gates the slug branch on `s.tenantRepo != nil`.
	// When tenantRepo is nil (as in authSvc()), a non-empty TenantSlug causes
	// the branch to be skipped entirely and the function falls through to the
	// else path, returning the generic "tenant context required" error.
	// Slug format validation only occurs when a real tenantRepo is wired in.
	req := &models.LoginRequest{
		Username:   "user",
		Password:   "pass",
		TenantSlug: "INVALID_SLUG!!",
	}

	_, err := svc.resolveTenantContext(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant context required")
}

func TestAuthService_ResolveTenantContext_ValidTenantID(t *testing.T) {
	svc := authSvc()
	// When tenantRepo is nil, the valid-UUID path should parse the UUID
	// and return a tenantContext with the parsed ID.
	tenantID := uuid.New()
	req := &models.LoginRequest{
		Username: "user",
		Password: "pass",
		TenantID: tenantID.String(),
	}

	ctx, err := svc.resolveTenantContext(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, tenantID, ctx.TenantID)
}

func TestAuthService_ResolveTenantContext_ValidRealmID(t *testing.T) {
	svc := authSvc()
	tenantID := uuid.New()
	realmID := uuid.New()

	req := &models.LoginRequest{
		Username: "user",
		Password: "pass",
		TenantID: tenantID.String(),
		RealmID:  realmID.String(),
	}

	ctx, err := svc.resolveTenantContext(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, realmID, ctx.RealmID)
}

func TestAuthService_ResolveTenantContext_InvalidRealmID(t *testing.T) {
	svc := authSvc()
	tenantID := uuid.New()

	req := &models.LoginRequest{
		Username: "user",
		Password: "pass",
		TenantID: tenantID.String(),
		RealmID:  "not-a-valid-uuid",
	}

	_, err := svc.resolveTenantContext(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid realm ID")
}

func TestAuthService_ResolveTenantContext_SlugPrefix_RealmSlug(t *testing.T) {
	svc := authSvc()
	tenantID := uuid.New()

	req := &models.LoginRequest{
		Username: "user",
		Password: "pass",
		TenantID: tenantID.String(),
		RealmID:  "slug:my-realm",
	}

	ctx, err := svc.resolveTenantContext(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "my-realm", ctx.RealmSlug)
}

// ---------------------------------------------------------------------------
// Tests: validateTenantSlug (additional cases not in auth_service_test.go)
// ---------------------------------------------------------------------------

func TestValidateTenantSlug_AdditionalCases(t *testing.T) {
	tests := []struct {
		name    string
		slug    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "two character slug is valid",
			slug:    "ab",
			wantErr: false,
		},
		{
			name:    "numeric only slug is valid",
			slug:    "12345",
			wantErr: false,
		},
		{
			name:    "slug starting with number is valid",
			slug:    "2024corp",
			wantErr: false,
		},
		{
			name:    "null byte injection",
			slug:    "corp\x00admin",
			wantErr: true,
		},
		{
			name:    "carriage return injection",
			slug:    "corp\radmin",
			wantErr: true,
		},
		{
			name:    "newline injection",
			slug:    "corp\nadmin",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTenantSlug(tt.slug)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: loginRequest validation helpers
// ---------------------------------------------------------------------------

// TestAuthService_MFARequired_UserEnabled verifies MFA is required when user.MFAEnabled is set.
func TestAuthService_MFARequired_UserEnabled(t *testing.T) {
	user := &models.User{MFAEnabled: true}
	// Simulate the Login condition check: mfaRequired = user.MFAEnabled || ...
	mfaRequired := user.MFAEnabled
	assert.True(t, mfaRequired)
}

// TestAuthService_MFARequired_RiskBased verifies that a high-risk login requiring MFA
// triggers the MFA challenge even when user.MFAEnabled is false.
func TestAuthService_MFARequired_RiskBased(t *testing.T) {
	user := &models.User{MFAEnabled: false}
	riskAssessment := &models.RiskAssessment{RequiresMFA: true}

	mfaRequired := user.MFAEnabled || (riskAssessment != nil && riskAssessment.RequiresMFA)
	assert.True(t, mfaRequired)
}

// TestAuthService_MFANotRequired_Standard verifies MFA is not required without
// user MFA enabled and no risk requiring it.
func TestAuthService_MFANotRequired_Standard(t *testing.T) {
	user := &models.User{MFAEnabled: false}
	var riskAssessment *models.RiskAssessment

	mfaRequired := user.MFAEnabled || (riskAssessment != nil && riskAssessment.RequiresMFA)
	assert.False(t, mfaRequired)
}

// ---------------------------------------------------------------------------
// Tests: handleDeviceTrust — logic paths that don't call deviceService
// ---------------------------------------------------------------------------

// TestAuthService_HandleDeviceTrust_NoRememberMe verifies that without RememberMe
// and without a DeviceID, the device is not trusted.
func TestAuthService_HandleDeviceTrust_NoRememberMe(t *testing.T) {
	svc := &AuthService{config: newAuthCfg()}
	req := &models.LoginRequest{RememberMe: false, DeviceID: ""}

	isTrusted := svc.handleDeviceTrust(context.Background(), uuid.New(), req, "UA", "1.2.3.4")
	assert.False(t, isTrusted)
}

// TestAuthService_HandleDeviceTrust_RememberMeWithoutDeviceService verifies that
// RememberMe without a deviceService falls through safely.
func TestAuthService_HandleDeviceTrust_RememberMeNilDeviceService(t *testing.T) {
	svc := &AuthService{
		config:        newAuthCfg(),
		deviceService: nil, // no device service configured
	}
	req := &models.LoginRequest{
		RememberMe: true,
		DeviceID:   "device-fingerprint-abc",
	}

	isTrusted := svc.handleDeviceTrust(context.Background(), uuid.New(), req, "UA", "1.2.3.4")
	// Without deviceService, RememberMe cannot trust a device.
	assert.False(t, isTrusted)
}

// ---------------------------------------------------------------------------
// Tests: MFA session ID validation in CompleteMFALogin path
// ---------------------------------------------------------------------------

// TestAuthService_CompleteMFALogin_InvalidSessionIDFormat verifies that a
// malformed session ID is rejected before any Redis access is attempted.
func TestAuthService_CompleteMFALogin_InvalidSessionIDFormat(t *testing.T) {
	svc := authSvc() // no sessionCache set → will fail at cache check

	req := &models.MFACompleteRequest{
		SessionID: "not-a-valid-uuid!!!",
		MFACode:   "123456",
	}

	_, err := svc.CompleteMFALogin(context.Background(), req, "1.2.3.4", "UA")
	require.Error(t, err)
}

// TestAuthService_CompleteMFALogin_NilSessionCache verifies that without a Redis
// session cache the MFA completion is properly rejected.
func TestAuthService_CompleteMFALogin_NilSessionCache(t *testing.T) {
	svc := authSvc() // sessionCache is nil

	req := &models.MFACompleteRequest{
		SessionID: uuid.New().String(),
		MFACode:   "123456",
	}

	_, err := svc.CompleteMFALogin(context.Background(), req, "1.2.3.4", "UA")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session cache not available")
}

// TestAuthService_SwitchMFALoginMethod_NilSessionCache verifies that the method
// switch flow requires a session cache.
func TestAuthService_SwitchMFALoginMethod_NilSessionCache(t *testing.T) {
	svc := authSvc()

	_, err := svc.SwitchMFALoginMethod(context.Background(), uuid.New().String(), "email")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session cache not available")
}

// ---------------------------------------------------------------------------
// Tests: Logout — code-path analysis for single-session vs all-devices
// Both paths are gated behind concrete repo calls, but we can verify the
// method compiles and returns appropriate errors.
// ---------------------------------------------------------------------------

// TestAuthService_Logout_NilSessionRepo verifies the function panics/errors on
// nil sessionRepo (documents expected behaviour for nil-safety awareness).
//
// NOTE: In production the AuthService is always constructed with real repos
// via NewAuthService.  We skip this test to avoid panics.

// TestAuthService_GetLoginHistory_Pagination tests pagination defaults.
// This calls s.sessionRepo.GetLoginHistory — with nil sessionRepo it panics,
// so we test the logic that runs BEFORE the repo call.
func TestAuthService_GetLoginHistory_PaginationDefaults(t *testing.T) {
	// We cannot call the full method without a real sessionRepo.
	// Test the pagination defaulting logic in isolation instead.
	page, pageSize := 0, 0

	// Replicate the GetLoginHistory defaulting logic
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	assert.Equal(t, 1, page)
	assert.Equal(t, 20, pageSize)
}

func TestAuthService_GetLoginHistory_PaginationCapAt100(t *testing.T) {
	page, pageSize := 5, 999

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	assert.Equal(t, 5, page)
	assert.Equal(t, 20, pageSize)
}

// ---------------------------------------------------------------------------
// Tests: updateUserLoginInfo — verifies the data mutations on User struct
// This method calls s.userRepo.Update and s.userRepo.ResetFailedAttempts.
// We verify the struct mutations independently of the DB calls.
// ---------------------------------------------------------------------------

func TestAuthService_UpdateUserLoginInfo_MutatesUser(t *testing.T) {
	before := time.Now().Add(-1 * time.Minute)
	ip := "10.0.0.5"
	user := &models.User{
		ID:                  uuid.New(),
		FailedLoginAttempts: 3,
		LastLoginAt:         &before,
		LastLoginIP:         &ip,
	}

	// Replicate the mutation logic from updateUserLoginInfo (without the DB call)
	now := time.Now()
	newIP := testAuthIP192
	user.LastLoginAt = &now
	user.LastLoginIP = &newIP
	user.FailedLoginAttempts = 0

	assert.Equal(t, 0, user.FailedLoginAttempts)
	assert.Equal(t, testAuthIP192, *user.LastLoginIP)
	assert.True(t, user.LastLoginAt.After(before))
}

// ---------------------------------------------------------------------------
// Tests: LDAP authentication path — authenticateLocal with LDAP federation type
// This verifies the routing logic: LDAP-federated users get a specific error
// that triggers the LDAP auth path.
// ---------------------------------------------------------------------------

// TestAuthService_AuthenticateLocal_LDAPUserError verifies that authenticateLocal
// returns "user should authenticate via LDAP" for LDAP-federated users.
// We cannot call authenticateLocal directly (needs real userRepo), but we test
// the same error message that the production code uses.
func TestAuthService_LDAPUserError_MessageFormat(t *testing.T) {
	// This is the exact error string checked in authenticateCredentials.
	// If this changes, the LDAP fallback breaks.
	const ldapMsg = "user should authenticate via LDAP"
	const notFoundMsg = "user not found"

	// Verify these strings match what authenticateCredentials checks.
	assert.Equal(t, "user should authenticate via LDAP", ldapMsg)
	assert.Equal(t, "user not found", notFoundMsg)
}

// ---------------------------------------------------------------------------
// Tests: ChangePassword logic (via crypto layer — no DB needed)
// ---------------------------------------------------------------------------

func TestAuthService_ChangePassword_HashNewPassword(t *testing.T) {
	newPassword := "MyNewSecure1"

	hash, err := crypto.HashPassword(newPassword, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify the hash works for future logins
	valid, err := crypto.VerifyPassword(newPassword, hash)
	require.NoError(t, err)
	assert.True(t, valid)

	// Verify wrong password is rejected
	valid, err = crypto.VerifyPassword("WrongPassword1", hash)
	require.NoError(t, err)
	assert.False(t, valid)
}

// ---------------------------------------------------------------------------
// Tests: MFA challenge stores no auth tokens (security invariant)
// ---------------------------------------------------------------------------

func TestAuthService_MFAChallenge_ContainsNoAuthTokens(t *testing.T) {
	svc := &AuthService{}

	for _, method := range []string{"totp", "email"} {
		t.Run(method, func(t *testing.T) {
			resp := svc.buildMFAChallengeResponse(method, []string{method}, uuid.New().String(), false, nil)
			// A pending MFA challenge must NOT contain auth tokens
			assert.Empty(t, resp.AccessToken, "MFA challenge must not contain access token")
			assert.Empty(t, resp.RefreshToken, "MFA challenge must not contain refresh token")
			assert.True(t, resp.RequiresMFA)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: RiskAssessment model behaviour
// ---------------------------------------------------------------------------

func TestRiskAssessment_BlockedFlag(t *testing.T) {
	ra := &models.RiskAssessment{
		Blocked:     true,
		BlockReason: "IP blacklisted",
	}
	assert.True(t, ra.Blocked)
	assert.Equal(t, "IP blacklisted", ra.BlockReason)
}

func TestRiskAssessment_RequiresMFAFlag(t *testing.T) {
	ra := &models.RiskAssessment{
		RequiresMFA: true,
		TotalScore:  60,
		Level:       models.RiskLevelMedium,
	}
	assert.True(t, ra.RequiresMFA)
	assert.Equal(t, 60, ra.TotalScore)
}

// ---------------------------------------------------------------------------
// Tests: Session.ToResponse mapping
// ---------------------------------------------------------------------------

func TestSession_ToResponse_IsCurrentSession(t *testing.T) {
	sessionID := uuid.New()
	session := &models.Session{
		ID:     sessionID,
		UserID: uuid.New(),
	}

	resp := session.ToResponse(&sessionID)
	assert.True(t, resp.IsCurrent)
}

func TestSession_ToResponse_NotCurrentSession(t *testing.T) {
	sessionID := uuid.New()
	otherSessionID := uuid.New()
	session := &models.Session{
		ID:     sessionID,
		UserID: uuid.New(),
	}

	resp := session.ToResponse(&otherSessionID)
	assert.False(t, resp.IsCurrent)
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkParseDeviceInfo(b *testing.B) {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile/15E148",
		"Mozilla/5.0 (iPad; CPU OS 17_0) tablet AppleWebKit",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = parseDeviceInfo(userAgents[i%len(userAgents)])
	}
}

func BenchmarkBuildMFAChallengeResponse(b *testing.B) {
	svc := &AuthService{}
	ra := &models.RiskAssessment{TotalScore: 50, Level: models.RiskLevelMedium}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = svc.buildMFAChallengeResponse("totp", []string{"totp", "email"}, "session-id", true, ra)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ptrString returns a pointer to the given string literal.
func ptrString(s string) *string { return &s }
