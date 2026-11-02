// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeWebAuthnRepo is an in-memory implementation of webAuthnRepo with
// observable record-keeping so tests can assert on persisted state without
// loading a real DB.
type fakeWebAuthnRepo struct {
	mu       sync.Mutex
	creds    map[uuid.UUID]*models.WebAuthnCredential // by row id
	byCredID map[string]*models.WebAuthnCredential    // by raw credential_id

	// counters for assertion
	signCountUpdates int
	cloneWarnings    int
	revokes          int
}

func newFakeWebAuthnRepo() *fakeWebAuthnRepo {
	return &fakeWebAuthnRepo{
		creds:    map[uuid.UUID]*models.WebAuthnCredential{},
		byCredID: map[string]*models.WebAuthnCredential{},
	}
}

func (r *fakeWebAuthnRepo) Create(_ context.Context, cred *models.WebAuthnCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cred.ID == uuid.Nil {
		cred.ID = uuid.New()
	}
	cred.CreatedAt = time.Now().UTC()
	r.creds[cred.ID] = cred
	r.byCredID[string(cred.CredentialID)] = cred
	return nil
}

func (r *fakeWebAuthnRepo) GetByCredentialID(_ context.Context, credentialID []byte) (*models.WebAuthnCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byCredID[string(credentialID)]
	if !ok {
		return nil, nil
	}
	return c, nil
}

func (r *fakeWebAuthnRepo) GetByID(_ context.Context, id uuid.UUID) (*models.WebAuthnCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.byCredID {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, nil
}

func (r *fakeWebAuthnRepo) ListByUser(_ context.Context, userID, tenantID uuid.UUID) ([]models.WebAuthnCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []models.WebAuthnCredential
	for _, c := range r.creds {
		if c.UserID == userID && c.TenantID == tenantID {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (r *fakeWebAuthnRepo) CountActiveByUser(_ context.Context, userID, tenantID uuid.UUID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, c := range r.creds {
		if c.UserID == userID && c.TenantID == tenantID && c.IsActive() {
			count++
		}
	}
	return count, nil
}

func (r *fakeWebAuthnRepo) ListDiscoverableByTenant(_ context.Context, tenantID uuid.UUID) ([]models.WebAuthnCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []models.WebAuthnCredential
	for _, c := range r.creds {
		if c.TenantID == tenantID && c.IsDiscoverable && c.IsActive() {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (r *fakeWebAuthnRepo) UpdateSignCount(_ context.Context, id uuid.UUID, signCount uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.creds[id]
	if !ok {
		return errors.New("not found")
	}
	c.SignCount = signCount
	now := time.Now().UTC()
	c.LastUsedAt = &now
	r.signCountUpdates++
	return nil
}

func (r *fakeWebAuthnRepo) UpdateLastUsedAt(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.creds[id]
	if !ok {
		return errors.New("not found")
	}
	now := time.Now().UTC()
	c.LastUsedAt = &now
	return nil
}

func (r *fakeWebAuthnRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.creds[id]
	if !ok {
		return nil
	}
	delete(r.creds, id)
	delete(r.byCredID, string(c.CredentialID))
	return nil
}

func (r *fakeWebAuthnRepo) Revoke(_ context.Context, id uuid.UUID, revokedBy uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.creds[id]
	if !ok {
		return errors.New("not found")
	}
	now := time.Now().UTC()
	c.RevokedAt = &now
	c.RevokedBy = &revokedBy
	r.revokes++
	return nil
}

func (r *fakeWebAuthnRepo) SetCloneWarning(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.creds[id]
	if !ok {
		return errors.New("not found")
	}
	c.CloneWarning = true
	r.cloneWarnings++
	return nil
}

// fakeSessionStore is an in-memory webAuthnSessionStorage for unit tests.
type fakeSessionStore struct {
	mu      sync.Mutex
	entries map[string]*webauthn.SessionData
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{entries: map[string]*webauthn.SessionData{}}
}

func (f *fakeSessionStore) Save(_ context.Context, sessionID string, data *webauthn.SessionData) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[sessionID] = data
	return nil
}

func (f *fakeSessionStore) Take(_ context.Context, sessionID string) (*webauthn.SessionData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.entries[sessionID]
	if !ok {
		return nil, errors.New("not found")
	}
	delete(f.entries, sessionID)
	return data, nil
}

// fakeUserLookup is an in-memory webAuthnUserLookup.
type fakeUserLookup struct {
	users map[uuid.UUID]*models.User
}

func (f *fakeUserLookup) GetByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	u, ok := f.users[id]
	if !ok {
		return nil, nil
	}
	return u, nil
}

// Update satisfies the webAuthnUserLookup interface. In-memory:
// replaces the stored user. Used by FinishRegistration to flip
// user.mfa_enabled once a passkey is persisted.
func (f *fakeUserLookup) Update(_ context.Context, u *models.User) error {
	if f.users == nil {
		f.users = map[uuid.UUID]*models.User{}
	}
	f.users[u.ID] = u
	return nil
}

// fakeCAEPublisher captures publish calls so the clone-detection test can
// assert that a CAEP credential_compromised event went out.
type fakeCAEPublisher struct {
	mu       sync.Mutex
	messages [][]byte
	channels []string
}

func (p *fakeCAEPublisher) Publish(_ context.Context, channel string, message []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.channels = append(p.channels, channel)
	p.messages = append(p.messages, append([]byte(nil), message...))
	return nil
}

// newServiceForTests builds a WebAuthnService with sane RP config + CAE
// service backed by a fake publisher. The returned publisher is the same
// instance the service publishes to, so tests can read p.messages after
// running a clone-detection scenario.
func newServiceForTests(t *testing.T, repo webAuthnRepo, store webAuthnSessionStorage, users webAuthnUserLookup) (*WebAuthnService, *fakeCAEPublisher) {
	t.Helper()
	pub := &fakeCAEPublisher{}
	cae := NewCAEService(pub, zap.NewNop())
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          "example.com",
		RPDisplayName: "HexxLock",
		RPOrigins:     []string{"https://accounts.example.com"},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification:   protocol.VerificationRequired,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
		},
	})
	require.NoError(t, err)
	svc := &WebAuthnService{
		repo:       repo,
		users:      users,
		sessions:   store,
		caeService: cae,
		logger:     zap.NewNop(),
		wa:         wa,
	}
	return svc, pub
}

// ---------------------------------------------------------------------------
// WebAuthnSessionCache (Redis-shaped storage)
// ---------------------------------------------------------------------------

// inMemKVStore matches the webauthnSessionStore interface (Get/Set/Del)
// without spinning up miniredis — sufficient for unit-testing the cache
// itself, which is just JSON serialisation + prefix-keyed Get/Set/Del.
type inMemKVStore struct {
	mu sync.Mutex
	m  map[string]string
}

func newInMemKVStore() *inMemKVStore { return &inMemKVStore{m: map[string]string{}} }

func (s *inMemKVStore) Get(_ context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[key], nil
}

func (s *inMemKVStore) Set(_ context.Context, key string, value interface{}, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch v := value.(type) {
	case []byte:
		s.m[key] = string(v)
	case string:
		s.m[key] = v
	default:
		return errors.New("unexpected value type")
	}
	return nil
}

func (s *inMemKVStore) Del(_ context.Context, keys ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		delete(s.m, k)
	}
	return nil
}

func TestWebAuthnSessionCache_RoundTrip(t *testing.T) {
	store := newInMemKVStore()
	cache := newWebAuthnSessionCacheWithStore(store)
	ctx := context.Background()

	want := &webauthn.SessionData{
		Challenge:        "abc123",
		RelyingPartyID:   "example.com",
		UserID:           []byte{0x01, 0x02},
		UserVerification: protocol.VerificationRequired,
	}

	id, err := NewSessionID()
	require.NoError(t, err)
	require.NotEmpty(t, id)

	require.NoError(t, cache.Save(ctx, id, want))

	got, err := cache.Take(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, want.Challenge, got.Challenge)
	assert.Equal(t, want.RelyingPartyID, got.RelyingPartyID)
	assert.Equal(t, want.UserID, got.UserID)
	assert.Equal(t, want.UserVerification, got.UserVerification)
}

func TestWebAuthnSessionCache_TakeIsSingleUse(t *testing.T) {
	store := newInMemKVStore()
	cache := newWebAuthnSessionCacheWithStore(store)
	ctx := context.Background()

	id, err := NewSessionID()
	require.NoError(t, err)
	require.NoError(t, cache.Save(ctx, id, &webauthn.SessionData{Challenge: "x"}))

	_, err = cache.Take(ctx, id)
	require.NoError(t, err, "first Take must succeed")

	_, err = cache.Take(ctx, id)
	require.Error(t, err, "second Take must fail — session is single-use")
}

func TestWebAuthnSessionCache_TakeMissingFails(t *testing.T) {
	cache := newWebAuthnSessionCacheWithStore(newInMemKVStore())
	_, err := cache.Take(context.Background(), "no-such-session")
	require.Error(t, err)
}

func TestWebAuthnSessionCache_RejectsEmptySessionID(t *testing.T) {
	cache := newWebAuthnSessionCacheWithStore(newInMemKVStore())
	require.Error(t, cache.Save(context.Background(), "", &webauthn.SessionData{}))
	_, err := cache.Take(context.Background(), "")
	require.Error(t, err)
}

func TestNewSessionID_ProducesDistinctValues(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 50; i++ {
		id, err := NewSessionID()
		require.NoError(t, err)
		_, dup := seen[id]
		require.False(t, dup, "NewSessionID returned a duplicate at iteration %d: %s", i, id)
		seen[id] = struct{}{}
	}
}

// ---------------------------------------------------------------------------
// applyAttestationPolicy
// ---------------------------------------------------------------------------

func TestApplyAttestationPolicy_RequireAttestation_RejectsNone(t *testing.T) {
	svc, _ := newServiceForTests(t, newFakeWebAuthnRepo(), newFakeSessionStore(), &fakeUserLookup{})
	libCred := &webauthn.Credential{AttestationType: "none"}
	policy := models.AttestationPolicy{RequireAttestation: true}

	err := svc.applyAttestationPolicy(libCred, policy, 0)
	require.Error(t, err, "RequireAttestation must reject AttestationType=none")
}

func TestApplyAttestationPolicy_RequireAttestation_AcceptsBasicFull(t *testing.T) {
	svc, _ := newServiceForTests(t, newFakeWebAuthnRepo(), newFakeSessionStore(), &fakeUserLookup{})
	libCred := &webauthn.Credential{AttestationType: "basic_full"}
	policy := models.AttestationPolicy{RequireAttestation: true}

	require.NoError(t, svc.applyAttestationPolicy(libCred, policy, 0))
}

func TestApplyAttestationPolicy_BlockSyncedPasskeys(t *testing.T) {
	svc, _ := newServiceForTests(t, newFakeWebAuthnRepo(), newFakeSessionStore(), &fakeUserLookup{})
	libCred := &webauthn.Credential{
		AttestationType: "basic_full",
		Flags:           webauthn.CredentialFlags{BackupEligible: true},
	}
	policy := models.AttestationPolicy{BlockSyncedPasskeys: true}

	err := svc.applyAttestationPolicy(libCred, policy, 0)
	require.Error(t, err, "BlockSyncedPasskeys must reject BackupEligible credentials")
}

func TestApplyAttestationPolicy_AAGUIDAllowlist_RejectsUnlisted(t *testing.T) {
	svc, _ := newServiceForTests(t, newFakeWebAuthnRepo(), newFakeSessionStore(), &fakeUserLookup{})
	libCred := &webauthn.Credential{
		AttestationType: "basic_full",
		Authenticator:   webauthn.Authenticator{AAGUID: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}},
	}
	policy := models.AttestationPolicy{
		AllowedAAGUIDs: []string{"deadbeef-dead-beef-dead-beefdeadbeef"},
	}

	err := svc.applyAttestationPolicy(libCred, policy, 0)
	require.Error(t, err, "AAGUID not in allowlist must be rejected")
}

func TestApplyAttestationPolicy_AAGUIDAllowlist_AcceptsListed(t *testing.T) {
	svc, _ := newServiceForTests(t, newFakeWebAuthnRepo(), newFakeSessionStore(), &fakeUserLookup{})
	aaguid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
	libCred := &webauthn.Credential{
		AttestationType: "basic_full",
		Authenticator:   webauthn.Authenticator{AAGUID: aaguid},
	}
	policy := models.AttestationPolicy{
		AllowedAAGUIDs: []string{"11223344-5566-7788-99aa-bbccddeeff00"},
	}

	require.NoError(t, svc.applyAttestationPolicy(libCred, policy, 0),
		"AAGUID matching the allowlist (case-insensitive, hyphen-formatted) must pass")
}

func TestApplyAttestationPolicy_MaxCredentialsPerUser(t *testing.T) {
	svc, _ := newServiceForTests(t, newFakeWebAuthnRepo(), newFakeSessionStore(), &fakeUserLookup{})
	libCred := &webauthn.Credential{AttestationType: "basic_full"}
	policy := models.AttestationPolicy{MaxCredentialsPerUser: 5}

	require.NoError(t, svc.applyAttestationPolicy(libCred, policy, 4),
		"4 existing credentials with cap of 5 must be allowed")

	err := svc.applyAttestationPolicy(libCred, policy, 5)
	require.Error(t, err, "5 existing credentials with cap of 5 must be rejected")
}

// ---------------------------------------------------------------------------
// completeAuthentication clone-detection path
// ---------------------------------------------------------------------------

func TestCompleteAuthentication_CloneWarning_RevokesAndEmitsCAEP(t *testing.T) {
	repo := newFakeWebAuthnRepo()
	userID := uuid.New()
	tenantID := uuid.New()
	credBytes := []byte("test-credential-id")
	dbCred := &models.WebAuthnCredential{
		ID:           uuid.New(),
		UserID:       userID,
		TenantID:     tenantID,
		CredentialID: credBytes,
		PublicKey:    []byte("test-public-key"),
		SignCount:    10,
	}
	require.NoError(t, repo.Create(context.Background(), dbCred))

	svc, pub := newServiceForTests(t, repo, newFakeSessionStore(), &fakeUserLookup{})

	// Simulate the library reporting a clone warning — the regression is
	// already detected upstream; completeAuthentication's job is to act on it.
	libCred := &webauthn.Credential{
		ID:        credBytes,
		PublicKey: dbCred.PublicKey,
		Authenticator: webauthn.Authenticator{
			SignCount:    5, // regressed from 10
			CloneWarning: true,
		},
	}

	_, err := svc.completeAuthentication(context.Background(), libCred, tenantID)
	require.Error(t, err, "clone warning must hard-reject the authentication")

	// Side effects: clone_warning persisted, credential revoked, CAEP fired.
	assert.Equal(t, 1, repo.cloneWarnings, "clone_warning must be persisted")
	assert.Equal(t, 1, repo.revokes, "credential must be auto-revoked")
	require.NotEmpty(t, pub.messages, "CAEP credential_compromised must be published")
	for _, msg := range pub.messages {
		assert.Contains(t, string(msg), "credential_compromised", "published event must reference credential_compromise")
		assert.Contains(t, string(msg), userID.String(), "published event must carry the affected user id")
	}
}

func TestCompleteAuthentication_HappyPath_UpdatesSignCount(t *testing.T) {
	repo := newFakeWebAuthnRepo()
	userID := uuid.New()
	tenantID := uuid.New()
	credBytes := []byte("happy-credential-id")
	dbCred := &models.WebAuthnCredential{
		ID:           uuid.New(),
		UserID:       userID,
		TenantID:     tenantID,
		CredentialID: credBytes,
		PublicKey:    []byte("happy-public-key"),
		SignCount:    10,
	}
	require.NoError(t, repo.Create(context.Background(), dbCred))

	svc, pub := newServiceForTests(t, repo, newFakeSessionStore(), &fakeUserLookup{})

	libCred := &webauthn.Credential{
		ID:        credBytes,
		PublicKey: dbCred.PublicKey,
		Authenticator: webauthn.Authenticator{
			SignCount:    11, // monotone increase
			CloneWarning: false,
		},
	}

	got, err := svc.completeAuthentication(context.Background(), libCred, tenantID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, uint32(11), got.SignCount, "service must surface the new sign count")
	assert.Equal(t, 1, repo.signCountUpdates, "happy-path must persist the new sign count")
	assert.Equal(t, 0, repo.cloneWarnings, "happy-path must not raise a clone warning")
	assert.Equal(t, 0, repo.revokes, "happy-path must not revoke the credential")
	assert.Empty(t, pub.messages, "happy-path must not publish CAEP events")
}

// ---------------------------------------------------------------------------
// webauthnUser adapter
// ---------------------------------------------------------------------------

func TestWebAuthnUser_IDIsRawUUIDBytes(t *testing.T) {
	u := &models.User{
		ID:       uuid.MustParse("11223344-5566-7788-99aa-bbccddeeff00"),
		TenantID: uuid.New(),
		Username: "alice@example.com",
	}
	wu := newWebAuthnUser(u, nil, true)

	id := wu.WebAuthnID()
	require.Len(t, id, 16, "WebAuthnID must be the 16 raw UUID bytes")

	// Round-trip: parsing the returned bytes back into a UUID must yield
	// the original. This is the contract callers (e.g. conditional-UI flow)
	// rely on when they reconstruct the user from a userHandle.
	got, err := uuid.FromBytes(id)
	require.NoError(t, err)
	assert.Equal(t, u.ID, got)
}

func TestWebAuthnUser_DisplayName_PrefersFirstLast(t *testing.T) {
	first := "Alice"
	last := "Müller"
	u := &models.User{
		ID:        uuid.New(),
		Username:  "alice@example.com",
		FirstName: &first,
		LastName:  &last,
	}
	wu := newWebAuthnUser(u, nil, true)

	assert.Equal(t, "alice@example.com", wu.WebAuthnName())
	assert.Equal(t, "Alice Müller", wu.WebAuthnDisplayName())
}

func TestWebAuthnUser_DisplayName_FallsBackToUsername(t *testing.T) {
	u := &models.User{
		ID:       uuid.New(),
		Username: "service-bot",
	}
	wu := newWebAuthnUser(u, nil, true)

	assert.Equal(t, "service-bot", wu.WebAuthnDisplayName(),
		"empty first/last must fall back to username")
}

func TestWebAuthnUser_FiltersInactiveCredentials(t *testing.T) {
	now := time.Now().UTC()
	revoked := now.Add(-1 * time.Hour)
	u := &models.User{ID: uuid.New(), TenantID: uuid.New(), Username: "alice"}

	dbCreds := []models.WebAuthnCredential{
		{ID: uuid.New(), CredentialID: []byte("active"), PublicKey: []byte("k1")},
		{ID: uuid.New(), CredentialID: []byte("revoked"), PublicKey: []byte("k2"), RevokedAt: &revoked},
	}

	wu := newWebAuthnUser(u, dbCreds, true)
	got := wu.WebAuthnCredentials()
	require.Len(t, got, 1, "activeOnly must drop revoked credentials")
	assert.Equal(t, []byte("active"), got[0].ID)
}

// ---------------------------------------------------------------------------
// containsAAGUID + bytesEqual
// ---------------------------------------------------------------------------

func TestContainsAAGUID_NormalisesHex(t *testing.T) {
	allowlist := []string{"11223344-5566-7788-99aa-bbccddeeff00"}

	// Raw 32-char hex matches the hyphenated allowlist entry.
	assert.True(t, containsAAGUID(allowlist, "112233445566778899aabbccddeeff00"))
	// Already-hyphenated input matches.
	assert.True(t, containsAAGUID(allowlist, "11223344-5566-7788-99aa-bbccddeeff00"))
	// Case-insensitive.
	assert.True(t, containsAAGUID(allowlist, "11223344-5566-7788-99AA-BBCCDDEEFF00"))
	// Non-match returns false.
	assert.False(t, containsAAGUID(allowlist, "deadbeef-dead-beef-dead-beefdeadbeef"))
}

func TestBytesEqual(t *testing.T) {
	assert.True(t, bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 3}))
	assert.False(t, bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 4}))
	assert.False(t, bytesEqual([]byte{1, 2, 3}, []byte{1, 2}))
	assert.True(t, bytesEqual(nil, nil))
	assert.True(t, bytesEqual(nil, []byte{}))
}

// ---------------------------------------------------------------------------
// acrFromAuthMethods (lives on the claims path but tested here for the
// passkey-specific ladder behaviour).
// ---------------------------------------------------------------------------

func TestAcrFromAuthMethods_HwkBeatsPwd(t *testing.T) {
	// When a session somehow records both hwk and pwd (e.g. step-up where
	// the user re-authenticated with a passkey on top of a password
	// session), the strongest authenticator dictates the AAL.
	got := acrFromAuthMethods([]string{"pwd", AMRValueHardwareKey, AMRValueUserVerification})
	assert.Equal(t, ACRValueAAL3, got, "presence of hwk dominates")
}

func TestAcrFromAuthMethods_OnlyUserIsNotAuthenticator(t *testing.T) {
	// "user" alone (user-verification flag) is a modifier, not an
	// authenticator type. Without an actual authenticator method present
	// we have nothing to anchor an ACR claim to.
	got := acrFromAuthMethods([]string{AMRValueUserVerification})
	assert.Equal(t, "", got, "user-only must not synthesize an ACR")
}
