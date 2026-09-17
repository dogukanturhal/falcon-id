// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// --- fixtures --------------------------------------------------------

type stubKeyProvider struct {
	key *rsa.PrivateKey
	err error
}

func (s *stubKeyProvider) ActiveKey() (crypto.Signer, string, error) {
	if s.err != nil {
		return nil, "", s.err
	}
	return s.key, "test-kid", nil
}

func newStubKeyProvider(t *testing.T) *stubKeyProvider {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return &stubKeyProvider{key: k}
}

type stubSSFRepo struct {
	streams []*models.SSFStream
	listErr error
}

func (s *stubSSFRepo) CreateStream(_ context.Context, _ *models.SSFStream) error { return nil }
func (s *stubSSFRepo) ListStreams(_ context.Context, _ uuid.UUID) ([]*models.SSFStream, error) {
	return s.streams, s.listErr
}
func (s *stubSSFRepo) GetStream(_ context.Context, _ uuid.UUID) (*models.SSFStream, error) {
	return nil, errors.New("not implemented in stub")
}
func (s *stubSSFRepo) UpdateStream(_ context.Context, _ *models.SSFStream) error { return nil }
func (s *stubSSFRepo) DeleteStream(_ context.Context, _ uuid.UUID) error         { return nil }

// strPtr is a test helper. The services package already has its own
// `ptr` so we use a different name here to avoid redeclaration.
func caepStrPtr(s string) *string { return &s }

func newEmitterFixture(t *testing.T, streams []*models.SSFStream) (*CAEPEmitter, *stubKeyProvider) {
	t.Helper()
	keys := newStubKeyProvider(t)
	repo := &stubSSFRepo{streams: streams}
	em, err := NewCAEPEmitter(
		CAEPEmitterConfig{Issuer: "https://id.test/"},
		repo,
		keys,
		zap.NewNop(),
	)
	if err != nil {
		t.Fatalf("NewCAEPEmitter: %v", err)
	}
	return em, keys
}

// --- tests -----------------------------------------------------------

func TestNewCAEPEmitter_ValidatesRequired(t *testing.T) {
	repo := &stubSSFRepo{}
	keys := newStubKeyProvider(t)

	if _, err := NewCAEPEmitter(CAEPEmitterConfig{}, repo, keys, nil); err == nil {
		t.Errorf("expected error on missing Issuer")
	}
	if _, err := NewCAEPEmitter(CAEPEmitterConfig{Issuer: "x"}, nil, keys, nil); err == nil {
		t.Errorf("expected error on nil streams")
	}
	if _, err := NewCAEPEmitter(CAEPEmitterConfig{Issuer: "x"}, repo, nil, nil); err == nil {
		t.Errorf("expected error on nil keys")
	}
}

func TestEmitSessionRevoked_DeliversToMatchingStream(t *testing.T) {
	var receivedJWT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/secevent+jwt" {
			t.Errorf("wrong Content-Type: %q", r.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(r.Body)
		receivedJWT = string(b)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tenantID := uuid.New()
	userID := uuid.New()
	stream := &models.SSFStream{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Audience:        []string{"https://rp.test"},
		DeliveryMethod:  models.SSFDeliveryPush,
		PushEndpointURL: caepStrPtr(srv.URL),
		Status:          models.SSFStreamEnabled,
		EventsRequested: []models.SSFEventType{models.CAEPSessionRevoked},
	}
	em, keys := newEmitterFixture(t, []*models.SSFStream{stream})

	n := em.EmitSessionRevoked(context.Background(), tenantID, userID, "logout")
	if n != 1 {
		t.Errorf("expected 1 delivery, got %d", n)
	}
	if receivedJWT == "" {
		t.Fatalf("receiver got no SET")
	}

	// Verify signature + structure.
	parsed, err := jwt.Parse(receivedJWT, func(_ *jwt.Token) (interface{}, error) {
		return &keys.key.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("SET verify: %v", err)
	}
	if parsed.Header["kid"] != "test-kid" {
		t.Errorf("kid: %v", parsed.Header["kid"])
	}
	if parsed.Header["typ"] != "secevent+jwt" {
		t.Errorf("typ: %v", parsed.Header["typ"])
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != "https://id.test/" {
		t.Errorf("iss: %v", claims["iss"])
	}
	if claims["aud"] != "https://rp.test" {
		t.Errorf("aud (single-element collapses to string): %v", claims["aud"])
	}
	events := claims["events"].(map[string]interface{})
	if _, ok := events[string(models.CAEPSessionRevoked)]; !ok {
		t.Errorf("events missing session-revoked URN: %v", events)
	}
}

func TestEmit_SkipsPausedStream(t *testing.T) {
	pinged := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pinged = true
	}))
	defer srv.Close()

	tenantID := uuid.New()
	stream := &models.SSFStream{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Audience:        []string{"https://rp.test"},
		DeliveryMethod:  models.SSFDeliveryPush,
		PushEndpointURL: caepStrPtr(srv.URL),
		Status:          models.SSFStreamPaused,
		EventsRequested: []models.SSFEventType{models.CAEPSessionRevoked},
	}
	em, _ := newEmitterFixture(t, []*models.SSFStream{stream})

	n := em.EmitSessionRevoked(context.Background(), tenantID, uuid.New(), "test")
	if n != 0 {
		t.Errorf("paused stream should not deliver, got %d", n)
	}
	if pinged {
		t.Errorf("paused stream receiver should NOT be called")
	}
}

func TestEmit_SkipsInboundStream(t *testing.T) {
	pinged := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pinged = true
	}))
	defer srv.Close()

	tenantID := uuid.New()
	stream := &models.SSFStream{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Audience:        []string{"https://rp.test"},
		DeliveryMethod:  models.SSFDeliveryPush,
		PushEndpointURL: caepStrPtr(srv.URL),
		Status:          models.SSFStreamEnabled,
		IsInbound:       true, // Falcon-ID is receiving from external, not transmitting
	}
	em, _ := newEmitterFixture(t, []*models.SSFStream{stream})

	n := em.EmitSessionRevoked(context.Background(), tenantID, uuid.New(), "test")
	if n != 0 {
		t.Errorf("inbound stream should not receive transmitter output, got %d", n)
	}
	if pinged {
		t.Errorf("inbound stream's URL should NOT be called")
	}
}

func TestEmit_SkipsPollOnlyStream(t *testing.T) {
	pinged := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pinged = true
	}))
	defer srv.Close()

	tenantID := uuid.New()
	stream := &models.SSFStream{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Audience:        []string{"https://rp.test"},
		DeliveryMethod:  models.SSFDeliveryPoll, // not push
		PushEndpointURL: caepStrPtr(srv.URL),
		Status:          models.SSFStreamEnabled,
	}
	em, _ := newEmitterFixture(t, []*models.SSFStream{stream})

	n := em.EmitSessionRevoked(context.Background(), tenantID, uuid.New(), "test")
	if n != 0 {
		t.Errorf("poll stream should not get push, got %d", n)
	}
	if pinged {
		t.Errorf("poll-only stream URL should NOT be pushed to")
	}
}

func TestEmit_RespectsEventsRequested(t *testing.T) {
	pinged := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pinged = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tenantID := uuid.New()
	stream := &models.SSFStream{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Audience:        []string{"https://rp.test"},
		DeliveryMethod:  models.SSFDeliveryPush,
		PushEndpointURL: caepStrPtr(srv.URL),
		Status:          models.SSFStreamEnabled,
		EventsRequested: []models.SSFEventType{models.CAEPCredentialChange}, // not session-revoked
	}
	em, _ := newEmitterFixture(t, []*models.SSFStream{stream})

	n := em.EmitSessionRevoked(context.Background(), tenantID, uuid.New(), "test")
	if n != 0 {
		t.Errorf("non-matching event should not deliver, got %d", n)
	}
	if pinged {
		t.Errorf("non-matching event should not call receiver")
	}
}

func TestEmit_EmptyEventsRequested_DeliversAll(t *testing.T) {
	pinged := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pinged++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tenantID := uuid.New()
	// EventsRequested empty = all events
	stream := &models.SSFStream{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Audience:        []string{"https://rp.test"},
		DeliveryMethod:  models.SSFDeliveryPush,
		PushEndpointURL: caepStrPtr(srv.URL),
		Status:          models.SSFStreamEnabled,
	}
	em, _ := newEmitterFixture(t, []*models.SSFStream{stream})

	em.EmitSessionRevoked(context.Background(), tenantID, uuid.New(), "test")
	em.EmitCredentialChange(context.Background(), tenantID, uuid.New(), "password", "update", "test")
	if pinged != 2 {
		t.Errorf("empty events_requested should deliver all event types, got %d/2", pinged)
	}
}

func TestEmit_ContinuesOnReceiverError(t *testing.T) {
	// First receiver 500, second 202 — verify iteration doesn't bail
	// on first failure.
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srvBad.Close()
	good := false
	srvGood := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		good = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srvGood.Close()

	tenantID := uuid.New()
	streams := []*models.SSFStream{
		{
			ID:              uuid.New(),
			TenantID:        tenantID,
			Audience:        []string{"https://bad.test"},
			DeliveryMethod:  models.SSFDeliveryPush,
			PushEndpointURL: caepStrPtr(srvBad.URL),
			Status:          models.SSFStreamEnabled,
		},
		{
			ID:              uuid.New(),
			TenantID:        tenantID,
			Audience:        []string{"https://good.test"},
			DeliveryMethod:  models.SSFDeliveryPush,
			PushEndpointURL: caepStrPtr(srvGood.URL),
			Status:          models.SSFStreamEnabled,
		},
	}
	em, _ := newEmitterFixture(t, streams)
	n := em.EmitSessionRevoked(context.Background(), tenantID, uuid.New(), "test")
	if n != 1 {
		t.Errorf("expected 1 successful delivery (1 receiver 5xx'd), got %d", n)
	}
	if !good {
		t.Errorf("second receiver should still have been called after first failed")
	}
}

func TestEmit_ActiveKeyFailure_NoDeliveries(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	defer srv.Close()

	tenantID := uuid.New()
	stream := &models.SSFStream{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Audience:        []string{"https://rp.test"},
		DeliveryMethod:  models.SSFDeliveryPush,
		PushEndpointURL: caepStrPtr(srv.URL),
		Status:          models.SSFStreamEnabled,
	}
	repo := &stubSSFRepo{streams: []*models.SSFStream{stream}}
	em, err := NewCAEPEmitter(
		CAEPEmitterConfig{Issuer: "https://id.test/"},
		repo,
		&stubKeyProvider{err: errors.New("kms down")},
		zap.NewNop(),
	)
	if err != nil {
		t.Fatalf("NewCAEPEmitter: %v", err)
	}
	n := em.EmitSessionRevoked(context.Background(), tenantID, uuid.New(), "test")
	if n != 0 {
		t.Errorf("ActiveKey failure should yield 0 deliveries, got %d", n)
	}
	if called {
		t.Errorf("receiver should not be reached when signing fails")
	}
}

func TestEmit_MultiAudArray(t *testing.T) {
	var receivedJWT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedJWT = string(b)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tenantID := uuid.New()
	stream := &models.SSFStream{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Audience:        []string{"https://rp1.test", "https://rp2.test"},
		DeliveryMethod:  models.SSFDeliveryPush,
		PushEndpointURL: caepStrPtr(srv.URL),
		Status:          models.SSFStreamEnabled,
	}
	em, keys := newEmitterFixture(t, []*models.SSFStream{stream})
	em.EmitSessionRevoked(context.Background(), tenantID, uuid.New(), "test")
	parsed, _ := jwt.Parse(receivedJWT, func(_ *jwt.Token) (interface{}, error) {
		return &keys.key.PublicKey, nil
	})
	claims := parsed.Claims.(jwt.MapClaims)
	aud, ok := claims["aud"].([]interface{})
	if !ok {
		t.Fatalf("multi-aud should serialize as array, got %T: %v", claims["aud"], claims["aud"])
	}
	if len(aud) != 2 {
		t.Errorf("expected 2 aud entries, got %d", len(aud))
	}
}

func TestEmitCredentialChange_Shape(t *testing.T) {
	var receivedJWT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedJWT = string(b)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tenantID := uuid.New()
	userID := uuid.New()
	stream := &models.SSFStream{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Audience:        []string{"https://rp.test"},
		DeliveryMethod:  models.SSFDeliveryPush,
		PushEndpointURL: caepStrPtr(srv.URL),
		Status:          models.SSFStreamEnabled,
	}
	em, keys := newEmitterFixture(t, []*models.SSFStream{stream})

	n := em.EmitCredentialChange(context.Background(), tenantID, userID, "password", "update", "rotated")
	if n != 1 {
		t.Fatalf("expected 1 delivery, got %d", n)
	}
	parsed, _ := jwt.Parse(receivedJWT, func(_ *jwt.Token) (interface{}, error) {
		return &keys.key.PublicKey, nil
	})
	claims := parsed.Claims.(jwt.MapClaims)
	events := claims["events"].(map[string]interface{})
	payload, ok := events[string(models.CAEPCredentialChange)].(map[string]interface{})
	if !ok {
		t.Fatalf("expected credential-change event, got: %v", events)
	}
	if payload["credential_type"] != "password" {
		t.Errorf("credential_type: %v", payload["credential_type"])
	}
	if payload["change_type"] != "update" {
		t.Errorf("change_type: %v", payload["change_type"])
	}
}

func TestEmit_NoStreamsForTenant(t *testing.T) {
	em, _ := newEmitterFixture(t, nil)
	n := em.EmitSessionRevoked(context.Background(), uuid.New(), uuid.New(), "test")
	if n != 0 {
		t.Errorf("no streams for tenant → 0 deliveries, got %d", n)
	}
}

func TestEmit_HonorsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tenantID := uuid.New()
	stream := &models.SSFStream{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Audience:        []string{"https://rp.test"},
		DeliveryMethod:  models.SSFDeliveryPush,
		PushEndpointURL: caepStrPtr(srv.URL),
		Status:          models.SSFStreamEnabled,
	}
	em, _ := newEmitterFixture(t, []*models.SSFStream{stream})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	// Just ensure no panic / no leak — return value is non-deterministic
	// under tight deadlines.
	_ = em.EmitSessionRevoked(ctx, tenantID, uuid.New(), "test")
}
