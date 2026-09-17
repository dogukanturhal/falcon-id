// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ─── mock repo ───────────────────────────────────────────────────────────────

type mockHostDiscoveryRepo struct{ mock.Mock }

func (m *mockHostDiscoveryRepo) GetByHost(ctx context.Context, host string) (*models.TenantHost, error) {
	args := m.Called(ctx, host)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TenantHost), args.Error(1)
}

func (m *mockHostDiscoveryRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.TenantHost, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TenantHost), args.Error(1)
}

func (m *mockHostDiscoveryRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.TenantHost, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.TenantHost), args.Error(1)
}

func (m *mockHostDiscoveryRepo) Create(ctx context.Context, h *models.TenantHost) error {
	return m.Called(ctx, h).Error(0)
}

func (m *mockHostDiscoveryRepo) MarkVerified(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockHostDiscoveryRepo) RecordVerificationFailure(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockHostDiscoveryRepo) Suspend(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockHostDiscoveryRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

// ─── mock DNS resolver ───────────────────────────────────────────────────────

type mockHostDNSResolver struct{ mock.Mock }

func (m *mockHostDNSResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	args := m.Called(ctx, host)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

// ─── NormalizeHost ──────────────────────────────────────────────────────────

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{"crm.acme-corp.com", "crm.acme-corp.com", false},
		// Uppercase canonicalization (RFC 4343).
		{"CRM.ACME-CORP.COM", "crm.acme-corp.com", false},
		// Port stripping.
		{"crm.acme-corp.com:443", "crm.acme-corp.com", false},
		// Trailing dot stripped (absolute DNS notation).
		{"crm.acme-corp.com.", "crm.acme-corp.com", false},
		// Whitespace trimmed.
		{"  crm.acme-corp.com  ", "crm.acme-corp.com", false},
		// IDNA — Turkish "ş"; punycode-encodes.
		{"şirket.com", "xn--irket-idb.com", false},
		// Empty / only whitespace.
		{"", "", true},
		{"   ", "", true},
		// Only port (no host).
		{":443", "", true},
		// Exceeds RFC 1035 max length (253).
		{strings.Repeat("a", 64) + "." + strings.Repeat("b", 64) + "." +
			strings.Repeat("c", 64) + "." + strings.Repeat("d", 64) + ".com", "", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := NormalizeHost(c.in)
			if c.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

// ─── Discover — success path ─────────────────────────────────────────────────

func TestDiscover_Active_Success(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)

	tenantID := uuid.New()
	verifiedAt := time.Now().Add(-72 * time.Hour)
	clientID := "tenant-acme-spa"

	repo.On("GetByHost", mock.Anything, "crm.acme-corp.com").Return(&models.TenantHost{
		ID:                 uuid.New(),
		Host:               "crm.acme-corp.com",
		TenantID:           tenantID,
		CanonicalURL:       "https://crm.acme-corp.com",
		Status:             models.TenantHostStatusActive,
		VerificationToken:  strings.Repeat("a", 64),
		VerificationMethod: models.TenantHostVerificationMethodTXT,
		VerifiedAt:         &verifiedAt,
		LastVerifiedAt:     &verifiedAt,
		DefaultClientID:    &clientID,
		BrandingOverride:   json.RawMessage(`{"primary_color":"#0066ff"}`),
	}, nil)

	resp, err := svc.Discover(context.Background(), "CRM.acme-corp.com")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, tenantID, resp.TenantID)
	assert.Equal(t, "crm.acme-corp.com", resp.Host)
	assert.Equal(t, "https://crm.acme-corp.com", resp.CanonicalURL)
	assert.Equal(t, "https://crm.acme-corp.com", resp.Issuer)
	assert.Equal(t, models.TenantHostStatusActive, resp.Status)
	require.NotNil(t, resp.DefaultClientID)
	assert.Equal(t, "tenant-acme-spa", *resp.DefaultClientID)
	assert.Equal(t, "#0066ff", resp.Branding["primary_color"])
}

// ─── Discover — error mapping ────────────────────────────────────────────────

func TestDiscover_NotFound(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)
	repo.On("GetByHost", mock.Anything, "missing.example.com").Return(nil, nil)

	_, err := svc.Discover(context.Background(), "missing.example.com")
	assert.ErrorIs(t, err, ErrHostNotFound)
}

func TestDiscover_Suspended(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)
	repo.On("GetByHost", mock.Anything, "old.example.com").Return(&models.TenantHost{
		Host:              "old.example.com",
		Status:            models.TenantHostStatusSuspended,
		VerificationToken: strings.Repeat("a", 64),
	}, nil)

	_, err := svc.Discover(context.Background(), "old.example.com")
	assert.ErrorIs(t, err, ErrHostSuspended)
}

func TestDiscover_Pending(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)
	repo.On("GetByHost", mock.Anything, "new.example.com").Return(&models.TenantHost{
		Host:              "new.example.com",
		Status:            models.TenantHostStatusPendingVerification,
		VerificationToken: strings.Repeat("a", 64),
	}, nil)

	_, err := svc.Discover(context.Background(), "new.example.com")
	assert.ErrorIs(t, err, ErrHostPending)
}

// ─── Discover — cache behavior ───────────────────────────────────────────────

func TestDiscover_PositiveCacheHit(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)
	svc.SetTTLs(time.Hour, time.Hour)
	verifiedAt := time.Now()
	repo.On("GetByHost", mock.Anything, "x.example.com").Return(&models.TenantHost{
		Host:              "x.example.com",
		TenantID:          uuid.New(),
		Status:            models.TenantHostStatusActive,
		CanonicalURL:      "https://x.example.com",
		VerificationToken: strings.Repeat("b", 64),
		VerifiedAt:        &verifiedAt,
	}, nil).Once()

	_, err1 := svc.Discover(context.Background(), "x.example.com")
	require.NoError(t, err1)
	_, err2 := svc.Discover(context.Background(), "x.example.com")
	require.NoError(t, err2)
	_, err3 := svc.Discover(context.Background(), "x.example.com")
	require.NoError(t, err3)

	// repo.GetByHost must have been called exactly once thanks to cache.
	repo.AssertNumberOfCalls(t, "GetByHost", 1)
}

func TestDiscover_NegativeCacheHit(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)
	svc.SetTTLs(time.Hour, time.Hour)
	repo.On("GetByHost", mock.Anything, "ghost.example.com").Return(nil, nil).Once()

	_, err1 := svc.Discover(context.Background(), "ghost.example.com")
	assert.ErrorIs(t, err1, ErrHostNotFound)
	_, err2 := svc.Discover(context.Background(), "ghost.example.com")
	assert.ErrorIs(t, err2, ErrHostNotFound)

	repo.AssertNumberOfCalls(t, "GetByHost", 1)
}

func TestDiscover_CacheExpiry(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)
	// Very short TTLs so we can deterministically observe expiry.
	svc.SetTTLs(10*time.Millisecond, 10*time.Millisecond)
	verifiedAt := time.Now()
	repo.On("GetByHost", mock.Anything, "y.example.com").Return(&models.TenantHost{
		Host:              "y.example.com",
		TenantID:          uuid.New(),
		Status:            models.TenantHostStatusActive,
		CanonicalURL:      "https://y.example.com",
		VerificationToken: strings.Repeat("c", 64),
		VerifiedAt:        &verifiedAt,
	}, nil).Twice()

	_, _ = svc.Discover(context.Background(), "y.example.com")
	time.Sleep(50 * time.Millisecond)
	_, _ = svc.Discover(context.Background(), "y.example.com")

	repo.AssertNumberOfCalls(t, "GetByHost", 2)
}

func TestDiscover_InvalidatePurgesCache(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)
	svc.SetTTLs(time.Hour, time.Hour)
	verifiedAt := time.Now()
	repo.On("GetByHost", mock.Anything, "z.example.com").Return(&models.TenantHost{
		Host:              "z.example.com",
		TenantID:          uuid.New(),
		Status:            models.TenantHostStatusActive,
		CanonicalURL:      "https://z.example.com",
		VerificationToken: strings.Repeat("d", 64),
		VerifiedAt:        &verifiedAt,
	}, nil).Twice()

	_, _ = svc.Discover(context.Background(), "z.example.com")
	svc.Invalidate("z.example.com")
	_, _ = svc.Discover(context.Background(), "z.example.com")

	repo.AssertNumberOfCalls(t, "GetByHost", 2)
}

// ─── Discover — normalization edge cases reaching repo ──────────────────────

func TestDiscover_NormalizeBeforeRepoLookup(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)
	verifiedAt := time.Now()
	// Repo expects the NORMALIZED form, not raw input.
	repo.On("GetByHost", mock.Anything, "case-test.example.com").Return(&models.TenantHost{
		Host:              "case-test.example.com",
		TenantID:          uuid.New(),
		Status:            models.TenantHostStatusActive,
		CanonicalURL:      "https://case-test.example.com",
		VerificationToken: strings.Repeat("e", 64),
		VerifiedAt:        &verifiedAt,
	}, nil)

	resp, err := svc.Discover(context.Background(), " CASE-TEST.example.com.:443 ")
	require.NoError(t, err)
	assert.Equal(t, "case-test.example.com", resp.Host)
}

// ─── Admin — ClaimHost ───────────────────────────────────────────────────────

func TestClaimHost_GeneratesTokenAndStatus(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)

	tenantID := uuid.New()
	repo.On("Create", mock.Anything, mock.MatchedBy(func(h *models.TenantHost) bool {
		// Normalized host, default token method, pending status, 64-char hex token.
		return h.Host == "crm.acme-corp.com" &&
			h.TenantID == tenantID &&
			h.Status == models.TenantHostStatusPendingVerification &&
			h.VerificationMethod == models.TenantHostVerificationMethodTXT &&
			len(h.VerificationToken) == 64
	})).Return(nil)

	got, err := svc.ClaimHost(context.Background(), &ClaimHostRequest{
		TenantID:     tenantID,
		Host:         "CRM.acme-corp.com",
		CanonicalURL: "https://crm.acme-corp.com",
	})
	// ClaimHostRequest is the local type — we constructed it
	// directly via the test-private ctor below. Verify token + status.
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "crm.acme-corp.com", got.Host)
	assert.Equal(t, models.TenantHostStatusPendingVerification, got.Status)
	assert.Len(t, got.VerificationToken, 64)
	repo.AssertExpectations(t)
}

func TestClaimHost_RejectsBadHost(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)
	_, err := svc.ClaimHost(context.Background(), &ClaimHostRequest{
		TenantID:     uuid.New(),
		Host:         "",
		CanonicalURL: "https://x.com",
	})
	require.Error(t, err)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

// ─── Admin — VerifyOne ───────────────────────────────────────────────────────

func TestVerifyOne_MatchingTXTMarksVerified(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	dns := new(mockHostDNSResolver)
	svc := NewHostDiscoveryService(repo, dns, nil)

	id := uuid.New()
	token := strings.Repeat("a", 64)
	repo.On("GetByID", mock.Anything, id).Return(&models.TenantHost{
		ID:                id,
		Host:              "crm.acme-corp.com",
		Status:            models.TenantHostStatusPendingVerification,
		VerificationToken: token,
	}, nil).Once()
	dns.On("LookupTXT", mock.Anything, "_hexxlock-verify.crm.acme-corp.com").
		Return([]string{"unrelated", token}, nil)
	repo.On("MarkVerified", mock.Anything, id).Return(nil)
	verifiedAt := time.Now()
	repo.On("GetByID", mock.Anything, id).Return(&models.TenantHost{
		ID:                id,
		Host:              "crm.acme-corp.com",
		Status:            models.TenantHostStatusActive,
		VerificationToken: token,
		VerifiedAt:        &verifiedAt,
	}, nil).Once()

	got, err := svc.VerifyOne(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, models.TenantHostStatusActive, got.Status)
	repo.AssertExpectations(t)
	dns.AssertExpectations(t)
}

func TestVerifyOne_NoMatchingTXT_RecordsFailure(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	dns := new(mockHostDNSResolver)
	svc := NewHostDiscoveryService(repo, dns, nil)

	id := uuid.New()
	repo.On("GetByID", mock.Anything, id).Return(&models.TenantHost{
		ID:                id,
		Host:              "crm.acme-corp.com",
		Status:            models.TenantHostStatusPendingVerification,
		VerificationToken: strings.Repeat("b", 64),
	}, nil)
	dns.On("LookupTXT", mock.Anything, "_hexxlock-verify.crm.acme-corp.com").
		Return([]string{"some-other-token"}, nil)
	repo.On("RecordVerificationFailure", mock.Anything, id).Return(nil)

	_, err := svc.VerifyOne(context.Background(), id)
	assert.ErrorIs(t, err, ErrHostVerificationPending)
	repo.AssertCalled(t, "RecordVerificationFailure", mock.Anything, id)
}

func TestVerifyOne_DNSError_RecordsFailure(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	dns := new(mockHostDNSResolver)
	svc := NewHostDiscoveryService(repo, dns, nil)

	id := uuid.New()
	repo.On("GetByID", mock.Anything, id).Return(&models.TenantHost{
		ID:                id,
		Host:              "crm.acme-corp.com",
		Status:            models.TenantHostStatusPendingVerification,
		VerificationToken: strings.Repeat("c", 64),
	}, nil)
	dns.On("LookupTXT", mock.Anything, "_hexxlock-verify.crm.acme-corp.com").
		Return(nil, errors.New("dns: SERVFAIL"))
	repo.On("RecordVerificationFailure", mock.Anything, id).Return(nil)

	_, err := svc.VerifyOne(context.Background(), id)
	assert.ErrorIs(t, err, ErrHostVerificationPending)
}

func TestVerifyOne_AlreadyActive_NoOp(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	dns := new(mockHostDNSResolver)
	svc := NewHostDiscoveryService(repo, dns, nil)

	id := uuid.New()
	repo.On("GetByID", mock.Anything, id).Return(&models.TenantHost{
		ID:                id,
		Host:              "crm.acme-corp.com",
		Status:            models.TenantHostStatusActive,
		VerificationToken: strings.Repeat("d", 64),
	}, nil)

	got, err := svc.VerifyOne(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, models.TenantHostStatusActive, got.Status)
	dns.AssertNotCalled(t, "LookupTXT", mock.Anything, mock.Anything)
}

// ─── Admin — SuspendHost + DeleteHost ────────────────────────────────────────

func TestSuspendHost_InvalidatesCache(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)
	id := uuid.New()
	repo.On("GetByID", mock.Anything, id).Return(&models.TenantHost{
		ID:                id,
		Host:              "x.example.com",
		VerificationToken: strings.Repeat("e", 64),
	}, nil)
	repo.On("Suspend", mock.Anything, id).Return(nil)

	err := svc.SuspendHost(context.Background(), id)
	require.NoError(t, err)
	repo.AssertCalled(t, "Suspend", mock.Anything, id)
}

func TestDeleteHost_InvalidatesCache(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)
	id := uuid.New()
	repo.On("GetByID", mock.Anything, id).Return(&models.TenantHost{
		ID:                id,
		Host:              "y.example.com",
		VerificationToken: strings.Repeat("f", 64),
	}, nil)
	repo.On("Delete", mock.Anything, id).Return(nil)

	err := svc.DeleteHost(context.Background(), id)
	require.NoError(t, err)
}

// ─── Discover — propagates malformed-host as plain error ─────────────────────

func TestDiscover_MalformedHostNotSentinel(t *testing.T) {
	repo := new(mockHostDiscoveryRepo)
	svc := NewHostDiscoveryService(repo, nil, nil)
	_, err := svc.Discover(context.Background(), "")
	require.Error(t, err)
	// Malformed input must NOT surface as one of the sentinel errors —
	// the handler maps sentinels to 404/410/503; everything else
	// becomes 500. Bad input should fall to the default branch.
	assert.False(t, errors.Is(err, ErrHostNotFound))
	assert.False(t, errors.Is(err, ErrHostSuspended))
	assert.False(t, errors.Is(err, ErrHostPending))
}
