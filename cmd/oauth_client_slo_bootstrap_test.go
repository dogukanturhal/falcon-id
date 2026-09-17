// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// TestMain installs a no-op zap logger before running tests in this
// package. The boot-hook calls logger.Info / logger.Warn / logger.Error
// which dereference logger.Log; production sets Log via InitLogger
// during `main()`, but tests skip that path.
func TestMain(m *testing.M) {
	logger.Log = zap.NewNop()
	os.Exit(m.Run())
}

// mockSeedRepo satisfies oauthClientSeedRepo for the boot-hook tests.
type mockSeedRepo struct {
	mock.Mock
}

func (m *mockSeedRepo) GetByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error) {
	args := m.Called(ctx, clientID)
	row, _ := args.Get(0).(*models.OAuthClient)
	return row, args.Error(1)
}

func (m *mockSeedRepo) Update(ctx context.Context, client *models.OAuthClient) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

// newSvcTalonRowAtSteady returns the OAuthClient row that
// applyOAuthClientSLODesired would converge on for svc-talon —
// matching the matrix exactly. Used to assert idempotency.
func newSvcTalonRowAtSteady() *models.OAuthClient {
	bcl := "https://internal.example.com/auth/backchannel-logout"
	fcl := "https://internal.example.com/auth/frontchannel-logout"
	return &models.OAuthClient{
		ID:                                uuid.New(),
		ClientID:                          "svc-talon",
		BackchannelLogoutURI:              &bcl,
		BackchannelLogoutSessionRequired:  true,
		FrontchannelLogoutURI:             &fcl,
		FrontchannelLogoutSessionRequired: true,
		AccessTokenLifetime:               900,
		IDTokenLifetime:                   900,
		RefreshTokenLifetime:              28800,
	}
}

// newPreSeedRow returns a row matching the audit-baseline state — a
// freshly-provisioned svc-* row with NULL BCL/FCL URIs and the
// bootstrap default 3600/3600/2592000 lifetimes (the values the
// per-service Crossplane Composition emits today).
func newPreSeedRow(clientID string) *models.OAuthClient {
	return &models.OAuthClient{
		ID:                   uuid.New(),
		ClientID:             clientID,
		AccessTokenLifetime:  3600,
		IDTokenLifetime:      3600,
		RefreshTokenLifetime: 2592000,
	}
}

// TestApplyOAuthClientSLODesired_FirstRunPatchesEverything verifies that
// running the seed against a fresh-from-Crossplane row patches BCL/FCL
// URIs + session_required + admin TTLs.
func TestApplyOAuthClientSLODesired_FirstRunPatchesEverything(t *testing.T) {
	repo := new(mockSeedRepo)
	pre := newPreSeedRow("svc-talon")

	repo.On("GetByClientID", mock.Anything, "svc-talon").Return(pre, nil).Once()
	repo.On("Update", mock.Anything, mock.MatchedBy(func(c *models.OAuthClient) bool {
		// Update SHOULD be called with the patched row. Assert all
		// load-bearing fields converged.
		require.NotNil(t, c.BackchannelLogoutURI, "BCL URI must be patched")
		require.NotNil(t, c.FrontchannelLogoutURI, "FCL URI must be patched")
		assert.Equal(t, "https://internal.example.com/auth/backchannel-logout", *c.BackchannelLogoutURI)
		assert.Equal(t, "https://internal.example.com/auth/frontchannel-logout", *c.FrontchannelLogoutURI)
		assert.True(t, c.BackchannelLogoutSessionRequired)
		assert.True(t, c.FrontchannelLogoutSessionRequired)
		assert.Equal(t, 900, c.AccessTokenLifetime)
		assert.Equal(t, 900, c.IDTokenLifetime)
		assert.Equal(t, 28800, c.RefreshTokenLifetime)
		return true
	})).Return(nil).Once()

	desired := matrixEntryByClientID(t, "svc-talon")
	applyOAuthClientSLODesired(context.Background(), repo, desired)

	repo.AssertExpectations(t)
}

// TestApplyOAuthClientSLODesired_IdempotentSecondRun verifies that
// calling against an already-converged row does NOT issue an Update.
// This is THE load-bearing property of the boot hook: pod restarts
// must not trigger spurious writes that pollute updated_at and inflate
// audit logs.
func TestApplyOAuthClientSLODesired_IdempotentSecondRun(t *testing.T) {
	repo := new(mockSeedRepo)
	steady := newSvcTalonRowAtSteady()

	repo.On("GetByClientID", mock.Anything, "svc-talon").Return(steady, nil).Once()
	// Critically: NO Update expectation. mock.AssertNotCalled would also
	// work but mockery's default behaviour is to fail on unexpected
	// invocations, which is what we want.

	desired := matrixEntryByClientID(t, "svc-talon")
	applyOAuthClientSLODesired(context.Background(), repo, desired)

	repo.AssertExpectations(t)
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
}

// TestApplyOAuthClientSLODesired_MissingRowSkipsSilently verifies that
// when GetByClientID returns ErrOAuthClientNotFound (e.g., the
// per-service Crossplane Job has not yet provisioned the client) the
// boot hook does NOT call Update — the row's creation is owned
// elsewhere.
func TestApplyOAuthClientSLODesired_MissingRowSkipsSilently(t *testing.T) {
	repo := new(mockSeedRepo)
	repo.On("GetByClientID", mock.Anything, "svc-vault").Return(nil, repositories.ErrOAuthClientNotFound).Once()

	desired := matrixEntryByClientID(t, "svc-vault")
	applyOAuthClientSLODesired(context.Background(), repo, desired)

	repo.AssertExpectations(t)
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
}

// TestApplyOAuthClientSLODesired_TransientErrorSkipsClient verifies
// non-NotFound errors short-circuit the per-client path without
// blocking subsequent matrix entries (the loop in
// bootstrapOAuthClientSLOSeed).
func TestApplyOAuthClientSLODesired_TransientErrorSkipsClient(t *testing.T) {
	repo := new(mockSeedRepo)
	repo.On("GetByClientID", mock.Anything, "svc-talon").Return(nil, errors.New("connection refused")).Once()

	desired := matrixEntryByClientID(t, "svc-talon")
	applyOAuthClientSLODesired(context.Background(), repo, desired)

	repo.AssertExpectations(t)
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
}

// TestApplyOAuthClientSLODesired_AdminTierTTLOnlyClientPatchesLifetimesNotURIs
// verifies matrix entries for Talon-fronted dual-RP apps without
// upstream BCL receivers (svc-argocd, svc-grafana, svc-awx, svc-dojo,
// svc-sonarqube, svc-vault) only patch token lifetimes — the BCL/FCL
// URI columns stay NULL because seeding URIs on RPs without shipping
// receivers would generate permanent client_error metrics.
func TestApplyOAuthClientSLODesired_AdminTierTTLOnlyClientPatchesLifetimesNotURIs(t *testing.T) {
	repo := new(mockSeedRepo)
	pre := newPreSeedRow("svc-grafana")

	repo.On("GetByClientID", mock.Anything, "svc-grafana").Return(pre, nil).Once()
	repo.On("Update", mock.Anything, mock.MatchedBy(func(c *models.OAuthClient) bool {
		assert.Nil(t, c.BackchannelLogoutURI, "BCL URI must remain NULL — no upstream receiver")
		assert.Nil(t, c.FrontchannelLogoutURI, "FCL URI must remain NULL — no upstream receiver")
		assert.Equal(t, 900, c.AccessTokenLifetime)
		assert.Equal(t, 900, c.IDTokenLifetime)
		assert.Equal(t, 28800, c.RefreshTokenLifetime)
		return true
	})).Return(nil).Once()

	desired := matrixEntryByClientID(t, "svc-grafana")
	applyOAuthClientSLODesired(context.Background(), repo, desired)

	repo.AssertExpectations(t)
}

// TestApplyOAuthClientSLODesired_GitLabHarborPatchBCLViaShim verifies
// svc-gitlab and svc-harbor get cluster-internal BCL URIs pointing at
// the platform-tools/bcl-receiver shims (which translate logout_token
// POSTs into upstream admin-API calls). FCL stays NULL — the shim is
// a server endpoint, not an iframe target.
func TestApplyOAuthClientSLODesired_GitLabHarborPatchBCLViaShim(t *testing.T) {
	for _, clientID := range []string{"svc-gitlab", "svc-harbor"} {
		t.Run(clientID, func(t *testing.T) {
			repo := new(mockSeedRepo)
			pre := newPreSeedRow(clientID)

			repo.On("GetByClientID", mock.Anything, clientID).Return(pre, nil).Once()
			repo.On("Update", mock.Anything, mock.MatchedBy(func(c *models.OAuthClient) bool {
				require.NotNil(t, c.BackchannelLogoutURI, "BCL URI must point at the in-cluster shim")
				assert.Contains(t, *c.BackchannelLogoutURI, "bcl-receiver.svc.cluster.local:8080/backchannel-logout")
				assert.True(t, c.BackchannelLogoutSessionRequired, "session_required must be true so OP emits sid")
				assert.Nil(t, c.FrontchannelLogoutURI, "FCL stays NULL — shim is server-only, not iframe-rendered")
				assert.Equal(t, 900, c.AccessTokenLifetime)
				return true
			})).Return(nil).Once()

			desired := matrixEntryByClientID(t, clientID)
			applyOAuthClientSLODesired(context.Background(), repo, desired)

			repo.AssertExpectations(t)
		})
	}
}

// TestMergeSLODesiredZeroLifetimePreservesExisting verifies that a zero
// in desired.AccessTokenLifetime does NOT overwrite a non-zero existing
// value — used as the "do not enforce" sentinel in the matrix for
// fields that should preserve whatever the operator has set.
func TestMergeSLODesiredZeroLifetimePreservesExisting(t *testing.T) {
	row := &models.OAuthClient{AccessTokenLifetime: 7200, IDTokenLifetime: 1800, RefreshTokenLifetime: 0}
	desired := oauthClientSLOSeedDesired{
		ClientID:             "test-client",
		AccessTokenLifetime:  0, // should NOT overwrite
		IDTokenLifetime:      0, // should NOT overwrite
		RefreshTokenLifetime: 0, // should NOT overwrite (target already 0)
	}
	changed := mergeSLODesired(row, desired)
	assert.False(t, changed, "zero desired lifetimes must not flag a change")
	assert.Equal(t, 7200, row.AccessTokenLifetime)
	assert.Equal(t, 1800, row.IDTokenLifetime)
	assert.Equal(t, 0, row.RefreshTokenLifetime)
}

// TestEqualStringPtr exercises the nil-aware comparison helper.
func TestEqualStringPtr(t *testing.T) {
	cases := []struct {
		name string
		a, b *string
		want bool
	}{
		{"both-nil", nil, nil, true},
		{"a-nil-only", nil, stringPtr("x"), false},
		{"b-nil-only", stringPtr("x"), nil, false},
		{"both-non-nil-equal", stringPtr("x"), stringPtr("x"), true},
		{"both-non-nil-different", stringPtr("x"), stringPtr("y"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, equalStringPtr(tc.a, tc.b))
		})
	}
}

// TestSLOSeedMatrixURIShapeConformance asserts every URI in the matrix
// parses cleanly — guards against typos that would crash the FCL
// iframe spec §3 query rebuild (frontchannel_logout_service.go:135).
//
// Internet-reachable URIs MUST be HTTPS (per OIDC spec §2). Cluster-
// internal `*.svc.cluster.local` URIs are allowed to be HTTP because
// Linkerd mTLS encrypts the wire at the mesh layer regardless of the
// URL scheme — these are server-to-server cluster-internal hops, not
// browser-facing endpoints.
func TestSLOSeedMatrixURIShapeConformance(t *testing.T) {
	for _, e := range oauthClientSLOSeedMatrix {
		t.Run(e.ClientID, func(t *testing.T) {
			for _, ptr := range []*string{e.BackchannelLogoutURI, e.FrontchannelLogoutURI} {
				if ptr == nil {
					continue // RPs without upstream receivers leave nil intentionally
				}
				u := *ptr
				parsed, err := url.Parse(u)
				require.NoError(t, err, "URI must parse: %s", u)
				assert.NotEmpty(t, parsed.Host, "URI must have a host: %s", u)
				assert.NotEmpty(t, parsed.Path, "URI must have a path: %s", u)
				assert.NotContains(t, u, " ", "URI must not contain spaces: %s", u)
				// Scheme must be http or https; http only allowed for
				// cluster-internal hops where Linkerd mTLS terminates.
				switch parsed.Scheme {
				case "https":
					// Always allowed for any host.
				case "http":
					assert.True(t,
						strings.HasSuffix(parsed.Host, ".svc.cluster.local") ||
							strings.HasSuffix(parsed.Host, ".svc.cluster.local:8080"),
						"http scheme only allowed for *.svc.cluster.local (mesh-protected): %s", u,
					)
				default:
					t.Errorf("unsupported URI scheme %q in %s", parsed.Scheme, u)
				}
			}
		})
	}
}

// TestSLOSeedMatrixCovers expected ensures the matrix isn't accidentally
// reduced below the platform's known first-party clients. If a client
// is intentionally removed, update this test alongside the matrix.
func TestSLOSeedMatrixCoversExpectedClients(t *testing.T) {
	expected := []string{
		"svc-talon", "svc-accounts",
		"svc-argocd", "svc-grafana", "svc-awx", "svc-dojo", "svc-sonarqube", "svc-vault",
		"svc-gitlab", "svc-harbor",
		"svc-integration-bus",
	}
	got := make(map[string]bool)
	for _, e := range oauthClientSLOSeedMatrix {
		got[e.ClientID] = true
	}
	for _, want := range expected {
		assert.True(t, got[want], "matrix missing expected client: %s", want)
	}
}

// matrixEntryByClientID is a test helper that returns the matrix row
// for a given client_id — bails the test if absent.
func matrixEntryByClientID(t *testing.T, clientID string) oauthClientSLOSeedDesired {
	t.Helper()
	for _, e := range oauthClientSLOSeedMatrix {
		if e.ClientID == clientID {
			return e
		}
	}
	t.Fatalf("matrix has no entry for client_id=%s", clientID)
	return oauthClientSLOSeedDesired{}
}
