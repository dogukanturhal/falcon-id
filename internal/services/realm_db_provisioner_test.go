// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Unit tests for pure helper functions
// ---------------------------------------------------------------------------

func TestSanitizeSlug(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "lowercase passthrough",
			input: "acme",
			want:  "acme",
		},
		{
			name:  "dashes converted to underscores",
			input: "acme-corp",
			want:  "acme_corp",
		},
		{
			name:  "uppercase lowercased",
			input: "AcmeCorp",
			want:  "acmecorp",
		},
		{
			name:  "mixed dashes and uppercase",
			input: "My-Enterprise-Realm",
			want:  "my_enterprise_realm",
		},
		{
			name:  "special chars dropped",
			input: "acme!@#$%^&*()+=[]{};:'\"",
			want:  "acme",
		},
		{
			name:  "spaces dropped",
			input: "acme corp",
			want:  "acmecorp",
		},
		{
			name:  "underscores preserved",
			input: "acme_corp",
			want:  "acme_corp",
		},
		{
			name:  "digits preserved",
			input: "realm42",
			want:  "realm42",
		},
		{
			name:  "long string truncated at 50 chars",
			input: strings.Repeat("a", 60),
			want:  strings.Repeat("a", 50),
		},
		{
			name:  "long string with mixed chars truncated correctly",
			input: strings.Repeat("ab", 30), // 60 chars, all valid
			want:  strings.Repeat("ab", 25), // 50 chars
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "only special chars becomes empty",
			input: "!!!@@@###",
			want:  "",
		},
		{
			name:  "dots dropped",
			input: "acme.corp.io",
			want:  "acmecorpio",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeSlug(tc.input)
			assert.Equal(t, tc.want, got)
			assert.LessOrEqual(t, len(got), 50, "result must not exceed 50 chars")
		})
	}
}

func TestGenerateSecurePassword(t *testing.T) {
	t.Parallel()

	t.Run("correct hex length", func(t *testing.T) {
		t.Parallel()
		// 32 bytes -> 64 hex chars
		pwd, err := generateSecurePassword(32)
		require.NoError(t, err)
		assert.Len(t, pwd, 64)
	})

	t.Run("all lowercase hex characters", func(t *testing.T) {
		t.Parallel()
		pwd, err := generateSecurePassword(32)
		require.NoError(t, err)
		for _, c := range pwd {
			assert.True(t,
				(c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
				"unexpected character %q in hex password", c,
			)
		}
	})

	t.Run("uniqueness across calls", func(t *testing.T) {
		t.Parallel()
		seen := make(map[string]struct{}, 10)
		for i := 0; i < 10; i++ {
			pwd, err := generateSecurePassword(32)
			require.NoError(t, err)
			_, duplicate := seen[pwd]
			assert.False(t, duplicate, "duplicate password generated")
			seen[pwd] = struct{}{}
		}
	})

	t.Run("small byte length", func(t *testing.T) {
		t.Parallel()
		pwd, err := generateSecurePassword(8)
		require.NoError(t, err)
		assert.Len(t, pwd, 16)
	})
}

func TestQuoteIdent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple identifier",
			input: "hexxlock_realm_acme",
			want:  `"hexxlock_realm_acme"`,
		},
		{
			name:  "role name",
			input: "realm_acme_corp",
			want:  `"realm_acme_corp"`,
		},
		{
			name:  "empty string",
			input: "",
			want:  `""`,
		},
		{
			name:  "identifier with digits",
			input: "realm_42",
			want:  `"realm_42"`,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := quoteIdent(tc.input)
			assert.Equal(t, tc.want, got)
			assert.True(t, strings.HasPrefix(got, `"`), "must start with double-quote")
			assert.True(t, strings.HasSuffix(got, `"`), "must end with double-quote")
		})
	}
}

// ---------------------------------------------------------------------------
// RealmDBProvisioner unit tests using a mock repository
// ---------------------------------------------------------------------------

// mockRealmDBRepo is a minimal in-memory implementation of RealmDatabaseRepository
// for use in unit tests. It records calls for assertion.
type mockRealmDBRepo struct {
	records         map[uuid.UUID]*models.RealmDatabase
	createErr       error
	getByRealmErr   error
	updateStatusErr error
	updateHealthErr error

	createdRecords []*models.RealmDatabase
	statusUpdates  []statusUpdate
	healthUpdates  []healthUpdate
}

type statusUpdate struct {
	realmID uuid.UUID
	status  string
}

type healthUpdate struct {
	realmID uuid.UUID
	status  string
	message string
}

func newMockRealmDBRepo() *mockRealmDBRepo {
	return &mockRealmDBRepo{
		records: make(map[uuid.UUID]*models.RealmDatabase),
	}
}

func (m *mockRealmDBRepo) GetByRealmID(_ context.Context, realmID uuid.UUID) (*models.RealmDatabase, error) {
	if m.getByRealmErr != nil {
		return nil, m.getByRealmErr
	}
	rd, ok := m.records[realmID]
	if !ok {
		return nil, errors.New("not found")
	}
	return rd, nil
}

func (m *mockRealmDBRepo) Create(_ context.Context, rd *models.RealmDatabase) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.records[rd.RealmID] = rd
	m.createdRecords = append(m.createdRecords, rd)
	return nil
}

func (m *mockRealmDBRepo) UpdateStatus(_ context.Context, realmID uuid.UUID, status string) error {
	if m.updateStatusErr != nil {
		return m.updateStatusErr
	}
	m.statusUpdates = append(m.statusUpdates, statusUpdate{realmID: realmID, status: status})
	if rd, ok := m.records[realmID]; ok {
		rd.Status = status
	}
	return nil
}

func (m *mockRealmDBRepo) UpdateHealthCheck(_ context.Context, realmID uuid.UUID, status string, message string) error {
	if m.updateHealthErr != nil {
		return m.updateHealthErr
	}
	m.healthUpdates = append(m.healthUpdates, healthUpdate{realmID: realmID, status: status, message: message})
	return nil
}

// TestProvisionDatabase_RejectsAlreadyActive verifies that calling
// ProvisionDatabase for a realm that already owns an active database returns
// an error and does not create a duplicate record.
func TestProvisionDatabase_RejectsAlreadyActive(t *testing.T) {
	t.Parallel()

	realmID := uuid.New()
	repo := newMockRealmDBRepo()

	// Pre-seed an active record.
	repo.records[realmID] = &models.RealmDatabase{
		ID:      uuid.New(),
		RealmID: realmID,
		Status:  string(models.RealmDatabaseStatusActive),
	}

	// masterPool is nil here — if we reach any pool call the test would panic,
	// which is itself a signal that the guard did not fire.
	p := &RealmDBProvisioner{
		masterPool:  nil,
		realmDBRepo: repo,
		config: RealmDBProvisionerConfig{
			DefaultSSLMode:            "require",
			DefaultPoolSize:           20,
			DefaultMaxIdleConns:       5,
			DefaultConnMaxLifetimeMin: 30,
		},
	}

	result, err := p.ProvisionDatabase(context.Background(), realmID, "acme", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), realmID.String())
	assert.NotNil(t, result, "should return the existing record even on rejection")
	assert.Len(t, repo.createdRecords, 0, "no new record should have been created")
}

// TestProvisionDatabase_AllowsReprovisionOfNonActiveRealm verifies that a realm
// whose existing record is NOT in the active state is allowed past the
// already-active guard. We observe this by confirming the guard-specific error
// message is NOT present; any subsequent error (or panic from the nil pool)
// is expected and asserted using assert.Panics.
func TestProvisionDatabase_AllowsReprovisionOfNonActiveRealm(t *testing.T) {
	t.Parallel()

	realmID := uuid.New()
	repo := newMockRealmDBRepo()

	// Pre-seed a decommissioned (non-active) record so the guard finds an
	// existing entry that is NOT active.
	repo.records[realmID] = &models.RealmDatabase{
		ID:      uuid.New(),
		RealmID: realmID,
		Status:  string(models.RealmDatabaseStatusDecommission),
	}

	p := &RealmDBProvisioner{
		masterPool:  nil, // intentionally nil — pool call will panic
		realmDBRepo: repo,
		config: RealmDBProvisionerConfig{
			DefaultSSLMode: "require",
		},
	}

	// The guard for "already active" must NOT fire. The nil pool causes a
	// panic when the provisioner tries to exec the CREATE ROLE statement.
	// We assert exactly that panic to prove the guard was bypassed.
	assert.Panics(t, func() {
		_, _ = p.ProvisionDatabase(context.Background(), realmID, "acme", "")
	}, "expected panic from nil masterPool — guard must not have blocked execution")
}

// TestDecommissionDatabase verifies that DecommissionDatabase delegates to the
// repository's UpdateStatus with the correct status value.
func TestDecommissionDatabase(t *testing.T) {
	t.Parallel()

	realmID := uuid.New()
	repo := newMockRealmDBRepo()
	repo.records[realmID] = &models.RealmDatabase{
		ID:      uuid.New(),
		RealmID: realmID,
		Status:  string(models.RealmDatabaseStatusActive),
	}

	p := &RealmDBProvisioner{
		masterPool:  nil,
		realmDBRepo: repo,
		config:      RealmDBProvisionerConfig{},
	}

	err := p.DecommissionDatabase(context.Background(), realmID)
	require.NoError(t, err)

	require.Len(t, repo.statusUpdates, 1)
	assert.Equal(t, realmID, repo.statusUpdates[0].realmID)
	assert.Equal(t, string(models.RealmDatabaseStatusDecommission), repo.statusUpdates[0].status)
}

// TestNewRealmDBProvisioner_Defaults verifies that zero-value config fields
// receive sensible defaults after construction.
func TestNewRealmDBProvisioner_Defaults(t *testing.T) {
	t.Parallel()

	repo := newMockRealmDBRepo()
	// keystoneClient may be nil here — the constructor stores it
	// without dereferencing; the only consumers (ProvisionDatabase /
	// MigrateRealmDatabase) are exercised by integration tests, not
	// this defaults-only unit.
	p := NewRealmDBProvisioner(nil, nil, repo, nil, RealmDBProvisionerConfig{})

	assert.Equal(t, "require", p.config.DefaultSSLMode)
	assert.Equal(t, 20, p.config.DefaultPoolSize)
	assert.Equal(t, 5, p.config.DefaultMaxIdleConns)
	assert.Equal(t, 30, p.config.DefaultConnMaxLifetimeMin)
	assert.Equal(t, "keystone-system", p.config.KeystoneNamespace)
	assert.Equal(t, "prod-eu-west-1-hub", p.config.KeystoneClusterRef)
	assert.Equal(t, "falcon-id-pg", p.config.KeystoneProviderRef)
	assert.Equal(t, "falcon-id-tenant-desired", p.config.KeystoneSchemaDefinitionName)
}

// TestNewRealmDBProvisioner_PreservesExplicitConfig verifies that non-zero
// config values are not overwritten by defaults.
func TestNewRealmDBProvisioner_PreservesExplicitConfig(t *testing.T) {
	t.Parallel()

	repo := newMockRealmDBRepo()
	cfg := RealmDBProvisionerConfig{
		DefaultSSLMode:               "disable",
		DefaultPoolSize:              50,
		DefaultMaxIdleConns:          10,
		DefaultConnMaxLifetimeMin:    60,
		KeystoneNamespace:            "alt-keystone-ns",
		KeystoneClusterRef:           "secondary-cluster",
		KeystoneProviderRef:          "alt-provider",
		KeystoneSchemaDefinitionName: "alt-tenant-sd",
	}
	p := NewRealmDBProvisioner(nil, nil, repo, nil, cfg)

	assert.Equal(t, "disable", p.config.DefaultSSLMode)
	assert.Equal(t, 50, p.config.DefaultPoolSize)
	assert.Equal(t, 10, p.config.DefaultMaxIdleConns)
	assert.Equal(t, 60, p.config.DefaultConnMaxLifetimeMin)
	assert.Equal(t, "alt-keystone-ns", p.config.KeystoneNamespace)
	assert.Equal(t, "secondary-cluster", p.config.KeystoneClusterRef)
	assert.Equal(t, "alt-provider", p.config.KeystoneProviderRef)
	assert.Equal(t, "alt-tenant-sd", p.config.KeystoneSchemaDefinitionName)
}
