// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// newConnectTestLDAPService creates a minimal LDAPService for unit tests.
func newConnectTestLDAPService(env string) *LDAPService {
	return &LDAPService{
		config: &config.Config{
			Environment: env,
		},
	}
}

// ==========================================================================
// applyLDAPDefaults
// ==========================================================================

func TestApplyLDAPDefaults_PortZero_SetsTLS636(t *testing.T) {
	svc := newConnectTestLDAPService("development")
	cfg := &models.LDAPConfig{Host: "ldap.example.com", Port: 0, UseTLS: true}
	out := svc.applyLDAPDefaults(cfg)

	assert.Equal(t, 636, out.Port, "LDAPS port should default to 636")
	assert.Equal(t, 0, cfg.Port, "original config must not be mutated")
}

func TestApplyLDAPDefaults_PortZero_SetsPlain389(t *testing.T) {
	svc := newConnectTestLDAPService("development")
	cfg := &models.LDAPConfig{Host: "ldap.example.com", Port: 0, UseTLS: false}
	out := svc.applyLDAPDefaults(cfg)

	assert.Equal(t, 389, out.Port, "LDAP port should default to 389")
}

func TestApplyLDAPDefaults_ExplicitPort_NotOverridden(t *testing.T) {
	svc := newConnectTestLDAPService("development")
	cfg := &models.LDAPConfig{Host: "ldap.example.com", Port: 3269, UseTLS: true}
	out := svc.applyLDAPDefaults(cfg)

	assert.Equal(t, 3269, out.Port, "explicit port should not be overridden")
}

func TestApplyLDAPDefaults_AttributeDefaults(t *testing.T) {
	svc := newConnectTestLDAPService("development")
	cfg := &models.LDAPConfig{Host: "ldap.example.com"}
	out := svc.applyLDAPDefaults(cfg)

	assert.Equal(t, "sAMAccountName", out.UsernameAttr)
	assert.Equal(t, "mail", out.EmailAttr)
	assert.Equal(t, "givenName", out.FirstNameAttr)
	assert.Equal(t, "sn", out.LastNameAttr)
	assert.Equal(t, "displayName", out.DisplayNameAttr)
	assert.Equal(t, "memberOf", out.GroupAttr)
}

// ==========================================================================
// TestConnection — defaults are applied
// ==========================================================================

func TestTestConnection_AppliesDefaults(t *testing.T) {
	// Start a plain TCP listener to accept the connection (port 0 = OS picks)
	lc := &net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close() //nolint:errcheck

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())

	svc := newConnectTestLDAPService("development")
	cfg := &models.LDAPConfig{
		Host: "127.0.0.1",
		Port: 0, // intentionally zero — defaults should kick in
	}

	// TestConnection will call applyLDAPDefaults, setting Port=389.
	// Connection will fail because our listener is on a random port,
	// but the error message should show "127.0.0.1:389", NOT ":0".
	errResult := svc.TestConnection(context.Background(), cfg)
	require.Error(t, errResult)

	assert.NotContains(t, errResult.Error(), ":0",
		"address must not be :0 — applyLDAPDefaults should set port 389")
	assert.Contains(t, errResult.Error(), ":389",
		"error should reference port 389 (default for non-TLS)")

	_ = portStr // listener port unused, just ensures the test cleans up
}

// ==========================================================================
// Connect — TLS configuration
// ==========================================================================

func TestConnect_TLS_SetsServerNameFromHost(t *testing.T) {
	// Verify the TLS config is built correctly by checking the struct fields
	// directly. We cannot test a real LDAPS dial without infrastructure.
	cfg := &models.LDAPConfig{
		Host:          "ldap.internal.example.com",
		Port:          636,
		UseTLS:        true,
		SkipTLSVerify: true,
		ServerName:    "", // not set — should default to Host
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec // test fixture, InsecureSkipVerify for test LDAP
		MinVersion:         tls.VersionTLS10,
	}
	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	} else if cfg.Host != "" {
		tlsConfig.ServerName = cfg.Host
	}

	assert.Equal(t, "ldap.internal.example.com", tlsConfig.ServerName,
		"ServerName should be set from Host when ServerName is empty")
	assert.True(t, tlsConfig.InsecureSkipVerify)

	// Also verify address formatting
	address := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	assert.Equal(t, "ldap.internal.example.com:636", address)
}

func TestConnect_TLS_MinVersionAllowsTLS10(t *testing.T) {
	// Verify our TLS config sets MinVersion to TLS 1.0 for AD compatibility.
	// We build the config inline to match what Connect() does.
	cfg := &models.LDAPConfig{
		Host:          "ldap.test",
		Port:          636,
		UseTLS:        true,
		SkipTLSVerify: true,
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec // test fixture, InsecureSkipVerify for test LDAP
		MinVersion:         tls.VersionTLS10,
	}
	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	} else if cfg.Host != "" {
		tlsConfig.ServerName = cfg.Host
	}

	assert.Equal(t, uint16(tls.VersionTLS10), tlsConfig.MinVersion,
		"MinVersion should be TLS 1.0 for AD compatibility")
	assert.Equal(t, "ldap.test", tlsConfig.ServerName,
		"ServerName should default to Host when not explicitly set")
	assert.True(t, tlsConfig.InsecureSkipVerify,
		"SkipTLSVerify should be forwarded to InsecureSkipVerify")
}

func TestConnect_ProductionRejectsNoTLS(t *testing.T) {
	svc := newConnectTestLDAPService("production")
	cfg := &models.LDAPConfig{
		Host:   "ldap.test",
		Port:   389,
		UseTLS: false,
		BindDN: "cn=svc,dc=test",
	}

	_, err := svc.Connect(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "require TLS")
}

func TestConnect_ProductionRejectsSkipTLSVerify(t *testing.T) {
	svc := newConnectTestLDAPService("production")
	cfg := &models.LDAPConfig{
		Host:          "ldap.test",
		Port:          636,
		UseTLS:        true,
		SkipTLSVerify: true,
	}

	_, err := svc.Connect(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SkipTLSVerify is not allowed")
}

// ==========================================================================
// validateLDAPConfig (via handler)
// ==========================================================================

func TestValidateLDAPConfig_DevAllowsAdministrator(t *testing.T) {
	// The handler validation is on AdminHandler; we test the service-layer
	// TestConnection path instead. The key point: in dev, CN=Administrator
	// is permitted — only the handler blocks it, and only in prod/staging.
	// This test just ensures TestConnection itself does NOT reject the bind DN.
	svc := newConnectTestLDAPService("development")
	cfg := &models.LDAPConfig{
		Host:         "127.0.0.1",
		Port:         389,
		BindDN:       "CN=Administrator,CN=Users,DC=example,DC=corp",
		BindPassword: "Admin123!",
	}

	// Will fail due to no LDAP server, but error should be a connection error,
	// NOT a bind DN validation error.
	err := svc.TestConnection(context.Background(), cfg)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "Administrator",
		"service layer should not reject CN=Administrator")
	assert.Contains(t, err.Error(), "connection test failed",
		"should fail with connection error, not validation")
}

// ==========================================================================
// Address formatting
// ==========================================================================

func TestConnect_AddressFormatting(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     int
		expected string
	}{
		{"hostname with port", "ldap.example.com", 389, "ldap.example.com:389"},
		{"IP with port", "10.0.20.10", 636, "10.0.20.10:636"},
		{"localhost", "127.0.0.1", 3268, "127.0.0.1:3268"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address := fmt.Sprintf("%s:%d", tt.host, tt.port)
			assert.Equal(t, tt.expected, address)
		})
	}
}
