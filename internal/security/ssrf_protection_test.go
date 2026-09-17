// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── ValidateMetadataURL ───────────────────────────────────────────────────────

func TestValidateMetadataURL_AcceptsPublicHTTPS(t *testing.T) {
	err := ValidateMetadataURL("https://idp.example.com/metadata", false)
	assert.NoError(t, err)
}

func TestValidateMetadataURL_RejectsHTTPWhenNotAllowed(t *testing.T) {
	err := ValidateMetadataURL("http://idp.example.com/metadata", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}

func TestValidateMetadataURL_AcceptsHTTPWhenAllowed(t *testing.T) {
	// allowHTTP=true simulates development mode.
	err := ValidateMetadataURL("http://idp.local/metadata", true)
	assert.NoError(t, err)
}

func TestValidateMetadataURL_RejectsFTPScheme(t *testing.T) {
	err := ValidateMetadataURL("ftp://idp.example.com/metadata", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}

func TestValidateMetadataURL_RejectsFileScheme(t *testing.T) {
	err := ValidateMetadataURL("file:///etc/passwd", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}

func TestValidateMetadataURL_RejectsEmptyURL(t *testing.T) {
	err := ValidateMetadataURL("", false)
	require.Error(t, err)
}

func TestValidateMetadataURL_BlocksEC2MetadataIP(t *testing.T) {
	// 169.254.169.254 is the AWS EC2 instance metadata endpoint.
	err := ValidateMetadataURL("https://169.254.169.254/latest/meta-data/", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func TestValidateMetadataURL_BlocksGCPMetadata(t *testing.T) {
	err := ValidateMetadataURL("https://metadata.google.internal/computeMetadata/v1/", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func TestValidateMetadataURL_BlocksGCPMetadataGoogle(t *testing.T) {
	err := ValidateMetadataURL("https://metadata.google.com/computeMetadata/v1/", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func TestValidateMetadataURL_BlocksAlibabaMetadata(t *testing.T) {
	// 100.100.100.200 is the Alibaba Cloud metadata endpoint.
	err := ValidateMetadataURL("https://100.100.100.200/latest/meta-data/", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func TestValidateMetadataURL_BlockedHostCaseInsensitive(t *testing.T) {
	// Hostnames are compared case-insensitively.
	err := ValidateMetadataURL("https://METADATA.GOOGLE.INTERNAL/", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func TestValidateMetadataURL_RejectsURLWithNoHostname(t *testing.T) {
	// A URL like "https://" has no hostname.
	err := ValidateMetadataURL("https://", false)
	require.Error(t, err)
}

func TestValidateMetadataURL_AcceptsHTTPSWithPath(t *testing.T) {
	err := ValidateMetadataURL("https://idp.example.com/sso/saml2/metadata?format=xml", false)
	assert.NoError(t, err)
}

func TestValidateMetadataURL_AcceptsHTTPSWithPort(t *testing.T) {
	err := ValidateMetadataURL("https://idp.example.com:8443/metadata", false)
	assert.NoError(t, err)
}

// ── SafeTransport (structural check only — no real DNS) ───────────────────────

func TestSafeTransport_ReturnsNonNil(t *testing.T) {
	tr := SafeTransport(false)
	require.NotNil(t, tr)
	assert.NotNil(t, tr.DialContext, "SafeTransport must install a custom DialContext")
}

func TestSafeTransport_AllowHTTP_ReturnsNonNil(t *testing.T) {
	tr := SafeTransport(true)
	require.NotNil(t, tr)
}
