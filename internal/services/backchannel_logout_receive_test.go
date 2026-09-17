// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestBackchannelLogoutReceive_RejectsByDefault asserts that without
// any TrustedIssuers configured, Receive refuses every token. This
// closes the previous-implementation vulnerability where
// ParseUnverified accepted any unsigned JWT and triggered arbitrary
// session invalidation.
func TestBackchannelLogoutReceive_RejectsByDefault(t *testing.T) {
	s := NewBackchannelLogoutService(nil, nil, BackchannelLogoutConfig{}, zap.NewNop())

	// Even a "well-formed" (unverified) token is refused.
	sub, err := s.Receive(context.Background(),
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlci1jaG9zZW4tc3ViIn0.fake")
	require.Error(t, err, "Receive must refuse when no trusted issuers configured")
	assert.True(t, errors.Is(err, ErrBackchannelReceiverDisabled),
		"error must wrap ErrBackchannelReceiverDisabled, got: %v", err)
	assert.Empty(t, sub)
}

// TestBackchannelLogoutReceive_EmptyTokenRejected asserts the empty-
// token early-return path still fires before the disabled-receiver
// check. This is just defensive — empty tokens shouldn't reach the
// HTTP handler in the first place but the service guards anyway.
func TestBackchannelLogoutReceive_EmptyTokenRejected(t *testing.T) {
	s := NewBackchannelLogoutService(nil, nil, BackchannelLogoutConfig{}, zap.NewNop())
	sub, err := s.Receive(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty logout_token")
	assert.Empty(t, sub)
}

// TestBackchannelLogoutReceive_ConfiguredRejectsUnsignedToken verifies
// that with TrustedIssuers configured, Receive rejects an unsigned /
// HS256 token (signature can't validate against an upstream RS256
// JWKS). The pre-F2 stub returned a "not yet implemented" error here;
// post-F2, the JWKS verifier rejects the same input on signature
// grounds. Either outcome is correct from a security standpoint —
// the test asserts NON-acceptance, not the specific error message.
func TestBackchannelLogoutReceive_ConfiguredRejectsUnsignedToken(t *testing.T) {
	s := NewBackchannelLogoutService(nil, nil, BackchannelLogoutConfig{}, zap.NewNop())
	s.SetReceiverConfig(BackchannelLogoutReceiverConfig{
		TrustedIssuers: []string{"https://upstream-idp.example.com"},
		Audience:       "our-client-id",
	})

	// Forged HS256 token claiming to be from a trusted issuer. The
	// JWKS verifier rejects because (a) HS256 is outside the allowed
	// methods for this receiver (RS256 only), and (b) even if it
	// weren't, the discovery doc fetch for example.com fails with a
	// connect error — both are NON-acceptance outcomes.
	sub, err := s.Receive(context.Background(),
		"eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Vwc3RyZWFtLWlkcC5leGFtcGxlLmNvbSJ9.fake")
	require.Error(t, err, "configured-but-untrusted token MUST be rejected")
	assert.False(t, errors.Is(err, ErrBackchannelReceiverDisabled),
		"NOT the disabled-receiver path — receiver IS configured")
	assert.Empty(t, sub)
}

// TestBackchannelLogoutReceive_RequiresAudience verifies that
// configuring TrustedIssuers without Audience surfaces a clear error
// rather than silently accepting any aud claim. spec §2.6 mandates
// audience validation; missing config is operator error, not a
// tolerable degraded mode.
func TestBackchannelLogoutReceive_RequiresAudience(t *testing.T) {
	s := NewBackchannelLogoutService(nil, nil, BackchannelLogoutConfig{}, zap.NewNop())
	s.SetReceiverConfig(BackchannelLogoutReceiverConfig{
		TrustedIssuers: []string{"https://idp.example.com"},
		// Audience intentionally omitted.
	})
	sub, err := s.Receive(context.Background(),
		"eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSJ9.x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Audience must be configured")
	assert.Empty(t, sub)
}

// TestBackchannelLogoutReceiverConfig_DefaultSkewAndCacheTTL verifies
// that SetReceiverConfig fills in zero defaults so a caller passing
// only TrustedIssuers + Audience gets sensible values.
func TestBackchannelLogoutReceiverConfig_DefaultSkewAndCacheTTL(t *testing.T) {
	s := NewBackchannelLogoutService(nil, nil, BackchannelLogoutConfig{}, zap.NewNop())
	s.SetReceiverConfig(BackchannelLogoutReceiverConfig{
		TrustedIssuers: []string{"https://idp.example.com"},
		Audience:       "client-id",
	})
	require.NotNil(t, s.receiverCfg)
	assert.NotZero(t, s.receiverCfg.MaxSkew, "MaxSkew default must fill in non-zero")
	assert.NotZero(t, s.receiverCfg.JWKSCacheTTL, "JWKSCacheTTL default must fill in non-zero")
}
