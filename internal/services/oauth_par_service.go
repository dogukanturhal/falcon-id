// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// PAREntry holds the fields of a pushed authorization request that the service
// layer needs to store and retrieve. It is defined in the services package so
// that the redis package can depend on it without causing an import cycle.
type PAREntry struct {
	Reference           string
	ClientID            string
	ResponseType        string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Display             string
	Prompt              string
	// AcrValues + MaxAge are propagated through PAR so that PAR-initiated
	// step-up / freshness gates fire identically to bare-query flows.
	// Pre-fix dropping these silently downgraded any RP that used PAR
	// with acr_values=mfa (no MFA prompt) or max_age=N (no freshness
	// check) — the /oauth/authorize handler enforces both off req.MaxAge
	// and req.AcrValues, so an empty PAR-forwarded value is functionally
	// a security-feature suppression.
	AcrValues string
	MaxAge    *int
	// LoginHint + LoginContext round-trip the same way: a PAR-initiated
	// authorize flow must produce an identical /oauth/login experience to
	// a bare-query one, or RPs that adopt PAR silently lose the
	// post-signup email pre-fill / copy-context fix.
	LoginHint    string
	LoginContext string
	ExpiresAt    int64 // Unix timestamp
}

// PARStore is the minimal interface the OAuth service needs from the backing store.
// The redis.PARStore in pkg/redis satisfies this interface via an adapter in cmd/services.go.
type PARStore interface {
	SetPAR(ctx context.Context, entry *PAREntry) error
	GetPAR(ctx context.Context, reference string) (*PAREntry, error)
	DeletePAR(ctx context.Context, reference string) error
}

// parStore is the unexported alias used inside the service.
type parStore = PARStore

// PARTTLSeconds is the lifetime of a pushed authorization request (RFC 9126 §2.1).
const PARTTLSeconds = 60

// SetPARStore wires the Redis PAR store into the OAuth provider service.
// Call this from cmd/services.go after constructing OAuthProviderService when Redis is available.
func (s *OAuthProviderService) SetPARStore(store parStore) {
	s.parStore = store
}

// PushAuthorizationRequest implements RFC 9126 §2.
//
// The caller must already have authenticated the client (client_id + client_secret or Basic auth)
// before invoking this method. The method validates the authorization request parameters
// against the client's registered configuration and stores them in Redis.
//
// Returns the request_uri and expires_in on success.
func (s *OAuthProviderService) PushAuthorizationRequest(
	ctx context.Context,
	client *models.OAuthClient,
	params *models.OAuthAuthorizeRequest,
) (*models.PARResponse, error) {
	if s.parStore == nil {
		return nil, fmt.Errorf("server_error: PAR store is not configured")
	}

	// Validate the authorization request parameters the same way the authorize endpoint does.
	if _, err := s.validateAuthorizeParams(client, params); err != nil {
		return nil, err
	}

	// Generate a cryptographically random reference token (256 bits).
	refBytes := make([]byte, 32)
	if _, err := rand.Read(refBytes); err != nil {
		return nil, fmt.Errorf("server_error: failed to generate request_uri reference: %w", err)
	}
	reference := base64.RawURLEncoding.EncodeToString(refBytes)

	expiresAt := time.Now().Add(PARTTLSeconds * time.Second).Unix()

	entry := &PAREntry{
		Reference:           reference,
		ClientID:            client.ClientID,
		ResponseType:        params.ResponseType,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		State:               params.State,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		Display:             params.Display,
		Prompt:              params.Prompt,
		AcrValues:           params.AcrValues,
		MaxAge:              params.MaxAge,
		LoginHint:           params.LoginHint,
		LoginContext:        params.LoginContext,
		ExpiresAt:           expiresAt,
	}

	if err := s.parStore.SetPAR(ctx, entry); err != nil {
		return nil, fmt.Errorf("server_error: failed to store PAR request: %w", err)
	}

	return &models.PARResponse{
		RequestURI: "urn:ietf:params:oauth:request_uri:" + reference,
		ExpiresIn:  PARTTLSeconds,
	}, nil
}

// ResolvePARRequest looks up a pushed authorization request by its request_uri and
// returns the equivalent OAuthAuthorizeRequest. The PAR entry is deleted from Redis
// after retrieval to enforce single-use semantics per RFC 9126 §4.
//
// Returns an error when:
//   - the PAR store is not configured
//   - the request_uri is unknown or expired
//   - the client_id in the request does not match the client that submitted the PAR
func (s *OAuthProviderService) ResolvePARRequest(
	ctx context.Context,
	clientID string,
	requestURI string,
) (*models.OAuthAuthorizeRequest, error) {
	if s.parStore == nil {
		return nil, fmt.Errorf("invalid_request: PAR is not supported by this server")
	}

	const prefix = "urn:ietf:params:oauth:request_uri:"
	if len(requestURI) <= len(prefix) {
		return nil, fmt.Errorf("invalid_request: malformed request_uri")
	}
	reference := requestURI[len(prefix):]

	entry, err := s.parStore.GetPAR(ctx, reference)
	if err != nil {
		return nil, fmt.Errorf("server_error: PAR store lookup failed: %w", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("invalid_request: request_uri not found or expired")
	}

	// RFC 9126 §4: the client_id in the authorization request MUST match the
	// client that submitted the PAR request.
	if entry.ClientID != clientID {
		return nil, fmt.Errorf("invalid_request: client_id mismatch for request_uri")
	}

	// Check expiry (belt-and-suspenders: Redis TTL handles this, but be explicit).
	if time.Now().Unix() > entry.ExpiresAt {
		// Best-effort cleanup; ignore error.
		_ = s.parStore.DeletePAR(ctx, reference)
		return nil, fmt.Errorf("invalid_request: request_uri has expired")
	}

	// Consume the PAR entry (single-use).
	if err := s.parStore.DeletePAR(ctx, reference); err != nil {
		// Non-fatal: Redis will expire the key; log would happen at the handler layer.
		// We continue rather than aborting the authorization flow.
		_ = err
	}

	return &models.OAuthAuthorizeRequest{
		ResponseType:        entry.ResponseType,
		ClientID:            entry.ClientID,
		RedirectURI:         entry.RedirectURI,
		Scope:               entry.Scope,
		State:               entry.State,
		Nonce:               entry.Nonce,
		CodeChallenge:       entry.CodeChallenge,
		CodeChallengeMethod: entry.CodeChallengeMethod,
		Display:             entry.Display,
		Prompt:              entry.Prompt,
		AcrValues:           entry.AcrValues,
		MaxAge:              entry.MaxAge,
		LoginHint:           entry.LoginHint,
		LoginContext:        entry.LoginContext,
	}, nil
}

// validateAuthorizeParams runs the subset of ValidateAuthorizeRequest checks that
// do not require a database lookup (the client is already loaded by the caller).
// It is called from PushAuthorizationRequest to validate parameters at push time.
func (s *OAuthProviderService) validateAuthorizeParams(client *models.OAuthClient, req *models.OAuthAuthorizeRequest) (*models.OAuthClient, error) {
	if !client.IsActive {
		return nil, fmt.Errorf("invalid_client: client is not active")
	}

	if req.ResponseType == "" {
		return nil, fmt.Errorf("invalid_request: response_type is required")
	}

	if !s.containsString(client.ResponseTypes, req.ResponseType) {
		return nil, fmt.Errorf("unsupported_response_type: %s is not allowed for this client", req.ResponseType)
	}

	if req.RedirectURI == "" {
		return nil, fmt.Errorf("invalid_request: redirect_uri is required")
	}

	// matchRedirectURI: exact-string for non-loopback URIs, port-fuzzy
	// for loopback (127.0.0.1 / ::1 / localhost) per RFC 8252 §7.3.
	// Same matcher used by the authorize endpoint — without this the
	// PAR path silently rejected native PKCE clients with OS-assigned
	// ephemeral loopback ports, even when the authorize path accepted
	// them. Caught live 2026-06-14 on device-agent registration.
	if !matchRedirectURI(client.RedirectURIs, req.RedirectURI) {
		return nil, fmt.Errorf("invalid_request: redirect_uri is not registered for this client")
	}

	// PKCE validation.
	if client.RequirePKCE || client.IsPublic {
		if req.CodeChallenge == "" {
			return nil, fmt.Errorf("invalid_request: code_challenge is required")
		}
		if req.CodeChallengeMethod != "" && req.CodeChallengeMethod != oauthAlgS256 {
			return nil, fmt.Errorf("invalid_request: only S256 code_challenge_method is supported")
		}
	}

	return client, nil
}
