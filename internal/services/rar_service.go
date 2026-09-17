// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"encoding/json"
	"fmt"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// RARService implements RFC 9396 Rich Authorization Requests processing.
//
// It is intentionally stateless: no constructor is required. All methods
// operate purely on the values passed to them.
type RARService struct{}

// NewRARService returns a new RARService.
func NewRARService() *RARService {
	return &RARService{}
}

// ParseAuthorizationDetails parses the raw JSON array string supplied as the
// authorization_details query parameter or form field (RFC 9396 §2).
//
// The input must be a JSON array whose elements are objects each containing at
// least the required 'type' field. Extra type-specific fields are preserved in
// AuthorizationDetail.Extra.
//
// Returns an error if the input is not valid JSON or does not represent a JSON
// array. An empty input is treated as no RAR being requested and returns nil,
// nil so callers can treat it transparently.
func (s *RARService) ParseAuthorizationDetails(raw string) ([]models.AuthorizationDetail, error) {
	if raw == "" {
		return nil, nil
	}

	var details []models.AuthorizationDetail
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		return nil, fmt.Errorf("invalid_authorization_details: failed to parse authorization_details: %w", err)
	}

	return details, nil
}

// ValidateAgainstClient checks that every AuthorizationDetail in details is
// allowed by the given client's AuthorizationDetailTypes list (RFC 9396 §9).
//
// When the client has no AuthorizationDetailTypes configured (nil or empty
// slice), all types are permitted — this matches the behaviour of servers that
// support RAR globally rather than per-client.
//
// Each detail is also checked for the required 'type' field.
func (s *RARService) ValidateAgainstClient(details []models.AuthorizationDetail, client models.OAuthClient) error {
	for i := range details {
		if err := details[i].Validate(client.AuthorizationDetailTypes); err != nil {
			return fmt.Errorf("invalid_authorization_details: %w", err)
		}
	}
	return nil
}

// EmbedInToken adds the authorization_details claim to the provided JWT claims
// map (RFC 9396 §7). The method is a no-op when details is empty or nil so
// that callers do not need to guard against the zero-value case.
//
// The claim value is the slice itself; JSON serialisation via jwt.MapClaims
// will render it as a JSON array using AuthorizationDetail.MarshalJSON.
func (s *RARService) EmbedInToken(claims map[string]interface{}, details []models.AuthorizationDetail) {
	if len(details) == 0 {
		return
	}
	claims["authorization_details"] = details
}
