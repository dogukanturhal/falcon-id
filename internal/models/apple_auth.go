// SPDX-License-Identifier: AGPL-3.0-or-later

package models

// AppleConfig stores Apple Sign In configuration in the identity provider's apple_config JSONB column.
type AppleConfig struct {
	TeamID              string `json:"team_id"`               // Apple Developer Team ID (10 chars)
	KeyID               string `json:"key_id"`                // Key ID for the private key
	ServicesID          string `json:"services_id"`           // Services ID (client_id for web)
	PrivateKeyEncrypted string `json:"private_key_encrypted"` // ECDSA P-256 private key (encrypted)
	BundleID            string `json:"bundle_id,omitempty"`   // iOS Bundle ID (optional)
	RedirectURI         string `json:"redirect_uri"`          // Redirect URI registered with Apple
}

// AppleIDTokenClaims represents claims from Apple's id_token
type AppleIDTokenClaims struct {
	Issuer          string `json:"iss"` // https://appleid.apple.com
	Audience        string `json:"aud"` // services_id
	ExpiresAt       int64  `json:"exp"`
	IssuedAt        int64  `json:"iat"`
	Subject         string `json:"sub"` // User's unique identifier
	Email           string `json:"email,omitempty"`
	EmailVerified   string `json:"email_verified,omitempty"` // "true" or "false" as string
	IsPrivateEmail  string `json:"is_private_email,omitempty"`
	RealUserStatus  int    `json:"real_user_status,omitempty"` // 0=unsupported, 1=unknown, 2=likely_real
	Nonce           string `json:"nonce,omitempty"`
	NonceSupported  bool   `json:"nonce_supported,omitempty"`
	AuthTime        int64  `json:"auth_time,omitempty"`
	TransferSubject string `json:"transfer_sub,omitempty"`
}

// AppleCallbackUserInfo represents user info sent only on first authorization via form_post.
// Apple sends this data exactly once — it must be captured on first callback.
type AppleCallbackUserInfo struct {
	Name  *AppleUserName `json:"name,omitempty"`
	Email string         `json:"email,omitempty"`
}

// AppleUserName is the name object within Apple's user callback data
type AppleUserName struct {
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}
