// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// webauthnUser adapts a Falcon-ID user + credential set to the webauthn.User
// interface expected by the go-webauthn library.
//
// SECURITY: WebAuthnID() returns the raw 16 bytes of the user's UUID. The
// W3C spec (§5.4.3) requires a stable, opaque, ≤64-byte handle that does
// NOT leak personally identifiable information. The UUID satisfies all
// three constraints; using the email or username here would leak PII into
// the authenticator's credential storage.
type webauthnUser struct {
	id          uuid.UUID
	name        string // typically email or username
	displayName string // human-readable label, may equal name
	creds       []webauthn.Credential
}

// newWebAuthnUser constructs the adapter from the falcon-id User model.
// activeOnly filters out revoked / expired credentials before passing them
// to the library so they're not advertised as allowedCredentials during
// authentication ceremonies.
func newWebAuthnUser(user *models.User, dbCreds []models.WebAuthnCredential, activeOnly bool) *webauthnUser {
	displayName := user.Username
	first := derefString(user.FirstName)
	last := derefString(user.LastName)
	if first != "" || last != "" {
		displayName = first
		if last != "" {
			if displayName != "" {
				displayName += " "
			}
			displayName += last
		}
	}
	return &webauthnUser{
		id:          user.ID,
		name:        user.Username,
		displayName: displayName,
		creds:       toLibraryCredentials(dbCreds, activeOnly),
	}
}

// WebAuthnID implements webauthn.User. Returns the user's UUID bytes.
func (u *webauthnUser) WebAuthnID() []byte {
	b, _ := u.id.MarshalBinary() // never errors for a valid uuid.UUID
	return b
}

// WebAuthnName implements webauthn.User. Returns the user's username.
func (u *webauthnUser) WebAuthnName() string { return u.name }

// WebAuthnDisplayName implements webauthn.User. Returns a human-readable label.
func (u *webauthnUser) WebAuthnDisplayName() string { return u.displayName }

// WebAuthnCredentials implements webauthn.User. Returns the registered
// credentials in the format expected by the library.
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// toLibraryCredentials converts persisted credential rows to the library's
// in-memory shape. The conversion is deliberately explicit (rather than
// relying on JSON round-trip) because the library struct contains binary
// fields with msgp tags that don't survive json.Marshal cleanly.
func toLibraryCredentials(dbCreds []models.WebAuthnCredential, activeOnly bool) []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(dbCreds))
	for i := range dbCreds {
		c := &dbCreds[i]
		if activeOnly && !c.IsActive() {
			continue
		}
		out = append(out, toLibraryCredential(c))
	}
	return out
}

func toLibraryCredential(c *models.WebAuthnCredential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			UserPresent:    true, // historical state — UV/UP at registration
			UserVerified:   true,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       c.AAGUID,
			SignCount:    c.SignCount,
			CloneWarning: c.CloneWarning,
		},
	}
}

// derefString returns "" when the pointer is nil, otherwise the dereferenced string.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// fromLibraryCredential maps a freshly minted *webauthn.Credential back to
// the persistence model. Used immediately after BeginRegistration completes
// so the new credential row carries every field the library validated.
func fromLibraryCredential(libCred *webauthn.Credential, userID, tenantID uuid.UUID, friendlyName string) *models.WebAuthnCredential {
	transports := make([]string, 0, len(libCred.Transport))
	for _, t := range libCred.Transport {
		transports = append(transports, string(t))
	}
	return &models.WebAuthnCredential{
		UserID:          userID,
		TenantID:        tenantID,
		CredentialID:    libCred.ID,
		PublicKey:       libCred.PublicKey,
		AttestationType: libCred.AttestationType,
		Transport:       transports,
		SignCount:       libCred.Authenticator.SignCount,
		AAGUID:          libCred.Authenticator.AAGUID,
		FriendlyName:    friendlyName,
		IsDiscoverable:  libCred.Flags.UserPresent && libCred.Flags.BackupEligible,
		BackupEligible:  libCred.Flags.BackupEligible,
		BackupState:     libCred.Flags.BackupState,
	}
}
