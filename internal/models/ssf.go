// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// SSFDeliveryMethod represents how events are delivered to a receiver.
// OpenID SSF spec §6 defines two mandatory delivery methods.
type SSFDeliveryMethod string

const (
	// SSFDeliveryPoll uses RFC 8936 polling — receiver fetches events on demand.
	SSFDeliveryPoll SSFDeliveryMethod = "urn:ietf:rfc:8936"
	// SSFDeliveryPush uses RFC 8935 push delivery — transmitter POSTs events to a callback URL.
	SSFDeliveryPush SSFDeliveryMethod = "urn:ietf:rfc:8935"
)

// SSFStreamStatus represents the operational state of a stream per OpenID SSF §7.1.2.
type SSFStreamStatus string

const (
	// SSFStreamEnabled means the stream is active and events are being delivered.
	SSFStreamEnabled SSFStreamStatus = "enabled"
	// SSFStreamPaused means delivery is temporarily suspended but the stream exists.
	SSFStreamPaused SSFStreamStatus = "paused"
	// SSFStreamDisabled means the stream is deactivated — no events are delivered.
	SSFStreamDisabled SSFStreamStatus = "disabled"
)

// SSFEventType represents the URI identifier for a security event type.
// These follow the CAEP and RISC event type URI conventions.
type SSFEventType string

const (
	// CAEPSessionRevoked is emitted when a session is explicitly terminated.
	// Receivers must immediately invalidate the referenced session.
	CAEPSessionRevoked SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

	// CAEPTokenClaimsChange is emitted when a user's roles or permissions change.
	// Receivers should re-evaluate access for active sessions.
	CAEPTokenClaimsChange SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change" //nolint:gosec // not a credential, this is an SSF event type name constant

	// CAEPCredentialChange is emitted when a credential is added, removed, or changed
	// (password change, MFA enrollment/revocation).
	CAEPCredentialChange SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/credential-change" //nolint:gosec // not a credential, this is an SSF event type name constant

	// CAEPAssuranceLevelChange is emitted when a user's authentication assurance level
	// changes (e.g., step-up auth completed or revoked).
	CAEPAssuranceLevelChange SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change" //nolint:gosec // not a credential, this is an SSF event type name constant

	// CAEPDeviceComplianceChange is emitted when a device's compliance status changes.
	// Reserved for future device management integration.
	CAEPDeviceComplianceChange SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"

	// RISCAccountDisabled is emitted by external transmitters (e.g., Google RISC)
	// when a user account is disabled at the source IDP.
	RISCAccountDisabled SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"

	// RISCAccountEnabled is emitted when a previously disabled account is re-enabled.
	RISCAccountEnabled SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"

	// RISCAccountCredentialChangeRequired is emitted when an external IDP detects
	// that a credential change is required (e.g., breach detected).
	RISCAccountCredentialChangeRequired SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required" //nolint:gosec // not a credential, this is an SSF event type name constant

	// RISCIdentifierChanged is emitted when an account's identifier (email/phone) changes.
	RISCIdentifierChanged SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"
)

// SSFSubjectFormat identifies the format of the SSFSubject identifier.
// OpenID SSF §3.2 defines these subject identifier formats.
type SSFSubjectFormat string

const (
	// SSFSubjectEmail identifies the subject by email address per RFC 5321.
	SSFSubjectEmail SSFSubjectFormat = "email"
	// SSFSubjectPhone identifies the subject by phone number in E.164 format.
	SSFSubjectPhone SSFSubjectFormat = "phone_number"
	// SSFSubjectIssuerSub identifies the subject by issuer+subject pair (iss/sub).
	SSFSubjectIssuerSub SSFSubjectFormat = "iss_sub"
	// SSFSubjectOpaque identifies the subject by an opaque provider-specific string.
	SSFSubjectOpaque SSFSubjectFormat = "opaque"
	// SSFSubjectDID identifies the subject by a Decentralized Identifier.
	SSFSubjectDID SSFSubjectFormat = "did"
)

// SSFSubject represents the subject of a security event, encoded in one of the
// formats defined by OpenID Subject Identifiers for Security Event Tokens.
type SSFSubject struct {
	// Format identifies which fields are populated.
	Format SSFSubjectFormat `json:"format"`

	// Email is populated when Format == SSFSubjectEmail.
	Email string `json:"email,omitempty"`

	// PhoneNumber is populated when Format == SSFSubjectPhone.
	PhoneNumber string `json:"phone_number,omitempty"`

	// Issuer is populated when Format == SSFSubjectIssuerSub.
	Issuer string `json:"iss,omitempty"`
	// Subject is populated when Format == SSFSubjectIssuerSub.
	Subject string `json:"sub,omitempty"`

	// ID is populated when Format == SSFSubjectOpaque or SSFSubjectDID.
	ID string `json:"id,omitempty"`
}

// SSFStream represents an SSF stream configuration. A stream defines the
// relationship between a transmitter (Falcon-ID) and a receiver (SIEM, IDP, etc.)
// or between an external transmitter and Falcon-ID acting as a receiver.
type SSFStream struct {
	// ID is the unique stream identifier assigned at creation.
	ID uuid.UUID `json:"stream_id" db:"id"`

	// TenantID scopes the stream to a specific tenant. Platform-level streams
	// that receive signals for all tenants use the HexxlockInternalTenantID.
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`

	// Issuer is the `iss` claim that will appear in SETs emitted on this stream.
	// For transmitter streams this is Falcon-ID's issuer URI.
	Issuer string `json:"iss" db:"issuer"`

	// Audience is the list of intended recipients for SETs on this stream.
	// Populated from the receiver's registration.
	Audience []string `json:"aud" db:"audience"`

	// DeliveryMethod determines how events reach the receiver.
	DeliveryMethod SSFDeliveryMethod `json:"delivery_method" db:"delivery_method"`

	// PushEndpointURL is the callback URL for push delivery (SSFDeliveryPush only).
	PushEndpointURL *string `json:"endpoint_url,omitempty" db:"push_endpoint_url"`

	// EventsRequested is the set of event types the receiver has subscribed to.
	// An empty slice means all supported event types.
	EventsRequested []SSFEventType `json:"events_requested" db:"events_requested"`

	// EventsDelivered is the set of event types actually emitted by this transmitter.
	// This may be a subset of EventsRequested based on what Falcon-ID supports.
	EventsDelivered []SSFEventType `json:"events_delivered" db:"events_delivered"`

	// Status is the current operational state of the stream.
	Status SSFStreamStatus `json:"status" db:"status"`

	// Description is an optional human-readable label for the stream.
	Description *string `json:"description,omitempty" db:"description"`

	// ReceiverPublicKeyURI is the JWKS URI used to encrypt SETs (if confidential delivery is required).
	ReceiverPublicKeyURI *string `json:"receiver_jwks_uri,omitempty" db:"receiver_jwks_uri"`

	// IsInbound is true when Falcon-ID acts as a receiver for an external transmitter.
	// False when Falcon-ID is the transmitter.
	IsInbound bool `json:"is_inbound" db:"is_inbound"`

	// ExternalTransmitterJWKSURI is the JWKS URI used to verify SETs from an
	// external transmitter (only relevant when IsInbound == true).
	ExternalTransmitterJWKSURI *string `json:"transmitter_jwks_uri,omitempty" db:"external_transmitter_jwks_uri"`

	// CreatedAt is the UTC timestamp when the stream was registered.
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt is the UTC timestamp of the last configuration change.
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// CreatedBy is the user or service principal that created the stream.
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// SecurityEventToken (SET) is a JWT structured per RFC 8417 carrying one or more
// security event payloads in the `events` claim. Falcon-ID mints SETs when acting
// as a transmitter and validates SETs when acting as a receiver.
type SecurityEventToken struct {
	// JTI is the unique JWT ID for this SET, used for deduplication and acknowledgement.
	JTI string `json:"jti"`

	// Issuer is the entity that created and signed the SET.
	Issuer string `json:"iss"`

	// IssuedAt is the Unix timestamp when the SET was minted.
	IssuedAt int64 `json:"iat"`

	// Audience is the intended recipients of this SET.
	Audience []string `json:"aud"`

	// Subject is the principal (user, device, etc.) that is the subject of the events.
	Subject *SSFSubject `json:"sub,omitempty"`

	// TransactionID optionally correlates this SET with other related SETs.
	TransactionID *string `json:"txn,omitempty"`

	// Events maps each event type URI to its event-specific claims.
	// A SET MUST contain at least one event. Multiple events share a single subject.
	Events map[SSFEventType]map[string]interface{} `json:"events"`
}

// SSFEvent is the persisted record of a SET emitted by Falcon-ID. It tracks
// delivery state for polling receivers and audit purposes.
type SSFEvent struct {
	// ID is the internal primary key.
	ID uuid.UUID `json:"id" db:"id"`

	// StreamID references the SSFStream this event was emitted on.
	StreamID uuid.UUID `json:"stream_id" db:"stream_id"`

	// JTI is the SET's JWT ID — globally unique per RFC 8417 §2.2.
	JTI string `json:"jti" db:"jti"`

	// EventType is the primary event type URI contained in the SET.
	EventType SSFEventType `json:"event_type" db:"event_type"`

	// SetToken is the compact serialization of the signed JWT SET.
	SetToken string `json:"set_token" db:"set_token"`

	// SubjectFormat is the format of the subject identifier.
	SubjectFormat *SSFSubjectFormat `json:"subject_format,omitempty" db:"subject_format"`

	// SubjectID is the resolved subject identifier (email, user ID, etc.).
	SubjectID *string `json:"subject_id,omitempty" db:"subject_id"`

	// TenantID is the tenant context for this event.
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`

	// DeliveredAt is set when the event has been acknowledged by the receiver.
	DeliveredAt *time.Time `json:"delivered_at,omitempty" db:"delivered_at"`

	// Acknowledged is true once the receiver has ACKed the event via the poll endpoint.
	Acknowledged bool `json:"acknowledged" db:"acknowledged"`

	// CreatedAt is when the SET was queued.
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// SSFReceiver represents an inbound SSF configuration — an external transmitter
// (e.g., Google RISC, Azure CAEP) that sends signals to Falcon-ID.
type SSFReceiver struct {
	// ID is the unique receiver identifier.
	ID uuid.UUID `json:"id" db:"id"`

	// StreamID references the SSFStream configured for inbound delivery.
	StreamID uuid.UUID `json:"stream_id" db:"stream_id"`

	// TenantID scopes the receiver to a tenant.
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`

	// TransmitterIssuer is the `iss` claim expected in SETs from this transmitter.
	TransmitterIssuer string `json:"transmitter_issuer" db:"transmitter_issuer"`

	// JWKSEndpoint is the URL where the transmitter's public keys can be fetched.
	JWKSEndpoint string `json:"jwks_endpoint" db:"jwks_endpoint"`

	// EventTypesHandled is the set of event types from this transmitter that
	// Falcon-ID will process and act upon.
	EventTypesHandled []SSFEventType `json:"event_types_handled" db:"event_types_handled"`

	// IsActive controls whether incoming SETs from this transmitter are processed.
	IsActive bool `json:"is_active" db:"is_active"`

	// CreatedAt is the UTC timestamp when the receiver was registered.
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt is the UTC timestamp of the last configuration change.
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// SSFConfiguration is the discovery document served at /.well-known/ssf-configuration.
// It follows the OpenID SSF spec §8 (Transmitter Configuration Metadata).
type SSFConfiguration struct {
	// Issuer is the transmitter's issuer URI — matches the `iss` claim in emitted SETs.
	Issuer string `json:"issuer"`

	// JWKSEndpoint is the URL where the transmitter's public keys can be fetched
	// to verify SET signatures.
	JWKSEndpoint string `json:"jwks_uri"`

	// DeliveryMethodsSupported lists the delivery method URNs this transmitter supports.
	DeliveryMethodsSupported []SSFDeliveryMethod `json:"delivery_methods_supported"`

	// ConfigurationEndpoint is the URL for stream management (create/update/delete streams).
	ConfigurationEndpoint string `json:"configuration_endpoint"`

	// StatusEndpoint is the URL for querying stream status.
	StatusEndpoint string `json:"status_endpoint"`

	// AddSubjectEndpoint is the URL for adding subjects to a stream.
	AddSubjectEndpoint string `json:"add_subject_endpoint,omitempty"`

	// RemoveSubjectEndpoint is the URL for removing subjects from a stream.
	RemoveSubjectEndpoint string `json:"remove_subject_endpoint,omitempty"`

	// VerificationEndpoint is the URL for requesting stream verification events.
	VerificationEndpoint string `json:"verification_endpoint,omitempty"`

	// EventsSupported lists the event type URIs this transmitter can emit.
	EventsSupported []SSFEventType `json:"events_supported"`

	// CriticalClaimsSupported lists the `crit` claim values this transmitter understands.
	CriticalClaimsSupported []string `json:"critical_claims_supported,omitempty"`
}

// SSFStreamRequest is the body for creating or updating an SSF stream.
type SSFStreamRequest struct {
	// Audience is the list of intended recipients for SETs on this stream.
	Audience []string `json:"aud" binding:"required,min=1"`

	// DeliveryMethod selects the delivery mechanism.
	DeliveryMethod SSFDeliveryMethod `json:"delivery_method" binding:"required,oneof=urn:ietf:rfc:8936 urn:ietf:rfc:8935"`

	// PushEndpointURL is required when DeliveryMethod is SSFDeliveryPush.
	PushEndpointURL *string `json:"endpoint_url,omitempty"`

	// EventsRequested is the set of event type URIs the receiver wants to receive.
	// An empty list is treated as "all supported events".
	EventsRequested []SSFEventType `json:"events_requested,omitempty"`

	// Description is an optional label.
	Description *string `json:"description,omitempty"`

	// ReceiverPublicKeyURI is the JWKS URI for encrypting SETs (optional, for confidential delivery).
	ReceiverPublicKeyURI *string `json:"receiver_jwks_uri,omitempty"`
}

// SSFStreamUpdateRequest is the body for PATCH /api/v1/ssf/streams/:id.
// All fields are optional; only non-nil fields are applied.
type SSFStreamUpdateRequest struct {
	// Status allows the receiver to pause, resume, or disable the stream.
	Status *SSFStreamStatus `json:"status,omitempty"`

	// EventsRequested updates the subscribed event types.
	EventsRequested []SSFEventType `json:"events_requested,omitempty"`

	// PushEndpointURL updates the callback URL for push delivery.
	PushEndpointURL *string `json:"endpoint_url,omitempty"`

	// Description updates the human-readable label.
	Description *string `json:"description,omitempty"`
}

// SSFStreamStatusResponse is returned by GET /api/v1/ssf/streams/:id/status.
// It mirrors the status object defined in OpenID SSF §7.1.
type SSFStreamStatusResponse struct {
	// Status is the current operational state.
	Status SSFStreamStatus `json:"status"`

	// Subject is the subject this status applies to. Nil means the status applies
	// to the entire stream.
	Subject *SSFSubject `json:"subject,omitempty"`
}

// SSFPollRequest is the body for POST /api/v1/ssf/poll (RFC 8936 §2.4).
type SSFPollRequest struct {
	// StreamID identifies the stream to poll.
	StreamID uuid.UUID `json:"stream_id" binding:"required"`

	// Acknowledgements is the list of JTIs from the previous poll response
	// that the receiver confirms it has processed.
	Acknowledgements []string `json:"ack,omitempty"`

	// MaxEvents caps the number of SETs returned in a single response.
	// A value of 0 means use the server default.
	MaxEvents int `json:"max_events,omitempty"`

	// ReturnImmediately controls whether the server returns immediately (true)
	// or holds the connection open until events are available (false = long-poll).
	ReturnImmediately bool `json:"return_immediately,omitempty"`
}

// SSFPollResponse is the response body for the poll endpoint (RFC 8936 §2.5).
type SSFPollResponse struct {
	// Sets maps each JTI to its compact serialised SET JWT.
	Sets map[string]string `json:"sets"`

	// MoreAvailable is true when the stream has more undelivered events than
	// were returned in this response. The receiver should poll again immediately.
	MoreAvailable bool `json:"more_available"`
}

// SSFReceiveRequest is the body for POST /api/v1/ssf/receive — inbound SET delivery.
type SSFReceiveRequest struct {
	// StreamID identifies which inbound stream this SET belongs to.
	StreamID uuid.UUID `json:"stream_id" binding:"required"`

	// SetToken is the compact serialisation of the signed JWT SET from the external transmitter.
	SetToken string `json:"set_token" binding:"required"`
}
