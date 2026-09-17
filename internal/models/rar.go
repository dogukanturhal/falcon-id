// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"fmt"
)

// AuthorizationDetail represents a single rich authorization request object
// as defined in RFC 9396 §2. The Type field is always required; all other
// standard fields are optional and type-specific.
//
// Extra captures any additional fields that the type definition may require
// beyond the standard set. These fields are round-tripped transparently so
// that downstream resource servers can interpret them without Falcon-ID
// needing to know the full schema of every type.
type AuthorizationDetail struct {
	Type       string                 `json:"type"`
	Actions    []string               `json:"actions,omitempty"`
	Locations  []string               `json:"locations,omitempty"`
	Datatypes  []string               `json:"datatypes,omitempty"`
	Identifier string                 `json:"identifier,omitempty"`
	Privileges []string               `json:"privileges,omitempty"`
	Extra      map[string]interface{} `json:"-"` // catch-all for type-specific fields
}

// knownRARFields is the set of top-level keys that are handled explicitly
// by AuthorizationDetail and therefore must not appear in Extra.
var knownRARFields = map[string]bool{
	"type":       true,
	"actions":    true,
	"locations":  true,
	"datatypes":  true,
	"identifier": true,
	"privileges": true,
}

// decodeRARField decodes a named field from a raw JSON map into dst.
// It returns an error when the field is present but malformed.
func decodeRARField(raw map[string]json.RawMessage, key string, dst interface{}) error {
	v, ok := raw[key]
	if !ok {
		return nil
	}
	if err := json.Unmarshal(v, dst); err != nil {
		return fmt.Errorf("authorization_detail: invalid %q: %w", key, err)
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler for AuthorizationDetail.
//
// It deserialises the standard RFC 9396 fields and collects every
// unrecognised key into the Extra map so that type-specific extensions
// are preserved without loss.
func (d *AuthorizationDetail) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("authorization_detail: invalid JSON object: %w", err)
	}

	// Decode the standard fields using the helper.
	for _, f := range []struct {
		key string
		dst interface{}
	}{
		{"type", &d.Type},
		{"actions", &d.Actions},
		{"locations", &d.Locations},
		{"datatypes", &d.Datatypes},
		{"identifier", &d.Identifier},
		{"privileges", &d.Privileges},
	} {
		if err := decodeRARField(raw, f.key, f.dst); err != nil {
			return err
		}
	}

	// Collect everything else into Extra.
	for key, val := range raw {
		if knownRARFields[key] {
			continue
		}
		if d.Extra == nil {
			d.Extra = make(map[string]interface{})
		}
		var v interface{}
		if err := json.Unmarshal(val, &v); err != nil {
			return fmt.Errorf("authorization_detail: invalid field %q: %w", key, err)
		}
		d.Extra[key] = v
	}

	return nil
}

// MarshalJSON implements json.Marshaler for AuthorizationDetail.
//
// It serialises the struct fields and merges the Extra map back so that
// downstream consumers receive a single, flat JSON object.
func (d AuthorizationDetail) MarshalJSON() ([]byte, error) {
	// Build a unified map: start with Extra so that standard fields take precedence.
	m := make(map[string]interface{}, len(d.Extra)+6)
	for k, v := range d.Extra {
		m[k] = v
	}

	m["type"] = d.Type

	if len(d.Actions) > 0 {
		m["actions"] = d.Actions
	}
	if len(d.Locations) > 0 {
		m["locations"] = d.Locations
	}
	if len(d.Datatypes) > 0 {
		m["datatypes"] = d.Datatypes
	}
	if d.Identifier != "" {
		m["identifier"] = d.Identifier
	}
	if len(d.Privileges) > 0 {
		m["privileges"] = d.Privileges
	}

	return json.Marshal(m)
}

// Validate checks that the AuthorizationDetail is well-formed per RFC 9396 §7.
// It verifies that the required 'type' field is present and, when a non-nil
// allowedTypes slice is provided, that the type value is in that set.
// An empty allowedTypes slice means all types are permitted.
func (d *AuthorizationDetail) Validate(allowedTypes []string) error {
	if d.Type == "" {
		return fmt.Errorf("authorization_detail: 'type' field is required")
	}

	if len(allowedTypes) == 0 {
		return nil
	}

	for _, t := range allowedTypes {
		if t == d.Type {
			return nil
		}
	}
	return fmt.Errorf("authorization_detail: type %q is not permitted for this client", d.Type)
}

// AuthorizationDetailsRequest is a slice of AuthorizationDetail values,
// corresponding to the JSON array sent in the authorization_details parameter.
type AuthorizationDetailsRequest []AuthorizationDetail
