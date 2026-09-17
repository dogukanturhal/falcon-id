// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateRFC8707Resource locks down the validation contract for
// the optional `resource` parameter on /oauth/token (and /oauth/
// authorize, once persisted). RFC 8707 §2 mandates an absolute URI
// with no fragment; we additionally restrict scheme to http/https
// (other schemes have no legitimate place as a token audience and
// invite confused-deputy attacks via custom-scheme resolvers).
func TestValidateRFC8707Resource(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		// errSubstr — substring of expected error message; empty when wantErr=false
		errSubstr string
	}{
		// happy paths
		{"https URL", "https://api.hexxlock.com", false, ""},
		{"https URL with path", "https://api.hexxlock.com/v1/users", false, ""},
		{"https URL with query", "https://api.hexxlock.com/v1/users?x=1", false, ""},
		{"http URL (in-cluster)", "http://falcon-id.falcon-id.svc.cluster.local", false, ""},
		{"https with port", "https://api.hexxlock.com:8443/v1", false, ""},

		// fragment rejected
		{"fragment present", "https://api.hexxlock.com/v1#section", true, "MUST NOT contain a URI fragment"},
		{"empty fragment marker", "https://api.hexxlock.com/v1#", true, "MUST NOT contain a URI fragment"},

		// not absolute
		{"relative path", "/v1/users", true, "must be an absolute URI"},
		{"scheme-relative", "//api.hexxlock.com", true, "must be an absolute URI"},

		// scheme restriction
		{"file://", "file:///etc/passwd", true, "scheme \"file\" is not permitted"},
		{"javascript:", "javascript:alert(1)", true, "scheme \"javascript\" is not permitted"},
		{"custom app scheme", "myapp://callback", true, "scheme \"myapp\" is not permitted"},
		{"data URI", "data:text/plain;base64,SGVsbG8=", true, "scheme \"data\" is not permitted"},

		// case-insensitive scheme handling
		{"HTTPS uppercase", "HTTPS://api.hexxlock.com", false, ""},
		{"Http mixed case", "Http://api.hexxlock.com", false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRFC8707Resource(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
