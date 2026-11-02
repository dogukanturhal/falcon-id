// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUserEventPayloadCarriesEmailVerified(t *testing.T) {
	b, err := json.Marshal(UserEventPayload{Email: "a@b.c", EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"email_verified":true`) {
		t.Fatalf("payload missing email_verified: %s", b)
	}
}
