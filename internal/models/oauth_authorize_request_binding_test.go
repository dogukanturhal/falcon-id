// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"

	"github.com/gin-gonic/gin/binding"
)

func TestOAuthAuthorizeRequest_AcceptsPrivateUseSchemeRedirect(t *testing.T) {
	for _, uri := range []string{
		"com.example.app:/oauth/callback",
		"https://example.com/oauth/mobile/callback",
		"http://127.0.0.1/oauth/callback",
	} {
		req := OAuthAuthorizeRequest{ResponseType: "code", ClientID: "svc-acmeapp-mobile", RedirectURI: uri}
		if err := binding.Validator.ValidateStruct(&req); err != nil {
			t.Fatalf("redirect_uri %q rejected by binding: %v", uri, err)
		}
	}
	req := OAuthAuthorizeRequest{ResponseType: "code", ClientID: "c"}
	if err := binding.Validator.ValidateStruct(&req); err == nil {
		t.Fatal("missing redirect_uri must still fail binding")
	}
}
