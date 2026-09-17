// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRequireScope_AllPresent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		scopes   string // space-separated scopes put in context
		required []string
		wantCode int
	}{
		{
			name:     "single scope present",
			scopes:   "events:publish",
			required: []string{"events:publish"},
			wantCode: http.StatusOK,
		},
		{
			name:     "multiple scopes all present",
			scopes:   "events:publish events:consume tenants:read",
			required: []string{"events:publish", "events:consume"},
			wantCode: http.StatusOK,
		},
		{
			name:     "no required scopes — always passes",
			scopes:   "",
			required: []string{},
			wantCode: http.StatusOK,
		},
		{
			name:     "nil required scopes — always passes",
			scopes:   "events:publish",
			required: nil,
			wantCode: http.StatusOK,
		},
		{
			name:     "required scope missing",
			scopes:   "events:consume",
			required: []string{"events:publish"},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "second required scope missing",
			scopes:   "events:publish",
			required: []string{"events:publish", "events:consume"},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "empty scope set",
			scopes:   "",
			required: []string{"events:publish"},
			wantCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)

			r.GET("/test",
				func(c *gin.Context) {
					// Pre-populate service_scopes as ServiceAuth would.
					c.Set(CtxKeyServiceScopes, tt.scopes)
				},
				RequireScope(tt.required...),
				func(c *gin.Context) {
					c.JSON(http.StatusOK, gin.H{"ok": true})
				},
			)

			req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.wantCode, w.Code, "unexpected status code")
		})
	}
}

func TestRequireAnyScope_AtLeastOne(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		scopes   string
		anyOf    []string
		wantCode int
	}{
		{
			name:     "first candidate matches",
			scopes:   "events:publish",
			anyOf:    []string{"events:publish", "admin:write"},
			wantCode: http.StatusOK,
		},
		{
			name:     "second candidate matches",
			scopes:   "admin:write",
			anyOf:    []string{"events:publish", "admin:write"},
			wantCode: http.StatusOK,
		},
		{
			name:     "none match",
			scopes:   "tenants:read",
			anyOf:    []string{"events:publish", "admin:write"},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "empty anyOf — always passes",
			scopes:   "",
			anyOf:    []string{},
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)

			r.GET("/test",
				func(c *gin.Context) {
					c.Set(CtxKeyServiceScopes, tt.scopes)
				},
				RequireAnyScope(tt.anyOf...),
				func(c *gin.Context) {
					c.JSON(http.StatusOK, gin.H{"ok": true})
				},
			)

			req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.wantCode, w.Code)
		})
	}
}

func TestGetServiceScopes_Parsing(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want map[string]struct{}
	}{
		{
			name: "single scope",
			raw:  "events:publish",
			want: map[string]struct{}{"events:publish": {}},
		},
		{
			name: "multiple scopes",
			raw:  "events:publish events:consume tenants:read",
			want: map[string]struct{}{
				"events:publish": {},
				"events:consume": {},
				"tenants:read":   {},
			},
		},
		{
			name: "empty string",
			raw:  "",
			want: map[string]struct{}{},
		},
		{
			name: "extra whitespace",
			raw:  "  events:publish  tenants:read  ",
			want: map[string]struct{}{
				"events:publish": {},
				"tenants:read":   {},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseServiceScopes(tt.raw)
			assert.Equal(t, tt.want, got)
		})
	}
}
