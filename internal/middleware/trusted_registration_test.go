// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestTrustedRegistration_SetsContextFlag — locks down the contract
// that the OAuth-client handlers depend on: when this middleware is
// mounted on a route, downstream handlers see the
// CtxKeyTrustedRegistration flag as true. When it is NOT mounted, the
// flag is absent (so c.GetBool returns false).
func TestTrustedRegistration_SetsContextFlag(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("middleware mounted → flag true", func(t *testing.T) {
		var observed bool
		var observedExists bool

		r := gin.New()
		r.Use(TrustedRegistration())
		r.GET("/x", func(c *gin.Context) {
			v, exists := c.Get(CtxKeyTrustedRegistration)
			observedExists = exists
			if exists {
				observed, _ = v.(bool)
			}
			c.Status(200)
		})

		req := httptest.NewRequest("GET", "/x", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		assert.True(t, observedExists, "TrustedRegistration must set the context key")
		assert.True(t, observed, "flag must be true on the trusted route")
		assert.Equal(t, 200, rec.Code)
	})

	t.Run("middleware NOT mounted → flag absent", func(t *testing.T) {
		var observedExists bool
		var observedFalse bool

		r := gin.New()
		r.GET("/x", func(c *gin.Context) {
			_, observedExists = c.Get(CtxKeyTrustedRegistration)
			// c.GetBool returns false when key is absent — that's the
			// contract the handler gate relies on (no panic, no
			// "untrusted means absent" ambiguity).
			observedFalse = !c.GetBool(CtxKeyTrustedRegistration)
			c.Status(200)
		})

		req := httptest.NewRequest("GET", "/x", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		assert.False(t, observedExists, "absent middleware must leave the key absent")
		assert.True(t, observedFalse, "c.GetBool must return false for the absent key (handler default-deny)")
		assert.Equal(t, 200, rec.Code)
	})
}
