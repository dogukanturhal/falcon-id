// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestBridgeServiceTenantToTenantID — locks down the tenant-source
// substitution that lets /api/v1/internal/oauth-clients reuse the
// existing admin handlers (which call middleware.GetTenantID via
// TenantIDKey) without forking handler logic.
//
// The bridge MUST 400 when the service JWT carried no tenant_id (a
// post-Bug-1+2 invariant violation), and MUST set TenantIDKey when it
// did so the downstream handler succeeds.
func TestBridgeServiceTenantToTenantID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()

	tests := []struct {
		name           string
		seedCtx        func(c *gin.Context)
		wantStatus     int
		wantTenantSet  bool
		wantTenantUUID uuid.UUID
	}{
		{
			name: "valid service tenant → promotes to TenantIDKey",
			seedCtx: func(c *gin.Context) {
				c.Set(CtxKeyServiceTenantID, tenantID.String())
			},
			wantStatus:     http.StatusOK,
			wantTenantSet:  true,
			wantTenantUUID: tenantID,
		},
		{
			name: "missing service tenant → 400",
			seedCtx: func(c *gin.Context) {
				// nothing set
			},
			wantStatus:    http.StatusBadRequest,
			wantTenantSet: false,
		},
		{
			name: "empty string service tenant → 400",
			seedCtx: func(c *gin.Context) {
				c.Set(CtxKeyServiceTenantID, "")
			},
			wantStatus:    http.StatusBadRequest,
			wantTenantSet: false,
		},
		{
			name: "non-UUID service tenant → 400 (defensive — tenant claim shape invariant)",
			seedCtx: func(c *gin.Context) {
				c.Set(CtxKeyServiceTenantID, "not-a-uuid")
			},
			wantStatus:    http.StatusBadRequest,
			wantTenantSet: false,
		},
		{
			name: "wrong type service tenant → 400",
			seedCtx: func(c *gin.Context) {
				c.Set(CtxKeyServiceTenantID, 12345)
			},
			wantStatus:    http.StatusBadRequest,
			wantTenantSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(func(c *gin.Context) {
				tt.seedCtx(c)
				c.Next()
			})
			r.Use(BridgeServiceTenantToTenantID())

			var observedTenant uuid.UUID
			var observedTenantSet bool
			r.GET("/x", func(c *gin.Context) {
				v, exists := c.Get(TenantIDKey)
				observedTenantSet = exists
				if exists {
					if id, ok := v.(uuid.UUID); ok {
						observedTenant = id
					}
				}
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code, "status mismatch")
			if tt.wantTenantSet {
				assert.True(t, observedTenantSet, "TenantIDKey should be set for downstream handler")
				assert.Equal(t, tt.wantTenantUUID, observedTenant, "promoted tenant UUID mismatch")
			} else {
				assert.False(t, observedTenantSet, "handler should not have run when bridge aborts")
			}
		})
	}
}
