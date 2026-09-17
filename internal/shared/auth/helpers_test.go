// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newTestContext creates a bare gin.Context backed by an httptest.ResponseRecorder.
// Values can be injected directly with c.Set() before calling the function under test.
func newTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	return c, w
}

// newTestUser builds a fully populated CurrentUser for use in helper tests.
func newTestUser() *CurrentUser {
	return &CurrentUser{
		ID:          uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		TenantID:    uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		Username:    "testuser",
		Email:       "test@example.com",
		Roles:       []string{"admin", "editor"},
		Permissions: []string{"core:users:read", "core:users:write", "billing:invoices:read"},
		SessionID:   uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
		AuthMethod:  AuthMethodJWT,
		ServiceName: "",
	}
}

// ============================================================================
// GetCurrentUser
// ============================================================================

func TestGetCurrentUser(t *testing.T) {
	t.Run("returns CurrentUser when set", func(t *testing.T) {
		c, _ := newTestContext()
		user := newTestUser()
		c.Set(CurrentUserKey, user)

		got := GetCurrentUser(c)
		require.NotNil(t, got)
		assert.Equal(t, user.ID, got.ID)
		assert.Equal(t, user.TenantID, got.TenantID)
	})

	t.Run("returns nil when key not set", func(t *testing.T) {
		c, _ := newTestContext()

		got := GetCurrentUser(c)
		assert.Nil(t, got)
	})

	t.Run("returns nil when wrong type stored", func(t *testing.T) {
		c, _ := newTestContext()
		c.Set(CurrentUserKey, "not-a-current-user")

		got := GetCurrentUser(c)
		assert.Nil(t, got)
	})
}

// ============================================================================
// GetTenantID
// ============================================================================

func TestGetTenantID(t *testing.T) {
	validTenantID := uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd")

	tests := []struct {
		name   string
		setup  func(c *gin.Context)
		wantID uuid.UUID
		wantOK bool
	}{
		{
			name: "from context as uuid.UUID",
			setup: func(c *gin.Context) {
				c.Set(TenantIDKey, validTenantID)
			},
			wantID: validTenantID,
			wantOK: true,
		},
		{
			name: "from context as valid string",
			setup: func(c *gin.Context) {
				c.Set(TenantIDKey, validTenantID.String())
			},
			wantID: validTenantID,
			wantOK: true,
		},
		{
			name: "from context as invalid string returns false",
			setup: func(c *gin.Context) {
				c.Set(TenantIDKey, "not-a-uuid")
			},
			wantID: uuid.Nil,
			wantOK: false,
		},
		{
			name: "from CurrentUser when context key absent",
			setup: func(c *gin.Context) {
				user := newTestUser()
				c.Set(CurrentUserKey, user)
			},
			wantID: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
			wantOK: true,
		},
		{
			name: "from CurrentUser skipped when TenantID is Nil",
			setup: func(c *gin.Context) {
				user := &CurrentUser{
					ID:       uuid.New(),
					TenantID: uuid.Nil,
				}
				c.Set(CurrentUserKey, user)
			},
			wantID: uuid.Nil,
			wantOK: false,
		},
		{
			name:   "missing entirely returns uuid.Nil and false",
			setup:  func(_ *gin.Context) {},
			wantID: uuid.Nil,
			wantOK: false,
		},
		{
			name: "context UUID takes precedence over CurrentUser",
			setup: func(c *gin.Context) {
				// Both the direct key and a CurrentUser are set; direct key wins.
				c.Set(TenantIDKey, validTenantID)
				user := newTestUser() // user has a different TenantID
				c.Set(CurrentUserKey, user)
			},
			wantID: validTenantID,
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestContext()
			tt.setup(c)

			gotID, gotOK := GetTenantID(c)
			assert.Equal(t, tt.wantID, gotID)
			assert.Equal(t, tt.wantOK, gotOK)
		})
	}
}

// ============================================================================
// MustGetTenantID
// ============================================================================

func TestMustGetTenantID(t *testing.T) {
	t.Run("returns tenant ID when present", func(t *testing.T) {
		c, _ := newTestContext()
		tenantID := uuid.MustParse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
		c.Set(TenantIDKey, tenantID)

		got := MustGetTenantID(c)
		assert.Equal(t, tenantID, got)
		// Request should not have been aborted
		assert.False(t, c.IsAborted())
	})

	t.Run("aborts with 500 when tenant ID missing", func(t *testing.T) {
		c, w := newTestContext()

		got := MustGetTenantID(c)

		assert.Equal(t, uuid.Nil, got)
		assert.True(t, c.IsAborted())
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var body map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &body)
		require.NoError(t, err)
		assert.Equal(t, "TENANT_CONTEXT_MISSING", body["code"])
	})
}

// ============================================================================
// GetUserID
// ============================================================================

func TestGetUserID(t *testing.T) {
	validUserID := uuid.MustParse("ffffffff-ffff-4fff-8fff-ffffffffffff")

	tests := []struct {
		name   string
		setup  func(c *gin.Context)
		wantID *uuid.UUID
	}{
		{
			name: "from context as uuid.UUID",
			setup: func(c *gin.Context) {
				c.Set(UserIDKey, validUserID)
			},
			wantID: &validUserID,
		},
		{
			name: "from context as valid string",
			setup: func(c *gin.Context) {
				c.Set(UserIDKey, validUserID.String())
			},
			wantID: &validUserID,
		},
		{
			name: "from context as invalid string returns nil",
			setup: func(c *gin.Context) {
				c.Set(UserIDKey, "garbage")
			},
			wantID: nil,
		},
		{
			name: "from CurrentUser when context key absent",
			setup: func(c *gin.Context) {
				user := newTestUser()
				c.Set(CurrentUserKey, user)
			},
			wantID: func() *uuid.UUID {
				id := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
				return &id
			}(),
		},
		{
			name: "from CurrentUser skipped when ID is Nil",
			setup: func(c *gin.Context) {
				user := &CurrentUser{ID: uuid.Nil}
				c.Set(CurrentUserKey, user)
			},
			wantID: nil,
		},
		{
			name:   "returns nil when nothing set",
			setup:  func(_ *gin.Context) {},
			wantID: nil,
		},
		{
			name: "context UUID takes precedence over CurrentUser",
			setup: func(c *gin.Context) {
				c.Set(UserIDKey, validUserID)
				c.Set(CurrentUserKey, newTestUser())
			},
			wantID: &validUserID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestContext()
			tt.setup(c)

			got := GetUserID(c)
			if tt.wantID == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, *tt.wantID, *got)
			}
		})
	}
}

// ============================================================================
// GetSessionID
// ============================================================================

func TestGetSessionID(t *testing.T) {
	validSessionID := uuid.MustParse("11111111-1111-4111-8111-111111111111")

	tests := []struct {
		name      string
		setup     func(c *gin.Context)
		wantNil   bool
		wantValue uuid.UUID
	}{
		{
			name: "from context as uuid.UUID",
			setup: func(c *gin.Context) {
				c.Set(SessionIDKey, validSessionID)
			},
			wantNil:   false,
			wantValue: validSessionID,
		},
		{
			name: "from context as valid string",
			setup: func(c *gin.Context) {
				c.Set(SessionIDKey, validSessionID.String())
			},
			wantNil:   false,
			wantValue: validSessionID,
		},
		{
			name: "from context as invalid string returns nil",
			setup: func(c *gin.Context) {
				c.Set(SessionIDKey, "not-a-uuid")
			},
			wantNil: true,
		},
		{
			name: "from CurrentUser when context key absent",
			setup: func(c *gin.Context) {
				user := newTestUser() // SessionID = cccccccc-...
				c.Set(CurrentUserKey, user)
			},
			wantNil:   false,
			wantValue: uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
		},
		{
			name: "from CurrentUser skipped when SessionID is Nil",
			setup: func(c *gin.Context) {
				user := &CurrentUser{SessionID: uuid.Nil}
				c.Set(CurrentUserKey, user)
			},
			wantNil: true,
		},
		{
			name:    "returns nil when nothing set",
			setup:   func(_ *gin.Context) {},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestContext()
			tt.setup(c)

			got := GetSessionID(c)
			if tt.wantNil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.wantValue, *got)
			}
		})
	}
}

// ============================================================================
// GetClaims
// ============================================================================

func TestGetClaims(t *testing.T) {
	t.Run("returns Claims when set", func(t *testing.T) {
		c, _ := newTestContext()
		claims := &Claims{
			UserID:   uuid.New(),
			TenantID: uuid.New(),
			Username: "claimuser",
			Email:    "claim@example.com",
		}
		c.Set(ClaimsKey, claims)

		got := GetClaims(c)
		require.NotNil(t, got)
		assert.Equal(t, claims.UserID, got.UserID)
		assert.Equal(t, claims.Username, got.Username)
	})

	t.Run("returns nil when key not set", func(t *testing.T) {
		c, _ := newTestContext()
		assert.Nil(t, GetClaims(c))
	})

	t.Run("returns nil when wrong type stored", func(t *testing.T) {
		c, _ := newTestContext()
		c.Set(ClaimsKey, "wrong-type")
		assert.Nil(t, GetClaims(c))
	})
}

// ============================================================================
// GetAuthMethod
// ============================================================================

func TestGetAuthMethod(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(c *gin.Context)
		wantOK AuthMethod
	}{
		{
			name: "returns JWT method when set",
			setup: func(c *gin.Context) {
				c.Set(AuthMethodKey, AuthMethodJWT)
			},
			wantOK: AuthMethodJWT,
		},
		{
			name: "returns API key method when set",
			setup: func(c *gin.Context) {
				c.Set(AuthMethodKey, AuthMethodAPIKey)
			},
			wantOK: AuthMethodAPIKey,
		},
		{
			name: "returns service account method when set",
			setup: func(c *gin.Context) {
				c.Set(AuthMethodKey, AuthMethodServiceAccount)
			},
			wantOK: AuthMethodServiceAccount,
		},
		{
			name:   "returns empty string when key not set",
			setup:  func(_ *gin.Context) {},
			wantOK: "",
		},
		{
			name: "returns empty string when wrong type stored",
			setup: func(c *gin.Context) {
				c.Set(AuthMethodKey, 42) // wrong type
			},
			wantOK: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestContext()
			tt.setup(c)
			assert.Equal(t, tt.wantOK, GetAuthMethod(c))
		})
	}
}

// ============================================================================
// IsServiceAuth / IsJWTAuth
// ============================================================================

func TestIsServiceAuth(t *testing.T) {
	tests := []struct {
		name   string
		method AuthMethod
		want   bool
	}{
		{"true for API key", AuthMethodAPIKey, true},
		{"false for JWT", AuthMethodJWT, false},
		{"false for service account", AuthMethodServiceAccount, false},
		{"false when not set", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestContext()
			if tt.method != "" {
				c.Set(AuthMethodKey, tt.method)
			}
			assert.Equal(t, tt.want, IsServiceAuth(c))
		})
	}
}

func TestIsJWTAuth(t *testing.T) {
	tests := []struct {
		name   string
		method AuthMethod
		want   bool
	}{
		{"true for JWT", AuthMethodJWT, true},
		{"false for API key", AuthMethodAPIKey, false},
		{"false for service account", AuthMethodServiceAccount, false},
		{"false when not set", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestContext()
			if tt.method != "" {
				c.Set(AuthMethodKey, tt.method)
			}
			assert.Equal(t, tt.want, IsJWTAuth(c))
		})
	}
}

// ============================================================================
// IsImpersonated / GetImpersonatorID
// ============================================================================

func TestIsImpersonated(t *testing.T) {
	impersonatorID := uuid.New()

	t.Run("true when ImpersonatorID UUID set", func(t *testing.T) {
		c, _ := newTestContext()
		c.Set(ImpersonatorIDKey, impersonatorID)
		assert.True(t, IsImpersonated(c))
	})

	t.Run("true when ImpersonatorID string set", func(t *testing.T) {
		c, _ := newTestContext()
		c.Set(ImpersonatorIDKey, impersonatorID.String())
		assert.True(t, IsImpersonated(c))
	})

	t.Run("false when not set", func(t *testing.T) {
		c, _ := newTestContext()
		assert.False(t, IsImpersonated(c))
	})
}

func TestGetImpersonatorID(t *testing.T) {
	impersonatorID := uuid.MustParse("22222222-2222-4222-8222-222222222222")

	tests := []struct {
		name    string
		setup   func(c *gin.Context)
		wantNil bool
		wantVal uuid.UUID
	}{
		{
			name: "from context as uuid.UUID",
			setup: func(c *gin.Context) {
				c.Set(ImpersonatorIDKey, impersonatorID)
			},
			wantNil: false,
			wantVal: impersonatorID,
		},
		{
			name: "from context as valid string",
			setup: func(c *gin.Context) {
				c.Set(ImpersonatorIDKey, impersonatorID.String())
			},
			wantNil: false,
			wantVal: impersonatorID,
		},
		{
			name: "returns nil for invalid string",
			setup: func(c *gin.Context) {
				c.Set(ImpersonatorIDKey, "not-a-uuid")
			},
			wantNil: true,
		},
		{
			name:    "returns nil when not set",
			setup:   func(_ *gin.Context) {},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestContext()
			tt.setup(c)

			got := GetImpersonatorID(c)
			if tt.wantNil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.wantVal, *got)
			}
		})
	}
}

// ============================================================================
// HasPermission
// ============================================================================

func TestHasPermission(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(c *gin.Context)
		permission string
		want       bool
	}{
		{
			name: "user has exact permission",
			setup: func(c *gin.Context) {
				user := &CurrentUser{Permissions: []string{"core:users:read"}}
				c.Set(CurrentUserKey, user)
			},
			permission: "core:users:read",
			want:       true,
		},
		{
			name: "user lacks permission",
			setup: func(c *gin.Context) {
				user := &CurrentUser{Permissions: []string{"core:users:read"}}
				c.Set(CurrentUserKey, user)
			},
			permission: "core:users:delete",
			want:       false,
		},
		{
			name: "user has wildcard grants all",
			setup: func(c *gin.Context) {
				user := &CurrentUser{Permissions: []string{"*"}}
				c.Set(CurrentUserKey, user)
			},
			permission: "anything:at:all",
			want:       true,
		},
		{
			name: "user has scoped wildcard",
			setup: func(c *gin.Context) {
				user := &CurrentUser{Permissions: []string{"core:users:*"}}
				c.Set(CurrentUserKey, user)
			},
			permission: "core:users:write",
			want:       true,
		},
		{
			name: "scoped wildcard does not match other namespace",
			setup: func(c *gin.Context) {
				user := &CurrentUser{Permissions: []string{"core:users:*"}}
				c.Set(CurrentUserKey, user)
			},
			permission: "billing:users:write",
			want:       false,
		},
		{
			name:       "no user in context returns false",
			setup:      func(_ *gin.Context) {},
			permission: "core:users:read",
			want:       false,
		},
		{
			name: "nil permissions slice returns false",
			setup: func(c *gin.Context) {
				user := &CurrentUser{Permissions: nil}
				c.Set(CurrentUserKey, user)
			},
			permission: "core:users:read",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestContext()
			tt.setup(c)
			assert.Equal(t, tt.want, HasPermission(c, tt.permission))
		})
	}
}

// ============================================================================
// HasRole
// ============================================================================

func TestHasRole(t *testing.T) {
	tests := []struct {
		name  string
		setup func(c *gin.Context)
		role  string
		want  bool
	}{
		{
			name: "user has role",
			setup: func(c *gin.Context) {
				user := &CurrentUser{Roles: []string{"admin", "editor"}}
				c.Set(CurrentUserKey, user)
			},
			role: "admin",
			want: true,
		},
		{
			name: "user lacks role",
			setup: func(c *gin.Context) {
				user := &CurrentUser{Roles: []string{"editor"}}
				c.Set(CurrentUserKey, user)
			},
			role: "admin",
			want: false,
		},
		{
			name: "empty roles returns false",
			setup: func(c *gin.Context) {
				user := &CurrentUser{Roles: []string{}}
				c.Set(CurrentUserKey, user)
			},
			role: "admin",
			want: false,
		},
		{
			name:  "no user in context returns false",
			setup: func(_ *gin.Context) {},
			role:  "admin",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestContext()
			tt.setup(c)
			assert.Equal(t, tt.want, HasRole(c, tt.role))
		})
	}
}

// ============================================================================
// HasAnyPermission
// ============================================================================

func TestHasAnyPermission(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		userPerms   []string
		setUser     bool
		want        bool
	}{
		{
			name:        "at least one permission matches",
			userPerms:   []string{"core:users:read"},
			setUser:     true,
			permissions: []string{"core:users:read", "core:users:write"},
			want:        true,
		},
		{
			name:        "no permissions match",
			userPerms:   []string{"billing:read"},
			setUser:     true,
			permissions: []string{"core:users:read", "core:users:write"},
			want:        false,
		},
		{
			name:        "wildcard satisfies any",
			userPerms:   []string{"*"},
			setUser:     true,
			permissions: []string{"any:permission:here"},
			want:        true,
		},
		{
			name:        "empty required permissions list returns false",
			userPerms:   []string{"core:users:read"},
			setUser:     true,
			permissions: []string{},
			want:        false,
		},
		{
			name:        "no user returns false",
			setUser:     false,
			permissions: []string{"core:users:read"},
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestContext()
			if tt.setUser {
				user := &CurrentUser{Permissions: tt.userPerms}
				c.Set(CurrentUserKey, user)
			}
			assert.Equal(t, tt.want, HasAnyPermission(c, tt.permissions...))
		})
	}
}

// ============================================================================
// HasAllPermissions
// ============================================================================

func TestHasAllPermissions(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		userPerms   []string
		setUser     bool
		want        bool
	}{
		{
			name:        "user has all required permissions",
			userPerms:   []string{"core:users:read", "core:users:write"},
			setUser:     true,
			permissions: []string{"core:users:read", "core:users:write"},
			want:        true,
		},
		{
			name:        "user missing one permission returns false",
			userPerms:   []string{"core:users:read"},
			setUser:     true,
			permissions: []string{"core:users:read", "core:users:write"},
			want:        false,
		},
		{
			name:        "wildcard satisfies all",
			userPerms:   []string{"*"},
			setUser:     true,
			permissions: []string{"core:users:read", "billing:invoices:write"},
			want:        true,
		},
		{
			name:        "empty required permissions list returns true",
			userPerms:   []string{"core:users:read"},
			setUser:     true,
			permissions: []string{},
			want:        true,
		},
		{
			name:        "no user returns false",
			setUser:     false,
			permissions: []string{"core:users:read"},
			want:        false,
		},
		{
			name:        "namespace wildcard satisfies all in same namespace",
			userPerms:   []string{"core:users:*"},
			setUser:     true,
			permissions: []string{"core:users:read", "core:users:write"},
			want:        true,
		},
		{
			name:        "namespace wildcard does not satisfy cross-namespace",
			userPerms:   []string{"core:users:*"},
			setUser:     true,
			permissions: []string{"core:users:read", "billing:invoices:write"},
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestContext()
			if tt.setUser {
				user := &CurrentUser{Permissions: tt.userPerms}
				c.Set(CurrentUserKey, user)
			}
			assert.Equal(t, tt.want, HasAllPermissions(c, tt.permissions...))
		})
	}
}

// ============================================================================
// GetServiceName
// ============================================================================

func TestGetServiceName(t *testing.T) {
	tests := []struct {
		name  string
		setup func(c *gin.Context)
		want  string
	}{
		{
			name: "from context ServiceNameKey",
			setup: func(c *gin.Context) {
				c.Set(ServiceNameKey, "billing")
			},
			want: "billing",
		},
		{
			name: "from CurrentUser.ServiceName when context key absent",
			setup: func(c *gin.Context) {
				user := &CurrentUser{
					ServiceName: "invoicing",
					AuthMethod:  AuthMethodAPIKey,
				}
				c.Set(CurrentUserKey, user)
			},
			want: "invoicing",
		},
		{
			name:  "returns empty string when nothing set",
			setup: func(_ *gin.Context) {},
			want:  "",
		},
		{
			name: "returns empty string when CurrentUser.ServiceName is empty",
			setup: func(c *gin.Context) {
				user := &CurrentUser{ServiceName: ""}
				c.Set(CurrentUserKey, user)
			},
			want: "",
		},
		{
			name: "context key takes precedence over CurrentUser",
			setup: func(c *gin.Context) {
				c.Set(ServiceNameKey, "direct-context-service")
				user := &CurrentUser{ServiceName: "user-service"}
				c.Set(CurrentUserKey, user)
			},
			want: "direct-context-service",
		},
		{
			name: "wrong type in context falls through to CurrentUser",
			setup: func(c *gin.Context) {
				c.Set(ServiceNameKey, 999) // wrong type - not a string
				user := &CurrentUser{ServiceName: "fallback-service"}
				c.Set(CurrentUserKey, user)
			},
			want: "fallback-service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestContext()
			tt.setup(c)
			assert.Equal(t, tt.want, GetServiceName(c))
		})
	}
}

// ============================================================================
// Integration: full auth flow via context helpers
// ============================================================================

// TestHelpers_FullJWTFlow verifies that all helpers work coherently when a
// context is populated the same way the JWT middleware populates it.
func TestHelpers_FullJWTFlow(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()
	impersonatorID := uuid.New()

	user := &CurrentUser{
		ID:          userID,
		TenantID:    tenantID,
		Username:    "alice",
		Email:       "alice@example.com",
		Roles:       []string{"admin"},
		Permissions: []string{"core:users:*", "billing:invoices:read"},
		SessionID:   sessionID,
		AuthMethod:  AuthMethodJWT,
	}

	c, _ := newTestContext()
	c.Set(CurrentUserKey, user)
	c.Set(TenantIDKey, tenantID)
	c.Set(UserIDKey, userID)
	c.Set(SessionIDKey, sessionID)
	c.Set(AuthMethodKey, AuthMethodJWT)
	c.Set(ImpersonatorIDKey, impersonatorID)

	// --- assertions ---
	gotUser := GetCurrentUser(c)
	require.NotNil(t, gotUser)
	assert.Equal(t, "alice", gotUser.Username)

	gotTenant, ok := GetTenantID(c)
	require.True(t, ok)
	assert.Equal(t, tenantID, gotTenant)

	gotMustTenant := MustGetTenantID(c)
	assert.Equal(t, tenantID, gotMustTenant)
	assert.False(t, c.IsAborted())

	gotUserID := GetUserID(c)
	require.NotNil(t, gotUserID)
	assert.Equal(t, userID, *gotUserID)

	gotSession := GetSessionID(c)
	require.NotNil(t, gotSession)
	assert.Equal(t, sessionID, *gotSession)

	assert.Equal(t, AuthMethodJWT, GetAuthMethod(c))
	assert.True(t, IsJWTAuth(c))
	assert.False(t, IsServiceAuth(c))

	assert.True(t, IsImpersonated(c))
	gotImp := GetImpersonatorID(c)
	require.NotNil(t, gotImp)
	assert.Equal(t, impersonatorID, *gotImp)

	assert.True(t, HasPermission(c, "core:users:read"))
	assert.True(t, HasPermission(c, "billing:invoices:read"))
	assert.False(t, HasPermission(c, "billing:invoices:write"))

	assert.True(t, HasRole(c, "admin"))
	assert.False(t, HasRole(c, "viewer"))

	assert.True(t, HasAnyPermission(c, "billing:invoices:write", "billing:invoices:read"))
	assert.True(t, HasAllPermissions(c, "core:users:read", "billing:invoices:read"))
	assert.False(t, HasAllPermissions(c, "core:users:read", "billing:invoices:write"))
}

// TestHelpers_FullAPIKeyFlow verifies that all helpers work correctly when a
// context is populated the same way the API key middleware populates it.
func TestHelpers_FullAPIKeyFlow(t *testing.T) {
	tenantID := uuid.New()
	serviceName := "billing"

	serviceUser := &CurrentUser{
		AuthMethod:  AuthMethodAPIKey,
		Roles:       []string{"service"},
		Permissions: []string{"billing:invoices:read", "billing:invoices:write"},
		ServiceName: serviceName,
	}

	c, _ := newTestContext()
	c.Set(AuthMethodKey, AuthMethodAPIKey)
	c.Set(ServiceNameKey, serviceName)
	c.Set(TenantIDKey, tenantID)
	c.Set(CurrentUserKey, serviceUser)

	assert.Equal(t, AuthMethodAPIKey, GetAuthMethod(c))
	assert.True(t, IsServiceAuth(c))
	assert.False(t, IsJWTAuth(c))
	assert.False(t, IsImpersonated(c))
	assert.Nil(t, GetImpersonatorID(c))
	assert.Equal(t, serviceName, GetServiceName(c))

	gotTenant, ok := GetTenantID(c)
	require.True(t, ok)
	assert.Equal(t, tenantID, gotTenant)

	assert.True(t, HasPermission(c, "billing:invoices:read"))
	assert.True(t, HasPermission(c, "billing:invoices:write"))
	assert.False(t, HasPermission(c, "core:users:read"))

	// Service user has no user ID or session ID
	assert.Nil(t, GetUserID(c))
	assert.Nil(t, GetSessionID(c))
}

// TestHelpers_ClaimsRoundtrip verifies GetClaims returns the same struct that
// was placed in the context, and that GetCurrentUser built from those claims
// reflects the same identity.
func TestHelpers_ClaimsRoundtrip(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()
	impersonatorID := uuid.New()

	claims := &Claims{
		UserID:         userID,
		TenantID:       tenantID,
		Username:       "bob",
		Email:          "bob@example.com",
		Roles:          []string{"viewer"},
		Permissions:    []string{"reports:read"},
		SessionID:      sessionID,
		ImpersonatorID: &impersonatorID,
	}

	user := NewCurrentUserFromClaims(claims)

	c, _ := newTestContext()
	c.Set(ClaimsKey, claims)
	c.Set(CurrentUserKey, user)

	gotClaims := GetClaims(c)
	require.NotNil(t, gotClaims)
	assert.Equal(t, userID, gotClaims.UserID)
	assert.Equal(t, "bob", gotClaims.Username)
	assert.True(t, gotClaims.IsImpersonated())

	gotUser := GetCurrentUser(c)
	require.NotNil(t, gotUser)
	assert.Equal(t, userID, gotUser.ID)
	assert.Equal(t, AuthMethodJWT, gotUser.AuthMethod)
}
