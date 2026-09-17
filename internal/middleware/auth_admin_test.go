// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// hexxlockTenantID is the UUID value of the exampletenant platform tenant.
var hexxlockTenantID = func() uuid.UUID {
	id, _ := uuid.Parse(models.HexxlockInternalTenantID)
	return id
}()

// newAuthMW builds an AuthMiddleware with nil services (sufficient for
// RequirePlatformAdmin, RequireTenantAdmin, etc. which only inspect the
// user stored in gin context).
func newAuthMW() *AuthMiddleware {
	return NewAuthMiddleware(nil, &config.Config{})
}

// injectUser injects a CurrentUser value into the gin context using the key
// that all auth_admin middlewares expect, then calls Next.
func injectUser(user *models.CurrentUser) gin.HandlerFunc {
	return func(c *gin.Context) {
		if user != nil {
			c.Set(CurrentUserKey, user)
		}
		c.Next()
	}
}

// okHandler is a terminal handler that returns 200 OK.
var okHandler = func(c *gin.Context) { c.Status(http.StatusOK) }

// runRequest builds a simple router with the supplied middleware stack, fires
// a GET /test request, and returns the recorded response.
func runRequest(handlers ...gin.HandlerFunc) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", handlers...)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// RequirePlatformAdmin
// ---------------------------------------------------------------------------

func TestRequirePlatformAdmin_ValidPlatformAdmin_Passes(t *testing.T) {
	user := &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        hexxlockTenantID,
		Username:        "platform-admin",
		IsPlatformAdmin: true,
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequirePlatformAdmin(), okHandler)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequirePlatformAdmin_NoUserInContext_Returns401(t *testing.T) {
	m := newAuthMW()

	w := runRequest(m.RequirePlatformAdmin(), okHandler)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequirePlatformAdmin_RegularUser_Returns403(t *testing.T) {
	user := &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        uuid.New(), // a regular tenant
		Username:        "alice",
		IsPlatformAdmin: false,
		Roles:           []string{"user"},
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequirePlatformAdmin(), okHandler)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequirePlatformAdmin_FlagSetButWrongTenant_Returns403(t *testing.T) {
	// IsPlatformAdmin=true but tenant is NOT exampletenant – defense in depth
	// must still block.
	user := &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        uuid.New(), // wrong tenant
		Username:        "impersonator",
		IsPlatformAdmin: true,
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequirePlatformAdmin(), okHandler)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequirePlatformAdmin_CorrectTenantButFlagFalse_Returns403(t *testing.T) {
	user := &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        hexxlockTenantID, // correct tenant
		Username:        "staff-member",
		IsPlatformAdmin: false, // but flag not set
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequirePlatformAdmin(), okHandler)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------------------------------------------------------------------------
// RequireTenantAdmin
// ---------------------------------------------------------------------------

func TestRequireTenantAdmin_AdminRole_Passes(t *testing.T) {
	tests := []struct {
		role string
	}{
		{"admin"},
		{"org_admin"},
		{"owner"},
		{"platform_admin"},
		{"super_admin"},
		// Case-insensitive variants
		{"Admin"},
		{"OWNER"},
	}

	m := newAuthMW()

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			user := &models.CurrentUser{
				ID:       uuid.New(),
				TenantID: uuid.New(),
				Username: "admin-user",
				Roles:    []string{tt.role},
			}
			w := runRequest(injectUser(user), m.RequireTenantAdmin(), okHandler)
			assert.Equal(t, http.StatusOK, w.Code, "role %q should be recognized as admin", tt.role)
		})
	}
}

func TestRequireTenantAdmin_UserRole_Returns403(t *testing.T) {
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Username: "regular-joe",
		Roles:    []string{"user", "viewer"},
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequireTenantAdmin(), okHandler)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireTenantAdmin_NoUserInContext_Returns401(t *testing.T) {
	m := newAuthMW()

	w := runRequest(m.RequireTenantAdmin(), okHandler)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireTenantAdmin_EmptyRoles_Returns403(t *testing.T) {
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Username: "no-roles",
		Roles:    []string{},
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequireTenantAdmin(), okHandler)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------------------------------------------------------------------------
// RequireTenantAdminOrPlatformAdmin
// ---------------------------------------------------------------------------

func TestRequireTenantAdminOrPlatformAdmin_PlatformAdmin_Passes(t *testing.T) {
	user := &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        hexxlockTenantID,
		Username:        "plat-admin",
		IsPlatformAdmin: true,
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequireTenantAdminOrPlatformAdmin(), okHandler)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireTenantAdminOrPlatformAdmin_TenantAdmin_Passes(t *testing.T) {
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Username: "tenant-admin",
		Roles:    []string{"admin"},
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequireTenantAdminOrPlatformAdmin(), okHandler)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireTenantAdminOrPlatformAdmin_RegularUser_Returns403(t *testing.T) {
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Username: "regular-user",
		Roles:    []string{"viewer"},
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequireTenantAdminOrPlatformAdmin(), okHandler)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireTenantAdminOrPlatformAdmin_NoUserInContext_Returns401(t *testing.T) {
	m := newAuthMW()

	w := runRequest(m.RequireTenantAdminOrPlatformAdmin(), okHandler)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireTenantAdminOrPlatformAdmin_PlatformAdminFlagButWrongTenant_Returns403(t *testing.T) {
	// IsPlatformAdmin flag without correct exampletenant tenant must NOT pass.
	user := &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        uuid.New(), // not exampletenant
		Username:        "faker",
		IsPlatformAdmin: true,
		Roles:           []string{},
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequireTenantAdminOrPlatformAdmin(), okHandler)
	// Will fall through to role check; no admin roles -> 403
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------------------------------------------------------------------------
// RequirePermission (SpiceDB-primary — authzEngine is sole authority)
// ---------------------------------------------------------------------------

func TestRequirePermission_UserHasPermission_Passes(t *testing.T) {
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
	}
	m := newAuthMW()
	m.SetAuthorizationEngine(grantPermsEngine("users:read"))

	w := runRequest(injectUser(user), m.RequirePermission("users:read"), okHandler)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequirePermission_Admin_UserLacksPermission_Returns403(t *testing.T) {
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
	}
	m := newAuthMW()
	m.SetAuthorizationEngine(grantPermsEngine("users:read"))

	w := runRequest(injectUser(user), m.RequirePermission("users:delete"), okHandler)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequirePermission_Admin_NoUserInContext_Returns401(t *testing.T) {
	m := newAuthMW()
	m.SetAuthorizationEngine(grantAllEngine())

	w := runRequest(m.RequirePermission("users:read"), okHandler)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// RequireRole
// ---------------------------------------------------------------------------

func TestRequireRole_Admin_UserHasRole_Passes(t *testing.T) {
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"admin", "user"},
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequireRole("admin"), okHandler)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireRole_Admin_UserLacksRole_Returns403(t *testing.T) {
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"user"},
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequireRole("admin"), okHandler)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireRole_NoUserInContext_Returns401(t *testing.T) {
	m := newAuthMW()

	w := runRequest(m.RequireRole("admin"), okHandler)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireRole_MultipleRolesAnyMatch_Passes(t *testing.T) {
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"moderator"},
	}
	m := newAuthMW()

	w := runRequest(injectUser(user), m.RequireRole("admin", "moderator"), okHandler)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// GetCurrentUser helper
// ---------------------------------------------------------------------------

func TestGetCurrentUser_ReturnsUser(t *testing.T) {
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Username: "test",
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(CurrentUserKey, user)

	got := GetCurrentUser(c)
	assert.Equal(t, user, got)
}

func TestGetCurrentUser_NoUser_ReturnsNil(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	got := GetCurrentUser(c)
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// RequireAllPermissions (SpiceDB-primary)
// ---------------------------------------------------------------------------

func TestRequireAllPermissions_AllPresent_Passes(t *testing.T) {
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
	}
	m := newAuthMW()
	m.SetAuthorizationEngine(grantPermsEngine("read", "write", "delete"))

	w := runRequest(injectUser(user), m.RequireAllPermissions("read", "write"), okHandler)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireAllPermissions_SomeMissing_Returns403(t *testing.T) {
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
	}
	m := newAuthMW()
	m.SetAuthorizationEngine(grantPermsEngine("read")) // missing "write"

	w := runRequest(injectUser(user), m.RequireAllPermissions("read", "write"), okHandler)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
