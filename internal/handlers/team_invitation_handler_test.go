// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TestTeamInvitationHandler_CreateInvitation_Unauthorized tests the 401 path.
func TestTeamInvitationHandler_CreateInvitation_Unauthorized(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	r := gin.New()
	r.POST("/invitations", h.CreateInvitation)

	body, _ := json.Marshal(models.CreateTeamInvitationRequest{
		Email:   "test@example.com",
		RoleIDs: []uuid.UUID{uuid.New()},
	})
	req := httptest.NewRequest(http.MethodPost, "/invitations", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestTeamInvitationHandler_CreateInvitation_InvalidEmail tests 400 on bad email.
func TestTeamInvitationHandler_CreateInvitation_InvalidEmail(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	user := &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New(), Permissions: []string{"*"}}

	r := gin.New()
	r.Use(injectCurrentUser(user))
	r.POST("/invitations", h.CreateInvitation)

	body, _ := json.Marshal(map[string]interface{}{
		"email":   "not-an-email",
		"roleIds": []string{uuid.New().String()},
	})
	req := httptest.NewRequest(http.MethodPost, "/invitations", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestTeamInvitationHandler_CreateInvitation_BlankCanonicalEmail(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	user := &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New(), Permissions: []string{"*"}}
	r := gin.New()
	r.Use(injectCurrentUser(user))
	r.POST("/invitations", h.CreateInvitation)

	body, _ := json.Marshal(map[string]interface{}{"email": " \t ", "roleIds": []string{uuid.New().String()}})
	req := httptest.NewRequest(http.MethodPost, "/invitations", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for blank canonical email, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestTeamInvitationHandler_CreateInvitation_RejectsImpersonation(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	r := gin.New()
	r.Use(injectCurrentUser(&models.CurrentUser{ID: uuid.New(), TenantID: uuid.New(), Permissions: []string{"*"}}))
	r.Use(func(c *gin.Context) { c.Set("impersonator_id", uuid.New()); c.Next() })
	r.POST("/invitations", h.CreateInvitation)
	req := httptest.NewRequest(http.MethodPost, "/invitations", bytes.NewBufferString(`{"email":"member@example.test","roleIds":["`+uuid.NewString()+`"]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 during impersonation, got %d", w.Code)
	}
}

// Every team mutation rejects impersonation before touching its repository or
// service dependency. Nil dependencies deliberately make an accidental call a
// panic, which is a stronger assertion than a passive mock expectation.
func TestTeamInvitationHandler_MutationsRejectImpersonationBeforeDependencies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	user := &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New(), Permissions: []string{"*"}}
	cases := []struct {
		name, method, path, body string
		bind                     func(*handlers.TeamInvitationHandler) gin.HandlerFunc
	}{
		{"create", http.MethodPost, "/invitations", `{"email":"member@example.test","roleIds":[]}`, func(h *handlers.TeamInvitationHandler) gin.HandlerFunc { return h.CreateInvitation }},
		{"resend", http.MethodPost, "/invitations/" + uuid.NewString() + "/actions/resend", "", func(h *handlers.TeamInvitationHandler) gin.HandlerFunc { return h.ResendInvitation }},
		{"revoke", http.MethodDelete, "/invitations/" + uuid.NewString(), "", func(h *handlers.TeamInvitationHandler) gin.HandlerFunc { return h.RevokeInvitation }},
		{"accept", http.MethodPost, "/invitations/accept", `{"token":"token"}`, func(h *handlers.TeamInvitationHandler) gin.HandlerFunc { return h.AcceptInvitation }},
		{"decline", http.MethodPost, "/invitations/decline", `{"token":"token"}`, func(h *handlers.TeamInvitationHandler) gin.HandlerFunc { return h.DeclineInvitation }},
		{"set roles", http.MethodPost, "/users/" + uuid.NewString() + "/roles", `{"roleIds":[]}`, func(h *handlers.TeamInvitationHandler) gin.HandlerFunc { return h.SetUserRoles }},
		{"deactivate", http.MethodDelete, "/users/" + uuid.NewString(), "", func(h *handlers.TeamInvitationHandler) gin.HandlerFunc { return h.DeactivateUser }},
		{"reactivate", http.MethodPost, "/users/" + uuid.NewString() + "/reactivate", "", func(h *handlers.TeamInvitationHandler) gin.HandlerFunc { return h.ReactivateUser }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
			r := gin.New()
			r.Use(injectCurrentUser(user))
			r.Use(func(c *gin.Context) { c.Set("impersonator_id", uuid.New()); c.Next() })
			switch tc.name {
			case "create":
				r.POST("/invitations", tc.bind(h))
			case "resend":
				r.POST("/invitations/:id/actions/resend", tc.bind(h))
			case "revoke":
				r.DELETE("/invitations/:id", tc.bind(h))
			case "accept":
				r.POST("/invitations/accept", tc.bind(h))
			case "decline":
				r.POST("/invitations/decline", tc.bind(h))
			case "set roles":
				r.POST("/users/:id/roles", tc.bind(h))
			case "deactivate":
				r.DELETE("/users/:id", tc.bind(h))
			default:
				r.POST("/users/:id/reactivate", tc.bind(h))
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			r.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestTeamInvitationHandler_ListInvitations_RejectsInvalidStatusAndOverflow(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	r := gin.New()
	r.Use(injectCurrentUser(&models.CurrentUser{ID: uuid.New(), TenantID: uuid.New(), Permissions: []string{"*"}}))
	r.GET("/invitations", h.ListInvitations)
	for _, target := range []string{"/invitations?status=deleted", "/invitations?page=999999999999999999999"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", target, w.Code)
		}
	}
}

// TestTeamInvitationHandler_AcceptInvitation_Unauthorized tests 401 path.
func TestTeamInvitationHandler_AcceptInvitation_Unauthorized(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	r := gin.New()
	r.POST("/invitations/accept", h.AcceptInvitation)

	body, _ := json.Marshal(models.AcceptTeamInvitationRequest{Token: "sometoken"})
	req := httptest.NewRequest(http.MethodPost, "/invitations/accept", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestTeamInvitationHandler_DeclineInvitation_Unauthorized tests 401 path.
//
// Control: DeclineInvitation must reject an unauthenticated caller the same
// way AcceptInvitation does (no currentUser in context) — a handler that
// forgot this check would happily 200/400 here instead of 401, which is
// exactly the class of gap this test exists to catch.
func TestTeamInvitationHandler_DeclineInvitation_Unauthorized(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	r := gin.New()
	r.POST("/invitations/decline", h.DeclineInvitation)

	body, _ := json.Marshal(models.AcceptTeamInvitationRequest{Token: "sometoken"})
	req := httptest.NewRequest(http.MethodPost, "/invitations/decline", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestTeamInvitationHandler_RevokeInvitation_Unauthorized tests 401 path.
func TestTeamInvitationHandler_RevokeInvitation_Unauthorized(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	r := gin.New()
	r.DELETE("/invitations/:id", h.RevokeInvitation)

	req := httptest.NewRequest(http.MethodDelete, "/invitations/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestTeamInvitationHandler_RevokeInvitation_InvalidID tests 400 on malformed UUID.
func TestTeamInvitationHandler_RevokeInvitation_InvalidID(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	user := &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New(), Permissions: []string{"*"}}

	r := gin.New()
	r.Use(injectCurrentUser(user))
	r.DELETE("/invitations/:id", h.RevokeInvitation)

	req := httptest.NewRequest(http.MethodDelete, "/invitations/not-a-uuid", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestTeamInvitationHandler_RevokeInvitation_NoLocalPermissionGate_V2Token is
// a control for the 2026-09-18 fix. requireTeamPermission used to call
// currentUser.HasPermission(permInvitationDelete) and return 403 "forbidden"
// on failure — but CurrentUser.Permissions is nil for a v2 (SpiceDB) token
// (nil here, same as the zero value produced by
// token_service_validation.go/extractSpiceDBClaims), so that local re-check
// denied every v2-token caller unconditionally regardless of their real
// SpiceDB grant. DELETE /api/v1/invitations/:id is already gated by
// authMiddleware.RequirePermission(permIAMInvitationsDelete) in
// cmd/routes.go — a real, SpiceDB-backed decision — so the handler must
// fall through to its own id-validation logic instead of re-denying.
//
// Before the fix this returned 403 without ever reaching id validation.
// After the fix, an invalid id reaches the (still-enforced) 400 branch.
func TestTeamInvitationHandler_RevokeInvitation_NoLocalPermissionGate_V2Token(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	r := gin.New()
	r.Use(injectCurrentUser(&models.CurrentUser{ID: uuid.New(), TenantID: uuid.New(), Permissions: nil}))
	r.DELETE("/invitations/:id", h.RevokeInvitation)

	req := httptest.NewRequest(http.MethodDelete, "/invitations/not-a-uuid", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (past the removed local permission gate) for an invalid id, got %d: %s", w.Code, w.Body.String())
	}
}

// TestTeamInvitationHandler_ListInvitations_Unauthorized tests 401 path.
func TestTeamInvitationHandler_ListInvitations_Unauthorized(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	r := gin.New()
	r.GET("/invitations", h.ListInvitations)

	req := httptest.NewRequest(http.MethodGet, "/invitations", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestTeamInvitationHandler_DeactivateUser_SelfDeactivation tests 400 on self-deactivation.
func TestTeamInvitationHandler_DeactivateUser_SelfDeactivation(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTeamInvitationHandler(nil, nil, nil, nil, nil, zap.NewNop())
	userID := uuid.New()
	user := &models.CurrentUser{ID: userID, TenantID: uuid.New(), Permissions: []string{"*"}}

	r := gin.New()
	r.Use(injectCurrentUser(user))
	r.DELETE("/users/:id", h.DeactivateUser)

	req := httptest.NewRequest(http.MethodDelete, "/users/"+userID.String(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for self-deactivation, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestTeamInvitation_IsValid exercises the IsValid method on the model.
func TestTeamInvitation_IsValid(t *testing.T) {
	t.Parallel()

	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-time.Second)

	cases := []struct {
		name      string
		status    models.TeamInvitationStatus
		expiresAt time.Time
		want      bool
	}{
		{"pending + future", models.TeamInvitationStatusPending, future, true},
		{"accepted + future", models.TeamInvitationStatusAccepted, future, false},
		{"revoked + future", models.TeamInvitationStatusRevoked, future, false},
		{"expired status + future", models.TeamInvitationStatusExpired, future, false},
		{"pending + past expires", models.TeamInvitationStatusPending, past, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			inv := models.TeamInvitation{
				ID:        uuid.New(),
				TenantID:  uuid.New(),
				Email:     "test@example.com",
				Status:    tc.status,
				ExpiresAt: tc.expiresAt,
			}
			if got := inv.IsValid(); got != tc.want {
				t.Errorf("IsValid()=%v, want %v (status=%q)", got, tc.want, tc.status)
			}
		})
	}
}
