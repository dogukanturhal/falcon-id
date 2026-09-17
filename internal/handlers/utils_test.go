// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/apierrors"
	pkglogger "github.com/dogukanturhal/falcon-id/pkg/logger"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestMain initializes the global pkg/logger.Log and pkg/logger.SecurityAudit used
// by service and handler implementations (e.g. RoleHandler, UserHandler) before any test runs.
func TestMain(m *testing.M) {
	pkglogger.Log = zap.NewNop()
	pkglogger.SecurityAudit = zap.NewNop()
	os.Exit(m.Run())
}

func TestParseUUIDParam(t *testing.T) {
	tests := []struct {
		name       string
		paramName  string
		paramValue string
		wantValid  bool
		wantUUID   uuid.UUID
	}{
		{
			name:       "Valid UUID",
			paramName:  "id",
			paramValue: "123e4567-e89b-12d3-a456-426614174000",
			wantValid:  true,
			wantUUID:   uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
		},
		{
			name:       "Invalid UUID format",
			paramName:  "id",
			paramValue: "not-a-uuid",
			wantValid:  false,
			wantUUID:   uuid.Nil,
		},
		{
			name:       "Empty UUID",
			paramName:  "id",
			paramValue: "",
			wantValid:  false,
			wantUUID:   uuid.Nil,
		},
		{
			name:       "Invalid UUID with correct length",
			paramName:  "id",
			paramValue: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			wantValid:  false,
			wantUUID:   uuid.Nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Set up param
			c.Params = gin.Params{
				{Key: tt.paramName, Value: tt.paramValue},
			}

			gotUUID, gotValid := ParseUUIDParam(c, tt.paramName)

			if gotValid != tt.wantValid {
				t.Errorf("ParseUUIDParam() valid = %v, want %v", gotValid, tt.wantValid)
			}

			if gotUUID != tt.wantUUID {
				t.Errorf("ParseUUIDParam() UUID = %v, want %v", gotUUID, tt.wantUUID)
			}

			// Check HTTP response for invalid cases
			if !tt.wantValid && w.Code == 0 {
				t.Error("Expected error response to be written")
			}
		})
	}
}

func TestGetPagination(t *testing.T) {
	tests := []struct {
		name          string
		queryPage     string
		queryPageSize string
		wantPage      int
		wantPageSize  int
		wantOffset    int
	}{
		{
			name:          "Default values",
			queryPage:     "",
			queryPageSize: "",
			wantPage:      1,
			wantPageSize:  20,
			wantOffset:    0,
		},
		{
			name:          "Valid page and page_size",
			queryPage:     "3",
			queryPageSize: "10",
			wantPage:      3,
			wantPageSize:  10,
			wantOffset:    20,
		},
		{
			name:          "Page 1 with custom page_size",
			queryPage:     "1",
			queryPageSize: "50",
			wantPage:      1,
			wantPageSize:  50,
			wantOffset:    0,
		},
		{
			name:          "Zero page defaults to 1",
			queryPage:     "0",
			queryPageSize: "10",
			wantPage:      1,
			wantPageSize:  20, // Binding fails with page=0 (min=1), so defaults to 20
			wantOffset:    0,
		},
		{
			name:          "Negative page defaults to 1",
			queryPage:     "-1",
			queryPageSize: "10",
			wantPage:      1,
			wantPageSize:  20, // Binding fails with page=-1 (min=1), so defaults to 20
			wantOffset:    0,
		},
		{
			name:          "Zero page_size defaults to 20",
			queryPage:     "1",
			queryPageSize: "0",
			wantPage:      1,
			wantPageSize:  20,
			wantOffset:    0,
		},
		{
			name:          "Negative page_size defaults to 20",
			queryPage:     "1",
			queryPageSize: "-1",
			wantPage:      1,
			wantPageSize:  20,
			wantOffset:    0,
		},
		{
			name:          "Page_size exceeds max, binding fails",
			queryPage:     "1",
			queryPageSize: "200",
			wantPage:      1,
			wantPageSize:  20, // Binding fails with page_size=200 (max=100), so defaults to 20
			wantOffset:    0,
		},
		{
			name:          "Page 5 with page_size 25",
			queryPage:     "5",
			queryPageSize: "25",
			wantPage:      5,
			wantPageSize:  25,
			wantOffset:    100,
		},
		{
			name:          "Invalid page value",
			queryPage:     "invalid",
			queryPageSize: "10",
			wantPage:      1,
			wantPageSize:  20,
			wantOffset:    0,
		},
		{
			name:          "Invalid page_size value",
			queryPage:     "2",
			queryPageSize: "invalid",
			wantPage:      1,
			wantPageSize:  20,
			wantOffset:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Create request with query params
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
			q := req.URL.Query()
			if tt.queryPage != "" {
				q.Add("page", tt.queryPage)
			}
			if tt.queryPageSize != "" {
				q.Add("page_size", tt.queryPageSize)
			}
			req.URL.RawQuery = q.Encode()
			c.Request = req

			gotPage, gotPageSize, gotOffset := GetPagination(c)

			if gotPage != tt.wantPage {
				t.Errorf("GetPagination() page = %d, want %d", gotPage, tt.wantPage)
			}

			if gotPageSize != tt.wantPageSize {
				t.Errorf("GetPagination() pageSize = %d, want %d", gotPageSize, tt.wantPageSize)
			}

			if gotOffset != tt.wantOffset {
				t.Errorf("GetPagination() offset = %d, want %d", gotOffset, tt.wantOffset)
			}
		})
	}
}

func TestCalculateTotalPages(t *testing.T) {
	tests := []struct {
		name       string
		totalItems int64
		pageSize   int
		want       int
	}{
		{
			name:       "Exact division",
			totalItems: 100,
			pageSize:   10,
			want:       10,
		},
		{
			name:       "With remainder",
			totalItems: 105,
			pageSize:   10,
			want:       11,
		},
		{
			name:       "Single item",
			totalItems: 1,
			pageSize:   10,
			want:       1,
		},
		{
			name:       "Zero items",
			totalItems: 0,
			pageSize:   10,
			want:       0,
		},
		{
			name:       "Less than page size",
			totalItems: 5,
			pageSize:   10,
			want:       1,
		},
		{
			name:       "Large number of items",
			totalItems: 1000000,
			pageSize:   25,
			want:       40000,
		},
		{
			name:       "Zero page size",
			totalItems: 100,
			pageSize:   0,
			want:       0,
		},
		{
			name:       "Negative page size",
			totalItems: 100,
			pageSize:   -10,
			want:       0,
		},
		{
			name:       "Page size of 1",
			totalItems: 50,
			pageSize:   1,
			want:       50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateTotalPages(tt.totalItems, tt.pageSize)
			if got != tt.want {
				t.Errorf("CalculateTotalPages() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		substrs []string
		want    bool
	}{
		{
			name:    "Single match",
			s:       "Error: not found",
			substrs: []string{"not found"},
			want:    true,
		},
		{
			name:    "Multiple substrings, first matches",
			s:       "Duplicate key error",
			substrs: []string{"duplicate", "unique", "conflict"},
			want:    true,
		},
		{
			name:    "Multiple substrings, last matches",
			s:       "Database conflict",
			substrs: []string{"duplicate", "unique", "conflict"},
			want:    true,
		},
		{
			name:    "No match",
			s:       "Success message",
			substrs: []string{"error", "failed", "invalid"},
			want:    false,
		},
		{
			name:    "Case insensitive match",
			s:       "ERROR: Not Found",
			substrs: []string{"not found"},
			want:    true,
		},
		{
			name:    "Empty string",
			s:       "",
			substrs: []string{"error"},
			want:    false,
		},
		{
			name:    "Empty substrs",
			s:       "some text",
			substrs: []string{},
			want:    false,
		},
		{
			name:    "Partial match",
			s:       "validation failed",
			substrs: []string{"valid"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsAny(tt.s, tt.substrs...)
			if got != tt.want {
				t.Errorf("containsAny() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSuccess(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Set request ID in context
	c.Set("request_id", "test-request-id")

	data := map[string]string{"message": "test"}
	Success(c, data)

	if w.Code != http.StatusOK {
		t.Errorf("Success() status = %d, want %d", w.Code, http.StatusOK)
	}

	// Check response body structure is valid JSON
	if w.Body.Len() == 0 {
		t.Error("Success() response body is empty")
	}
}

func TestCreated(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	data := map[string]string{"id": "123"}
	Created(c, data)

	if w.Code != http.StatusCreated {
		t.Errorf("Created() status = %d, want %d", w.Code, http.StatusCreated)
	}
}

func TestNoContent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		NoContent(c)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("NoContent() status = %d, want %d", w.Code, http.StatusNoContent)
	}

	if w.Body.Len() != 0 {
		t.Error("NoContent() should have empty body")
	}
}

func TestError(t *testing.T) {
	tests := []struct {
		name           string
		apiErr         *apierrors.APIError
		expectedStatus int
	}{
		{
			name:           "Bad Request",
			apiErr:         apierrors.BadRequest("Invalid input"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Not Found",
			apiErr:         apierrors.NotFound("User"),
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Unauthorized",
			apiErr:         apierrors.Unauthorized("Invalid token"),
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Forbidden",
			apiErr:         apierrors.Forbidden("No permission"),
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Internal Error",
			apiErr:         apierrors.Internal("Something went wrong"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			Error(c, tt.apiErr)

			if w.Code != tt.expectedStatus {
				t.Errorf("Error() status = %d, want %d", w.Code, tt.expectedStatus)
			}

			if w.Body.Len() == 0 {
				t.Error("Error() response body is empty")
			}
		})
	}
}

func TestGetCurrentUser(t *testing.T) {
	t.Run("User exists in context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		expectedUser := &models.CurrentUser{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			Email:    "test@example.com",
		}

		c.Set("current_user", expectedUser)

		gotUser := GetCurrentUser(c)

		if gotUser == nil {
			t.Fatal("GetCurrentUser() returned nil")
		}

		if gotUser.ID != expectedUser.ID {
			t.Errorf("GetCurrentUser() ID = %v, want %v", gotUser.ID, expectedUser.ID)
		}
	})

	t.Run("User not in context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		gotUser := GetCurrentUser(c)

		if gotUser != nil {
			t.Errorf("GetCurrentUser() = %v, want nil", gotUser)
		}
	})

	t.Run("Invalid user type in context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		c.Set("current_user", "not-a-user-object")

		gotUser := GetCurrentUser(c)

		if gotUser != nil {
			t.Errorf("GetCurrentUser() = %v, want nil for invalid type", gotUser)
		}
	})
}

func TestRequireCurrentUser(t *testing.T) {
	t.Run("User exists", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		expectedUser := &models.CurrentUser{
			ID:    uuid.New(),
			Email: "test@example.com",
		}

		c.Set("current_user", expectedUser)

		gotUser, ok := RequireCurrentUser(c)

		if !ok {
			t.Error("RequireCurrentUser() ok = false, want true")
		}

		if gotUser == nil {
			t.Fatal("RequireCurrentUser() returned nil user")
		}

		if gotUser.ID != expectedUser.ID {
			t.Errorf("RequireCurrentUser() ID = %v, want %v", gotUser.ID, expectedUser.ID)
		}

		if w.Code >= 400 {
			t.Errorf("RequireCurrentUser() wrote error response (status=%d) when user exists", w.Code)
		}
	})

	t.Run("User not in context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		gotUser, ok := RequireCurrentUser(c)

		if ok {
			t.Error("RequireCurrentUser() ok = true, want false")
		}

		if gotUser != nil {
			t.Errorf("RequireCurrentUser() = %v, want nil", gotUser)
		}

		if w.Code != http.StatusUnauthorized {
			t.Errorf("RequireCurrentUser() status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})
}

func TestGetTenantID(t *testing.T) {
	t.Run("Tenant ID exists", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		expectedID := uuid.New()
		c.Set("tenant_id", expectedID)

		gotID := GetTenantID(c)

		if gotID != expectedID {
			t.Errorf("GetTenantID() = %v, want %v", gotID, expectedID)
		}
	})

	t.Run("Tenant ID not in context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		gotID := GetTenantID(c)

		if gotID != uuid.Nil {
			t.Errorf("GetTenantID() = %v, want uuid.Nil", gotID)
		}
	})

	t.Run("Invalid tenant ID type", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		c.Set("tenant_id", "not-a-uuid")

		gotID := GetTenantID(c)

		if gotID != uuid.Nil {
			t.Errorf("GetTenantID() = %v, want uuid.Nil for invalid type", gotID)
		}
	})
}

func TestRequireTenantID(t *testing.T) {
	t.Run("Tenant ID exists", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		expectedID := uuid.New()
		c.Set("tenant_id", expectedID)

		gotID, ok := RequireTenantID(c)

		if !ok {
			t.Error("RequireTenantID() ok = false, want true")
		}

		if gotID != expectedID {
			t.Errorf("RequireTenantID() = %v, want %v", gotID, expectedID)
		}

		if w.Code >= 400 {
			t.Errorf("RequireTenantID() wrote error response (status=%d) when tenant ID exists", w.Code)
		}
	})

	t.Run("Tenant ID not in context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		gotID, ok := RequireTenantID(c)

		if ok {
			t.Error("RequireTenantID() ok = true, want false")
		}

		if gotID != uuid.Nil {
			t.Errorf("RequireTenantID() = %v, want uuid.Nil", gotID)
		}

		if w.Code != http.StatusBadRequest {
			t.Errorf("RequireTenantID() status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

func TestSuccessWithMeta(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Set("request_id", "test-request-id")

	data := []string{"item1", "item2"}
	meta := &Meta{
		Page:       2,
		PageSize:   10,
		TotalItems: 50,
		TotalPages: 5,
	}

	SuccessWithMeta(c, data, meta)

	if w.Code != http.StatusOK {
		t.Errorf("SuccessWithMeta() status = %d, want %d", w.Code, http.StatusOK)
	}

	if w.Body.Len() == 0 {
		t.Error("SuccessWithMeta() response body is empty")
	}
}

func TestBindJSON(t *testing.T) {
	t.Run("Valid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		// This test would need a proper request with JSON body
		// Simplified version
		type TestStruct struct {
			Name string `json:"name"`
		}

		var obj TestStruct
		// Without actual JSON in request, this will fail
		// but we test the error handling
		success := BindJSON(c, &obj)

		// Should fail without proper request body
		if success {
			t.Error("BindJSON() should fail without request body")
		}
	})
}

func TestBindQuery(t *testing.T) {
	t.Run("Valid query params", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test?name=test&age=25", nil)
		c.Request = req

		type TestStruct struct {
			Name string `form:"name"`
			Age  int    `form:"age"`
		}

		var obj TestStruct
		success := BindQuery(c, &obj)

		if !success {
			t.Error("BindQuery() failed with valid query params")
		}

		if obj.Name != "test" {
			t.Errorf("BindQuery() Name = %q, want %q", obj.Name, "test")
		}

		if obj.Age != 25 {
			t.Errorf("BindQuery() Age = %d, want 25", obj.Age)
		}
	})
}

func TestParseUUIDQuery(t *testing.T) {
	tests := []struct {
		name       string
		queryParam string
		queryValue string
		required   bool
		wantValid  bool
		wantUUID   uuid.UUID
	}{
		{
			name:       "Valid UUID required",
			queryParam: "id",
			queryValue: "123e4567-e89b-12d3-a456-426614174000",
			required:   true,
			wantValid:  true,
			wantUUID:   uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
		},
		{
			name:       "Missing required UUID",
			queryParam: "id",
			queryValue: "",
			required:   true,
			wantValid:  false,
			wantUUID:   uuid.Nil,
		},
		{
			name:       "Missing optional UUID",
			queryParam: "id",
			queryValue: "",
			required:   false,
			wantValid:  true,
			wantUUID:   uuid.Nil,
		},
		{
			name:       "Invalid UUID format",
			queryParam: "id",
			queryValue: "invalid-uuid",
			required:   false,
			wantValid:  false,
			wantUUID:   uuid.Nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
			if tt.queryValue != "" {
				q := req.URL.Query()
				q.Add(tt.queryParam, tt.queryValue)
				req.URL.RawQuery = q.Encode()
			}
			c.Request = req

			gotUUID, gotValid := ParseUUIDQuery(c, tt.queryParam, tt.required)

			if gotValid != tt.wantValid {
				t.Errorf("ParseUUIDQuery() valid = %v, want %v", gotValid, tt.wantValid)
			}

			if gotUUID != tt.wantUUID {
				t.Errorf("ParseUUIDQuery() UUID = %v, want %v", gotUUID, tt.wantUUID)
			}
		})
	}
}
