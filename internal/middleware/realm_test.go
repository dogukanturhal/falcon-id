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
)

// ==================== Context helpers ====================

// TestSetAndGetCurrentRealm verifies that setRealmContext stores the realm and
// that the helper functions retrieve each field correctly.
func TestSetAndGetCurrentRealm(t *testing.T) {
	realmID := uuid.New()
	realm := &models.Realm{
		ID:     realmID,
		Slug:   "acme",
		Type:   models.RealmTypeEnterprise,
		Status: models.RealmStatusActive,
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	setRealmContext(c, realm, "header_slug")

	got := GetCurrentRealm(c)
	assert.NotNil(t, got)
	assert.Equal(t, realmID, got.ID)
	assert.Equal(t, "acme", got.Slug)
}

// TestGetCurrentRealmID_Present verifies GetCurrentRealmID returns the correct
// UUID when a realm has been set in the context.
func TestGetCurrentRealmID_Present(t *testing.T) {
	realmID := uuid.New()
	realm := &models.Realm{
		ID:     realmID,
		Slug:   "demo",
		Type:   models.RealmTypeEnterprise,
		Status: models.RealmStatusActive,
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	setRealmContext(c, realm, "header_id")

	got := GetCurrentRealmID(c)
	assert.NotNil(t, got)
	assert.Equal(t, realmID, *got)
}

// TestGetCurrentRealmID_Absent verifies GetCurrentRealmID returns nil when no
// realm has been set in the context.
func TestGetCurrentRealmID_Absent(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	got := GetCurrentRealmID(c)
	assert.Nil(t, got)
}

// TestGetCurrentRealmSlug verifies the slug helper round-trips correctly.
func TestGetCurrentRealmSlug(t *testing.T) {
	realm := &models.Realm{
		ID:     uuid.New(),
		Slug:   "my-realm",
		Type:   models.RealmTypeEnterprise,
		Status: models.RealmStatusActive,
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	setRealmContext(c, realm, "url_prefix")

	assert.Equal(t, "my-realm", GetCurrentRealmSlug(c))
}

// TestGetCurrentRealmSlug_Absent verifies the slug helper returns an empty
// string when no realm is in context.
func TestGetCurrentRealmSlug_Absent(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	assert.Equal(t, "", GetCurrentRealmSlug(c))
}

// TestGetRealmType verifies the type helper returns the correct realm type.
func TestGetRealmType(t *testing.T) {
	realm := &models.Realm{
		ID:     uuid.New(),
		Slug:   "platform",
		Type:   models.RealmTypePlatform,
		Status: models.RealmStatusActive,
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	setRealmContext(c, realm, "default")

	assert.Equal(t, models.RealmTypePlatform, GetRealmType(c))
}

// TestGetRealmType_Absent verifies the type helper returns an empty string when
// no realm is in context.
func TestGetRealmType_Absent(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	assert.Equal(t, models.RealmType(""), GetRealmType(c))
}

// TestGetRealmSource verifies the extraction-source helper returns the correct
// string that was provided to setRealmContext.
func TestGetRealmSource(t *testing.T) {
	realm := &models.Realm{
		ID:     uuid.New(),
		Slug:   "x",
		Type:   models.RealmTypeEnterprise,
		Status: models.RealmStatusActive,
	}

	for _, source := range []string{"url_prefix", "header_id", "header_slug", "subdomain", "custom_domain", "default"} {
		t.Run(source, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			setRealmContext(c, realm, source)
			assert.Equal(t, source, GetRealmSource(c))
		})
	}
}

// TestGetCurrentRealm_Absent verifies GetCurrentRealm returns nil when context
// is empty.
func TestGetCurrentRealm_Absent(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	assert.Nil(t, GetCurrentRealm(c))
}

// ==================== MustGetCurrentRealm ====================

// TestMustGetCurrentRealm_Present verifies MustGetCurrentRealm returns the realm
// and does not abort the request when one is present.
func TestMustGetCurrentRealm_Present(t *testing.T) {
	realm := &models.Realm{
		ID:     uuid.New(),
		Slug:   "ok-realm",
		Type:   models.RealmTypeEnterprise,
		Status: models.RealmStatusActive,
	}

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		setRealmContext(c, realm, "default")
		got := MustGetCurrentRealm(c)
		if got == nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestMustGetCurrentRealm_Absent verifies MustGetCurrentRealm aborts with 500
// when no realm is in context.
func TestMustGetCurrentRealm_Absent(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		// No realm set — MustGetCurrentRealm should abort.
		MustGetCurrentRealm(c)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestMustGetCurrentRealmID_Absent verifies MustGetCurrentRealmID aborts with
// 500 when no realm ID is in context.
func TestMustGetCurrentRealmID_Absent(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		MustGetCurrentRealmID(c)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==================== RequireRealm (standalone middleware) ====================

// TestRequireRealm_WithRealmInContext verifies that RequireRealm passes through
// when a realm has already been placed into the context.
func TestRequireRealm_WithRealmInContext(t *testing.T) {
	realm := &models.Realm{
		ID:     uuid.New(),
		Slug:   "present",
		Type:   models.RealmTypeEnterprise,
		Status: models.RealmStatusActive,
	}

	// Build a minimal middleware that stubs realm into context before RequireRealm.
	rm := &RealmMiddleware{}

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		setRealmContext(c, realm, "stub")
		c.Next()
	}, rm.RequireRealm(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRequireRealm_WithoutRealmInContext verifies that RequireRealm returns 400
// when no realm is present in the context.
func TestRequireRealm_WithoutRealmInContext(t *testing.T) {
	rm := &RealmMiddleware{}

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", rm.RequireRealm(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ==================== extractSubdomain ====================

// TestExtractSubdomain_TableDriven validates the subdomain extraction helper
// across a variety of host strings.
func TestExtractSubdomain_TableDriven(t *testing.T) {
	tests := []struct {
		host     string
		expected string
	}{
		{"acme.hexxlock.com", "acme"},
		{"tenant1.example.com", "tenant1"},
		{"www.hexxlock.com", ""},           // www is skipped
		{"api.hexxlock.com", ""},           // api is skipped
		{"hexxlock.com", ""},               // no subdomain
		{"localhost", ""},                  // single part
		{"api.acme.hexxlock.com", "acme"},  // api prefix skipped, second part used
		{"acme.hexxlock.com:8080", "acme"}, // port stripped
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := extractSubdomain(tt.host)
			assert.Equal(t, tt.expected, got)
		})
	}
}
