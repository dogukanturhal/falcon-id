// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// deviceServiceFake – test double for *services.DeviceService
// ---------------------------------------------------------------------------

type deviceServiceFake struct {
	// GetUserDevices
	devicesResp *models.DeviceListResponse
	devicesErr  error

	// GetDevice
	device    *models.Device
	deviceErr error

	// TrustDevice
	trustErr error

	// UntrustDevice
	untrustErr error

	// DeleteDevice
	deleteErr error

	// RenameDevice
	renameErr error
}

func (f *deviceServiceFake) GetUserDevices(_ context.Context, _ uuid.UUID, _, _ int) (*models.DeviceListResponse, error) {
	return f.devicesResp, f.devicesErr
}

func (f *deviceServiceFake) GetDevice(_ context.Context, _ uuid.UUID) (*models.Device, error) {
	return f.device, f.deviceErr
}

func (f *deviceServiceFake) TrustDevice(_ context.Context, _, _ uuid.UUID, _ string) error {
	return f.trustErr
}

func (f *deviceServiceFake) UntrustDevice(_ context.Context, _, _ uuid.UUID) error {
	return f.untrustErr
}

func (f *deviceServiceFake) DeleteDevice(_ context.Context, _, _ uuid.UUID) error {
	return f.deleteErr
}

func (f *deviceServiceFake) RenameDevice(_ context.Context, _, _ uuid.UUID, _ string) error {
	return f.renameErr
}

// ---------------------------------------------------------------------------
// deviceHandlerShim – mirrors DeviceHandler logic against the fake service
// ---------------------------------------------------------------------------

type deviceHandlerShim struct {
	svc *deviceServiceFake
}

func newDeviceTestRouter(svc *deviceServiceFake, withUser bool, userID uuid.UUID) *gin.Engine {
	router := gin.New()
	injectUser := func(c *gin.Context) {
		if withUser {
			c.Set("current_user", &models.CurrentUser{
				ID:       userID,
				TenantID: uuid.New(),
				Email:    "test@example.com",
			})
		}
		c.Next()
	}
	h := &deviceHandlerShim{svc: svc}
	router.Use(injectUser)
	router.GET("/devices", h.ListDevices)
	router.GET("/devices/:id", h.GetDevice)
	router.POST("/devices/:id/trust", h.TrustDevice)
	router.DELETE("/devices/:id/trust", h.UntrustDevice)
	router.DELETE("/devices/:id", h.DeleteDevice)
	router.PUT("/devices/:id/rename", h.RenameDevice)
	return router
}

func deviceCurrentUser(c *gin.Context) *models.CurrentUser {
	val, exists := c.Get("current_user")
	if !exists {
		return nil
	}
	u, ok := val.(*models.CurrentUser)
	if !ok {
		return nil
	}
	return u
}

func (h *deviceHandlerShim) ListDevices(c *gin.Context) {
	user := deviceCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	page, pageSize, _ := GetPagination(c)
	response, err := h.svc.GetUserDevices(c.Request.Context(), user.ID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, response)
}

func (h *deviceHandlerShim) GetDevice(c *gin.Context) {
	user := deviceCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	deviceID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}
	device, err := h.svc.GetDevice(c.Request.Context(), deviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	if device == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}
	if device.UserID != user.ID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}
	c.JSON(http.StatusOK, device.ToResponse())
}

func (h *deviceHandlerShim) TrustDevice(c *gin.Context) {
	user := deviceCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	deviceID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}
	var req models.TrustDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	err = h.svc.TrustDevice(c.Request.Context(), user.ID, deviceID, req.TrustDuration)
	if err != nil {
		switch err.Error() {
		case msgDeviceNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		case msgDeviceNotBelongToUser:
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Device trusted successfully"})
}

func (h *deviceHandlerShim) UntrustDevice(c *gin.Context) {
	user := deviceCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	deviceID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}
	err = h.svc.UntrustDevice(c.Request.Context(), user.ID, deviceID)
	if err != nil {
		switch err.Error() {
		case msgDeviceNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		case msgDeviceNotBelongToUser:
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Device trust removed"})
}

func (h *deviceHandlerShim) DeleteDevice(c *gin.Context) {
	user := deviceCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	deviceID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}
	err = h.svc.DeleteDevice(c.Request.Context(), user.ID, deviceID)
	if err != nil {
		switch err.Error() {
		case msgDeviceNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		case msgDeviceNotBelongToUser:
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Device removed successfully"})
}

func (h *deviceHandlerShim) RenameDevice(c *gin.Context) {
	user := deviceCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	deviceID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}
	var req struct {
		Name string `json:"name" binding:"required,min=1,max=255"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: name is required (max 255 characters)"})
		return
	}
	err = h.svc.RenameDevice(c.Request.Context(), user.ID, deviceID, req.Name)
	if err != nil {
		switch err.Error() {
		case msgDeviceNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		case msgDeviceNotBelongToUser:
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Device renamed successfully"})
}

// ---------------------------------------------------------------------------
// HTTP helpers for device tests
// ---------------------------------------------------------------------------

func performDeviceRequest(router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, path, nil)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func decodeDeviceBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

func buildTestDevice(userID uuid.UUID, trusted bool) *models.Device {
	deviceID := uuid.New()
	name := "Chrome on macOS"
	devType := "desktop"
	browser := "Chrome"
	os := "macOS"
	ip := "192.168.1.1"
	now := time.Now()
	var trustExpiry *time.Time
	if trusted {
		t := now.Add(30 * 24 * time.Hour)
		trustExpiry = &t
	}
	return &models.Device{
		ID:              deviceID,
		UserID:          userID,
		FingerprintHash: "abc123hash",
		DeviceName:      &name,
		DeviceType:      &devType,
		Browser:         &browser,
		OS:              &os,
		IsTrusted:       trusted,
		FirstSeenAt:     now,
		LastSeenAt:      now,
		LastIP:          &ip,
		TrustExpiresAt:  trustExpiry,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// ---------------------------------------------------------------------------
// Tests: ListDevices (GET /devices)
// ---------------------------------------------------------------------------

func TestDevice_ListDevices(t *testing.T) {
	userID := uuid.New()

	t.Run("returns paginated list of devices", func(t *testing.T) {
		d1 := buildTestDevice(userID, false)
		d2 := buildTestDevice(userID, true)
		svc := &deviceServiceFake{
			devicesResp: &models.DeviceListResponse{
				Devices:    []models.DeviceResponse{*d1.ToResponse(), *d2.ToResponse()},
				Total:      2,
				Page:       1,
				PageSize:   20,
				TotalPages: 1,
			},
		}
		router := newDeviceTestRouter(svc, true, userID)
		w := performDeviceRequest(router, http.MethodGet, "/devices", "")

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.DeviceListResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Len(t, resp.Devices, 2)
		assert.Equal(t, int64(2), resp.Total)
		assert.Equal(t, 1, resp.Page)
	})

	t.Run("returns empty list when no devices registered", func(t *testing.T) {
		svc := &deviceServiceFake{
			devicesResp: &models.DeviceListResponse{
				Devices:    []models.DeviceResponse{},
				Total:      0,
				Page:       1,
				PageSize:   20,
				TotalPages: 0,
			},
		}
		router := newDeviceTestRouter(svc, true, userID)
		w := performDeviceRequest(router, http.MethodGet, "/devices", "")

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.DeviceListResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Empty(t, resp.Devices)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, false, userID)
		w := performDeviceRequest(router, http.MethodGet, "/devices", "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &deviceServiceFake{devicesErr: errors.New("db error")}
		router := newDeviceTestRouter(svc, true, userID)
		w := performDeviceRequest(router, http.MethodGet, "/devices", "")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: TrustDevice (POST /devices/:id/trust)
// ---------------------------------------------------------------------------

func TestDevice_TrustDevice(t *testing.T) {
	userID := uuid.New()

	t.Run("trusts device without duration (permanent)", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, true, userID)
		path := "/devices/" + uuid.New().String() + "/trust"
		w := performDeviceRequest(router, http.MethodPost, path, `{}`)

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeDeviceBody(t, w)
		assert.Equal(t, "Device trusted successfully", body["message"])
	})

	t.Run("trusts device with 30d duration", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, true, userID)
		path := "/devices/" + uuid.New().String() + "/trust"
		w := performDeviceRequest(router, http.MethodPost, path, `{"trust_duration":"30d"}`)

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeDeviceBody(t, w)
		assert.Equal(t, "Device trusted successfully", body["message"])
	})

	t.Run("device not found returns 404", func(t *testing.T) {
		svc := &deviceServiceFake{trustErr: errors.New(msgDeviceNotFound)}
		router := newDeviceTestRouter(svc, true, userID)
		path := "/devices/" + uuid.New().String() + "/trust"
		w := performDeviceRequest(router, http.MethodPost, path, `{}`)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("device belongs to another user returns 403", func(t *testing.T) {
		svc := &deviceServiceFake{trustErr: errors.New(msgDeviceNotBelongToUser)}
		router := newDeviceTestRouter(svc, true, userID)
		path := "/devices/" + uuid.New().String() + "/trust"
		w := performDeviceRequest(router, http.MethodPost, path, `{}`)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("invalid device ID returns 400", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, true, userID)
		w := performDeviceRequest(router, http.MethodPost, "/devices/not-a-uuid/trust", `{}`)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, false, userID)
		path := "/devices/" + uuid.New().String() + "/trust"
		w := performDeviceRequest(router, http.MethodPost, path, `{}`)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: UntrustDevice (DELETE /devices/:id/trust)
// ---------------------------------------------------------------------------

func TestDevice_UntrustDevice(t *testing.T) {
	userID := uuid.New()

	t.Run("removes trust from device", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, true, userID)
		path := "/devices/" + uuid.New().String() + "/trust"
		w := performDeviceRequest(router, http.MethodDelete, path, "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeDeviceBody(t, w)
		assert.Equal(t, "Device trust removed", body["message"])
	})

	t.Run("device not found returns 404", func(t *testing.T) {
		svc := &deviceServiceFake{untrustErr: errors.New(msgDeviceNotFound)}
		router := newDeviceTestRouter(svc, true, userID)
		path := "/devices/" + uuid.New().String() + "/trust"
		w := performDeviceRequest(router, http.MethodDelete, path, "")

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("device belongs to another user returns 403", func(t *testing.T) {
		svc := &deviceServiceFake{untrustErr: errors.New(msgDeviceNotBelongToUser)}
		router := newDeviceTestRouter(svc, true, userID)
		path := "/devices/" + uuid.New().String() + "/trust"
		w := performDeviceRequest(router, http.MethodDelete, path, "")

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("invalid device ID returns 400", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, true, userID)
		w := performDeviceRequest(router, http.MethodDelete, "/devices/invalid-id/trust", "")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, false, userID)
		path := "/devices/" + uuid.New().String() + "/trust"
		w := performDeviceRequest(router, http.MethodDelete, path, "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: DeleteDevice (DELETE /devices/:id)
// ---------------------------------------------------------------------------

func TestDevice_DeleteDevice(t *testing.T) {
	userID := uuid.New()

	t.Run("removes device from account", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, true, userID)
		path := "/devices/" + uuid.New().String()
		w := performDeviceRequest(router, http.MethodDelete, path, "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeDeviceBody(t, w)
		assert.Equal(t, "Device removed successfully", body["message"])
	})

	t.Run("device not found returns 404", func(t *testing.T) {
		svc := &deviceServiceFake{deleteErr: errors.New(msgDeviceNotFound)}
		router := newDeviceTestRouter(svc, true, userID)
		path := "/devices/" + uuid.New().String()
		w := performDeviceRequest(router, http.MethodDelete, path, "")

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("device belongs to another user returns 403", func(t *testing.T) {
		svc := &deviceServiceFake{deleteErr: errors.New(msgDeviceNotBelongToUser)}
		router := newDeviceTestRouter(svc, true, userID)
		path := "/devices/" + uuid.New().String()
		w := performDeviceRequest(router, http.MethodDelete, path, "")

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("invalid device ID returns 400", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, true, userID)
		w := performDeviceRequest(router, http.MethodDelete, "/devices/not-uuid", "")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, false, userID)
		path := "/devices/" + uuid.New().String()
		w := performDeviceRequest(router, http.MethodDelete, path, "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("unexpected service error returns 500", func(t *testing.T) {
		svc := &deviceServiceFake{deleteErr: errors.New("unexpected internal failure")}
		router := newDeviceTestRouter(svc, true, userID)
		path := "/devices/" + uuid.New().String()
		w := performDeviceRequest(router, http.MethodDelete, path, "")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: GetDevice (GET /devices/:id)
// ---------------------------------------------------------------------------

func TestDevice_GetDevice(t *testing.T) {
	userID := uuid.New()

	t.Run("returns device details for owner", func(t *testing.T) {
		device := buildTestDevice(userID, false)
		svc := &deviceServiceFake{device: device}
		router := newDeviceTestRouter(svc, true, userID)
		path := "/devices/" + device.ID.String()
		w := performDeviceRequest(router, http.MethodGet, path, "")

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.DeviceResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, device.ID, resp.ID)
		assert.Equal(t, false, resp.IsTrusted)
	})

	t.Run("returns trusted device with trust expiry", func(t *testing.T) {
		device := buildTestDevice(userID, true)
		svc := &deviceServiceFake{device: device}
		router := newDeviceTestRouter(svc, true, userID)
		path := "/devices/" + device.ID.String()
		w := performDeviceRequest(router, http.MethodGet, path, "")

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.DeviceResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.IsTrusted)
		assert.NotNil(t, resp.TrustExpiresAt)
	})

	t.Run("device not found returns 404", func(t *testing.T) {
		svc := &deviceServiceFake{device: nil}
		router := newDeviceTestRouter(svc, true, userID)
		path := "/devices/" + uuid.New().String()
		w := performDeviceRequest(router, http.MethodGet, path, "")
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("device belongs to other user returns 404 (ownership check)", func(t *testing.T) {
		otherUserID := uuid.New()
		device := buildTestDevice(otherUserID, false)
		svc := &deviceServiceFake{device: device}
		router := newDeviceTestRouter(svc, true, userID) // logged in as different user
		path := "/devices/" + device.ID.String()
		w := performDeviceRequest(router, http.MethodGet, path, "")
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid device ID returns 400", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, true, userID)
		w := performDeviceRequest(router, http.MethodGet, "/devices/not-a-uuid", "")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, false, userID)
		path := "/devices/" + uuid.New().String()
		w := performDeviceRequest(router, http.MethodGet, path, "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: RenameDevice (PUT /devices/:id/rename)
// ---------------------------------------------------------------------------

func TestDevice_RenameDevice(t *testing.T) {
	userID := uuid.New()

	t.Run("renames device successfully", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, true, userID)
		path := "/devices/" + uuid.New().String() + "/rename"
		w := performDeviceRequest(router, http.MethodPut, path, `{"name":"My Work Laptop"}`)

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeDeviceBody(t, w)
		assert.Equal(t, "Device renamed successfully", body["message"])
	})

	t.Run("missing name returns 400", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, true, userID)
		path := "/devices/" + uuid.New().String() + "/rename"
		w := performDeviceRequest(router, http.MethodPut, path, `{}`)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("device not found returns 404", func(t *testing.T) {
		svc := &deviceServiceFake{renameErr: errors.New(msgDeviceNotFound)}
		router := newDeviceTestRouter(svc, true, userID)
		path := "/devices/" + uuid.New().String() + "/rename"
		w := performDeviceRequest(router, http.MethodPut, path, `{"name":"New Name"}`)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newDeviceTestRouter(&deviceServiceFake{}, false, userID)
		path := "/devices/" + uuid.New().String() + "/rename"
		w := performDeviceRequest(router, http.MethodPut, path, `{"name":"New Name"}`)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
