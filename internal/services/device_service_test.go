// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	testUserAgentSimple    = "Mozilla/5.0"
	testUserAgentWinChrome = "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"
)

// ---------------------------------------------------------------------------
// Mock implementation
// ---------------------------------------------------------------------------

type mockDeviceRepo struct {
	mock.Mock
}

func (m *mockDeviceRepo) UpsertDevice(ctx context.Context, device *models.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *mockDeviceRepo) GetByUserID(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]models.Device, int64, error) {
	args := m.Called(ctx, userID, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.Device), args.Get(1).(int64), args.Error(2)
}

func (m *mockDeviceRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Device, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Device), args.Error(1)
}

func (m *mockDeviceRepo) TrustDevice(ctx context.Context, id uuid.UUID, expiresAt *time.Time) error {
	args := m.Called(ctx, id, expiresAt)
	return args.Error(0)
}

func (m *mockDeviceRepo) UntrustDevice(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockDeviceRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockDeviceRepo) IsTrustedDevice(ctx context.Context, userID uuid.UUID, fingerprintHash string) (bool, error) {
	args := m.Called(ctx, userID, fingerprintHash)
	return args.Bool(0), args.Error(1)
}

func (m *mockDeviceRepo) CleanupExpiredTrust(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockDeviceRepo) Update(ctx context.Context, device *models.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *mockDeviceRepo) GetByFingerprint(ctx context.Context, userID uuid.UUID, fingerprintHash string) (*models.Device, error) {
	args := m.Called(ctx, userID, fingerprintHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Device), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newDeviceService(repo deviceServiceDeviceRepo) *DeviceService {
	return NewDeviceService(repo)
}

func buildDevice(userID uuid.UUID) *models.Device {
	deviceType := "desktop"
	browser := "Chrome"
	os := "Windows 10/11"
	deviceName := "Chrome on Windows 10/11"
	lastIP := testAuthIP
	now := time.Now()
	return &models.Device{
		ID:              uuid.New(),
		UserID:          userID,
		FingerprintHash: "abc123def456abc123def456abc123de",
		DeviceName:      &deviceName,
		DeviceType:      &deviceType,
		Browser:         &browser,
		OS:              &os,
		IsTrusted:       false,
		FirstSeenAt:     now,
		LastSeenAt:      now,
		LastIP:          &lastIP,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// ---------------------------------------------------------------------------
// TestDeviceService_RecordDevice
// ---------------------------------------------------------------------------

func TestDeviceService_RecordDevice_NewDevice(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	repo := new(mockDeviceRepo)
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"
	ip := "192.168.1.100"

	repo.On("UpsertDevice", ctx, mock.AnythingOfType("*models.Device")).Return(nil)

	svc := newDeviceService(repo)
	device, err := svc.RecordDevice(ctx, userID, userAgent, ip, nil)

	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Equal(t, userID, device.UserID)
	assert.NotEmpty(t, device.FingerprintHash)
	require.NotNil(t, device.DeviceType)
	assert.Equal(t, "desktop", *device.DeviceType)
	require.NotNil(t, device.Browser)
	assert.Equal(t, "Chrome", *device.Browser)

	repo.AssertExpectations(t)
}

func TestDeviceService_RecordDevice_WithFingerprint(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	repo := new(mockDeviceRepo)
	repo.On("UpsertDevice", ctx, mock.AnythingOfType("*models.Device")).Return(nil)

	fingerprint := &models.DeviceFingerprint{
		UserAgent:    "Mozilla/5.0 ...",
		ScreenWidth:  1920,
		ScreenHeight: 1080,
		ColorDepth:   24,
		Timezone:     "Europe/Istanbul",
		Language:     "en-US",
		Platform:     "Win32",
	}

	svc := newDeviceService(repo)
	device, err := svc.RecordDevice(ctx, userID, fingerprint.UserAgent, testAuthIP, fingerprint)

	require.NoError(t, err)
	require.NotNil(t, device)
	assert.NotEmpty(t, device.FingerprintHash)
}

func TestDeviceService_RecordDevice_MobileUserAgent(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	repo := new(mockDeviceRepo)
	repo.On("UpsertDevice", ctx, mock.AnythingOfType("*models.Device")).Return(nil)

	svc := newDeviceService(repo)
	mobileUA := "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36"
	device, err := svc.RecordDevice(ctx, userID, mobileUA, "10.0.0.2", nil)

	require.NoError(t, err)
	require.NotNil(t, device.DeviceType)
	assert.Equal(t, "mobile", *device.DeviceType)
}

func TestDeviceService_RecordDevice_UpsertError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	repo := new(mockDeviceRepo)
	repo.On("UpsertDevice", ctx, mock.AnythingOfType("*models.Device")).Return(errors.New("db write error"))

	svc := newDeviceService(repo)
	device, err := svc.RecordDevice(ctx, userID, testUserAgentSimple, "127.0.0.1", nil)

	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "failed to record device")
}

// ---------------------------------------------------------------------------
// TestDeviceService_GetUserDevices
// ---------------------------------------------------------------------------

func TestDeviceService_GetUserDevices_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	repo := new(mockDeviceRepo)
	devices := []models.Device{
		*buildDevice(userID),
		*buildDevice(userID),
	}

	repo.On("GetByUserID", ctx, userID, 1, 20).Return(devices, int64(2), nil)

	svc := newDeviceService(repo)
	result, err := svc.GetUserDevices(ctx, userID, 1, 20)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Devices, 2)
	assert.Equal(t, int64(2), result.Total)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 20, result.PageSize)
	assert.Equal(t, 1, result.TotalPages)

	repo.AssertExpectations(t)
}

func TestDeviceService_GetUserDevices_DefaultPagination(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	repo := new(mockDeviceRepo)
	// Service defaults page=0→1, pageSize=0→20
	repo.On("GetByUserID", ctx, userID, 1, 20).Return([]models.Device{}, int64(0), nil)

	svc := newDeviceService(repo)
	result, err := svc.GetUserDevices(ctx, userID, 0, 0)

	require.NoError(t, err)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 20, result.PageSize)
}

func TestDeviceService_GetUserDevices_PageSizeCappedAt100(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	repo := new(mockDeviceRepo)
	repo.On("GetByUserID", ctx, userID, 1, 20).Return([]models.Device{}, int64(0), nil)

	svc := newDeviceService(repo)
	result, err := svc.GetUserDevices(ctx, userID, 1, 200) // over-limit → capped to 20

	require.NoError(t, err)
	assert.Equal(t, 20, result.PageSize)
}

func TestDeviceService_GetUserDevices_RepoError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	repo := new(mockDeviceRepo)
	repo.On("GetByUserID", ctx, userID, 1, 20).Return(nil, int64(0), errors.New("db error"))

	svc := newDeviceService(repo)
	result, err := svc.GetUserDevices(ctx, userID, 1, 20)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get devices")
}

func TestDeviceService_GetUserDevices_TotalPagesCalculation(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	repo := new(mockDeviceRepo)
	devices := make([]models.Device, 5)
	for i := range devices {
		devices[i] = *buildDevice(userID)
	}
	repo.On("GetByUserID", ctx, userID, 1, 2).Return(devices[:2], int64(5), nil)

	svc := newDeviceService(repo)
	result, err := svc.GetUserDevices(ctx, userID, 1, 2)

	require.NoError(t, err)
	assert.Equal(t, 3, result.TotalPages) // ceil(5/2) = 3
}

// ---------------------------------------------------------------------------
// TestDeviceService_TrustDevice
// ---------------------------------------------------------------------------

func TestDeviceService_TrustDevice_30Days(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	device := buildDevice(userID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)
	repo.On("TrustDevice", ctx, device.ID, mock.AnythingOfType("*time.Time")).Return(nil)

	svc := newDeviceService(repo)
	err := svc.TrustDevice(ctx, userID, device.ID, "30d")

	require.NoError(t, err)
	repo.AssertExpectations(t)

	// Verify expiry arg is approximately 30 days from now
	trustCall := repo.Calls[1]
	expiresAt := trustCall.Arguments[2].(*time.Time)
	require.NotNil(t, expiresAt)
	expected := time.Now().Add(30 * 24 * time.Hour)
	assert.WithinDuration(t, expected, *expiresAt, 5*time.Second)
}

func TestDeviceService_TrustDevice_90Days(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	device := buildDevice(userID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)
	repo.On("TrustDevice", ctx, device.ID, mock.AnythingOfType("*time.Time")).Return(nil)

	svc := newDeviceService(repo)
	err := svc.TrustDevice(ctx, userID, device.ID, "90d")

	require.NoError(t, err)
	trustCall := repo.Calls[1]
	expiresAt := trustCall.Arguments[2].(*time.Time)
	require.NotNil(t, expiresAt)
	expected := time.Now().Add(90 * 24 * time.Hour)
	assert.WithinDuration(t, expected, *expiresAt, 5*time.Second)
}

func TestDeviceService_TrustDevice_Forever(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	device := buildDevice(userID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)
	// expiresAt nil pointer expected for "forever"
	repo.On("TrustDevice", ctx, device.ID, (*time.Time)(nil)).Return(nil)

	svc := newDeviceService(repo)
	err := svc.TrustDevice(ctx, userID, device.ID, "forever")

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestDeviceService_TrustDevice_EmptyDuration_DefaultsTo30Days(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	device := buildDevice(userID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)
	// Empty string → "forever" branch: nil expiry
	repo.On("TrustDevice", ctx, device.ID, (*time.Time)(nil)).Return(nil)

	svc := newDeviceService(repo)
	err := svc.TrustDevice(ctx, userID, device.ID, "")

	require.NoError(t, err)
}

func TestDeviceService_TrustDevice_UnknownDuration_DefaultsTo30Days(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	device := buildDevice(userID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)
	repo.On("TrustDevice", ctx, device.ID, mock.AnythingOfType("*time.Time")).Return(nil)

	svc := newDeviceService(repo)
	err := svc.TrustDevice(ctx, userID, device.ID, "2w") // unknown → defaults to 30d

	require.NoError(t, err)
	trustCall := repo.Calls[1]
	expiresAt := trustCall.Arguments[2].(*time.Time)
	require.NotNil(t, expiresAt)
	expected := time.Now().Add(30 * 24 * time.Hour)
	assert.WithinDuration(t, expected, *expiresAt, 5*time.Second)
}

func TestDeviceService_TrustDevice_DeviceNotFound(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	deviceID := uuid.New()

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, deviceID).Return(nil, nil)

	svc := newDeviceService(repo)
	err := svc.TrustDevice(ctx, userID, deviceID, "30d")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device not found")
}

func TestDeviceService_TrustDevice_GetByIDError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	deviceID := uuid.New()

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, deviceID).Return(nil, errors.New("db error"))

	svc := newDeviceService(repo)
	err := svc.TrustDevice(ctx, userID, deviceID, "30d")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get device")
}

func TestDeviceService_TrustDevice_WrongUser(t *testing.T) {
	ctx := context.Background()
	deviceOwnerID := uuid.New()
	callerID := uuid.New()

	device := buildDevice(deviceOwnerID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)

	svc := newDeviceService(repo)
	err := svc.TrustDevice(ctx, callerID, device.ID, "30d")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device does not belong to user")
}

// ---------------------------------------------------------------------------
// TestDeviceService_UntrustDevice
// ---------------------------------------------------------------------------

func TestDeviceService_UntrustDevice_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	device := buildDevice(userID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)
	repo.On("UntrustDevice", ctx, device.ID).Return(nil)

	svc := newDeviceService(repo)
	err := svc.UntrustDevice(ctx, userID, device.ID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestDeviceService_UntrustDevice_DeviceNotFound(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	deviceID := uuid.New()

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, deviceID).Return(nil, nil)

	svc := newDeviceService(repo)
	err := svc.UntrustDevice(ctx, userID, deviceID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device not found")
}

func TestDeviceService_UntrustDevice_WrongUser(t *testing.T) {
	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	device := buildDevice(ownerID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)

	svc := newDeviceService(repo)
	err := svc.UntrustDevice(ctx, callerID, device.ID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device does not belong to user")
}

func TestDeviceService_UntrustDevice_RepoError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	device := buildDevice(userID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)
	repo.On("UntrustDevice", ctx, device.ID).Return(errors.New("db error"))

	svc := newDeviceService(repo)
	err := svc.UntrustDevice(ctx, userID, device.ID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to untrust device")
}

// ---------------------------------------------------------------------------
// TestDeviceService_DeleteDevice
// ---------------------------------------------------------------------------

func TestDeviceService_DeleteDevice_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	device := buildDevice(userID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)
	repo.On("Delete", ctx, device.ID).Return(nil)

	svc := newDeviceService(repo)
	err := svc.DeleteDevice(ctx, userID, device.ID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestDeviceService_DeleteDevice_NotFound(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	deviceID := uuid.New()

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, deviceID).Return(nil, nil)

	svc := newDeviceService(repo)
	err := svc.DeleteDevice(ctx, userID, deviceID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device not found")
}

func TestDeviceService_DeleteDevice_GetByIDError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	deviceID := uuid.New()

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, deviceID).Return(nil, errors.New("db error"))

	svc := newDeviceService(repo)
	err := svc.DeleteDevice(ctx, userID, deviceID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get device")
}

func TestDeviceService_DeleteDevice_WrongUser(t *testing.T) {
	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	device := buildDevice(ownerID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)

	svc := newDeviceService(repo)
	err := svc.DeleteDevice(ctx, callerID, device.ID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device does not belong to user")
}

func TestDeviceService_DeleteDevice_DeleteError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	device := buildDevice(userID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)
	repo.On("Delete", ctx, device.ID).Return(errors.New("foreign key violation"))

	svc := newDeviceService(repo)
	err := svc.DeleteDevice(ctx, userID, device.ID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete device")
}

// ---------------------------------------------------------------------------
// TestDeviceService_GenerateFingerprint
// ---------------------------------------------------------------------------

func TestDeviceService_GenerateFingerprint_Deterministic(t *testing.T) {
	svc := newDeviceService(nil)

	fp := &models.DeviceFingerprint{
		UserAgent:           testUserAgentSimple,
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		ColorDepth:          24,
		Timezone:            "UTC",
		Language:            "en-US",
		Platform:            "Win32",
		CanvasHash:          "canvas123",
		WebGLVendor:         "NVIDIA",
		WebGLRenderer:       "RTX 3080",
		FontsHash:           "fonts456",
		HardwareConcurrency: 8,
		DeviceMemory:        16,
	}

	hash1 := svc.GenerateFingerprint(fp)
	hash2 := svc.GenerateFingerprint(fp)

	assert.Equal(t, hash1, hash2, "same fingerprint data should always produce same hash")
	assert.Len(t, hash1, 64, "SHA-256 hex digest should be 64 characters")
}

func TestDeviceService_GenerateFingerprint_DifferentInputs(t *testing.T) {
	svc := newDeviceService(nil)

	fp1 := &models.DeviceFingerprint{
		UserAgent:   "Mozilla/5.0 Chrome",
		ScreenWidth: 1920,
	}
	fp2 := &models.DeviceFingerprint{
		UserAgent:   "Mozilla/5.0 Firefox",
		ScreenWidth: 1920,
	}

	hash1 := svc.GenerateFingerprint(fp1)
	hash2 := svc.GenerateFingerprint(fp2)

	assert.NotEqual(t, hash1, hash2, "different inputs should produce different hashes")
}

// ---------------------------------------------------------------------------
// TestDeviceService_ParseUserAgent
// ---------------------------------------------------------------------------

func TestDeviceService_ParseUserAgent_TableDriven(t *testing.T) {
	svc := newDeviceService(nil)

	tests := []struct {
		name           string
		userAgent      string
		wantDeviceType string
		wantBrowser    string
		wantOS         string
	}{
		{
			name:           "Windows Chrome desktop",
			userAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantDeviceType: "desktop",
			wantBrowser:    "Chrome",
			wantOS:         "Windows 10/11",
		},
		{
			name:           "Android mobile Chrome",
			userAgent:      "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			wantDeviceType: "mobile",
			wantBrowser:    "Chrome",
			wantOS:         "Android",
		},
		{
			name:           "iPad tablet Safari",
			userAgent:      "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			wantDeviceType: "tablet",
			wantBrowser:    "Safari",
			wantOS:         "iPadOS",
		},
		{
			name:           "iPhone mobile Safari",
			userAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			wantDeviceType: "mobile",
			wantBrowser:    "Safari",
			wantOS:         "iOS",
		},
		{
			name:           "Linux Firefox desktop",
			userAgent:      "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
			wantDeviceType: "desktop",
			wantBrowser:    "Firefox",
			wantOS:         "Linux",
		},
		{
			name:           "macOS Edge desktop",
			userAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Edg/120.0",
			wantDeviceType: "desktop",
			wantBrowser:    "Edge",
			wantOS:         "macOS",
		},
		{
			name:           "unknown user agent",
			userAgent:      "CustomBot/1.0",
			wantDeviceType: "desktop",
			wantBrowser:    "Unknown",
			wantOS:         "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deviceType, browser, os := svc.ParseUserAgent(tt.userAgent)

			assert.Equal(t, tt.wantDeviceType, deviceType)
			assert.Equal(t, tt.wantBrowser, browser)
			assert.Equal(t, tt.wantOS, os)
		})
	}
}

// ---------------------------------------------------------------------------
// TestDeviceService_CheckDeviceIsNew
// ---------------------------------------------------------------------------

func TestDeviceService_CheckDeviceIsNew_TrulyNewDevice(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	repo := new(mockDeviceRepo)
	userAgent := testUserAgentWinChrome
	ip := testAuthIP

	svc := newDeviceService(repo)
	fingerprintHash := svc.GenerateSimpleFingerprint(userAgent, ip)

	// Device not found by fingerprint
	repo.On("GetByFingerprint", ctx, userID, fingerprintHash).Return(nil, nil)
	// RecordDevice will be called internally
	repo.On("UpsertDevice", ctx, mock.AnythingOfType("*models.Device")).Return(nil)

	isNew, device, err := svc.CheckDeviceIsNew(ctx, userID, userAgent, ip)

	require.NoError(t, err)
	assert.True(t, isNew)
	require.NotNil(t, device)
}

func TestDeviceService_CheckDeviceIsNew_ExistingDevice(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	repo := new(mockDeviceRepo)
	userAgent := testUserAgentWinChrome
	ip := testAuthIP

	svc := newDeviceService(repo)
	fingerprintHash := svc.GenerateSimpleFingerprint(userAgent, ip)

	existingDevice := buildDevice(userID)
	existingDevice.FingerprintHash = fingerprintHash

	repo.On("GetByFingerprint", ctx, userID, fingerprintHash).Return(existingDevice, nil)
	// Update last seen called for existing device
	repo.On("Update", ctx, mock.AnythingOfType("*models.Device")).Return(nil)

	isNew, device, err := svc.CheckDeviceIsNew(ctx, userID, userAgent, ip)

	require.NoError(t, err)
	assert.False(t, isNew)
	require.NotNil(t, device)
}

func TestDeviceService_CheckDeviceIsNew_GetByFingerprintError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	repo := new(mockDeviceRepo)
	userAgent := testUserAgentSimple
	ip := testAuthIP

	svc := newDeviceService(repo)
	fingerprintHash := svc.GenerateSimpleFingerprint(userAgent, ip)

	repo.On("GetByFingerprint", ctx, userID, fingerprintHash).Return(nil, errors.New("db error"))

	isNew, device, err := svc.CheckDeviceIsNew(ctx, userID, userAgent, ip)

	assert.Error(t, err)
	assert.False(t, isNew)
	assert.Nil(t, device)
}

// ---------------------------------------------------------------------------
// TestDeviceService_IsTrustedDevice
// ---------------------------------------------------------------------------

func TestDeviceService_IsTrustedDevice_Trusted(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	userAgent := testUserAgentSimple
	ip := testAuthIP

	repo := new(mockDeviceRepo)
	svc := newDeviceService(repo)
	hash := svc.GenerateSimpleFingerprint(userAgent, ip)

	repo.On("IsTrustedDevice", ctx, userID, hash).Return(true, nil)

	trusted, err := svc.IsTrustedDevice(ctx, userID, userAgent, ip, nil)

	require.NoError(t, err)
	assert.True(t, trusted)
}

func TestDeviceService_IsTrustedDevice_NotTrusted(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	userAgent := "Mozilla/5.0 Safari"
	ip := "192.168.0.1"

	repo := new(mockDeviceRepo)
	svc := newDeviceService(repo)
	hash := svc.GenerateSimpleFingerprint(userAgent, ip)

	repo.On("IsTrustedDevice", ctx, userID, hash).Return(false, nil)

	trusted, err := svc.IsTrustedDevice(ctx, userID, userAgent, ip, nil)

	require.NoError(t, err)
	assert.False(t, trusted)
}

// ---------------------------------------------------------------------------
// TestDeviceService_CleanupExpiredTrust
// ---------------------------------------------------------------------------

func TestDeviceService_CleanupExpiredTrust_Success(t *testing.T) {
	ctx := context.Background()

	repo := new(mockDeviceRepo)
	repo.On("CleanupExpiredTrust", ctx).Return(int64(3), nil)

	svc := newDeviceService(repo)
	count, err := svc.CleanupExpiredTrust(ctx)

	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestDeviceService_CleanupExpiredTrust_NothingToClean(t *testing.T) {
	ctx := context.Background()

	repo := new(mockDeviceRepo)
	repo.On("CleanupExpiredTrust", ctx).Return(int64(0), nil)

	svc := newDeviceService(repo)
	count, err := svc.CleanupExpiredTrust(ctx)

	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestDeviceService_CleanupExpiredTrust_Error(t *testing.T) {
	ctx := context.Background()

	repo := new(mockDeviceRepo)
	repo.On("CleanupExpiredTrust", ctx).Return(int64(0), errors.New("db error"))

	svc := newDeviceService(repo)
	count, err := svc.CleanupExpiredTrust(ctx)

	assert.Error(t, err)
	assert.Equal(t, int64(0), count)
	assert.Contains(t, err.Error(), "failed to cleanup expired trust")
}

// ---------------------------------------------------------------------------
// TestDeviceService_RenameDevice
// ---------------------------------------------------------------------------

func TestDeviceService_RenameDevice_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	device := buildDevice(userID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)
	repo.On("Update", ctx, mock.AnythingOfType("*models.Device")).Return(nil)

	svc := newDeviceService(repo)
	err := svc.RenameDevice(ctx, userID, device.ID, "My Work Laptop")

	require.NoError(t, err)
	// Verify device name was updated
	require.NotNil(t, device.DeviceName)
	assert.Equal(t, "My Work Laptop", *device.DeviceName)
}

func TestDeviceService_RenameDevice_NotFound(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	deviceID := uuid.New()

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, deviceID).Return(nil, nil)

	svc := newDeviceService(repo)
	err := svc.RenameDevice(ctx, userID, deviceID, "New Name")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device not found")
}

// ---------------------------------------------------------------------------
// TestDeviceService_GetDevice
// ---------------------------------------------------------------------------

func TestDeviceService_GetDevice_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	device := buildDevice(userID)

	repo := new(mockDeviceRepo)
	repo.On("GetByID", ctx, device.ID).Return(device, nil)

	svc := newDeviceService(repo)
	result, err := svc.GetDevice(ctx, device.ID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, device.ID, result.ID)
}

// ---------------------------------------------------------------------------
// TestDeviceService_TrustDeviceByFingerprint
// ---------------------------------------------------------------------------

func TestDeviceService_TrustDeviceByFingerprint_ExistingDevice(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	fingerprintHash := "abc123def456abc123def456abc123de"
	userAgent := "Mozilla/5.0 Chrome/120.0"
	ip := testAuthIP

	device := buildDevice(userID)
	device.FingerprintHash = fingerprintHash

	repo := new(mockDeviceRepo)
	repo.On("GetByFingerprint", ctx, userID, fingerprintHash).Return(device, nil)
	repo.On("TrustDevice", ctx, device.ID, mock.AnythingOfType("*time.Time")).Return(nil)

	svc := newDeviceService(repo)
	result, err := svc.TrustDeviceByFingerprint(ctx, userID, fingerprintHash, userAgent, ip, 30)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsTrusted)
	require.NotNil(t, result.TrustExpiresAt)
}

func TestDeviceService_TrustDeviceByFingerprint_NewDevice(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	fingerprintHash := "newdevicehash123456789012345678"
	userAgent := "Mozilla/5.0 Chrome/120.0"
	ip := "10.0.0.2"

	newDevice := buildDevice(userID)
	newDevice.FingerprintHash = fingerprintHash

	repo := new(mockDeviceRepo)
	// First call: device not found
	repo.On("GetByFingerprint", ctx, userID, fingerprintHash).Return(nil, nil).Once()
	// Create the device
	repo.On("UpsertDevice", ctx, mock.AnythingOfType("*models.Device")).Return(nil)
	// Fetch the created device
	repo.On("GetByFingerprint", ctx, userID, fingerprintHash).Return(newDevice, nil).Once()
	// Trust it
	repo.On("TrustDevice", ctx, newDevice.ID, mock.AnythingOfType("*time.Time")).Return(nil)

	svc := newDeviceService(repo)
	result, err := svc.TrustDeviceByFingerprint(ctx, userID, fingerprintHash, userAgent, ip, 30)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsTrusted)
}

func TestDeviceService_TrustDeviceByFingerprint_ForeverTrust(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	fingerprintHash := "abc123def456abc123def456abc123de"
	userAgent := testUserAgentSimple
	ip := testAuthIP

	device := buildDevice(userID)
	device.FingerprintHash = fingerprintHash

	repo := new(mockDeviceRepo)
	repo.On("GetByFingerprint", ctx, userID, fingerprintHash).Return(device, nil)
	// Duration 0 → no expiry
	repo.On("TrustDevice", ctx, device.ID, (*time.Time)(nil)).Return(nil)

	svc := newDeviceService(repo)
	result, err := svc.TrustDeviceByFingerprint(ctx, userID, fingerprintHash, userAgent, ip, 0)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Nil(t, result.TrustExpiresAt)
}

// ---------------------------------------------------------------------------
// TestDeviceService_GenerateSimpleFingerprint
// ---------------------------------------------------------------------------

func TestDeviceService_GenerateSimpleFingerprint_Deterministic(t *testing.T) {
	svc := newDeviceService(nil)

	ua := testUserAgentWinChrome
	ip := testAuthIP

	h1 := svc.GenerateSimpleFingerprint(ua, ip)
	h2 := svc.GenerateSimpleFingerprint(ua, ip)

	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64)
}

func TestDeviceService_GenerateSimpleFingerprint_DifferentUAs(t *testing.T) {
	svc := newDeviceService(nil)

	h1 := svc.GenerateSimpleFingerprint("Mozilla/5.0 Chrome", testAuthIP)
	h2 := svc.GenerateSimpleFingerprint("Mozilla/5.0 Firefox", testAuthIP)

	assert.NotEqual(t, h1, h2)
}
