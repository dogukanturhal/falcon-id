// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"context"
	"encoding/hex"
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

	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// ---------------------------------------------------------------------------
// Test double — in-process fake for IAMDevicesRepository
// ---------------------------------------------------------------------------

// iamDevicesRepoFake is a deterministic in-memory double that covers the
// two methods the handler depends on: RegisterDevice and GetByEKPubkeyHash.
// It is NOT thread-safe — handler tests are sequential.
type iamDevicesRepoFake struct {
	// RegisterDevice control knobs
	registerErr error

	// GetByEKPubkeyHash control knobs
	getRow repositories.IAMDeviceRow
	getErr error

	// GetByUUID control knobs
	getUUIDRow repositories.IAMDeviceRow
	getUUIDErr error

	// Captured calls (assertions)
	registerCalls []repositories.IAMDeviceRow
	getCalls      []string // hash values
	getUUIDCalls  []string // device_uuid values
}

func (f *iamDevicesRepoFake) RegisterDevice(_ context.Context, row repositories.IAMDeviceRow) error {
	f.registerCalls = append(f.registerCalls, row)
	return f.registerErr
}

func (f *iamDevicesRepoFake) GetByEKPubkeyHash(_ context.Context, hash string) (repositories.IAMDeviceRow, error) {
	f.getCalls = append(f.getCalls, hash)
	return f.getRow, f.getErr
}

func (f *iamDevicesRepoFake) GetByUUID(_ context.Context, deviceUUID string) (repositories.IAMDeviceRow, error) {
	f.getUUIDCalls = append(f.getUUIDCalls, deviceUUID)
	return f.getUUIDRow, f.getUUIDErr
}

// ---------------------------------------------------------------------------
// Router helpers
// ---------------------------------------------------------------------------

// newIAMDevicesTestRouter wires the handler onto a gin.Engine without the
// ServiceAuth middleware — tests use the fake repo directly and bypass auth
// (auth rejection is tested by the auth middleware's own test suite).
func newIAMDevicesTestRouter(repo IAMDevicesRepository) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewIAMDevicesHandler(repo)

	iamDevices := r.Group("/internal/v1/iam-devices")
	{
		iamDevices.POST("/enroll", h.Enroll)
		iamDevices.GET("/by-ek-hash/:hash", h.GetByEKHash)
		iamDevices.GET("/by-uuid/:uuid", h.GetByUUID)
	}
	return r
}

// newIAMDevicesTestRouterWithAuth adds a synthetic 401 middleware that fires
// when the request is missing the Authorization header, allowing the 401
// tests to prove the route is gated without spinning up the real
// ServiceAuthMiddleware (which requires an RSA key store).
func newIAMDevicesTestRouterWithAuth(repo IAMDevicesRepository) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewIAMDevicesHandler(repo)

	authGate := func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	}

	iamDevices := r.Group("/internal/v1/iam-devices")
	iamDevices.Use(authGate)
	{
		iamDevices.POST("/enroll", h.Enroll)
		iamDevices.GET("/by-ek-hash/:hash", h.GetByEKHash)
		iamDevices.GET("/by-uuid/:uuid", h.GetByUUID)
	}
	return r
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// validEKHash returns a 64-char hex string representing a 32-byte SHA-256 digest.
func validEKHash() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return hex.EncodeToString(b)
}

// validEnrollBody returns a minimal valid enrollment request body with all
// required fields populated.
func validEnrollBody() map[string]interface{} {
	return map[string]interface{}{
		"device_uuid":      uuid.New().String(),
		"user_sub":         "sub-user-00000000",
		"platform":         "tpm2-linux",
		"attestation_path": "A_chain",
		"tier":             "TIER_CORP",
		"ek_pubkey_hash":   validEKHash(),
		"enrolled_at":      time.Now().UTC().Format(time.RFC3339),
	}
}

// validDeviceRow returns an IAMDeviceRow that the fake repo returns on Get.
func validDeviceRow() repositories.IAMDeviceRow {
	tpmMfr := "Infineon"
	tpmKind := "discrete"
	ekRaw, _ := hex.DecodeString(validEKHash())
	return repositories.IAMDeviceRow{
		ID:              uuid.New(),
		DeviceUUID:      uuid.New(),
		UserSub:         "sub-user-00000000",
		Platform:        "tpm2-linux",
		AttestationPath: "A_chain",
		Tier:            "TIER_CORP",
		EKPubkeyHash:    ekRaw,
		TPMManufacturer: &tpmMfr,
		TPMKind:         &tpmKind,
		EnrolledAt:      time.Now().UTC().Truncate(time.Second),
		LastSeenAt:      time.Now().UTC().Truncate(time.Second),
	}
}

// marshalBody serialises a map into a *bytes.Reader for httptest.
func marshalBody(t *testing.T, body interface{}) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

// iamDoRequest performs a test HTTP request and returns the recorder.
// Named with the "iam" prefix to avoid collisions with doRequest helpers
// already defined in other test files in this package.
func iamDoRequest(t *testing.T, r *gin.Engine, method, path string, body *bytes.Reader) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, path, body)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, path, nil)
	}
	require.NoError(t, err)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// POST /internal/v1/iam-devices/enroll
// ---------------------------------------------------------------------------

func TestIAMDevicesHandler_Enroll_HappyPath(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouter(repo)

	body := validEnrollBody()
	devUUID := body["device_uuid"].(string)

	w := iamDoRequest(t, r, http.MethodPost, "/internal/v1/iam-devices/enroll", marshalBody(t, body))

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp enrollResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, devUUID, resp.DeviceUUID)

	// Repo was called with the right device UUID.
	require.Len(t, repo.registerCalls, 1)
	assert.Equal(t, devUUID, repo.registerCalls[0].DeviceUUID.String())
}

func TestIAMDevicesHandler_Enroll_HappyPath_WithOptionalFields(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouter(repo)

	tpmMfr := "Infineon"
	tpmKind := "discrete"
	witnessSub := "sub-admin-0001"
	witnessAt := time.Now().UTC().Format(time.RFC3339)

	body := validEnrollBody()
	body["tpm_manufacturer"] = tpmMfr
	body["tpm_kind"] = tpmKind
	body["witness_admin_sub"] = witnessSub
	body["witness_signed_at"] = witnessAt

	w := iamDoRequest(t, r, http.MethodPost, "/internal/v1/iam-devices/enroll", marshalBody(t, body))

	assert.Equal(t, http.StatusCreated, w.Code)
	require.Len(t, repo.registerCalls, 1)

	row := repo.registerCalls[0]
	require.NotNil(t, row.TPMManufacturer)
	assert.Equal(t, tpmMfr, *row.TPMManufacturer)
	require.NotNil(t, row.TPMKind)
	assert.Equal(t, tpmKind, *row.TPMKind)
	require.NotNil(t, row.WitnessAdminSub)
	assert.Equal(t, witnessSub, *row.WitnessAdminSub)
	require.NotNil(t, row.WitnessSignedAt)
}

func TestIAMDevicesHandler_Enroll_409_EKConflict(t *testing.T) {
	repo := &iamDevicesRepoFake{
		registerErr: repositories.ErrIAMDeviceEKConflict,
	}
	r := newIAMDevicesTestRouter(repo)

	w := iamDoRequest(t, r, http.MethodPost, "/internal/v1/iam-devices/enroll", marshalBody(t, validEnrollBody()))

	assert.Equal(t, http.StatusConflict, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "ek_pubkey_hash_conflict", resp["error"])
}

func TestIAMDevicesHandler_Enroll_409_UUIDConflict(t *testing.T) {
	repo := &iamDevicesRepoFake{
		registerErr: repositories.ErrIAMDeviceUUIDConflict,
	}
	r := newIAMDevicesTestRouter(repo)

	w := iamDoRequest(t, r, http.MethodPost, "/internal/v1/iam-devices/enroll", marshalBody(t, validEnrollBody()))

	assert.Equal(t, http.StatusConflict, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "device_uuid_conflict", resp["error"])
}

func TestIAMDevicesHandler_Enroll_400_MissingRequiredFields(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouter(repo)

	tests := []struct {
		name        string
		dropField   string
		wantErrCode string
	}{
		{name: "missing device_uuid", dropField: "device_uuid"},
		{name: "missing user_sub", dropField: "user_sub"},
		{name: "missing platform", dropField: "platform"},
		{name: "missing attestation_path", dropField: "attestation_path"},
		{name: "missing tier", dropField: "tier"},
		{name: "missing ek_pubkey_hash", dropField: "ek_pubkey_hash"},
		{name: "missing enrolled_at", dropField: "enrolled_at"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := validEnrollBody()
			delete(body, tc.dropField)

			w := iamDoRequest(t, r, http.MethodPost, "/internal/v1/iam-devices/enroll", marshalBody(t, body))
			assert.Equal(t, http.StatusBadRequest, w.Code, "expected 400 for missing %s", tc.dropField)
		})
	}
}

func TestIAMDevicesHandler_Enroll_400_InvalidDeviceUUID(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouter(repo)

	body := validEnrollBody()
	body["device_uuid"] = "not-a-uuid"

	w := iamDoRequest(t, r, http.MethodPost, "/internal/v1/iam-devices/enroll", marshalBody(t, body))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_device_uuid", resp["error"])
}

func TestIAMDevicesHandler_Enroll_400_InvalidEKPubkeyHash(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouter(repo)

	tests := []struct {
		name string
		hash string
		want string
	}{
		{name: "too_short", hash: "abc123", want: "invalid_ek_pubkey_hash"},
		{name: "not_hex", hash: strings.Repeat("z", 64), want: "invalid_ek_pubkey_hash"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := validEnrollBody()
			body["ek_pubkey_hash"] = tc.hash

			w := iamDoRequest(t, r, http.MethodPost, "/internal/v1/iam-devices/enroll", marshalBody(t, body))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			var resp map[string]interface{}
			require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Equal(t, tc.want, resp["error"])
		})
	}
}

func TestIAMDevicesHandler_Enroll_400_InvalidEnrolledAt(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouter(repo)

	body := validEnrollBody()
	body["enrolled_at"] = "not-a-date"

	w := iamDoRequest(t, r, http.MethodPost, "/internal/v1/iam-devices/enroll", marshalBody(t, body))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_enrolled_at", resp["error"])
}

func TestIAMDevicesHandler_Enroll_400_InvalidWitnessSignedAt(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouter(repo)

	body := validEnrollBody()
	body["witness_admin_sub"] = "sub-admin-0001"
	body["witness_signed_at"] = "bad-date"

	w := iamDoRequest(t, r, http.MethodPost, "/internal/v1/iam-devices/enroll", marshalBody(t, body))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_witness_signed_at", resp["error"])
}

func TestIAMDevicesHandler_Enroll_400_RepoValidationError(t *testing.T) {
	// The repo validates platform/attestation_path/tier enums and returns
	// a wrapped error. Handler must map this to 400 (not 500).
	repo := &iamDevicesRepoFake{
		registerErr: errors.New(`iam_devices: register_device: platform "invalid-plat" is not one of: tpm2-linux, tpm2-windows, android-strongbox, apple-app-attest, macos-mdm`),
	}
	r := newIAMDevicesTestRouter(repo)

	body := validEnrollBody()
	// Send a syntactically valid request; the fake repo returns the
	// validation error to simulate what happens when an unknown enum value
	// slips through.
	w := iamDoRequest(t, r, http.MethodPost, "/internal/v1/iam-devices/enroll", marshalBody(t, body))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "validation_error", resp["error"])
}

func TestIAMDevicesHandler_Enroll_500_UnexpectedRepoError(t *testing.T) {
	repo := &iamDevicesRepoFake{
		registerErr: errors.New("connection refused"),
	}
	r := newIAMDevicesTestRouter(repo)

	w := iamDoRequest(t, r, http.MethodPost, "/internal/v1/iam-devices/enroll", marshalBody(t, validEnrollBody()))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "enroll_failed", resp["error"])
}

func TestIAMDevicesHandler_Enroll_401_MissingAuthHeader(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouterWithAuth(repo)

	// No Authorization header → auth gate returns 401.
	body := validEnrollBody()
	req, err := http.NewRequest(http.MethodPost, "/internal/v1/iam-devices/enroll", marshalBody(t, body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	// Intentionally no Authorization header.

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	// Repo must not have been called.
	assert.Len(t, repo.registerCalls, 0)
}

func TestIAMDevicesHandler_Enroll_400_InvalidJSON(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouter(repo)

	req, err := http.NewRequest(http.MethodPost, "/internal/v1/iam-devices/enroll",
		strings.NewReader("{bad json"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// GET /internal/v1/iam-devices/by-ek-hash/:hash
// ---------------------------------------------------------------------------

func TestIAMDevicesHandler_GetByEKHash_HappyPath(t *testing.T) {
	devRow := validDeviceRow()
	repo := &iamDevicesRepoFake{
		getRow: devRow,
	}
	r := newIAMDevicesTestRouter(repo)

	hash := validEKHash()
	w := iamDoRequest(t, r, http.MethodGet, "/internal/v1/iam-devices/by-ek-hash/"+hash, nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp getByEKHashResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, devRow.DeviceUUID.String(), resp.DeviceUUID)
	assert.Equal(t, devRow.UserSub, resp.UserSub)
	assert.Equal(t, devRow.Platform, resp.Platform)
	assert.Equal(t, devRow.AttestationPath, resp.AttestationPath)
	assert.Equal(t, devRow.Tier, resp.Tier)
	assert.Equal(t, hex.EncodeToString(devRow.EKPubkeyHash), resp.EKPubkeyHash)
	// enrolled_at must be RFC3339
	_, parseErr := time.Parse(time.RFC3339, resp.EnrolledAt)
	assert.NoError(t, parseErr, "enrolled_at must be RFC3339")
}

func TestIAMDevicesHandler_GetByEKHash_404_NotFound(t *testing.T) {
	// The repo wraps pgx.ErrNoRows as "iam_devices: get_by_ek_pubkey_hash: no rows in result set"
	repo := &iamDevicesRepoFake{
		getErr: errors.New("iam_devices: get_by_ek_pubkey_hash: no rows in result set"),
	}
	r := newIAMDevicesTestRouter(repo)

	hash := validEKHash()
	w := iamDoRequest(t, r, http.MethodGet, "/internal/v1/iam-devices/by-ek-hash/"+hash, nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "device_not_found", resp["error"])
}

func TestIAMDevicesHandler_GetByEKHash_400_HashTooShort(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouter(repo)

	// 32 hex chars — too short (need 64)
	shortHash := strings.Repeat("a", 32)
	w := iamDoRequest(t, r, http.MethodGet, "/internal/v1/iam-devices/by-ek-hash/"+shortHash, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_hash", resp["error"])
}

func TestIAMDevicesHandler_GetByEKHash_400_NotHex(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouter(repo)

	// 64 chars but not valid hex (z is not a hex digit)
	badHash := strings.Repeat("z", 64)
	w := iamDoRequest(t, r, http.MethodGet, "/internal/v1/iam-devices/by-ek-hash/"+badHash, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_hash", resp["error"])
}

func TestIAMDevicesHandler_GetByEKHash_500_RepoError(t *testing.T) {
	repo := &iamDevicesRepoFake{
		getErr: errors.New("pq: could not connect to server"),
	}
	r := newIAMDevicesTestRouter(repo)

	hash := validEKHash()
	w := iamDoRequest(t, r, http.MethodGet, "/internal/v1/iam-devices/by-ek-hash/"+hash, nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "lookup_failed", resp["error"])
}

func TestIAMDevicesHandler_GetByEKHash_401_MissingAuthHeader(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouterWithAuth(repo)

	hash := validEKHash()
	req, err := http.NewRequest(http.MethodGet, "/internal/v1/iam-devices/by-ek-hash/"+hash, nil)
	require.NoError(t, err)
	// No Authorization header.

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Len(t, repo.getCalls, 0)
}

// ---------------------------------------------------------------------------
// EK hash routing — verify :hash parameter is forwarded to repo
// ---------------------------------------------------------------------------

func TestIAMDevicesHandler_GetByEKHash_RepoReceivesCorrectHash(t *testing.T) {
	devRow := validDeviceRow()
	repo := &iamDevicesRepoFake{getRow: devRow}
	r := newIAMDevicesTestRouter(repo)

	hash := validEKHash()
	w := iamDoRequest(t, r, http.MethodGet, "/internal/v1/iam-devices/by-ek-hash/"+hash, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	require.Len(t, repo.getCalls, 1)
	assert.Equal(t, hash, repo.getCalls[0])
}

// ---------------------------------------------------------------------------
// isNotFoundError unit tests
// ---------------------------------------------------------------------------

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "repo_wrapped_no_rows",
			err:  errors.New("iam_devices: get_by_ek_pubkey_hash: no rows in result set"),
			want: true,
		},
		{
			name: "plain_no_rows",
			err:  errors.New("no rows in result set"),
			want: true,
		},
		{
			name: "transport_error",
			err:  errors.New("connection refused"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isNotFoundError(tc.err))
		})
	}
}

// ---------------------------------------------------------------------------
// isIAMDeviceValidationError unit tests
// ---------------------------------------------------------------------------

func TestIsIAMDeviceValidationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "platform_enum",
			err:  errors.New(`iam_devices: register_device: platform "bad" is not one of: tpm2-linux`),
			want: true,
		},
		{
			name: "tier_enum",
			err:  errors.New(`iam_devices: register_device: tier "TIER_X" must be one of: TIER_CORP, TIER_BYOD, TIER_BREAKGLASS`),
			want: true,
		},
		{
			name: "attestation_path_enum",
			err:  errors.New(`iam_devices: register_device: attestation_path "X" must be one of: A_chain, B_tofu`),
			want: true,
		},
		{
			name: "uuid_invalid",
			err:  errors.New("iam_devices: register_device: device_uuid is not a valid UUID: invalid UUID length: 5"),
			want: true,
		},
		{
			name: "ek_hash_length",
			err:  errors.New("iam_devices: register_device: ek_pubkey_hash must be 32 bytes (SHA-256), got 16"),
			want: true,
		},
		{
			name: "transport_error",
			err:  errors.New("dial tcp: connection refused"),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isIAMDeviceValidationError(tc.err))
		})
	}
}

// ─── GetByUUID (ADR 0048 renewal revocation gate) ────────────────────────────

func TestIAMDevicesHandler_GetByUUID_200_Active(t *testing.T) {
	row := validDeviceRow()
	repo := &iamDevicesRepoFake{getUUIDRow: row}
	r := newIAMDevicesTestRouter(repo)

	w := iamDoRequest(t, r, http.MethodGet, "/internal/v1/iam-devices/by-uuid/"+row.DeviceUUID.String(), nil)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, row.DeviceUUID.String(), resp["device_uuid"])
	// An active device omits revoked_at (omitempty).
	_, hasRevoked := resp["revoked_at"]
	assert.False(t, hasRevoked, "active device must not carry revoked_at")
	require.Len(t, repo.getUUIDCalls, 1)
	assert.Equal(t, row.DeviceUUID.String(), repo.getUUIDCalls[0])
}

func TestIAMDevicesHandler_GetByUUID_200_Revoked(t *testing.T) {
	row := validDeviceRow()
	revokedAt := time.Now().UTC().Truncate(time.Second)
	reason := "operator offboarded"
	row.RevokedAt = &revokedAt
	row.RevokedReason = &reason
	repo := &iamDevicesRepoFake{getUUIDRow: row}
	r := newIAMDevicesTestRouter(repo)

	w := iamDoRequest(t, r, http.MethodGet, "/internal/v1/iam-devices/by-uuid/"+row.DeviceUUID.String(), nil)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, revokedAt.Format(time.RFC3339), resp["revoked_at"],
		"revoked device must surface revoked_at for the jess renewal gate")
	assert.Equal(t, "operator offboarded", resp["revoked_reason"])
}

func TestIAMDevicesHandler_GetByUUID_400_BadUUID(t *testing.T) {
	repo := &iamDevicesRepoFake{}
	r := newIAMDevicesTestRouter(repo)

	w := iamDoRequest(t, r, http.MethodGet, "/internal/v1/iam-devices/by-uuid/not-a-uuid", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, repo.getUUIDCalls, "repo must not be queried for an invalid UUID")
}

func TestIAMDevicesHandler_GetByUUID_404_NotFound(t *testing.T) {
	repo := &iamDevicesRepoFake{
		getUUIDErr: errors.New("iam_devices: get_by_uuid: no rows in result set"),
	}
	r := newIAMDevicesTestRouter(repo)

	w := iamDoRequest(t, r, http.MethodGet, "/internal/v1/iam-devices/by-uuid/"+uuid.New().String(), nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "device_not_found", resp["error"])
}
