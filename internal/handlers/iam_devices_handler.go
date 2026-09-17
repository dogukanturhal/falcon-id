// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// IAMDevicesRepository is the narrow interface the handler depends on.
// It is satisfied by *repositories.IAMDevicesRepository in production and
// by a test double in unit tests.
//
// Narrow interface discipline keeps handler tests fast (no real DB, no
// testcontainer startup) while the repository layer carries its own
// pgxmock test suite.
type IAMDevicesRepository interface {
	RegisterDevice(ctx context.Context, row repositories.IAMDeviceRow) error
	GetByEKPubkeyHash(ctx context.Context, hash string) (repositories.IAMDeviceRow, error)
	GetByUUID(ctx context.Context, deviceUUID string) (repositories.IAMDeviceRow, error)
}

// IAMDevicesHandler serves the ZTNA Phase 3 device enrollment endpoints.
// Both endpoints live under /internal/v1/iam-devices/ and are protected by
// ServiceAuth middleware (OAuth2 client_credentials Bearer) — they are never
// exposed at the public edge.
//
// Consumer: jess controller (feat/ztna-phase3-controller-wiring) via
// devicepolicy.FalconIDEnrollmentStore (HTTP client). The JSON field names
// here must byte-for-byte match the jess falconIDEnrollRequest /
// falconIDGetByEKResponse structs.
//
// References:
//   - ADR 0043 §3.c.0 — ZTNA Phase 3 device-cert profile
//   - falcon-id!285 — IAMDevicesRepository (repositories/iam_devices_repository.go)
//   - jess feat/ztna-phase3-controller-wiring — consuming client
type IAMDevicesHandler struct {
	repo IAMDevicesRepository
}

// NewIAMDevicesHandler constructs a handler wired to the given repository.
func NewIAMDevicesHandler(repo IAMDevicesRepository) *IAMDevicesHandler {
	return &IAMDevicesHandler{repo: repo}
}

// ─── Request / Response shapes ───────────────────────────────────────────────
//
// These types mirror the jess client structs in
// devicepolicy/falconid_enrollment_store.go exactly (same json tags,
// same snake_case names). Any divergence breaks the s2s contract.

// enrollRequest is the JSON body for POST /internal/v1/iam-devices/enroll.
// Matches jess falconIDEnrollRequest.
type enrollRequest struct {
	DeviceUUID      string `json:"device_uuid"`
	UserSub         string `json:"user_sub"`
	Platform        string `json:"platform"`
	AttestationPath string `json:"attestation_path"`
	Tier            string `json:"tier"`
	// EKPubkeyHash is the 64-char lowercase hex encoding of SHA-256(EK pubkey PEM).
	// Decoded to []byte before writing to the ek_pubkey_hash bytea column.
	EKPubkeyHash    string  `json:"ek_pubkey_hash"`
	TPMManufacturer *string `json:"tpm_manufacturer,omitempty"`
	TPMKind         *string `json:"tpm_kind,omitempty"`
	WitnessAdminSub *string `json:"witness_admin_sub,omitempty"`
	WitnessSignedAt *string `json:"witness_signed_at,omitempty"` // RFC3339
	EnrolledAt      string  `json:"enrolled_at"`                 // RFC3339 UTC

	// Hardware identity (OEM SMBIOS/DMI) collected by the hexxlock-access
	// agent at enrollment. All optional — omitted/empty persist as "".
	// Shared cross-repo contract field names (snake_case).
	SerialNumber string `json:"serial_number"`
	Model        string `json:"model"`
	Manufacturer string `json:"manufacturer"`
}

// enrollResponse is returned on a successful 201. Matches jess
// falconIDEnrollResponse. Only DeviceUUID is required — the jess caller
// uses its own EKPubkeyHash as the anchor and does not store the DB-assigned
// surrogate ID.
type enrollResponse struct {
	DeviceUUID string `json:"device_uuid"`
}

// getByEKHashResponse is returned by GET /internal/v1/iam-devices/by-ek-hash/:hash.
// Matches jess falconIDGetByEKResponse.
type getByEKHashResponse struct {
	DeviceUUID      string  `json:"device_uuid"`
	UserSub         string  `json:"user_sub"`
	Platform        string  `json:"platform"`
	AttestationPath string  `json:"attestation_path"`
	Tier            string  `json:"tier"`
	EKPubkeyHash    string  `json:"ek_pubkey_hash"` // hex-encoded
	TPMManufacturer *string `json:"tpm_manufacturer,omitempty"`
	TPMKind         *string `json:"tpm_kind,omitempty"`
	WitnessAdminSub *string `json:"witness_admin_sub,omitempty"`
	EnrolledAt      string  `json:"enrolled_at"` // RFC3339
	// Hardware identity (empty string when the agent did not capture it).
	SerialNumber string `json:"serial_number"`
	Model        string `json:"model"`
	Manufacturer string `json:"manufacturer"`
}

// ─── Handlers ────────────────────────────────────────────────────────────────

// Enroll handles POST /internal/v1/iam-devices/enroll.
//
// Auth:   serviceAuthMiddleware.ServiceAuth() — mounted at the route group.
// Status code policy:
//
//	201 Created  — device registered; body: {"device_uuid": "<uuid>"}
//	400 Bad Request — validation error (missing field, invalid enum value,
//	                  malformed UUID, bad hex, non-RFC3339 timestamp)
//	409 Conflict — ek_pubkey_hash already registered (re-enrollment / impersonation
//	               signal); jess treats this as ErrVerification → 403 to caller
//	500 Internal Server Error — transport-class errors; structured log emitted
func (h *IAMDevicesHandler) Enroll(c *gin.Context) {
	var req enrollRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_json", "details": err.Error()})
		return
	}

	// Validate required string fields before hitting the repo.
	if req.DeviceUUID == "" || req.UserSub == "" || req.Platform == "" ||
		req.AttestationPath == "" || req.Tier == "" || req.EKPubkeyHash == "" || req.EnrolledAt == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_required_fields",
			"details": "device_uuid, user_sub, platform, attestation_path, tier, ek_pubkey_hash, enrolled_at are required"})
		return
	}

	// Validate and parse device_uuid.
	deviceUUID, err := uuid.Parse(req.DeviceUUID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_device_uuid",
			"details": "device_uuid must be a valid UUID"})
		return
	}

	// Decode ek_pubkey_hash: 64 hex chars → 32 bytes.
	if len(req.EKPubkeyHash) != 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_ek_pubkey_hash",
			"details": "ek_pubkey_hash must be 64 hex characters (SHA-256 hex-encoded)"})
		return
	}
	ekHash, err := hex.DecodeString(req.EKPubkeyHash)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_ek_pubkey_hash",
			"details": "ek_pubkey_hash is not valid hex"})
		return
	}

	// Parse enrolled_at (RFC3339).
	enrolledAt, err := time.Parse(time.RFC3339, req.EnrolledAt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_enrolled_at",
			"details": "enrolled_at must be RFC3339 (e.g. 2006-01-02T15:04:05Z)"})
		return
	}

	// Parse optional witness_signed_at.
	var witnessSignedAt *time.Time
	if req.WitnessSignedAt != nil {
		t, tErr := time.Parse(time.RFC3339, *req.WitnessSignedAt)
		if tErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_witness_signed_at",
				"details": "witness_signed_at must be RFC3339 when present"})
			return
		}
		witnessSignedAt = &t
	}

	row := repositories.IAMDeviceRow{
		DeviceUUID:      deviceUUID,
		UserSub:         req.UserSub,
		Platform:        req.Platform,
		AttestationPath: req.AttestationPath,
		Tier:            req.Tier,
		EKPubkeyHash:    ekHash,
		TPMManufacturer: req.TPMManufacturer,
		TPMKind:         req.TPMKind,
		WitnessAdminSub: req.WitnessAdminSub,
		WitnessSignedAt: witnessSignedAt,
		EnrolledAt:      enrolledAt.UTC(),
		LastSeenAt:      enrolledAt.UTC(),
		SerialNumber:    req.SerialNumber,
		Model:           req.Model,
		Manufacturer:    req.Manufacturer,
	}

	if err := h.repo.RegisterDevice(c.Request.Context(), row); err != nil {
		switch {
		case errors.Is(err, repositories.ErrIAMDeviceEKConflict):
			c.JSON(http.StatusConflict, gin.H{
				"error":      "ek_pubkey_hash_conflict",
				"details":    "ek_pubkey_hash is already registered; re-enrollment conflicts are a security signal",
				"constraint": "iam_devices_ek_pubkey_hash_key",
			})
		case errors.Is(err, repositories.ErrIAMDeviceUUIDConflict):
			c.JSON(http.StatusConflict, gin.H{
				"error":      "device_uuid_conflict",
				"details":    "device_uuid is already registered with a different ek_pubkey_hash",
				"constraint": "iam_devices_device_uuid_key",
			})
		default:
			// Check if this is a validation error (pre-flight, from repo layer).
			// The repo wraps validation errors as "iam_devices: register_device: <detail>".
			// We surface those as 400; all other errors are 500.
			if isIAMDeviceValidationError(err) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "validation_error", "details": stripRepoPrefix(err.Error())})
				return
			}
			logger.Error("IAMDevicesHandler.Enroll: repository error",
				zap.Error(err),
				zap.String("device_uuid", req.DeviceUUID),
				zap.String("user_sub", req.UserSub),
				zap.String("remote_addr", GetClientIP(c)),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "enroll_failed"})
		}
		return
	}

	c.JSON(http.StatusCreated, enrollResponse{DeviceUUID: req.DeviceUUID})
}

// getByUUIDResponse is returned by GET /internal/v1/iam-devices/by-uuid/:uuid.
// Superset of getByEKHashResponse: it ALSO carries revocation state
// (revoked_at / revoked_reason) so the jess device-cert renewal handler
// (ADR 0048) can refuse to renew a revoked-but-not-yet-expired device.
// Matches jess falconIDGetByUUIDResponse.
type getByUUIDResponse struct {
	DeviceUUID      string  `json:"device_uuid"`
	UserSub         string  `json:"user_sub"`
	Platform        string  `json:"platform"`
	AttestationPath string  `json:"attestation_path"`
	Tier            string  `json:"tier"`
	EKPubkeyHash    string  `json:"ek_pubkey_hash"` // hex-encoded
	TPMManufacturer *string `json:"tpm_manufacturer,omitempty"`
	TPMKind         *string `json:"tpm_kind,omitempty"`
	WitnessAdminSub *string `json:"witness_admin_sub,omitempty"`
	EnrolledAt      string  `json:"enrolled_at"`          // RFC3339
	RevokedAt       string  `json:"revoked_at,omitempty"` // RFC3339; empty = active
	RevokedReason   *string `json:"revoked_reason,omitempty"`
	// Hardware identity (empty string when the agent did not capture it).
	SerialNumber string `json:"serial_number"`
	Model        string `json:"model"`
	Manufacturer string `json:"manufacturer"`
}

// GetByUUID handles GET /internal/v1/iam-devices/by-uuid/:uuid.
//
// Auth:   serviceAuthMiddleware.ServiceAuth() — mounted at the route group.
// :uuid must be a valid UUID (the device's SPIFFE-SAN identity).
//
// Status code policy:
//
//	200 OK         — device found; body: getByUUIDResponse (incl. revoked_at)
//	400 Bad Request — :uuid is not a valid UUID
//	404 Not Found  — no device with this UUID
//	500 Internal Server Error — transport-class errors; structured log emitted
//
// Consumer: jess device-cert renewal handler (ADR 0048) — checks revoked_at
// to fail-closed on a revoked device before minting a fresh cert.
func (h *IAMDevicesHandler) GetByUUID(c *gin.Context) {
	deviceUUID := c.Param("uuid")
	if _, err := uuid.Parse(deviceUUID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_uuid",
			"details": "uuid path parameter is not a valid UUID",
		})
		return
	}

	row, err := h.repo.GetByUUID(c.Request.Context(), deviceUUID)
	if err != nil {
		if isNotFoundError(err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "device_not_found",
				"details": "no device registered for the supplied device_uuid",
			})
			return
		}
		logger.Error("IAMDevicesHandler.GetByUUID: repository error",
			zap.Error(err),
			zap.String("device_uuid", deviceUUID),
			zap.String("remote_addr", GetClientIP(c)),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup_failed"})
		return
	}

	resp := getByUUIDResponse{
		DeviceUUID:      row.DeviceUUID.String(),
		UserSub:         row.UserSub,
		Platform:        row.Platform,
		AttestationPath: row.AttestationPath,
		Tier:            row.Tier,
		EKPubkeyHash:    hex.EncodeToString(row.EKPubkeyHash),
		TPMManufacturer: row.TPMManufacturer,
		TPMKind:         row.TPMKind,
		WitnessAdminSub: row.WitnessAdminSub,
		EnrolledAt:      row.EnrolledAt.UTC().Format(time.RFC3339),
		RevokedReason:   row.RevokedReason,
		SerialNumber:    row.SerialNumber,
		Model:           row.Model,
		Manufacturer:    row.Manufacturer,
	}
	if row.RevokedAt != nil {
		resp.RevokedAt = row.RevokedAt.UTC().Format(time.RFC3339)
	}

	c.JSON(http.StatusOK, resp)
}

// GetByEKHash handles GET /internal/v1/iam-devices/by-ek-hash/:hash.
//
// Auth:   serviceAuthMiddleware.ServiceAuth() — mounted at the route group.
// :hash must be a 64-char lowercase hex string (SHA-256 of the EK pubkey PEM).
//
// Status code policy:
//
//	200 OK       — device found; body: getByEKHashResponse
//	400 Bad Request — :hash is not 64 valid hex chars
//	404 Not Found — no enrollment for this EK hash (Path B first-seen, clean path)
//	500 Internal Server Error — transport-class errors; structured log emitted
func (h *IAMDevicesHandler) GetByEKHash(c *gin.Context) {
	hash := c.Param("hash")

	// Validate: must be exactly 64 lowercase hex characters.
	if len(hash) != 64 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_hash",
			"details": "hash must be 64 hex characters (SHA-256 hex-encoded), got " + string(rune(len(hash))),
		})
		return
	}
	if _, err := hex.DecodeString(hash); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_hash",
			"details": "hash is not valid hex",
		})
		return
	}

	row, err := h.repo.GetByEKPubkeyHash(c.Request.Context(), hash)
	if err != nil {
		// The repository wraps pgx.ErrNoRows — use errors.Is across the chain.
		// We check the error message as a fallback because pgx.ErrNoRows is
		// re-wrapped by the repo layer with fmt.Errorf("…: %w", pgx.ErrNoRows).
		if isNotFoundError(err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "device_not_found",
				"details": "no device registered for the supplied ek_pubkey_hash",
			})
			return
		}
		logger.Error("IAMDevicesHandler.GetByEKHash: repository error",
			zap.Error(err),
			zap.String("ek_hash", hash),
			zap.String("remote_addr", GetClientIP(c)),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup_failed"})
		return
	}

	resp := getByEKHashResponse{
		DeviceUUID:      row.DeviceUUID.String(),
		UserSub:         row.UserSub,
		Platform:        row.Platform,
		AttestationPath: row.AttestationPath,
		Tier:            row.Tier,
		EKPubkeyHash:    hex.EncodeToString(row.EKPubkeyHash),
		TPMManufacturer: row.TPMManufacturer,
		TPMKind:         row.TPMKind,
		WitnessAdminSub: row.WitnessAdminSub,
		EnrolledAt:      row.EnrolledAt.UTC().Format(time.RFC3339),
		SerialNumber:    row.SerialNumber,
		Model:           row.Model,
		Manufacturer:    row.Manufacturer,
	}

	c.JSON(http.StatusOK, resp)
}

// ─── Error classification helpers ────────────────────────────────────────────

// isNotFoundError returns true when the error chain contains pgx.ErrNoRows.
// The repository layer wraps it as:
//
//	fmt.Errorf("iam_devices: get_by_ek_pubkey_hash: %w", pgx.ErrNoRows)
//
// so errors.Is(err, pgx.ErrNoRows) traverses the chain when the error uses
// %w. For test doubles that use errors.New() directly (plain string, no
// unwrap chain), we fall back to a substring check on the canonical
// pgx.ErrNoRows message ("no rows in result set").
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Fast path: %w-wrapped chain from the real repository.
	for unwrapped := err; unwrapped != nil; unwrapped = errors.Unwrap(unwrapped) {
		if unwrapped.Error() == "no rows in result set" {
			return true
		}
	}
	// Fallback: plain errors.New() from test doubles or non-wrapped errors.
	return iamDevicesStrContains(err.Error(), "no rows in result set")
}

// isIAMDeviceValidationError returns true when the error originates from the
// repository's pre-flight validation (platform enum, attestation_path enum,
// tier enum, UUID format, EK hash length). The repository wraps these as
// "iam_devices: register_device: <field> …".
// This heuristic keeps transport-class pgconn errors out of the 400 path.
func isIAMDeviceValidationError(err error) bool {
	msg := err.Error()
	validationPhrases := []string{
		"is not one of:",
		"must be one of:",
		"must be UUIDv4",
		"not a valid UUID",
		"must be 32 bytes",
		"attestation_path",
		"device_uuid is not",
	}
	for _, phrase := range validationPhrases {
		if iamDevicesStrContains(msg, phrase) {
			return true
		}
	}
	return false
}

// stripRepoPrefix removes the "iam_devices: register_device: " prefix that
// the repository prepends to validation error messages before surfacing them
// in the HTTP response.
func stripRepoPrefix(msg string) string {
	prefixes := []string{
		"iam_devices: register_device: ",
		"iam_devices: get_by_ek_pubkey_hash: ",
	}
	for _, p := range prefixes {
		if len(msg) > len(p) && msg[:len(p)] == p {
			return msg[len(p):]
		}
	}
	return msg
}

// iamDevicesStrContains is a zero-dependency substring check scoped to
// this file to avoid name collisions with other test helpers in the
// handlers package (the handlers package shares a single test binary).
func iamDevicesStrContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
