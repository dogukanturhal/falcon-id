// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// internal_storage_handler.go provides a lightweight presigned-download URL
// generator for internal service-to-service calls.
//
// C# business modules (CRM, PLM, etc.) call
//   POST /api/v1/internal/storage/presigned-download
// with a JSON body containing a tenantId and objectKey, and receive back a
// time-limited presigned GET URL that the browser can use directly.
//
// The handler uses the official MinIO Go client, which natively targets
// MinIO and any S3-compatible backend. The presigned URL is generated against
// the *external* MinIO endpoint so the host in the SigV4 signature matches
// what the browser sends — generating against the internal endpoint and
// rewriting the host afterwards would invalidate the signature.

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	// presignedURLExpiry is the lifetime of each generated presigned URL.
	presignedURLExpiry = 1 * time.Hour
)

// InternalStorageConfig holds the MinIO connection parameters.
type InternalStorageConfig struct {
	// Endpoint is the internal S3-compatible endpoint (e.g. "minio:9000").
	Endpoint string
	// ExternalEndpoint is the host:port rewritten into the returned URL so that
	// browser clients can reach MinIO.  When empty, Endpoint is used instead.
	ExternalEndpoint string
	// AccessKey / SecretKey are the MinIO root credentials.
	AccessKey string
	SecretKey string
	// DefaultBucket is used when the bucket cannot be derived from the object key.
	DefaultBucket string
}

// InternalStorageHandler generates presigned MinIO download URLs for internal
// callers (C# business modules).
type InternalStorageHandler struct {
	cfg    InternalStorageConfig
	client *minio.Client
}

// NewInternalStorageHandler creates a new handler and initialises the MinIO
// client pointed at the configured external endpoint (so that SigV4 signatures
// match the host the browser ultimately resolves).
func NewInternalStorageHandler(cfg InternalStorageConfig) (*InternalStorageHandler, error) {
	if cfg.ExternalEndpoint == "" {
		cfg.ExternalEndpoint = cfg.Endpoint
	}

	// Use the external endpoint for presigning so that the host in the
	// signature matches what the browser sends. SigV4 includes the Host
	// header, so generating against the internal endpoint and rewriting the
	// host afterwards invalidates the signature.
	client, err := minio.New(cfg.ExternalEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: false, // in-cluster MinIO is plain HTTP
	})
	if err != nil {
		return nil, fmt.Errorf("NewInternalStorageHandler: build MinIO client: %w", err)
	}

	return &InternalStorageHandler{
		cfg:    cfg,
		client: client,
	}, nil
}

// presignedDownloadRequest is the JSON body sent by C# callers.
// C# StorageClient uses snake_case serialisation (JsonNamingPolicy.SnakeCaseLower).
type presignedDownloadRequest struct {
	TenantID  string `json:"tenant_id"  binding:"required"`
	ObjectKey string `json:"object_key" binding:"required"`
}

// presignedDownloadResponse is the JSON response returned to callers.
// C# PresignedDownloadResult expects download_url, expires_at, method (snake_case).
type presignedDownloadResponse struct {
	DownloadURL string    `json:"download_url"`
	ExpiresAt   time.Time `json:"expires_at"`
	Method      string    `json:"method"`
}

// PresignedDownload handles POST /api/v1/internal/storage/presigned-download.
//
// It derives the bucket name from the object key prefix (the segment between
// "tenants/<uuid>/" and the next slash encodes the product name, e.g. "crm"),
// falls back to the configured default bucket when no prefix is recognised,
// then generates a presigned GET URL valid for presignedURLExpiry.
//
// The host in the returned URL matches the externally-accessible address so
// that browsers can follow the link.
func (h *InternalStorageHandler) PresignedDownload(c *gin.Context) {
	var req presignedDownloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request body",
			"details": err.Error(),
		})
		return
	}

	bucket := h.bucketFromObjectKey(req.ObjectKey)
	expiresAt := time.Now().UTC().Add(presignedURLExpiry)

	presignedURL, err := h.client.PresignedGetObject(
		c.Request.Context(),
		bucket,
		req.ObjectKey,
		presignedURLExpiry,
		url.Values{},
	)
	if err != nil {
		logger.Log.Error("failed to generate presigned URL",
			zap.String("bucket", bucket),
			zap.String("object_key", req.ObjectKey),
			zap.String("tenant_id", req.TenantID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to generate presigned URL",
		})
		return
	}

	logger.Log.Debug("presigned download URL generated",
		zap.String("tenant_id", req.TenantID),
		zap.String("bucket", bucket),
		zap.String("object_key", req.ObjectKey),
		zap.Time("expires_at", expiresAt),
	)

	c.JSON(http.StatusOK, presignedDownloadResponse{
		DownloadURL: presignedURL.String(),
		ExpiresAt:   expiresAt,
		Method:      "GET",
	})
}

// bucketFromObjectKey attempts to derive a bucket name from a well-known
// object key structure.
//
// Expected key format:
//
//	tenants/<tenant-uuid>/<product>/...
//	                     ^^^^^^^^^
//	                     used to build "hexxlock-<product>"
//
// Examples:
//
//	"tenants/abc/crm/images/file.jpg"  → "hexxlock-crm"
//	"tenants/abc/plm/docs/spec.pdf"    → "hexxlock-plm"
//	"random/key.txt"                   → cfg.DefaultBucket
func (h *InternalStorageHandler) bucketFromObjectKey(_ string) string {
	// All ExampleSuite tenant files are stored in a single "example" bucket
	// with path-based partitioning: tenants/<uuid>/<module>/...
	return h.cfg.DefaultBucket
}
