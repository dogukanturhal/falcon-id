// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	avatarMaxSize             = 2 * 1024 * 1024 // 2 MB
	avatarBucket              = "hexxlock-avatars"
	msgNotAuthenticatedAvatar = "Not authenticated"
)

var allowedImageTypes = map[string]bool{
	"image/jpeg": true,
	"image/jpg":  true,
	"image/png":  true,
	"image/webp": true,
	"image/gif":  true,
}

// AvatarUploadHandler handles user avatar uploads to MinIO.
type AvatarUploadHandler struct {
	client      *minio.Client
	authService *services.AuthService
}

// NewAvatarUploadHandler creates a handler with direct MinIO access.
func NewAvatarUploadHandler(cfg InternalStorageConfig, authService *services.AuthService) (*AvatarUploadHandler, error) {
	// Fail-fast on missing credentials. The previous behaviour silently
	// fell back to viper dev defaults (`hexxlock` / `hexxlock_minio_dev_2024`)
	// and only surfaced the breakage via a `SignatureDoesNotMatch (HTTP 403)`
	// warning at HeadBucket time, which was easy to miss in startup logs.
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("NewAvatarUploadHandler: MINIO_ACCESS_KEY and MINIO_SECRET_KEY must be set")
	}

	if cfg.ExternalEndpoint == "" {
		cfg.ExternalEndpoint = cfg.Endpoint
	}

	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: false, // in-cluster MinIO is plain HTTP
	})
	if err != nil {
		return nil, fmt.Errorf("NewAvatarUploadHandler: build MinIO client: %w", err)
	}

	// Ensure bucket exists (best-effort — MinIO may already have it).
	exists, err := client.BucketExists(context.Background(), avatarBucket)
	if err != nil || !exists {
		if mkErr := client.MakeBucket(context.Background(), avatarBucket, minio.MakeBucketOptions{}); mkErr != nil {
			logger.Warn("Could not create avatar bucket (may already exist)", zap.Error(mkErr))
		}
	}

	return &AvatarUploadHandler{
		client:      client,
		authService: authService,
	}, nil
}

// UploadMyAvatar handles POST /api/v1/auth/me/avatar
func (h *AvatarUploadHandler) UploadMyAvatar(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedAvatar})
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file provided"})
		return
	}
	defer file.Close() //nolint:errcheck

	// Validate size
	if header.Size > avatarMaxSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File too large. Maximum size is 2MB."})
		return
	}

	// Validate content type
	contentType := header.Header.Get("Content-Type")
	if !allowedImageTypes[contentType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Allowed: JPEG, PNG, WebP, GIF."})
		return
	}

	// Read file into memory
	data, err := io.ReadAll(io.LimitReader(file, avatarMaxSize+1))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}
	if int64(len(data)) > avatarMaxSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File too large. Maximum size is 2MB."})
		return
	}

	// Generate object key: avatars/{user_id}/{uuid}.{ext}
	ext := filepath.Ext(header.Filename)
	if ext == "" {
		ext = ".jpg"
	}
	objectKey := fmt.Sprintf("avatars/%s/%s%s", user.ID.String(), uuid.New().String(), ext)

	// Upload directly to MinIO
	_, err = h.client.PutObject(c.Request.Context(), avatarBucket, objectKey,
		bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: contentType},
	)
	if err != nil {
		logger.Error("Failed to upload avatar to MinIO", zap.Error(err), zap.String("user_id", user.ID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload avatar"})
		return
	}

	// Store the object key (not a presigned URL) — images are served via GetMyAvatar proxy
	_, updateErr := h.authService.UpdateProfile(c.Request.Context(), user.ID, &models.UpdateProfileRequest{
		AvatarURL: &objectKey,
	})
	if updateErr != nil {
		logger.Error("Failed to update user avatar_url", zap.Error(updateErr), zap.String("user_id", user.ID.String()))
	}

	c.JSON(http.StatusOK, gin.H{
		"object_key": objectKey,
	})
}

// GetMyAvatar handles GET /api/v1/auth/avatar — proxies image from MinIO (authenticated)
func (h *AvatarUploadHandler) GetMyAvatar(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedAvatar})
		return
	}
	h.serveAvatar(c, user.ID)
}

// GetUserAvatar handles GET /api/v1/users/:id/avatar — public avatar proxy
func (h *AvatarUploadHandler) GetUserAvatar(c *gin.Context) {
	idStr := c.Param("id")
	userID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}
	h.serveAvatar(c, userID)
}

func (h *AvatarUploadHandler) serveAvatar(c *gin.Context, userID uuid.UUID) {
	userResp, err := h.authService.GetCurrentUser(c.Request.Context(), userID)
	if err != nil || userResp == nil || userResp.AvatarURL == nil || *userResp.AvatarURL == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "No avatar set"})
		return
	}

	objectKey := *userResp.AvatarURL

	obj, err := h.client.GetObject(c.Request.Context(), avatarBucket, objectKey, minio.GetObjectOptions{})
	if err != nil {
		logger.Error("Failed to get avatar from MinIO", zap.Error(err), zap.String("object_key", objectKey))
		c.JSON(http.StatusNotFound, gin.H{"error": "Avatar not found"})
		return
	}
	defer obj.Close() //nolint:errcheck

	// minio-go returns metadata via Stat() on the *Object.
	stat, err := obj.Stat()
	if err != nil {
		logger.Error("Failed to stat avatar object", zap.Error(err), zap.String("object_key", objectKey))
		c.JSON(http.StatusNotFound, gin.H{"error": "Avatar not found"})
		return
	}

	contentType := "image/jpeg"
	if stat.ContentType != "" {
		contentType = stat.ContentType
	}

	c.Header("Cache-Control", "public, max-age=3600")
	c.DataFromReader(http.StatusOK, stat.Size, contentType, obj, nil)
}

// DeleteMyAvatar handles DELETE /api/v1/auth/me/avatar
func (h *AvatarUploadHandler) DeleteMyAvatar(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedAvatar})
		return
	}

	// Clear avatar_url in profile
	emptyURL := ""
	_, err := h.authService.UpdateProfile(c.Request.Context(), user.ID, &models.UpdateProfileRequest{
		AvatarURL: &emptyURL,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove avatar"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Avatar removed"})
}
