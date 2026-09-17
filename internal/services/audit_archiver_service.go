// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/encrypt"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	// DefaultRetentionDays is the default active retention period (1 year)
	DefaultRetentionDays = 365

	// ArchiveRetentionYears is the archive retention period (7 years for compliance)
	ArchiveRetentionYears = 7

	// MaxArchiveBatchSize is the maximum number of records to archive in one batch
	MaxArchiveBatchSize = 10000
)

// AuditArchiverConfig holds configuration for audit log archiving
type AuditArchiverConfig struct {
	S3Bucket          string
	S3Region          string
	S3Endpoint        string // For MinIO or custom S3 endpoints (host:port form, scheme via S3UseSSL)
	S3UseSSL          bool   // True for HTTPS endpoints, false for plain HTTP (default)
	RetentionDays     int
	ObjectLockEnabled bool
	EncryptionEnabled bool
}

// AuditArchiverService handles archiving of audit logs to S3 with Object Lock
type AuditArchiverService struct {
	auditService *AuditService
	db           *pgxpool.Pool
	client       *minio.Client
	config       *AuditArchiverConfig
}

// NewAuditArchiverService creates a new audit archiver service
func NewAuditArchiverService(
	auditService *AuditService,
	db *pgxpool.Pool,
	cfg *AuditArchiverConfig,
) (*AuditArchiverService, error) {
	if cfg == nil {
		return nil, fmt.Errorf("archiver config is required")
	}

	// Strip any scheme prefix the caller may have included; minio-go expects
	// host:port form and decides scheme via the Secure option.
	endpoint := strings.TrimPrefix(strings.TrimPrefix(cfg.S3Endpoint, "https://"), "http://")
	if endpoint == "" {
		return nil, fmt.Errorf("audit archiver: S3Endpoint is required")
	}

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewEnvAWS(), // Falls back to env vars (AWS_ACCESS_KEY_ID etc.) — same surface the previous SDK used.
		Secure: cfg.S3UseSSL,
		Region: cfg.S3Region,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build MinIO client: %w", err)
	}

	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = DefaultRetentionDays
	}

	return &AuditArchiverService{
		auditService: auditService,
		db:           db,
		client:       client,
		config:       cfg,
	}, nil
}

// ArchiveTenantLogs archives audit logs for a specific tenant
func (s *AuditArchiverService) ArchiveTenantLogs(ctx context.Context, tenantID uuid.UUID, performedBy *uuid.UUID) error {
	logger.Info("Starting audit log archival",
		zap.String("tenant_id", tenantID.String()),
		zap.Int("retention_days", s.config.RetentionDays),
	)

	// Get logs to archive
	logs, err := s.auditService.GetAuditLogsForArchive(ctx, tenantID, s.config.RetentionDays)
	if err != nil {
		return fmt.Errorf("failed to get audit logs for archive: %w", err)
	}

	if len(logs) == 0 {
		logger.Info("No audit logs to archive", zap.String("tenant_id", tenantID.String()))
		return nil
	}

	logger.Info("Found audit logs to archive",
		zap.String("tenant_id", tenantID.String()),
		zap.Int("count", len(logs)),
	)

	// Archive in batches
	batchCount := 0
	for i := 0; i < len(logs); i += MaxArchiveBatchSize {
		end := i + MaxArchiveBatchSize
		if end > len(logs) {
			end = len(logs)
		}

		batch := logs[i:end]
		if err := s.archiveBatch(ctx, tenantID, batch, performedBy); err != nil {
			logger.Error("Failed to archive batch",
				zap.Error(err),
				zap.Int("batch_number", batchCount+1),
			)
			return fmt.Errorf("failed to archive batch %d: %w", batchCount+1, err)
		}

		batchCount++
	}

	logger.Info("Completed audit log archival",
		zap.String("tenant_id", tenantID.String()),
		zap.Int("total_logs", len(logs)),
		zap.Int("batches", batchCount),
	)

	return nil
}

// archiveBatch archives a batch of audit logs to S3
func (s *AuditArchiverService) archiveBatch(ctx context.Context, tenantID uuid.UUID, logs []models.AuditLog, performedBy *uuid.UUID) error {
	if len(logs) == 0 {
		return nil
	}

	batchID := uuid.New()
	startDate := logs[len(logs)-1].CreatedAt // Oldest
	endDate := logs[0].CreatedAt             // Newest

	// Convert logs to JSON
	logsJSON, err := json.Marshal(logs)
	if err != nil {
		return fmt.Errorf("failed to marshal logs: %w", err)
	}

	// Compress with gzip
	var compressed bytes.Buffer
	gzWriter := gzip.NewWriter(&compressed)
	if _, err := gzWriter.Write(logsJSON); err != nil {
		return fmt.Errorf("failed to compress logs: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	compressedData := compressed.Bytes()

	// Calculate checksum
	hash := sha256.Sum256(compressedData)
	checksum := hex.EncodeToString(hash[:])

	// Generate S3 key
	s3Key := fmt.Sprintf(
		"audit-logs/%s/%d/%s/%s.json.gz",
		tenantID.String(),
		startDate.Year(),
		startDate.Format("01-January"),
		batchID.String(),
	)

	// Build PutObject options.
	opts := minio.PutObjectOptions{
		ContentType: "application/gzip",
		UserMetadata: map[string]string{
			"tenant-id":    tenantID.String(),
			"batch-id":     batchID.String(),
			"record-count": fmt.Sprintf("%d", len(logs)),
			"start-date":   startDate.Format(time.RFC3339),
			"end-date":     endDate.Format(time.RFC3339),
			"checksum":     checksum,
		},
	}

	// Server-side encryption: SSE-S3 (AES256) — server-managed key, same
	// behaviour as `s3.ServerSideEncryptionAes256` in the AWS SDK.
	if s.config.EncryptionEnabled {
		opts.ServerSideEncryption = encrypt.NewSSE()
	}

	// Object Lock — Compliance mode pins the retention until-date so even
	// admins cannot delete or shorten retention before expiry.
	var lockUntil time.Time
	if s.config.ObjectLockEnabled {
		lockUntil = time.Now().AddDate(ArchiveRetentionYears, 0, 0)
		opts.Mode = minio.Compliance
		opts.RetainUntilDate = lockUntil
	}

	// Upload to S3
	uploadResult, err := s.client.PutObject(ctx, s.config.S3Bucket, s3Key,
		bytes.NewReader(compressedData), int64(len(compressedData)), opts,
	)
	if err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	logger.Info("Uploaded audit logs to S3",
		zap.String("s3_key", s3Key),
		zap.String("batch_id", batchID.String()),
		zap.Int("record_count", len(logs)),
		zap.Int64("size_bytes", int64(len(compressedData))),
	)

	// Create archive metadata
	fileSize := int64(len(compressedData))
	var s3ETag *string
	if uploadResult.ETag != "" {
		etag := uploadResult.ETag
		s3ETag = &etag
	}
	metadata := &models.AuditArchiveMetadata{
		TenantID:          tenantID,
		ArchiveBatchID:    batchID,
		StartDate:         startDate,
		EndDate:           endDate,
		RecordCount:       int64(len(logs)),
		S3Bucket:          s.config.S3Bucket,
		S3Key:             s3Key,
		S3ETag:            s3ETag,
		FileSizeBytes:     &fileSize,
		CompressionType:   "gzip",
		Encrypted:         s.config.EncryptionEnabled,
		ObjectLockEnabled: s.config.ObjectLockEnabled,
		ChecksumSHA256:    &checksum,
		CreatedBy:         performedBy,
	}

	if s.config.ObjectLockEnabled {
		metadata.ObjectLockUntil = &lockUntil
	}

	if err := s.auditService.CreateArchiveMetadata(ctx, metadata); err != nil {
		return fmt.Errorf("failed to create archive metadata: %w", err)
	}

	// Mark logs as archived
	logIDs := make([]uuid.UUID, len(logs))
	for i, log := range logs {
		logIDs[i] = log.ID
	}

	archiveLocation := fmt.Sprintf("s3://%s/%s", s.config.S3Bucket, s3Key)
	if err := s.auditService.MarkAuditLogsAsArchived(ctx, logIDs, archiveLocation); err != nil {
		return fmt.Errorf("failed to mark logs as archived: %w", err)
	}

	return nil
}

// GetArchivedLogs retrieves and decompresses archived logs from S3
func (s *AuditArchiverService) GetArchivedLogs(ctx context.Context, s3Key string) ([]models.AuditLog, error) {
	obj, err := s.client.GetObject(ctx, s.config.S3Bucket, s3Key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to download from S3: %w", err)
	}
	defer obj.Close() //nolint:errcheck

	// Decompress
	gzReader, err := gzip.NewReader(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close() //nolint:errcheck

	// Decode JSON
	var logs []models.AuditLog
	if err := json.NewDecoder(gzReader).Decode(&logs); err != nil {
		return nil, fmt.Errorf("failed to decode logs: %w", err)
	}

	return logs, nil
}

// VerifyArchiveIntegrity verifies the integrity of an archived batch
func (s *AuditArchiverService) VerifyArchiveIntegrity(ctx context.Context, metadata *models.AuditArchiveMetadata) (bool, error) {
	obj, err := s.client.GetObject(ctx, metadata.S3Bucket, metadata.S3Key, minio.GetObjectOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to download from S3: %w", err)
	}
	defer obj.Close() //nolint:errcheck

	// Read all data
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(obj); err != nil {
		return false, fmt.Errorf("failed to read from S3: %w", err)
	}

	// Calculate checksum
	hash := sha256.Sum256(buf.Bytes())
	checksum := hex.EncodeToString(hash[:])

	// Compare with stored checksum
	if metadata.ChecksumSHA256 == nil {
		return false, fmt.Errorf("no stored checksum available")
	}

	return checksum == *metadata.ChecksumSHA256, nil
}

