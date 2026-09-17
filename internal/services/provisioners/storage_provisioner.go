// SPDX-License-Identifier: AGPL-3.0-or-later

package provisioners

import (
	"context"
	"fmt"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/lifecycle"
	"go.uber.org/zap"
)

// StorageResourceProvisioner provisions S3-compatible (MinIO) storage buckets
// or tenant path prefixes within a shared bucket, depending on the strategy
// configured in the product manifest.
//
// # Strategies
//
//   - "shared"    – a single shared bucket is used for all tenants; each tenant
//     receives a dedicated path prefix of the form "tenants/{tenant_slug}/".
//   - "dedicated" – a brand-new bucket named
//     "tenant-{tenant_slug}-{resource_name}" is created for the tenant.
//
// When the S3 endpoint is unreachable or credentials are missing, Provision
// returns a simulated result so that the provisioning saga continues unblocked
// in local development.
type StorageResourceProvisioner struct {
	endpoint  string
	accessKey string
	secretKey string
	useSSL    bool
	// sharedBucket is the name of the bucket used for the "shared" strategy.
	// Defaults to "hexxlock-shared-storage" when empty.
	sharedBucket string
	log          *zap.SugaredLogger
}

// StorageProvisionerOptions holds optional configuration fields for
// StorageResourceProvisioner beyond the required credentials.
type StorageProvisionerOptions struct {
	// SharedBucket overrides the default shared bucket name.
	SharedBucket string
}

// NewStorageResourceProvisioner creates a StorageResourceProvisioner backed by
// an S3-compatible endpoint (e.g., MinIO).
//
// endpoint should be the host:port form expected by the minio-go client (no
// scheme prefix). useSSL must be true for HTTPS endpoints and false for plain
// HTTP.
func NewStorageResourceProvisioner(
	endpoint, accessKey, secretKey string,
	useSSL bool,
	log *zap.SugaredLogger,
	opts ...StorageProvisionerOptions,
) *StorageResourceProvisioner {
	p := &StorageResourceProvisioner{
		endpoint:     endpoint,
		accessKey:    accessKey,
		secretKey:    secretKey,
		useSSL:       useSSL,
		sharedBucket: "hexxlock-shared-storage",
		log:          log,
	}
	for _, o := range opts {
		if o.SharedBucket != "" {
			p.sharedBucket = o.SharedBucket
		}
	}
	return p
}

// ResourceType satisfies ResourceProvisioner.
func (p *StorageResourceProvisioner) ResourceType() string { return "storage_bucket" }

// Provision creates a MinIO/S3 bucket or prefix for the tenant.
//
// Config keys read from req.Config:
//   - "strategy"       string – "shared" (default) or "dedicated"
//   - "lifecycle_days" int    – object expiry in days (0 = no lifecycle rule)
func (p *StorageResourceProvisioner) Provision(ctx context.Context, req ResourceProvisionRequest) (*ResourceProvisionResult, error) {
	strategy := stringFromConfig(req.Config, "strategy", "shared")
	lifecycleDays := intFromConfig(req.Config, "lifecycle_days", 0)

	client, err := p.newClient()
	if err != nil {
		p.log.Warnw("StorageResourceProvisioner: S3 client unavailable, using simulated result",
			"endpoint", p.endpoint,
			"error", err,
		)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"strategy":  strategy,
			"simulated": true,
		}), nil
	}

	switch strategy {
	case "dedicated":
		return p.provisionDedicated(ctx, client, req, lifecycleDays)
	default:
		return p.provisionShared(ctx, client, req, lifecycleDays)
	}
}

// provisionShared ensures the shared bucket exists and returns the tenant path prefix.
func (p *StorageResourceProvisioner) provisionShared(
	ctx context.Context,
	client *minio.Client,
	req ResourceProvisionRequest,
	lifecycleDays int,
) (*ResourceProvisionResult, error) {
	bucket := p.sharedBucket
	prefix := fmt.Sprintf("tenants/%s/", req.TenantSlug)

	if err := p.ensureBucket(ctx, client, bucket); err != nil {
		p.log.Warnw("StorageResourceProvisioner: failed to ensure shared bucket, using simulated result",
			"bucket", bucket,
			"error", err,
		)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"bucket_name": bucket,
			"path_prefix": prefix,
			"strategy":    "shared",
		}), nil
	}

	if lifecycleDays > 0 {
		if err := p.applyLifecycleRule(ctx, client, bucket, prefix, lifecycleDays); err != nil {
			// Non-fatal: log and continue.
			p.log.Warnw("StorageResourceProvisioner: failed to apply lifecycle rule (non-fatal)",
				"bucket", bucket,
				"prefix", prefix,
				"days", lifecycleDays,
				"error", err,
			)
		}
	}

	p.log.Infow("StorageResourceProvisioner: shared prefix provisioned",
		"tenant_slug", req.TenantSlug,
		"bucket", bucket,
		"prefix", prefix,
	)

	return &ResourceProvisionResult{
		Status: "active",
		ProvisionedConfig: map[string]interface{}{
			"bucket_name": bucket,
			"path_prefix": prefix,
			"strategy":    "shared",
		},
	}, nil
}

// provisionDedicated creates a tenant-specific bucket.
func (p *StorageResourceProvisioner) provisionDedicated(
	ctx context.Context,
	client *minio.Client,
	req ResourceProvisionRequest,
	lifecycleDays int,
) (*ResourceProvisionResult, error) {
	// Sanitise the slug: S3 bucket names are lowercase, alphanumeric + hyphens, 3-63 chars.
	slug := sanitiseS3Name(req.TenantSlug)
	res := sanitiseS3Name(req.ResourceName)
	bucket := fmt.Sprintf("tenant-%s-%s", slug, res)
	// Enforce the 63-character S3 bucket name limit.
	if len(bucket) > 63 {
		bucket = bucket[:63]
	}

	if err := p.ensureBucket(ctx, client, bucket); err != nil {
		p.log.Warnw("StorageResourceProvisioner: failed to create dedicated bucket, using simulated result",
			"bucket", bucket,
			"error", err,
		)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"bucket_name": bucket,
			"path_prefix": "",
			"strategy":    "dedicated",
		}), nil
	}

	if lifecycleDays > 0 {
		if err := p.applyLifecycleRule(ctx, client, bucket, "", lifecycleDays); err != nil {
			p.log.Warnw("StorageResourceProvisioner: failed to apply lifecycle rule on dedicated bucket (non-fatal)",
				"bucket", bucket,
				"days", lifecycleDays,
				"error", err,
			)
		}
	}

	p.log.Infow("StorageResourceProvisioner: dedicated bucket provisioned",
		"tenant_slug", req.TenantSlug,
		"bucket", bucket,
	)

	return &ResourceProvisionResult{
		Status: "active",
		ProvisionedConfig: map[string]interface{}{
			"bucket_name": bucket,
			"path_prefix": "",
			"strategy":    "dedicated",
		},
	}, nil
}

// Deprovision removes a dedicated bucket or marks the shared prefix as inactive.
// For shared-strategy resources, this is a no-op because removing the prefix
// would require deleting all objects under it — a destructive operation that
// should be handled by a separate data-retention job.
func (p *StorageResourceProvisioner) Deprovision(ctx context.Context, req ResourceDeprovisionRequest) error {
	strategy := stringFromConfig(req.ProvisionedConfig, "strategy", "shared")
	if strategy != "dedicated" {
		// Shared strategy: prefix cleanup is handled out-of-band by the
		// data-retention policy; nothing to do here.
		p.log.Infow("StorageResourceProvisioner.Deprovision: shared strategy — skipping prefix removal",
			"tenant_slug", req.TenantSlug,
		)
		return nil
	}

	bucketName := stringFromConfig(req.ProvisionedConfig, "bucket_name", "")
	if bucketName == "" {
		p.log.Warnw("StorageResourceProvisioner.Deprovision: no bucket_name in provisioned config, skipping",
			"tenant_slug", req.TenantSlug,
		)
		return nil
	}

	client, err := p.newClient()
	if err != nil {
		p.log.Warnw("StorageResourceProvisioner.Deprovision: S3 client unavailable, skipping bucket deletion",
			"bucket", bucketName,
			"error", err,
		)
		return nil
	}

	err = client.RemoveBucket(ctx, bucketName)
	if err != nil {
		// Treat "bucket already gone" as success.
		if isS3NotFound(err) {
			return nil
		}
		// Non-fatal: log and continue so the instance can still be marked deleted.
		p.log.Warnw("StorageResourceProvisioner.Deprovision: failed to delete bucket (non-fatal)",
			"bucket", bucketName,
			"error", err,
		)
		return nil
	}

	p.log.Infow("StorageResourceProvisioner.Deprovision: dedicated bucket deleted",
		"bucket", bucketName,
	)
	return nil
}

// HealthCheck verifies that the bucket is accessible.
func (p *StorageResourceProvisioner) HealthCheck(ctx context.Context, req ResourceHealthCheckRequest) (*ResourceHealthResult, error) {
	bucketName := stringFromConfig(req.ProvisionedConfig, "bucket_name", "")
	if bucketName == "" {
		return &ResourceHealthResult{Healthy: false, Message: "no bucket_name in provisioned config"}, nil
	}

	client, err := p.newClient()
	if err != nil {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("S3 client unavailable: %v", err),
		}, nil
	}

	exists, err := client.BucketExists(ctx, bucketName)
	if err != nil {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("bucket %q not accessible: %v", bucketName, err),
		}, nil
	}
	if !exists {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("bucket %q does not exist", bucketName),
		}, nil
	}

	return &ResourceHealthResult{
		Healthy: true,
		Message: fmt.Sprintf("bucket %q is accessible", bucketName),
	}, nil
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// newClient constructs a MinIO client pointed at p.endpoint.
// minio-go uses path-style addressing automatically when needed.
func (p *StorageResourceProvisioner) newClient() (*minio.Client, error) {
	if p.endpoint == "" {
		return nil, fmt.Errorf("StorageResourceProvisioner: endpoint not configured")
	}
	if p.accessKey == "" || p.secretKey == "" {
		return nil, fmt.Errorf("StorageResourceProvisioner: credentials not configured")
	}

	// Strip any scheme prefix the caller may have included; minio-go expects
	// host:port form and decides scheme via the Secure option.
	endpoint := strings.TrimPrefix(strings.TrimPrefix(p.endpoint, "https://"), "http://")

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(p.accessKey, p.secretKey, ""),
		Secure: p.useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("StorageResourceProvisioner: build MinIO client: %w", err)
	}
	return client, nil
}

// ensureBucket creates the bucket if it does not already exist.
func (p *StorageResourceProvisioner) ensureBucket(ctx context.Context, client *minio.Client, bucket string) error {
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return fmt.Errorf("ensureBucket: head bucket %q: %w", bucket, err)
	}
	if exists {
		return nil
	}

	if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		return fmt.Errorf("ensureBucket: create bucket %q: %w", bucket, err)
	}
	return nil
}

// applyLifecycleRule sets an expiry lifecycle rule on the bucket, scoped to
// prefix if non-empty.
func (p *StorageResourceProvisioner) applyLifecycleRule(ctx context.Context, client *minio.Client, bucket, prefix string, days int) error {
	cfg := lifecycle.NewConfiguration()
	rule := lifecycle.Rule{
		ID:     "hexxlock-auto-expire",
		Status: "Enabled",
		Expiration: lifecycle.Expiration{
			Days: lifecycle.ExpirationDays(days),
		},
	}
	if prefix != "" {
		rule.RuleFilter = lifecycle.Filter{Prefix: prefix}
	}
	cfg.Rules = append(cfg.Rules, rule)

	if err := client.SetBucketLifecycle(ctx, bucket, cfg); err != nil {
		return fmt.Errorf("applyLifecycleRule: %w", err)
	}
	return nil
}

// sanitiseS3Name converts an arbitrary string into a form safe for S3 bucket
// name components: lowercase, alphanumeric and hyphens only.
func sanitiseS3Name(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if r == '-' || r == '_' {
			b.WriteByte('-')
		}
	}
	result := strings.Trim(b.String(), "-")
	if result == "" {
		return "resource"
	}
	return result
}

// isS3NotFound returns true when err represents a 404 / NoSuchBucket response.
func isS3NotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "NoSuchBucket") ||
		strings.Contains(msg, "NotFound") ||
		strings.Contains(msg, "404")
}
