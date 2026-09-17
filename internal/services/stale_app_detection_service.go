// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// StaleAppThresholds defines the criteria used to classify an application as stale.
type StaleAppThresholds struct {
	// NoSignInDays is the number of consecutive days without any sign-in activity
	// after which an application is considered stale. Default: 90.
	NoSignInDays int

	// AllCredsExpiredApp indicates whether an application with all credentials
	// expired (no valid client secrets or certificates) is classified as stale.
	AllCredsExpiredApp bool

	// NoAssignedUsers indicates whether an application with no users or groups
	// assigned to any of its service principals is classified as stale.
	NoAssignedUsers bool
}

// StaleAppInfo holds the stale-detection result for a single application.
type StaleAppInfo struct {
	ApplicationID   uuid.UUID  `json:"application_id"`
	DisplayName     string     `json:"display_name"`
	StaleReason     string     `json:"stale_reason"`
	StaleSince      *time.Time `json:"stale_since,omitempty"`
	LastSignInAt    *time.Time `json:"last_sign_in_at,omitempty"`
	SPCount         int        `json:"sp_count"`
	ActiveCredCount int        `json:"active_cred_count"`
}

// StaleDetectionResult holds the aggregate output of a single detection run.
type StaleDetectionResult struct {
	TotalApps  int            `json:"total_apps"`
	StaleApps  []StaleAppInfo `json:"stale_apps"`
	StaleCount int            `json:"stale_count"`
	CheckedAt  time.Time      `json:"checked_at"`
}

// staleAppRepo is the subset of ApplicationRepository consumed by this service.
type staleAppRepo interface {
	// ListActive returns all non-deleted, active applications.
	ListActive(ctx context.Context) ([]models.Application, error)
	// MarkStale records the first detection timestamp on an application.
	// Implementations should be idempotent (first-detection-wins).
	MarkStale(ctx context.Context, appID uuid.UUID, since time.Time) error
	// ClearStale removes the stale marker when an application regains activity.
	ClearStale(ctx context.Context, appID uuid.UUID) error
}

// staleSignInChecker answers whether an application has had sign-in activity
// within the configured look-back window. Implementations may query an
// audit log, metrics store, or the last_sign_in_at column.
type staleSignInChecker interface {
	HasRecentActivity(ctx context.Context, appID uuid.UUID, days int) (bool, error)
}

// staleSPCounter returns the number of active service principals provisioned
// for an application. An application with zero SPs is considered orphaned.
type staleSPCounter interface {
	GetServicePrincipalCount(ctx context.Context, appID uuid.UUID) (int64, error)
}

// StaleAppDetectionService scans all active application objects and identifies
// those that are dormant according to configurable thresholds. It mirrors the
// "Stale Apps" report in Microsoft Entra ID's Identity Secure Score.
//
// Detection logic (evaluated in order; first match wins):
//  1. No sign-in activity within NoSignInDays days.
//  2. Zero active service principals across all tenants.
//
// When an application transitions from stale → active, the stale marker is
// cleared so it no longer appears in subsequent reports.
type StaleAppDetectionService struct {
	appRepo       staleAppRepo
	signInChecker staleSignInChecker
	spCounter     staleSPCounter
	thresholds    StaleAppThresholds
}

// NewStaleAppDetectionService constructs a StaleAppDetectionService with
// sensible defaults (90-day inactivity window). All dependencies are required
// except signInChecker and spCounter — if nil they are silently skipped and
// only the remaining checks are applied.
func NewStaleAppDetectionService(
	appRepo staleAppRepo,
	signInChecker staleSignInChecker,
	spCounter staleSPCounter,
) *StaleAppDetectionService {
	return &StaleAppDetectionService{
		appRepo:       appRepo,
		signInChecker: signInChecker,
		spCounter:     spCounter,
		thresholds: StaleAppThresholds{
			NoSignInDays:       90,
			AllCredsExpiredApp: true,
			NoAssignedUsers:    true,
		},
	}
}

// WithThresholds replaces the default thresholds. Returns the receiver so it
// can be chained with the constructor.
func (s *StaleAppDetectionService) WithThresholds(t StaleAppThresholds) *StaleAppDetectionService {
	s.thresholds = t
	return s
}

// DetectStaleApps iterates over all active application objects and applies the
// configured staleness checks. It updates the database via MarkStale /
// ClearStale so the result is consistent across multiple callers.
//
// Platform apps (IsPlatformApp == true) and preauthorized apps are exempt from
// all checks — these are well-known HexxLock-owned applications that are always
// considered healthy.
func (s *StaleAppDetectionService) DetectStaleApps(ctx context.Context) (*StaleDetectionResult, error) {
	apps, err := s.appRepo.ListActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("StaleAppDetectionService.DetectStaleApps: %w", err)
	}

	now := time.Now()
	staleApps := make([]StaleAppInfo, 0)

	for _, app := range apps {
		// Platform and preauthorized apps are always considered healthy.
		if app.IsPlatformApp || app.Preauthorized {
			continue
		}

		staleReason := s.evaluateStaleness(ctx, app)

		if staleReason != "" {
			staleSince := app.StaleSince
			if staleSince == nil {
				staleSince = &now
				// Best-effort: persist the first detection timestamp.
				// Failure here is non-fatal — the next run will retry.
				_ = s.appRepo.MarkStale(ctx, app.ID, now)
			}

			spCount := int64(0)
			if s.spCounter != nil {
				spCount, _ = s.spCounter.GetServicePrincipalCount(ctx, app.ID)
			}

			staleApps = append(staleApps, StaleAppInfo{
				ApplicationID: app.ID,
				DisplayName:   app.DisplayName,
				StaleReason:   staleReason,
				StaleSince:    staleSince,
				LastSignInAt:  app.LastSignInAt,
				SPCount:       int(spCount),
			})
		} else if app.StaleSince != nil {
			// The application previously flagged as stale but now shows activity —
			// clear the marker so it disappears from the next report.
			_ = s.appRepo.ClearStale(ctx, app.ID)
		}
	}

	return &StaleDetectionResult{
		TotalApps:  len(apps),
		StaleApps:  staleApps,
		StaleCount: len(staleApps),
		CheckedAt:  now,
	}, nil
}

// evaluateStaleness applies each staleness rule in priority order and returns
// the first matching reason string, or an empty string if the app is healthy.
func (s *StaleAppDetectionService) evaluateStaleness(ctx context.Context, app models.Application) string {
	// Rule 1: No recent sign-in activity.
	if s.signInChecker != nil {
		hasActivity, err := s.signInChecker.HasRecentActivity(ctx, app.ID, s.thresholds.NoSignInDays)
		if err == nil && !hasActivity {
			return fmt.Sprintf("no_sign_in_%dd", s.thresholds.NoSignInDays)
		}
	}

	// Rule 2: No service principals (orphaned app object).
	if s.spCounter != nil {
		spCount, err := s.spCounter.GetServicePrincipalCount(ctx, app.ID)
		if err == nil && spCount == 0 {
			return "no_service_principals"
		}
	}

	return ""
}
