// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

const (
	workspaceNameMin = 2
	workspaceNameMax = 200
	// workspaceBackfillMax bounds one backfill pass so a runaway table cannot
	// turn an admin click into thousands of S2S calls.
	workspaceBackfillMax = 2000
)

// ErrInvalidWorkspaceName is returned for a name that is empty, out of range or
// the placeholder itself.
var ErrInvalidWorkspaceName = errors.New("invalid workspace name")

// WorkspaceNameStore is the iam_tenants access the service needs.
// Satisfied by *repositories.TenantRepository.
type WorkspaceNameStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
	RenameDisplayNameIfPlaceholder(ctx context.Context, id uuid.UUID, name string) (bool, error)
	ListNameStates(ctx context.Context) ([]repositories.TenantNameState, error)
}

// TenantManagementNameClient reads and renames the tenant in tenant-management,
// the system of record that admin and billing lists show (tenants.name).
type TenantManagementNameClient interface {
	GetName(ctx context.Context, tenantID uuid.UUID) (string, error)
	UpdateName(ctx context.Context, tenantID uuid.UUID, name string) error
}

// DefaultCompanyNameReader returns the title of a tenant's default legal entity
// from business. found=false means the tenant has none (yet).
type DefaultCompanyNameReader interface {
	DefaultCompanyName(ctx context.Context, tenantID uuid.UUID) (name string, found bool, err error)
}

// WorkspaceRenameOutcome is what RenameIfPlaceholder did.
type WorkspaceRenameOutcome string

const (
	WorkspaceRenamed      WorkspaceRenameOutcome = "renamed"
	WorkspaceAlreadyNamed WorkspaceRenameOutcome = "already_named"
	WorkspaceNotFound     WorkspaceRenameOutcome = "not_found"
)

// Backfill item actions.
const (
	BackfillActionRename   = "rename"                 // placeholder -> first legal entity's title
	BackfillActionSyncTM   = "sync_tenant_management" // falcon-id has a real name, tenant-management still the placeholder
	BackfillActionNoEntity = "no_entity"              // placeholder and no legal entity to take a name from
	BackfillActionError    = "error"
)

// WorkspaceBackfillItem is one tenant the backfill looked at and found a
// placeholder on. Names are only ever the tenant's own (entity title or its
// existing workspace name); nothing is invented.
type WorkspaceBackfillItem struct {
	TenantID     uuid.UUID `json:"tenantId"`
	Slug         string    `json:"slug"`
	Action       string    `json:"action"`
	ProposedName string    `json:"proposedName,omitempty"`
	Applied      bool      `json:"applied"`
	Error        string    `json:"error,omitempty"`
}

// WorkspaceBackfillReport is the result of one backfill pass.
type WorkspaceBackfillReport struct {
	DryRun  bool                    `json:"dryRun"`
	Scanned int                     `json:"scanned"`
	Items   []WorkspaceBackfillItem `json:"items"`
	Counts  map[string]int          `json:"counts"`
}

// TenantWorkspaceNameService owns replacing the signup placeholder workspace
// name. Two entry points: RenameIfPlaceholder (business calls it when the first
// legal entity is created) and Backfill (platform admin, existing tenants).
// Both are idempotent and never overwrite a real name.
type TenantWorkspaceNameService struct {
	store   WorkspaceNameStore
	tm      TenantManagementNameClient // nil: tenant-management sync disabled
	company DefaultCompanyNameReader   // nil: backfill disabled
	logger  *zap.Logger
}

// NewTenantWorkspaceNameService builds the service. tm and company may be nil
// (S2S creds missing); the dependent behaviour is then skipped or refused.
func NewTenantWorkspaceNameService(store WorkspaceNameStore, tm TenantManagementNameClient, company DefaultCompanyNameReader, logger *zap.Logger) *TenantWorkspaceNameService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &TenantWorkspaceNameService{store: store, tm: tm, company: company, logger: logger}
}

// NormalizeWorkspaceName trims name and checks it is a usable workspace name.
func NormalizeWorkspaceName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if l := utf8.RuneCountInString(n); l < workspaceNameMin || l > workspaceNameMax {
		return "", fmt.Errorf("%w: must be %d-%d characters", ErrInvalidWorkspaceName, workspaceNameMin, workspaceNameMax)
	}
	if models.IsPlaceholderTenantName(n) {
		return "", fmt.Errorf("%w: placeholder", ErrInvalidWorkspaceName)
	}
	return n, nil
}

// RenameIfPlaceholder renames the tenant to name only while its workspace name
// is still the placeholder. tenant-management is updated first (idempotent PUT),
// then the local row with a conditional UPDATE, so a failure between the two
// leaves the tenant still a placeholder here and a retry completes it.
func (s *TenantWorkspaceNameService) RenameIfPlaceholder(ctx context.Context, tenantID uuid.UUID, name string) (WorkspaceRenameOutcome, error) {
	n, err := NormalizeWorkspaceName(name)
	if err != nil {
		return "", err
	}
	tenant, err := s.store.GetByID(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("load tenant: %w", err)
	}
	if tenant == nil {
		return WorkspaceNotFound, nil
	}
	if !models.IsPlaceholderTenantName(tenant.DisplayName) {
		return WorkspaceAlreadyNamed, nil
	}
	if s.tm != nil {
		if err := s.tm.UpdateName(ctx, tenantID, n); err != nil {
			return "", fmt.Errorf("rename in tenant-management: %w", err)
		}
	}
	changed, err := s.store.RenameDisplayNameIfPlaceholder(ctx, tenantID, n)
	if err != nil {
		return "", err
	}
	if !changed {
		return WorkspaceAlreadyNamed, nil
	}
	s.logger.Info("workspace placeholder name replaced", zap.String("tenant_id", tenantID.String()))
	return WorkspaceRenamed, nil
}

// PushName mirrors a workspace name a user just saved (PATCH tenant settings)
// into tenant-management so admin and billing lists agree with the product.
// Best effort by design: the user-facing save already succeeded, and the
// backfill reconciles any tenant this misses.
func (s *TenantWorkspaceNameService) PushName(ctx context.Context, tenantID uuid.UUID, name string) {
	if s == nil || s.tm == nil {
		return
	}
	n := strings.TrimSpace(name)
	if n == "" || models.IsPlaceholderTenantName(n) {
		return
	}
	if err := s.tm.UpdateName(ctx, tenantID, n); err != nil {
		s.logger.Warn("workspace name push to tenant-management failed",
			zap.String("tenant_id", tenantID.String()), zap.Error(err))
	}
}

// Backfill finds tenants still carrying the placeholder and fixes the ones that
// can be fixed from data the tenant already owns:
//   - falcon-id placeholder + default legal entity -> rename to the entity title;
//   - falcon-id has a real name, tenant-management still the placeholder -> copy it;
//   - falcon-id placeholder and no legal entity -> reported, left untouched.
//
// dryRun reports the same items without writing. Idempotent: a second apply
// finds nothing left to do.
func (s *TenantWorkspaceNameService) Backfill(ctx context.Context, dryRun bool) (*WorkspaceBackfillReport, error) {
	if s.company == nil {
		return nil, errors.New("workspace name backfill unavailable: business client not configured")
	}
	states, err := s.store.ListNameStates(ctx)
	if err != nil {
		return nil, err
	}
	if len(states) > workspaceBackfillMax {
		states = states[:workspaceBackfillMax]
	}
	report := &WorkspaceBackfillReport{DryRun: dryRun, Scanned: len(states), Items: []WorkspaceBackfillItem{}, Counts: map[string]int{}}

	for _, st := range states {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		item, ok := s.backfillOne(ctx, st, dryRun)
		if !ok {
			continue
		}
		report.Items = append(report.Items, item)
		report.Counts[item.Action]++
	}
	return report, nil
}

func (s *TenantWorkspaceNameService) backfillOne(ctx context.Context, st repositories.TenantNameState, dryRun bool) (WorkspaceBackfillItem, bool) {
	item := WorkspaceBackfillItem{TenantID: st.ID, Slug: st.Slug}
	fail := func(err error) (WorkspaceBackfillItem, bool) {
		item.Action = BackfillActionError
		item.Error = err.Error()
		s.logger.Warn("workspace name backfill step failed", zap.String("tenant_id", st.ID.String()), zap.Error(err))
		return item, true
	}

	if !models.IsPlaceholderTenantName(st.DisplayName) {
		// Real name here; only tenant-management may still lag behind.
		if s.tm == nil {
			return item, false
		}
		tmName, err := s.tm.GetName(ctx, st.ID)
		if err != nil {
			return fail(err)
		}
		if !models.IsPlaceholderTenantName(tmName) {
			return item, false
		}
		item.Action = BackfillActionSyncTM
		item.ProposedName = strings.TrimSpace(st.DisplayName)
		if !dryRun {
			if err := s.tm.UpdateName(ctx, st.ID, item.ProposedName); err != nil {
				return fail(err)
			}
			item.Applied = true
		}
		return item, true
	}

	title, found, err := s.company.DefaultCompanyName(ctx, st.ID)
	if err != nil {
		return fail(err)
	}
	title = strings.TrimSpace(title)
	if !found || title == "" || models.IsPlaceholderTenantName(title) {
		item.Action = BackfillActionNoEntity
		return item, true
	}
	n, err := NormalizeWorkspaceName(title)
	if err != nil {
		return fail(err)
	}
	item.Action = BackfillActionRename
	item.ProposedName = n
	if !dryRun {
		outcome, err := s.RenameIfPlaceholder(ctx, st.ID, n)
		if err != nil {
			return fail(err)
		}
		item.Applied = outcome == WorkspaceRenamed
	}
	return item, true
}
