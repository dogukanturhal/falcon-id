// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	notificationRecipientsMaxUsers       = 500
	notificationRecipientsMaxRoles       = 5
	notificationRecipientsMaxPermissions = 5
	notificationRecipientsCheckWorkers   = 8
)

var (
	notificationRoleName       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	notificationPermissionName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}(:[a-z][a-z0-9_-]{0,63}){2}$`)
)

type NotificationRecipientReader interface {
	ListNotificationRecipients(ctx context.Context, tenantID uuid.UUID, userIDs []uuid.UUID, systemRoles []string) ([]repositories.NotificationRecipientRow, error)
}

type NotificationPermissionChecker interface {
	CheckPermission(ctx context.Context, req services.PermissionRequest) (*services.PermissionResult, error)
}

// NotificationRecipientsHandler serves the service-to-service recipient
// directory used by business to decide who may receive a tenant notification
// (e.g. e-document credit alerts). Results are resolved live and never cached.
type NotificationRecipientsHandler struct {
	recipients  NotificationRecipientReader
	permissions NotificationPermissionChecker
}

func NewNotificationRecipientsHandler(recipients NotificationRecipientReader, permissions NotificationPermissionChecker) *NotificationRecipientsHandler {
	return &NotificationRecipientsHandler{recipients: recipients, permissions: permissions}
}

type notificationRecipientMember struct {
	UserID         uuid.UUID       `json:"user_id"`
	Email          string          `json:"email"`
	Active         bool            `json:"active"`
	MembershipKind string          `json:"membership_kind"`
	SystemRoles    []string        `json:"system_roles"`
	ExternalScopes []string        `json:"external_scopes"`
	Decisions      map[string]bool `json:"decisions"`
}

// Resolve answers POST /internal/v1/tenants/:id/notification-recipients.
// The member set is the requested user_ids plus every active holder of one of
// system_roles; each member carries a decision per requested permission.
func (h *NotificationRecipientsHandler) Resolve(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil || tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_tenant"})
		return
	}
	if !authorizeDirectoryTenant(c, tenantID) {
		return
	}
	var req struct {
		UserIDs     []uuid.UUID `json:"user_ids" binding:"max=500"`
		SystemRoles []string    `json:"system_roles" binding:"max=5"`
		Permissions []string    `json:"permissions" binding:"required,min=1,max=5"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_notification_recipients_request"})
		return
	}
	userIDs, ok := uniqueNonNilUUIDs(req.UserIDs)
	roles, rolesOK := uniqueMatching(req.SystemRoles, notificationRoleName)
	perms, permsOK := uniqueMatching(req.Permissions, notificationPermissionName)
	if !ok || !rolesOK || !permsOK || len(perms) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_notification_recipients_request"})
		return
	}

	rows, err := h.recipients.ListNotificationRecipients(c.Request.Context(), tenantID, userIDs, roles)
	if err != nil {
		notificationRecipientsUnavailable(c)
		return
	}
	members := make([]notificationRecipientMember, len(rows))
	for i, row := range rows {
		members[i] = notificationRecipientMember{
			UserID:         row.UserID,
			Email:          row.Email,
			Active:         row.Active,
			MembershipKind: row.MembershipKind,
			SystemRoles:    nonNilStrings(row.SystemRoles),
			// B7 fills this from the SMMM external scope grants; until then
			// external members report no scopes.
			ExternalScopes: []string{},
			Decisions:      make(map[string]bool, len(perms)),
		}
		for _, p := range perms {
			members[i].Decisions[p] = false
		}
	}
	if !h.decide(c.Request.Context(), tenantID, members, perms) {
		notificationRecipientsUnavailable(c)
		return
	}
	c.JSON(http.StatusOK, gin.H{"tenant_id": tenantID, "complete": true, "members": members})
}

// decide fills Decisions for active members only (inactive members are all
// false). It reports false when any check errors, so callers never receive a
// partial answer marked complete.
func (h *NotificationRecipientsHandler) decide(ctx context.Context, tenantID uuid.UUID, members []notificationRecipientMember, perms []string) bool {
	type job struct {
		member int
		perm   string
	}
	jobs := make(chan job)
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		failed bool
	)
	for w := 0; w < notificationRecipientsCheckWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				res, err := h.permissions.CheckPermission(ctx, services.PermissionRequest{UserID: members[j.member].UserID, TenantID: tenantID, Permission: j.perm})
				mu.Lock()
				if err != nil || res == nil {
					failed = true
				} else {
					members[j.member].Decisions[j.perm] = res.Allowed
				}
				mu.Unlock()
			}
		}()
	}
	for i := range members {
		if !members[i].Active {
			continue
		}
		for _, p := range perms {
			jobs <- job{member: i, perm: p}
		}
	}
	close(jobs)
	wg.Wait()
	return !failed
}

func notificationRecipientsUnavailable(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{"code": "notification_recipients_unavailable"})
}

func uniqueNonNilUUIDs(in []uuid.UUID) ([]uuid.UUID, bool) {
	seen := make(map[uuid.UUID]bool, len(in))
	out := make([]uuid.UUID, 0, len(in))
	for _, id := range in {
		if id == uuid.Nil {
			return nil, false
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, true
}

func uniqueMatching(in []string, re *regexp.Regexp) ([]string, bool) {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !re.MatchString(s) {
			return nil, false
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, true
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
