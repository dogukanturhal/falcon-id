// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// memberVisibility is the resolved per-field visibility for a member, with the
// product defaults applied. The defaults MUST match the accounts
// People-&-sharing DEFAULT_VISIBILITY so a member who never touched the control
// is exposed exactly as the UI implies.
type memberVisibility struct {
	email    bool
	phone    bool
	jobTitle bool
}

// parseMemberVisibility reads preferences.global.visibility from the raw prefs
// JSON. Unset fields fall back to the defaults (email shown, phone hidden,
// title shown). Malformed/empty prefs => all defaults (fail safe toward the
// member's stated intent, never over-exposing phone).
func parseMemberVisibility(prefs []byte) memberVisibility {
	v := memberVisibility{email: true, phone: false, jobTitle: true}
	if len(prefs) == 0 {
		return v
	}
	var p struct {
		Global struct {
			Visibility struct {
				Email    *bool `json:"email"`
				Phone    *bool `json:"phone"`
				JobTitle *bool `json:"job_title"`
			} `json:"visibility"`
		} `json:"global"`
	}
	if err := json.Unmarshal(prefs, &p); err != nil {
		return v
	}
	if p.Global.Visibility.Email != nil {
		v.email = *p.Global.Visibility.Email
	}
	if p.Global.Visibility.Phone != nil {
		v.phone = *p.Global.Visibility.Phone
	}
	if p.Global.Visibility.JobTitle != nil {
		v.jobTitle = *p.Global.Visibility.JobTitle
	}
	return v
}

// memberDisplayName derives a peer-safe display name — never the email (which
// is itself visibility-gated). Order: display_name, then "First Last", then
// username.
func memberDisplayName(u *models.User) string {
	if u.DisplayName != nil && strings.TrimSpace(*u.DisplayName) != "" {
		return strings.TrimSpace(*u.DisplayName)
	}
	first, last := "", ""
	if u.FirstName != nil {
		first = *u.FirstName
	}
	if u.LastName != nil {
		last = *u.LastName
	}
	if full := strings.TrimSpace(first + " " + last); full != "" {
		return full
	}
	return u.Username
}

// ListMemberDirectory returns the visibility-filtered directory of OTHER active
// members in the viewer's tenant. Name + avatar are always returned; email,
// phone and title appear only where the member made them visible. Two queries
// total (member list with PII decrypted + one bulk preferences fetch) — no
// N+1. The viewer is excluded; deactivated members are excluded.
func (s *UserService) ListMemberDirectory(ctx context.Context, tenantID, viewerID uuid.UUID, page, pageSize int) ([]models.MemberCard, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	// One lean, paginated query: active members (viewer excluded), PII
	// decrypted, prefs inline, no roles fetch. total drives pagination.
	users, total, err := s.userRepo.ListTenantMemberCards(ctx, tenantID, viewerID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("ListMemberDirectory: %w", err)
	}

	cards := make([]models.MemberCard, 0, len(users))
	for i := range users {
		u := users[i]
		vis := parseMemberVisibility(u.Preferences)
		card := models.MemberCard{
			ID:        u.ID.String(),
			Name:      memberDisplayName(&u),
			AvatarURL: u.AvatarURL,
		}
		if vis.email {
			e := u.Email
			card.Email = &e
		}
		if vis.phone {
			card.Phone = u.Phone
		}
		if vis.jobTitle {
			card.Title = u.Title
		}
		cards = append(cards, card)
	}
	return cards, total, nil
}
