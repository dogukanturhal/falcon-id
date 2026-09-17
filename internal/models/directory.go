// SPDX-License-Identifier: AGPL-3.0-or-later

package models

// MemberCard is a tenant member's directory entry as seen by a PEER (another
// member of the same tenant). Name + avatar are always present (identity);
// email, phone and title appear ONLY when that member's profile-visibility
// preferences (preferences.global.visibility) allow it. This is the server-side
// enforcement surface for the accounts People-&-sharing visibility controls —
// the directory never returns a field a member chose to hide, regardless of
// what the viewer requests.
type MemberCard struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	AvatarURL *string `json:"avatar_url,omitempty"`
	Title     *string `json:"title,omitempty"`
	Email     *string `json:"email,omitempty"`
	Phone     *string `json:"phone,omitempty"`
}
