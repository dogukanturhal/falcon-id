// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import "strings"

func maskMFAEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "your email address"
	}
	return string([]rune(parts[0])[0]) + "***@" + parts[1]
}
