// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import "net/url"

func loginResumeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	if q.Get("prompt") == "login" {
		q.Del("prompt")
	}
	u.RawQuery = q.Encode()
	return u.String()
}
