// SPDX-License-Identifier: AGPL-3.0-or-later

// Package opsconsole serves the HexxLock Control staff console's "people"
// surface on the operator chain: ServiceAuth + RequireScope + operatorauth
// (RequireOperator / RequireStepUp). The actor is always the verified
// X-Actor-Assertion, never a request body; every mutation carries a reason
// code + justification and is recorded in platform_admin_audit_log.
package opsconsole

import "strings"

// MaskEmail renders j***@d***.com. Anything that is not an email is masked as
// a name.
func MaskEmail(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return MaskName(email)
	}
	local, domain := email[:at], email[at+1:]
	dom := domain
	tld := ""
	if dot := strings.LastIndex(domain, "."); dot > 0 {
		dom, tld = domain[:dot], domain[dot:]
	}
	return firstRune(local) + "***@" + firstRune(dom) + "***" + tld
}

// MaskName keeps the first letter of each word: "Jane Doe" -> "J*** D***".
func MaskName(name string) string {
	words := strings.Fields(name)
	if len(words) == 0 {
		return ""
	}
	for i, w := range words {
		words[i] = firstRune(w) + "***"
	}
	return strings.Join(words, " ")
}

// MaskPhone keeps only the last two digits.
func MaskPhone(phone string) string {
	var digits []rune
	for _, r := range phone {
		if r >= '0' && r <= '9' {
			digits = append(digits, r)
		}
	}
	if len(digits) < 2 {
		return "*******"
	}
	return "*******" + string(digits[len(digits)-2:])
}

// MaskUsername masks a username only when it looks like an email (usernames
// are plaintext and frequently are the address).
func MaskUsername(username string) string {
	if strings.Contains(username, "@") {
		return MaskEmail(username)
	}
	return MaskName(username)
}

func firstRune(s string) string {
	for _, r := range s {
		return string(r)
	}
	return ""
}
