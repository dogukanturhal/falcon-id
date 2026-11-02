// SPDX-License-Identifier: AGPL-3.0-or-later

// Package productslug centralises the acmeweb <-> acmeapp product-slug alias.
//
// The product slug is being renamed acmeweb -> acmeapp by a deferred Keystone
// migration bundle (iam_products.slug, iam_cluster_instances.product_slug).
// Until and after that bundle runs, falcon-id must treat both spellings as the
// same product. Every slug/module comparison or lookup must go through here
// rather than comparing against a literal.
package productslug

import "strings"

const (
	// Legacy is the pre-rename slug.
	Legacy = "acmeweb"
	// Current is the post-rename slug.
	Current = "acmeapp"
)

// normalize lower-cases and trims a slug for comparison.
func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// Aliases returns every spelling equivalent to slug (including slug itself,
// verbatim). Unaliased slugs return a single-element slice holding slug as given. Suitable as the
// argument of `slug = ANY($1)`.
func Aliases(slug string) []string {
	n := normalize(slug)
	if n == Legacy || n == Current {
		return []string{Current, Legacy}
	}
	return []string{slug}
}

// Expand returns the given slugs plus their aliases, de-duplicated, order
// preserved (first occurrence wins). Non-aliased entries are passed through
// unchanged (not normalized) so non-product module names keep their casing.
func Expand(slugs []string) []string {
	if slugs == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(slugs)+1)
	out := make([]string, 0, len(slugs)+1)
	add := func(s string) {
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range slugs {
		add(s)
		if n := normalize(s); n == Legacy || n == Current {
			for _, a := range Aliases(n) {
				add(a)
			}
		}
	}
	return out
}

// Equivalent reports whether a and b name the same product, case-insensitively,
// treating acmeweb and acmeapp as one.
func Equivalent(a, b string) bool {
	na, nb := normalize(a), normalize(b)
	if na == nb {
		return true
	}
	return (na == Legacy || na == Current) && (nb == Legacy || nb == Current)
}

// Contains reports whether haystack holds a slug equivalent to needle.
func Contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if Equivalent(s, needle) {
			return true
		}
	}
	return false
}
