// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildAuthorizeSuccessRedirect_EscapesStateAndPreservesQuery(t *testing.T) {
	out := buildAuthorizeSuccessRedirect("https://rp.example.com/cb?tenant=a%26b&x=1", "CODE", "s&code=evil#frag", "https://id.example.com")
	u, err := url.Parse(out)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "CODE", q.Get("code"))
	assert.Equal(t, "s&code=evil#frag", q.Get("state"), "state must round-trip escaped, not inject params")
	assert.Equal(t, "https://id.example.com", q.Get("iss"))
	assert.Equal(t, "a&b", q.Get("tenant"), "existing redirect_uri query must be preserved")
	assert.Equal(t, "1", q.Get("x"))
	assert.Equal(t, "", u.Fragment, "state must not smuggle a fragment")
	assert.Equal(t, 1, countQuestionMarks(out), "no second '?'")
}

func TestBuildAuthorizeSuccessRedirect_NoState(t *testing.T) {
	out := buildAuthorizeSuccessRedirect("https://rp.example.com/cb", "C", "", "iss")
	u, _ := url.Parse(out)
	assert.False(t, u.Query().Has("state"))
	assert.Equal(t, "C", u.Query().Get("code"))
}

func countQuestionMarks(s string) int {
	n := 0
	for _, r := range s {
		if r == '?' {
			n++
		}
	}
	return n
}
