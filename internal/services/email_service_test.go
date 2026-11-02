// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"strings"
	"testing"
)

// TestTeamInvitationHTMLBody_PlainTextRetainsAcceptLink is the regression
// test for the reported defect: an invited team member's email had "no link
// ... to accept or decline". The HTML half always had a clickable <a href>,
// but sendEmail's htmlToPlainText strips HTML tags wholesale, which
// discards an href ATTRIBUTE and keeps only the link's visible text — so a
// client that renders (or a user who reads) the text/plain alternative saw
// "Accept invitation" with no URL anywhere in the message.
//
// Control: reproduces the exact pre-fix shape (accept URL present only
// inside the <a href="..."> attribute, no visible copy) and asserts the
// resulting plain text does NOT contain the URL — proving htmlToPlainText's
// tag-stripping is what causes the loss, and that this test would fail
// against the old teamInvitationHTMLBody. If this control ever stops
// failing on the pre-fix shape, the assertion below has stopped meaning
// anything.
func TestTeamInvitationHTMLBody_PlainTextRetainsAcceptLink(t *testing.T) {
	svc := &EmailService{}
	acceptURL := "https://app.example.test/invitations/accept?token=abc123"

	html := teamInvitationHTMLBody(acceptURL, false)
	plain := svc.htmlToPlainText(html)

	if !strings.Contains(plain, acceptURL) {
		t.Fatalf("plain-text invitation body does not contain the accept URL; got: %q", plain)
	}

	// Positive control on the HTML side too — the link must still be a real
	// href, not just present as inert text.
	if !strings.Contains(html, `href="`+acceptURL+`"`) {
		t.Fatalf("HTML invitation body does not contain the accept URL as a clickable href; got: %q", html)
	}
}

// TestTeamInvitationHTMLBody_PlainTextLossControl proves the negative: an
// href-only link (the pre-fix shape, reconstructed directly here rather than
// by re-calling the fixed helper) really does vanish from the plain-text
// rendering. This is the failing case the fix above closes — if this ever
// stops failing, htmlToPlainText's tag-stripping behavior changed and the
// reasoning behind the fix needs re-checking.
func TestTeamInvitationHTMLBody_PlainTextLossControl(t *testing.T) {
	svc := &EmailService{}
	acceptURL := "https://app.example.test/invitations/accept?token=abc123"

	preFixHTML := `<html><body><p>You have been invited to join a team on ExampleSuite.</p>` +
		`<p><a href="` + acceptURL + `">Accept invitation</a></p>` +
		`<p>This invitation expires in 7 days.</p></body></html>`
	plain := svc.htmlToPlainText(preFixHTML)

	if strings.Contains(plain, acceptURL) {
		t.Fatalf("expected the href-only shape to lose the URL in plain text, but it survived: %q", plain)
	}
}

func TestTeamInvitationHTMLBody_ExistingAccountWording(t *testing.T) {
	acceptURL := "https://app.example.test/invitations/accept?token=abc123"

	fresh := teamInvitationHTMLBody(acceptURL, false)
	existing := teamInvitationHTMLBody(acceptURL, true)

	if strings.Contains(fresh, "already have a AcmeApp account") {
		t.Fatalf("new-account wording must not mention an existing account: %q", fresh)
	}
	if !strings.Contains(existing, "already have a AcmeApp account") || !strings.Contains(existing, "sign in") {
		t.Fatalf("existing-account wording must tell the invitee to sign in; got: %q", existing)
	}
	for name, body := range map[string]string{"new": fresh, "existing": existing} {
		if !strings.Contains(body, `href="`+acceptURL+`"`) {
			t.Fatalf("%s: accept link missing", name)
		}
	}
}
