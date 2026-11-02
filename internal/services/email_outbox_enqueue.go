// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// emailOutboxInserter is the narrow write side of the outbox needed by
// EmailService. Satisfied by *repositories.EmailOutboxRepository.
type emailOutboxInserter interface {
	Insert(ctx context.Context, tx repositories.DBTX, row *repositories.EmailOutboxRow) error
}

// SetOutbox enables durable queueing for non-credential mail.
//
// Optional: with no outbox set, every template is sent synchronously —
// which is exactly the behaviour before the outbox existed, so the
// service degrades to the previous, correct path rather than failing.
func (s *EmailService) SetOutbox(o emailOutboxInserter) {
	s.outbox = o
}

// SendRendered delivers an already-rendered message immediately.
//
// This is the drainer's delivery entry point: the body was rendered and
// stored at enqueue time, so there is nothing left to template. It is
// also the reason sendEmail stays unexported — everything that renders
// goes through the typed Send* helpers.
//
// Per-tenant SMTP config is resolved HERE, at send time, not at enqueue
// time, so a tenant that corrects its relay settings while messages are
// queued gets the corrected settings on the next attempt.
func (s *EmailService) SendRendered(ctx context.Context, tenantID uuid.UUID, template, to, subject, htmlBody string) error {
	// Queued templates are never the AcmeApp-branded invitation templates
	// (TeamInvitationEmailTemplate is credential-bearing and never queued —
	// see EnqueueOrSend/MayQueue below), so the sender override never
	// applies on this path.
	return s.sendEmail(ctx, tenantID, template, to, subject, htmlBody, "")
}

// EnqueueOrSend writes a rendered message to the outbox when the
// template is queueable, and otherwise sends it synchronously.
//
// THE GUARD. MayQueue is consulted on every call and fails closed on
// unknown templates, so a template nobody classified is sent
// synchronously rather than persisted. This is the code-side half of the
// policy; the table's CHECK constraint is the database-side half, and if
// the two ever diverge the INSERT errors — the safe direction.
//
// Credential-bearing mail (one-time codes, password-reset and magic
// links) therefore never reaches the outbox table, by construction:
//
//   - Falcon-ID persists no plaintext one-time code today; the MFA
//     repository stores only CodeHash. Queueing a rendered body would put
//     live, currently-valid credentials at rest in Postgres, where every
//     backup, replica and logical dump would carry them.
//
//   - Retry is the wrong semantic for a one-time code. NIST SP 800-63B
//     §5.1.3.2 bounds out-of-band authentication at 10 minutes with single
//     use, so redelivering after an outage produces a DEAD code, having
//     extended the window a live one sat in storage.
//
// tx may be nil for a standalone enqueue. Passing the caller's
// transaction is preferred — that is the whole point of a transactional
// outbox: the business change and the queued message commit together, or
// neither does.
func (s *EmailService) EnqueueOrSend(
	ctx context.Context,
	tx repositories.DBTX,
	tenantID uuid.UUID,
	template, to, subject, htmlBody string,
) error {
	if s.outbox == nil || tx == nil || !MayQueue(template) {
		// Same reasoning as SendRendered: nothing routed through the
		// generic enqueue/send path is a AcmeApp invitation template.
		return s.sendEmail(ctx, tenantID, template, to, subject, htmlBody, "")
	}
	row := &repositories.EmailOutboxRow{
		TenantID:  tenantID,
		Template:  template,
		Recipient: to,
		Subject:   subject,
		BodyHTML:  htmlBody,
	}
	return s.outbox.Insert(ctx, tx, row)
}
