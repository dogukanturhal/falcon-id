# Mearax Settings Keystone Requirements

Falcon-ID carries a defensive local migration for fresh databases, but Keystone
remains the production schema authority and must reconcile these prerequisites
before this build runs.

## Team invitation lifecycle

- `iam_team_invitations` must have a partial unique index named
  `idx_iam_team_invitations_pending_tenant_email_normalized_unique` on
  `(tenant_id, email_normalized) WHERE status = 'pending'`, where
  `email_normalized` is generated as `lower(btrim(email))`.
- The table must permit the terminal `expired` status. Falcon-ID changes an
  expired pending row to `expired` in the same transaction that inserts a
  replacement invitation.
- `iam_email_outbox` must be declared in Falcon-ID's authoritative
  `SchemaDefinition`, not only created by a `MigrationBundle`, and must contain
  the columns used by
  `EmailOutboxRepository.Insert`: `tenant_id`, `template`, `recipient`,
  `subject`, and `body_html`, together with its normal pending/retry fields.
- Its template CHECK allow-list must not include `team_invitation`. Team links
  grant roles and remain credential-bearing even though acceptance also
  requires an authenticated account with the invited email. Falcon-ID hashes
  the token in `iam_team_invitations`, commits the invitation and audit, then
  hands the rendered message directly to SMTP. A failed handoff attempts an
  immediate compare-and-set revocation so a retry issues a fresh token.
- Keep `EMAIL_OUTBOX_ENABLED=false` until the cross-tenant drainer has a
  dedicated privileged database role. The table now forces strict tenant RLS;
  the outbox remains reserved for non-credential security notices and SMTP
  tests, never Team invitation links.

## Permission seed and grants

Falcon-ID synchronously registers these IAM definitions before serving routes:

- `iam:invitations:read`, `iam:invitations:create`, `iam:invitations:delete`
- `iam:users:read`, `iam:users:update`, `iam:users:delete`
- `iam:service_accounts:read`, `iam:service_principals:read`

Keystone must grant only the required definitions to the canonical tenant
administrator roles that should operate the Team page: `admin`, `org_admin`,
`owner`, `platform_admin`, and `super_admin`. Do not grant them to `iam_admin`
and do not grant `iam:*:*` or broad module wildcards. The existing
`GET /api/v1/roles` remains authorized by `core:roles:read`; Keystone must seed
and grant that exact permission on clusters where it is absent.

Falcon-ID additively grants the same exact set when a future self-service
signup creates or reuses its `org_admin` role, then synchronously writes the
permission and user-role relationships to SpiceDB. The PostgreSQL grant is
additive and durable before external synchronization, allowing the reconciler
to repair transient SpiceDB failures without replacing unrelated grants.

## External dependency

Invitation persistence and SMTP delivery cannot be one atomic transaction.
After the database commit, Falcon-ID either observes SMTP acceptance or revokes
the pending invitation on failure; a process crash at that boundary can leave
an active invitation that was not delivered, which an administrator can revoke
and reissue. SMTP acceptance remains an external at-least-once dependency.
