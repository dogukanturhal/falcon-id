# Falcon-ID XOAUTH2 for mail clients — architecture proposal

**Status:** PROPOSED — design draft, not implemented. Review + approval required before Phase 1 starts.
**Audience:** platform team operators + Falcon-ID maintainers.
**Author:** drafted W23 2026-05-02 from the W23 follow-up handoff (item D).
**Related memory:** internal engineering notes, internal engineering notes, internal engineering notes.

---

## 1. Goal

Let HexxLock employees authenticate to their **Exchange mailboxes** through Falcon-ID's OIDC flow instead of entering a separate `Administrator@hexxlock.corp` password into Outlook / Thunderbird / Apple Mail.

Today every mail client is configured with a static password (the AD account password). Rotating that password rotates the mailbox auth too — high-friction operationally and impossible to MFA-gate per-app.

After this lands, mail-client auth inherits the full Falcon-ID gate: passkeys + WebAuthn, risk-MFA, session blacklisting, OIDC backchannel logout, etc. Stopping someone's mail access becomes a Falcon-ID `revoke session` click instead of an AD password reset cascade.

## 2. Scope

**In scope:**
- Desktop mail clients on managed laptops (Outlook, Thunderbird, Apple Mail) — submission (SMTP `:587`) + retrieval (IMAP `:993`).
- Webmail for mobile/BYOD (no XOAUTH2 path that works reliably across iOS Mail / Gmail Android).

**Out of scope:**
- Inbound MX `:25` from external senders — public mail must accept whatever the sending MTA negotiates, OIDC has no role here.
- Programmatic SMTP from cluster workloads (Alertmanager, application notifications) — those use service-account credentials with narrowly-scoped Vault secrets, not OIDC.
- Microsoft 365 / Exchange Online — we self-host Exchange Server 2022, this design is for that.

## 3. Topology

```
                                                          ┌──────────────┐
                                                          │ Falcon-ID    │
                                                          │ (id.hexxlock │
                                                          │      .com)   │
                                                          └──────┬───────┘
                                                                 │ OIDC discovery
                                                                 │ + token endpoint
                                                                 │
                       ┌─── XOAUTH2 over TLS ────────────────────┴──────┐
                       │                                                │
┌──────────────┐  ┌────┴────────────────┐                  ┌────────────┴────────┐
│ Outlook /    │  │  Dovecot SASL +     │  static service- │  Exchange Server    │
│ Thunderbird  ├──┤  Postfix submission │  account creds   │  2022               │
│ Apple Mail   │  │  (XOAUTH2 proxy)    ├──────────────────┤  (mail.hexxlock.    │
└──────────────┘  └─────────┬───────────┘  IMAP/SMTP       │   corp)             │
                            │                              └─────────────────────┘
                            │ token introspection
                            │ (RFC 7662 against
                            │  Falcon-ID)
                            ▼
                       ┌────────────┐
                       │ Falcon-ID  │
                       │ /introspect│
                       └────────────┘

┌──────────────┐  ┌─────────────────────┐
│ iOS Mail /   │  │  Roundcube webmail  │  same proxy backend
│ Gmail Android├──┤  (browser OIDC      ├─────────────────────► Exchange
│ (no XOAUTH2) │  │   redirect)         │
└──────────────┘  └─────────────────────┘
```

## 4. Component responsibilities

### 4.1 Dovecot (SASL+IMAP) + Postfix (SMTP submission) — XOAUTH2 proxy

A new VM `mail-proxy.hexxlock.corp` (or a pod, depending on operator preference — see open question Q1) runs:

- **Dovecot** — accepts IMAP `:993` from clients with SASL `XOAUTH2` mechanism. Dovecot's `auth_mechanisms = xoauth2` config + `passdb { driver = oauth2 }` validates the bearer token via `tokeninfo_url=https://id.hexxlock.com/oauth/introspect`.
- **Postfix submission** — `:587` STARTTLS + `smtpd_sasl_type = dovecot` so SMTP submission shares the Dovecot SASL socket.
- **Backend hop** — once token validates, the proxy opens an IMAP/SMTP session to Exchange using a **static per-user service-account credential** stored in Vault. That credential is a separate Exchange "ApplicationImpersonation" account — `mail-proxy@hexxlock.corp` with permission to act as the introspection-resolved `username` claim's mailbox.

**Why a proxy and not Exchange directly:** Exchange Server 2022 supports OAuth via the EvoSTS endpoint (Microsoft's federated AAD trust), but configuring it for a non-AAD IdP (Falcon-ID) requires either undocumented manifest hacks or running ADFS in front. Both paths are higher operational risk than Dovecot+Postfix XOAUTH2 SASL — a well-understood pattern documented by Dovecot, Postfix, and every major XOAUTH2-enabled IMAP provider.

### 4.2 Falcon-ID — OIDC scope + introspection

Two new scopes:
- `mail:smtp-submit` — required to send via the proxy `:587`.
- `mail:imap-read` — required to fetch via the proxy `:993`.

Both scopes are surfaced on the Falcon-ID consent screen as "Send mail on your behalf" / "Read your mail" so users see what the mail client is requesting. Internal first-party clients (Outlook on managed laptops) can mark `is_first_party=true` to suppress the consent prompt per the existing first-party policy.

The proxy validates tokens via the existing `/oauth/introspect` endpoint (RFC 7662). The introspection response's `username` claim drives the mailbox lookup. The `scope` claim must include the operation's required scope (`mail:smtp-submit` for SMTP `MAIL FROM`, `mail:imap-read` for IMAP `LOGIN`).

### 4.3 Roundcube (webmail) for mobile / BYOD

iOS Mail and Android Gmail do not implement XOAUTH2 against arbitrary OAuth IdPs (only Google + Microsoft). Forcing them through the Dovecot proxy with a per-user app password is operationally identical to today and provides no OIDC win.

The mobile path is **Roundcube** at `https://webmail.hexxlock.com`:
- Browser-based login → standard Falcon-ID OIDC dance.
- Session cookie carries the access token; Roundcube's IMAP/SMTP backend uses the same `mail-proxy.hexxlock.corp` proxy with the user's bearer token.
- Same scope gates apply.

This keeps mobile users on the OIDC path without any client-side XOAUTH2 capability.

## 5. Phased implementation

| Week | Deliverable | Verify |
|------|-------------|--------|
| 1 | Falcon-ID scopes (`mail:smtp-submit`, `mail:imap-read`) + RP registration + DB seed migration | New scopes appear in `/.well-known/openid-configuration` `scopes_supported`; consent screen renders both with friendly descriptions |
| 2 | Dovecot+Postfix XOAUTH2 proxy on `mail-proxy.hexxlock.corp` + Vault-stored Exchange backend creds + Calico GNP for proxy → Exchange traffic | `openssl s_client -connect mail-proxy:993 -starttls imap` succeeds; `swaks --auth XOAUTH2 --auth-user $USER --auth-password $TOKEN` lands a test message |
| 3 | Roundcube deploy as Helm chart + OIDC integration + DNS for `webmail.hexxlock.com` + Talon route + Falcon-ID RP registration with `redirect_uri=https://webmail.hexxlock.com/oauth/callback` | Browser login at `https://webmail.hexxlock.com` lands on Falcon-ID, returns to Roundcube with active session, INBOX populates |
| 4+ | Soak window + flip-docs for users (Outlook profile setup wizard, Thunderbird XOAUTH2 howto, mobile = "use webmail") + Grafana dashboard for proxy auth-failure rate + alert on auth-failure spike | <1% auth-failure rate over 7d, no `5xx` from proxy in `id.hexxlock.com` logs, op survey shows >90% of laptop users migrated within 30d |

## 6. Open questions (need user decision before Phase 1)

**Q1 — Proxy as VM or pod?**
- **VM** option: provisioned via existing infra-ansible host-provisioning workflow, Vault Agent for backend creds, native systemd Dovecot+Postfix. Operationally identical to PMG but adds a 5th mail VM.
- **Pod** option: Helm chart in the cluster, Linkerd-meshed, cleaner blast radius for restarts, but introduces a new pod-network → Exchange path that needs Calico GNP work + new mail-flow on the cluster.
- Recommendation: VM, because mail uptime is a hard SLO and we already have mail-VM operations dialled in (PMG + Exchange backups, monitoring, runbooks). Adding mail to the cluster is net-new ops surface.

**Q2 — Token TTL?**
- Short (5min) tokens with refresh = standard OIDC, but every mail-client refresh cycle hits Falcon-ID `/introspect`.
- Long (8h) tokens = fewer introspect calls but a leaked token is valid for hours.
- Recommendation: 1h access token + 24h refresh, identical to the rest of the Falcon-ID issued tokens (per internal engineering notes). On revoke (Falcon-ID `/revoke`), the proxy's introspection check catches the next call within 1h.

**Q3 — Backend Exchange creds: per-user or shared service account?**
- Per-user = user A's leaked proxy session can only access user A's mailbox, but provisioning per-user credentials in Vault requires a Crossplane-managed `ExchangeMailboxCredential` resource (net-new infra).
- Shared `mail-proxy@hexxlock.corp` with `ApplicationImpersonation` = simpler, but a leaked proxy session could (in theory) impersonate any mailbox if the proxy's introspection logic is bypassed.
- Recommendation: shared service account + tight Falcon-ID scope enforcement + audit log every proxy → Exchange action. The blast-radius difference is acceptable given that mail-proxy itself is already a high-trust component.

**Q4 — Deprecation lane for current static passwords?**
- Hard cutoff — disable basic auth on Exchange `:587` + `:993` after the soak window.
- Soft cutoff — leave basic auth enabled but log every basic-auth login + email the user "please switch to OIDC".
- Recommendation: 30-day soft cutoff, then hard cutoff. Matches the 4-week implementation cadence with a 4-week migration window.

## 7. What's NOT in this design

- **Calendar / contacts (CalDAV / CardDAV)** — mail-only for Phase 1. CalDAV/CardDAV via the same proxy is a Phase 2 follow-up.
- **Activesync / EAS** — Activesync auth is Microsoft-specific and we don't want to reimplement it. iOS Mail / Android Gmail can use the Roundcube webmail path instead.
- **External submitters** — only HexxLock-employee mailboxes. Customer / third-party submission is rejected at the proxy.
- **End-to-end encryption (S/MIME / PGP)** — orthogonal; the proxy only mediates auth, not message content.

## 8. Acceptance criteria for "done"

- All HexxLock employees on managed laptops use OIDC for SMTP submission + IMAP retrieval.
- Mobile / BYOD users use webmail at `webmail.hexxlock.com`.
- Static AD password for mailbox auth is disabled on Exchange (basic auth off on `:587` + `:993`).
- Falcon-ID `/revoke` propagates to mail-proxy within 1h on the next token-refresh boundary.
- Grafana dashboard shows proxy auth-success rate, scope-rejection rate, backend Exchange auth latency.
- Runbook for "mail user can't authenticate" with diagnosis steps that cover OIDC token, scope, proxy session, Exchange backend.

---

**Next step:** review + approval. If green, start Phase 1 (Falcon-ID scope additions + RP registration). If not, comment on the open questions or push back on the topology.
