# GDPR Article 30 — Records of Processing Activities (ROPA)

**Controller**: HexxLock Inc.
**Last reviewed**: 2026-05-25
**Review cadence**: Quarterly (next: 2026-08-25)
**Owner**: Data Protection Officer (privacy@example.com)
**Lawful basis register**: see §4

This document is the canonical GDPR Article 30(1) records artifact for the HexxLock identity platform (Falcon-ID IdP + Accounts portal). It is produced for inspection on demand by supervisory authorities (KVKK in Turkey, Datenschutzbehörden in EU member states) and supplied under NDA to enterprise customers conducting vendor due diligence.

The companion document `gdpr-records-of-processing-as-processor.md` (Article 30(2)) covers processing performed on behalf of customers (where HexxLock is processor, not controller).

---

## 1. Identity of the controller and DPO

| Field | Value |
|---|---|
| Legal entity | HexxLock Inc. |
| Registered office | _(Yes — fill in legal address before sharing externally)_ |
| Data Protection Officer | privacy@example.com |
| EU representative (Art. 27) | _(if no EU establishment)_ |
| UK representative (UK GDPR Art. 27) | _(if no UK establishment)_ |
| KVKK Data Controllers' Registry (VERBIS) | _(Turkish registration ID, mandatory if ≥100 employees or processes special-category data of Turkish residents)_ |

---

## 2. Processing activities

Each row in §2 is one "processing activity" in the Art. 30(1) sense — a coherent set of operations performed for a single purpose. Subsections per activity follow the Art. 30(1)(b–g) order.

### 2.1 — Account registration and authentication

- **Purpose**: Establish and maintain a user account; verify identity at login; enforce multi-factor authentication; protect against credential-stuffing / account takeover.
- **Categories of data subjects**: Self-registered end-users; users provisioned via federated IdP (SAML/OIDC/LDAP); users provisioned via SCIM.
- **Categories of personal data**:
  - Identifiers: email address (hashed for lookup via HMAC-SHA256 with rotating key; ciphertext stored alongside under envelope encryption), username, internal UUID, federation NameID (SAML), `sub` claim (OIDC).
  - Profile: first name, last name, display name, phone number (optional), profile picture (uploaded by user).
  - Authentication factors: Argon2id password hash (never plaintext), TOTP shared secret (AES-GCM encrypted), WebAuthn public-key credentials + AAGUID, push-MFA device tokens, recovery backup codes (Argon2id hashed).
  - Session metadata: IP address, user-agent, country code (from MaxMind GeoLite2 or equivalent), device fingerprint, login outcome (success/blocked/mfa_challenged).
- **Recipients**: Internal — application servers (TLS in transit, envelope-encrypted at rest), session cache (Redis, in-VPC), audit log (immutable, HMAC-chain integrity). External — none for this activity except (a) federated IdP if the user authenticates via SSO and (b) email delivery provider for OTP/notifications (see §2.3).
- **Cross-border transfers**: None for EU-data-residency tenants. Tenants on global tier may have data processed in either EU or US regions per their region pinning. SCCs (2021 set) in place with US-region processors via Cloudflare and Google Workspace; no FRA-derogated transfers.
- **Retention**: Active account — for the life of the account. Soft-deleted account — 30 days then hard-deleted except (i) audit log (7 years for legal/regulatory hold per §3) and (ii) anonymized aggregates retained indefinitely.
- **Lawful basis**: Art. 6(1)(b) performance of contract (user signed up for the service).
- **Source**: Directly from the data subject (form submission, OAuth callback, federation assertion).
- **Technical and organizational measures**: see §3.

### 2.2 — Authorization and OAuth/OIDC token issuance

- **Purpose**: Issue access tokens and ID tokens scoped to the user's authorized resources; enforce step-up authentication for sensitive operations; satisfy enterprise customer authorization policies (RBAC + ReBAC via SpiceDB).
- **Categories of data subjects**: All authenticated users.
- **Categories of personal data**:
  - Token claims: `sub`, `tid` (tenant), `rid` (realm), `auth_time`, `amr`, `acr`, `roles`, custom claims per OAuth client.
  - DPoP confirmation: `cnf.jkt` (key thumbprint binding, RFC 9449).
  - Session row: `iam_user_sessions` linking access token JTI to user, authenticated_at, expires_at, auth_methods_used (RFC 8176).
- **Recipients**: OAuth clients (RPs) bound by client registration (per-client redirect URI allowlist), the user's user-agent (token in HttpOnly cookie or response body), audit log.
- **Cross-border transfers**: None additional beyond §2.1.
- **Retention**: Tokens — JWT lifetime (15 min access / 30 days refresh, configurable per realm). Session row — until session termination + 30 days for revocation propagation. Audit — 7 years.
- **Lawful basis**: Art. 6(1)(b) performance of contract; Art. 6(1)(f) legitimate interest for fraud prevention.

### 2.3 — Transactional and security notifications

- **Purpose**: Notify users of security-relevant events (new sign-in, password change, MFA enrollment, account-locked); deliver OTPs (email channel); send account-recovery codes.
- **Categories of data subjects**: All authenticated users.
- **Categories of personal data**: Email address, name (for personalization), event metadata (IP, device, geo).
- **Recipients**: SMTP / transactional email provider (currently SES; previously SendGrid). DPA in place; SCCs (2021) cover any US-region delivery for EU-tenant users.
- **Cross-border transfers**: As above for email provider.
- **Retention**: Notification log — 90 days (for delivery debugging + user-facing activity feed). Email-content templates — indefinite. OTP — single-use, 10-minute TTL.
- **Lawful basis**: Art. 6(1)(b) performance of contract for security notifications (mandatory — see Art. 32 obligation). Art. 6(1)(a) consent for marketing/product-update categories.

### 2.4 — Audit logging and security telemetry

- **Purpose**: Detect and investigate account compromise, abuse, and policy violations; satisfy SOC 2 / ISO 27001 audit controls; produce evidence for regulatory inquiry; enable Continuous Access Evaluation (CAE) and Shared Signals Framework (SSF) emissions.
- **Categories of data subjects**: All users and service accounts.
- **Categories of personal data**: User identifier, IP address, user-agent, geo, action taken (login/logout/role-change/token-issue/etc.), correlation ID, request ID, outcome, risk signals.
- **Recipients**: SIEM pipeline (Wazuh + SOC team); enterprise customers via per-tenant audit log API (their own data only). Outbound CAEP receivers per Continuous Access Evaluation (1.0 Final spec) — only when customer subscribes.
- **Cross-border transfers**: None.
- **Retention**: 7 years (financial regulatory baseline; longer if held under legal hold).
- **Lawful basis**: Art. 6(1)(c) legal obligation (PCI-DSS where applicable + national equivalent of NIS2); Art. 6(1)(f) legitimate interest (security of network and information systems, Recital 49).

### 2.5 — Customer support and incident response

- **Purpose**: Investigate user-reported issues; respond to support tickets; conduct post-incident analysis after security events.
- **Categories of data subjects**: Users who contact support; users affected by an incident.
- **Categories of personal data**: As §2.1–2.4 plus ticket content (free-form, may include screenshots).
- **Recipients**: Internal support engineers; in scope for any post-incident write-up (anonymized).
- **Retention**: Support ticket — 2 years after resolution. Incident reports — 7 years.
- **Lawful basis**: Art. 6(1)(b) for resolving the user's own complaint; Art. 6(1)(f) for investigating incidents affecting other users.

### 2.6 — Compliance with legal obligations (subject access, deletion, export)

- **Purpose**: Honor data subject rights under GDPR Articles 15 (access), 16 (rectification), 17 (erasure), 18 (restriction), 20 (portability), 21 (objection).
- **Categories of data subjects**: Any user submitting a rights request.
- **Categories of personal data**: All personal data above (aggregated for export); proof of identity validation (we use existing authenticated session, no additional ID collection).
- **Recipients**: The data subject themselves; DPO and legal counsel internally.
- **Cross-border transfers**: None.
- **Retention**: Request log — 3 years (for evidence of compliance).
- **Lawful basis**: Art. 6(1)(c) legal obligation (GDPR itself).

### 2.7 — Marketing and product communications (consent-based)

- **Purpose**: Send product updates, newsletters, feature announcements, marketing communications to users who have explicitly opted in.
- **Categories of data subjects**: Users who have given consent on the Notifications preferences page.
- **Categories of personal data**: Email, display name, locale, product-usage signals (for relevance).
- **Recipients**: Marketing email tool (DPA in place).
- **Retention**: Until consent withdrawn, then 30-day grace + delete from active list. Consent ledger retained 7 years as evidence.
- **Lawful basis**: Art. 6(1)(a) consent. Consent is granular per category, revocable at any time via the notifications page or unsubscribe link, and recorded in an immutable consent ledger.

### 2.8 — Billing and payment (B2B subscription)

- **Purpose**: Bill paying customers for their HexxLock subscription.
- **Categories of data subjects**: Billing contacts of customer organizations.
- **Categories of personal data**: Name, email, billing address, tax ID. **No cardholder data** — payment cards are tokenized via Stripe; we hold only the Stripe customer ID and Stripe-issued token. PCI-DSS SAQ-A scope-out.
- **Recipients**: Stripe (DPA + 2021 SCCs for any US processing of EU billing contacts).
- **Cross-border transfers**: Stripe via SCCs.
- **Retention**: Invoice — 7 years (Turkish tax law TPK Art. 251 + EU member state equivalents typically 7-10 years).
- **Lawful basis**: Art. 6(1)(b) contract; Art. 6(1)(c) legal obligation (tax law).

---

## 3. Technical and organizational measures (Art. 30(1)(g) summary)

Detail per measure category. Each row maps to ISO 27001:2022 Annex A controls + SOC 2 Common Criteria.

| Measure | Implementation | Standard |
|---|---|---|
| Encryption in transit | TLS 1.3 ingress (Linkerd-terminated); TLS 1.2 minimum for outbound | A.8.24, CC6.7 |
| Encryption at rest | Per-tenant envelope encryption (AES-GCM with `enc:v1` framing; DEK wrapped by Vault KEK; HMAC-SHA256 email hash for lookup with rotating key) | A.8.24, CC6.1 |
| Pseudonymization | Email stored as HMAC-SHA256 hash for query; plaintext encrypted under tenant DEK; user IDs are opaque ULIDs (no PII embedded) | A.5.34, CC6.1 |
| Access controls | RBAC on admin endpoints; ReBAC (SpiceDB) for object-level authorization; least-privilege service accounts; mTLS for service-to-service (SPIFFE identities) | A.5.15-A.5.18, CC6.1-CC6.3 |
| Authentication | Argon2id passwords; phishing-resistant MFA (WebAuthn) mandatory for admin roles; risk-based step-up (RFC 9470); HIBP credential-stuffing protection | A.5.17, A.8.5, CC6.1 |
| Audit logging | Immutable append-only with HMAC chain; 7-year retention; SIEM streaming | A.5.28, A.8.15, CC7.2-CC7.4 |
| Backups | Daily encrypted backups to S3-compatible store (Backblaze B2 secondary); quarterly restore drills | A.5.33, A.8.13, CC9.1 |
| Disaster recovery | Multi-AZ primary; documented RPO ≤4h / RTO ≤2h tier-1; annual DR exercise | A.5.30, A.5.31, CC9.1 |
| Incident response | 24/7 on-call; documented playbook (`docs/operator-runbooks/incident-response.md`); 72-hour breach notification process per Art. 33; tabletop quarterly | A.5.24-A.5.27, CC7.5 |
| Vendor management | DPA + SCCs (2021) with each processor; processor inventory in §5 below; pre-engagement security review | A.5.19-A.5.21, CC9.2 |
| Vulnerability management | Trivy scanning in CI; Harbor admission control; Snyk + GitHub Advanced Security; SBOM (CycloneDX) per release signed with Cosign | A.8.8, CC7.1 |
| Secure development | Signed commits (gitlab-cosign); mandatory code review; SAST (SonarQube + Semgrep); pre-commit secret scanning | A.8.25-A.8.31, CC8.1 |
| Personnel | Background checks for engineers with prod access; least-privilege offboarding playbook; mandatory annual security training | A.6.1-A.6.6, CC1.4 |
| Physical security | Cloud-provider responsibility (AWS / Hetzner / colo) with documented SOC 2 / ISO 27001 evidence | A.7.1-A.7.13, CC6.4 |

---

## 4. Lawful basis register

| Processing activity | Art. 6(1) basis | Art. 9 basis (if special category) |
|---|---|---|
| Account registration (2.1) | (b) contract | n/a |
| Token issuance (2.2) | (b) contract + (f) fraud prevention | n/a |
| Security notifications (2.3, mandatory) | (b) contract + (c) legal obligation | n/a |
| Marketing notifications (2.7) | (a) consent | n/a |
| Audit logging (2.4) | (c) legal + (f) network security | n/a |
| Support tickets (2.5) | (b) + (f) | n/a |
| Rights requests (2.6) | (c) GDPR itself | n/a |
| Billing (2.8) | (b) + (c) tax | n/a |

---

## 5. Sub-processor list

This list is publicly published at `https://example.com/legal/subprocessors` and changes are notified to customers with ≥30-day notice per our DPA.

| Sub-processor | Role | Region | DPA | SCC 2021 |
|---|---|---|---|---|
| AWS (us-east-1, eu-west-1) | Compute + storage (S3 backups) | Multi | yes | yes (US transfers) |
| Hetzner (Helsinki, Falkenstein) | Compute (EU-primary tier) | EU | yes | n/a (EU-only) |
| Cloudflare | CDN + DDoS + Workers | Multi | yes | yes |
| Stripe | Payment processing | US | yes | yes |
| Sentry (Functional Software) | Error tracking | US | yes | yes |
| Datadog | Observability (metrics, traces) | EU + US | yes | yes (US) |
| SES (AWS) | Transactional email | US + EU | yes | yes (US) |
| GitHub | Source code hosting (private repos only) | US | yes | yes |
| GitLab self-hosted | Internal source code hosting | EU (Hetzner) | n/a (in-house) | n/a |

Any new sub-processor triggers a 30-day customer notice + change-log entry on the public page.

---

## 6. Data subject rights — operational SLA

| Right | Endpoint | SLA |
|---|---|---|
| Art. 15 access | `/api/portal/privacy/export` + downloadable bundle | 30 days |
| Art. 16 rectification | `/api/portal/profile` (self-serve) | Immediate (self-serve) |
| Art. 17 erasure | `/api/portal/privacy/delete` with 30-day grace | 30 days from grace expiry |
| Art. 18 restriction | `/api/portal/privacy/restrict` (todo — currently bulk via §2.7 consent revoke) | 30 days |
| Art. 20 portability | Same bundle as Art. 15 (JSON, structured machine-readable) | 30 days |
| Art. 21 objection | `/api/portal/notifications` for marketing; legitimate-interest objections via privacy@example.com | 30 days |
| Art. 7(3) consent withdrawal | `/api/portal/notifications` per category | Immediate |

---

## 7. Transfer impact assessment summary (Art. 46)

For each cross-border transfer (US sub-processors): SCCs (2021) Module 2 (Controller → Processor) in place; supplementary measures per CJEU C-311/18 Schrems II:
- Encryption at rest with EU-held key (HexxLock retains KEK in Vault, located in EU primary region; only DEK ciphertext leaves the EU)
- Audit log of US-region access (so any access can be reconstructed)
- Contractual challenge / notice obligations per SCCs (Clause 14, 15)
- US sub-processors are not subject to FISA Section 702 in the categories that would intercept HexxLock data per their public transparency reports

A full Transfer Impact Assessment (TIA) document is held under NDA and available to enterprise customers on request.

---

## 8. Review and change log

| Date | Author | Change |
|---|---|---|
| 2026-05-25 | DPO | Initial draft per GDPR Art. 30(1) audit |

This document is to be updated:
- Quarterly (review cadence)
- Immediately upon adding/removing a processing activity
- Immediately upon adding/removing a sub-processor
- Upon any material change to retention / lawful basis / cross-border transfer

Out-of-band changes are logged inline in this section with date + author + reason.

---

## Companion documents (referenced)

- `docs/compliance/gdpr-records-of-processing-as-processor.md` — Art. 30(2) records (where HexxLock is processor for customer data)
- `docs/compliance/transfer-impact-assessment.md` — full TIA per Schrems II
- `docs/compliance/data-protection-impact-assessment.md` — DPIA covering high-risk processing activities (Art. 35)
- `docs/operator-runbooks/incident-response.md` — Art. 33/34 breach notification playbook
- `https://example.com/legal/subprocessors` — public sub-processor list with 30-day change notification

---

_End of Article 30 Records._
