# SLO regression — BCL/FCL fan-out silently disabled (2026-05-10)

## Summary

Live audit of `iam_oauth_clients` on `falcon-id-pg` (cnpg-clusters
namespace) shows **0 of 12 active OAuth clients** carry a
`backchannel_logout_uri` or `frontchannel_logout_uri`. The OP-side
`BackchannelLogoutService.NotifyLogout` and
`FrontchannelLogoutService.BuildIFrames` therefore fan out to **zero
RPs** on every Sign Out — silently. The bug is invisible from the
Falcon-ID side because both services degrade to a no-op when the
client list is empty (no log line, no metric).

## Baseline (queried 2026-05-10 from `falcon-id-pg-1` primary)

```
total | with_bcl | with_fcl | first_party | internal
   12 |        0 |        0 |          12 |        0
```

Per-client:

| client_id              | grant                       | scopes                            | bcl_uri | fcl_uri |
|------------------------|-----------------------------|-----------------------------------|---------|---------|
| `svc-talon`            | authorization_code+refresh  | openid,email,profile,groups,roles |   —     |   —     |
| `svc-accounts`         | authorization_code+refresh  | openid,email,profile,groups,roles |   —     |   —     |
| `svc-argocd`           | authorization_code+refresh  | openid,email,profile,groups,roles |   —     |   —     |
| `svc-grafana`          | authorization_code+refresh  | openid,profile,email,roles        |   —     |   —     |
| `svc-awx`              | authorization_code+refresh  | openid,email,profile,groups,roles |   —     |   —     |
| `svc-dojo`             | authorization_code+refresh  | openid,email,profile,groups       |   —     |   —     |
| `svc-gitlab`           | authorization_code+refresh  | openid,email,profile,groups,roles |   —     |   —     |
| `svc-harbor`           | authorization_code+refresh  | openid,email,profile,roles        |   —     |   —     |
| `svc-sonarqube`        | authorization_code+refresh  | openid,email,profile,roles        |   —     |   —     |
| `svc-vault`            | authorization_code+refresh  | openid,email,profile,groups,roles |   —     |   —     |
| `svc-integration-bus`  | client_credentials          | service:register                  |  n/a    |  n/a    |
| `dWqlfMOxNlth6wAqfUUJ3g` (Crossplane provisioner) | client_credentials | admin:oauth-clients |  n/a    |  n/a    |

Verified receivers exist on the RP side:

- Talon `/auth/backchannel-logout` POST + `/auth/frontchannel-logout` GET — `talon !30` + `feat/tier1-frontchannel-logout-receiver`.
- Accounts BFF `/api/auth/backchannel-logout` + `/api/auth/frontchannel-logout` — `frontend !17`.
- GitLab BCL shim — `gitlab-bcl-receiver.gitlab-bcl-receiver.svc.cluster.local:8080/backchannel-logout` (Go module at `platform-tools/bcl-receiver`; verified Running 2/2 in cluster). Translates `logout_token` POSTs into GitLab admin block-user API calls.
- Harbor BCL shim — `harbor-bcl-receiver.harbor-bcl-receiver.svc.cluster.local:8080/backchannel-logout` (same module, harbor cmd binary; Running 2/2). Translates into Harbor admin user-disable API calls.

So the OP-side emitter wiring is correct; the seed values for
`backchannel_logout_uri` / `frontchannel_logout_uri` /
`backchannel_logout_session_required` /
`frontchannel_logout_session_required` are simply absent from the DB.

## Root cause

`falcon-id-pg` fresh-initdb during the 2026-05-07 cluster recovery
event (per internal engineering notes) wiped
`iam_oauth_clients`. The recovery rebuilt the table via the
`bootstrapProvisionerOAuthClient` Go boot hook (FI!142 pattern) +
the per-service Crossplane provisioning chain, neither of which seeds
SLO URIs. The original seed was carried by SQL migrations 217 (BCL)
and 219 (FCL) authored alongside `falcon-id !61` /
`feat/tier1-oidc-id-token-sid-claim`; those migrations did not
re-execute against the fresh DB because the project moved to Keystone-
managed schema partway through the regression window and the per-
client UPDATE statements were not carried into the Keystone bundle.

## Spec implications (NIST SP 800-63B-4 §5.2 + OIDC BCL/FCL 1.0)

§5.2 of NIST 800-63B-4 mandates that session termination at one
authoritative point MUST propagate to all session bearers. With BCL
and FCL silenced, Sign Out at `accounts.hexxlock.com` leaves admin-
tier sessions at `internal.example.com` alive for up to Talon's 8h
`SessionHardTTL`, which is an audit gap on the privileged-tools
estate.

## Detection gap

`BackchannelLogoutService.NotifyLogout` and
`FrontchannelLogoutService.BuildIFrames` both return nil silently when
the client list is empty:

- `internal/services/backchannel_logout_service.go:183-185`
- `internal/services/frontchannel_logout_service.go:107-109`

Future regressions of the same shape would go undetected. The
Phase 0 hardening landing alongside this audit adds `iam_oauth_bcl_no_clients_total{tenant_id}`
and `iam_oauth_fcl_no_clients_total{tenant_id}` Prometheus counters
plus a structured WARN log on the empty-client path so the next
fresh-initdb leaves a visible signal.

## Closure path (multi-MR — see `docs/audits/2026-05-10-slo-restoration-plan.md`)

1. **Phase 0** (this MR): audit doc + WARN logging + Prometheus counters.
2. **Phase 1** (this MR): `bootstrapOAuthClientSLOSeed` Go boot hook restores BCL/FCL URIs + session_required for `svc-talon` and `svc-accounts` (the only RPs with shipping receivers today).
3. **Phase 3** (this MR): NIST AAL2 / AAL1-2 TTL matrix applied to all 12 clients via the same boot hook.
4. **GAP B** (this MR): removes `BACKCHANNEL_LOGOUT_ENDPOINTS` static-endpoint env-var workaround (no longer required once Phase 1 lands DB seeds).
5. Subsequent MRs cover Phase 2 (transactional outbox + retry), Phase 4 (XServiceClient XRD plumbing), Phase 5 (RFC 7009 fan-out + edge metrics), Phase 6 (WORM audit + dashboards), and `GAP A` / `GAP C` per the master plan.
