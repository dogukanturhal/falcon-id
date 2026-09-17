# falcon-id Follow-Up Items

Tracked items that are deferred from the current repo-split work and need follow-up action.

---

## 1. ESO: Use `vault.example.com` instead of in-cluster Vault address

**Current state:** ESO `SecretStore` references `vault-ha.vault.svc.cluster.local` (in-cluster HA Vault).

**Required change:** Switch to `vault.example.com` (external Vault ingress) so that:
- ESO continues to work when falcon-id moves to a second cluster or a second DC.
- Per-cluster vault-bunker scaling is not disrupted by the ESO config being baked to a single cluster's DNS.

**Phase:** Phase 3 (multi-cluster readiness).

**Reference:** Platform architecture decision — single cluster today, multi-DC/multi-cluster from day one for forward scalability.

---

## 2. `harbor-falcon-id-creds` Secret: Migrate to ESO management

**Current state:** The `harbor-falcon-id-creds` pull-secret is provisioned manually or via a one-off job and is not lifecycle-managed by External Secrets Operator.

**Blocker:** ESO needs a Vault root/approle token scoped to the in-cluster Vault (vault-ha) to read the Harbor robot credentials path.

**Required change:**
1. Add a Vault AppRole or scoped token for ESO in the falcon-id namespace.
2. Create a `SecretStore` + `ExternalSecret` targeting `harbor-falcon-id-creds`.
3. Remove any manual provisioning steps from the runbook.

---

## 3. Platform monorepo cleanup

After falcon-id is stable in its standalone repo, the following should be removed from `hexxlock/platform`:

- `falcon-id/` — source code directory (now lives in standalone repo).
- `deploy/helm/falcon-id/` — Helm chart (now lives in `hexxlock/falcon-id`).
- CI jobs referencing `falcon-id` in `platform/.gitlab-ci.yml`.

**Risk:** Do NOT remove until the standalone pipeline has proven stable in production (at least one full sign+deploy cycle through registry.example.com/falcon-id).

---

## 4. Platform MR !22: HARBOR_REGISTRY change for other services

Platform MR !22 changed `HARBOR_REGISTRY` to the in-cluster registry address. This change needs to be reviewed and applied consistently for all other services that still reference the old external harbor address.

**Action:** Review each service's CI variables and Helm chart image references after MR !22 is merged.

---

## 5. HPA metrics: Verify metrics-server is scraping falcon-id pods

**Symptom:** HPA may not be scaling falcon-id pods if metrics-server cannot reach them (e.g. missing ServiceMonitor or network policy blocking scrape path).

**Required checks:**
1. Confirm `kubectl top pods -n hexxlock-prod` returns values for falcon-id pods.
2. Verify `ServiceMonitor` exists and has correct label selectors matching the Prometheus operator config.
3. Check NetworkPolicy in the `hexxlock-prod` namespace does not block metrics-server scrape port (TCP 8080 / metrics endpoint).
4. If HPA targets custom metrics (RPS), confirm Prometheus adapter is configured with the correct `metricsQuery` for falcon-id.
