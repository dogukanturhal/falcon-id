# Cosign supply-chain keys

This directory holds the **public** half of the cosign keypair used by the
hexxlock/platform CI pipeline to sign every container image and SLSA
provenance attestation.

## Files

| File         | Purpose                                                            |
| ------------ | ------------------------------------------------------------------ |
| `cosign.pub` | Public verification key. Safe to commit. Used by `cosign verify`,  |
|              | by the Kyverno admission policy in `deploy/kyverno/`, and by any   |
|              | downstream consumer that wants to attest provenance.               |

## Where the private key lives

The matching private key is **not** in this repo. It is stored as a
GitLab project-level CI variable on `hexxlock/platform`:

| Variable               | Type   | Protected | Masked | Notes                                        |
| ---------------------- | ------ | --------- | ------ | -------------------------------------------- |
| `COSIGN_PRIVATE_KEY`   | file   | yes       | n/a    | Multiline PEM, GitLab writes it to a temp    |
|                        |        |           |        | file at job time. The variable's value at    |
|                        |        |           |        | runtime is the *path* to that file.          |
| `COSIGN_PASSWORD`      | env    | yes       | yes    | Decryption password for the private key.    |

`protected: true` means GitLab only injects these variables on jobs that
run on a protected branch (`master`). Merge-request pipelines therefore
**do not** see the key, and the `.sign-service` template treats the key
as optional on MRs (soft) and mandatory on master (hard) — the difference
is enforced via `rules:` + `allow_failure:` in `.gitlab-ci.yml`.

## Rotation

1. On a workstation that has `cosign` installed:
   ```sh
   COSIGN_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)"
   cosign generate-key-pair
   ```
2. Replace `cosign.pub` in this directory with the new public key and
   commit it on a feature branch (do **not** rotate without an MR — every
   image already in the registry was signed with the old key).
3. Update `COSIGN_PRIVATE_KEY` (file) and `COSIGN_PASSWORD` (env) in
   GitLab CI variables for the platform project.
4. Rebuild and re-sign all currently deployed images so the new key is
   the only valid signature; only then revoke the old key.

## Migration to Vault (TODO)

Long-term the private key + password should live in Vault under
`secret/example/platform/ci/cosign/{key,password}` and be pulled at job
time via the `.vault-auth` template. This requires the `gitlab-platform`
JWT auth role to be configured on `vault.example.com` first; until that
is done, GitLab CI variables are the canonical source of truth.
