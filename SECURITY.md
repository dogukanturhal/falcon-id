# Security policy

Falcon ID issues tokens and holds credential material for the tenants that use
it. Please report vulnerabilities privately.

## Reporting a vulnerability

Use GitHub private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**
(<https://github.com/dogukanturhal/falcon-id/security/advisories/new>).

If you cannot use GitHub, email **dogukanturhal@hexxlock.com**. Do not post
details in a public issue, discussion or chat.

Please include:

- What the issue is and which version or commit is affected.
- A way to reproduce it: the requests, the client and tenant configuration,
  what you saw and what you expected.
- Who can trigger it (anonymous, an authenticated user, a tenant admin) and
  what they gain.
- Whether you want to be credited.

We acknowledge reports within two business days.

## Disclosure

We follow a 90-day coordinated disclosure window from acknowledgement.

| Day | What happens |
|---|---|
| 0 | Report acknowledged, triage starts. |
| 0-7 | Severity assessed (CVSS v3.1); a CVE is requested if it applies. |
| 7-60 | Fix developed and reviewed privately. |
| ~90 | Patched release and advisory published together. |

A simple fix ships sooner. If a fix needs a behaviour change we may agree a
longer window with you, never without telling you. If the issue is being
exploited we release immediately. Reporters are credited unless they ask not
to be. There is no bug bounty.

## Supported versions

Falcon ID has no tagged release yet. Until there is one, only the `main`
branch receives security fixes. After the first release, only the latest minor
version will.

## Scope

In scope: the service and the CLIs in this repository, the token, session,
MFA, SAML, SCIM and authorization code paths, the default configuration, the
container image and release artifacts (checksums, SBOM, signatures).

Out of scope: vulnerabilities in PostgreSQL, Redis, SpiceDB or other
dependencies (report those upstream; tell us if Falcon ID's use of them makes
it worse), findings that need an already-compromised database or signing key,
and the known gaps listed under "Status and limitations" in the README (for
example DPoP key binding on refresh tokens). Those are tracked openly and a
report about them is welcome as an ordinary issue.

## Verifying releases

Release assets carry a checksum file signed with cosign keyless signing, and
an SBOM. Container images are signed and have a build provenance attestation.
Dependencies are watched by Dependabot and CodeQL, and `govulncheck` runs on
every pull request.
