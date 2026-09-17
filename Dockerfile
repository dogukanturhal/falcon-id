# Build stage
# Upgraded to Go 1.26-alpine (go1.26.2) — fixes all Go stdlib CVEs that require
# 1.25.9 (CVE-2026-32282/32289/27144/27143/32288/32283/27140/32281/32280) AND
# CVE-2026-33810 (crypto/x509 case-sensitive excludedSubtrees) which is only
# fixed in 1.26.2 and not backported to 1.25.x.
FROM mirror.gcr.io/library/golang:1.26.6-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates openssh-client

# SSH deploy key for fetching private GitLab modules.
# Passed as a build-arg; only lives in the builder stage (not the final image).
ARG GITLAB_DEPLOY_KEY=""
# SSH destination host override.
# github.com:22 is NOT reachable from pod egress (hairpin NAT through
# OPNsense back to the gitlab-ssh LoadBalancer doesn't work on our CNI). CI
# builds run inside the cluster as kaniko pods; they must route through the
# in-cluster gitlab-ssh service directly. Same fix landed in the .gitlab-ci.yml
# template (commit ae8e902). Local/dev docker builds use the default public
# FQDN. CI overrides via --build-arg GITLAB_SSH_HOST=gitlab-ssh.monitoring.svc.cluster.local
ARG GITLAB_SSH_HOST=github.com
# PRIVATE_MODULES_RO_PAT — canonical group-level RO PAT for fetching ANY
# private hexxlock Go module via HTTPS+netrc. Provisioned by infrastructure-iac
# as a `gitlab_group_variable` on group 6 (`hexxlock`), protected=false +
# masked=true, scopes read_api+read_repository. Use this first.
#
# KEYSTONE_RO_PAT — legacy keystone-scope-only fallback. Pre-dates the
# 7-repo cohort split. Cannot reach platform-shared / cohort repos.
# Kept as fallback for backward compat with any environment that still
# only ships the project-level keystone variable.
ARG PRIVATE_MODULES_RO_PAT=""
ARG KEYSTONE_RO_PAT=""
# Netrc login for HTTPS auth. `oauth2` is the canonical username for a
# personal/group access token. Override only when using a deploy token
# (`gldt-...`) that requires a different login.
ARG KEYSTONE_RO_USER="oauth2"

# The url rewrite maps github.com/dogukanturhal/ vanity paths to the actual GitLab SSH remote.

# GOPROXY plumbed in from CI as a build-arg so BuildKit's in-Dockerfile
# `go mod download` (line 85 below) hits the in-cluster Athens proxy
# instead of `proxy.golang.org`. Without this, Athens never sees the
# build-stage traffic and each `docker build` pays 5+ min fetching
# modules from the internet on the BuildKit pod's egress path.
#
# Default `direct` is the safe fallback: outside CI (local `docker
# build`), modules pull straight from origin like vanilla Go. CI
# overrides via `--opt build-arg:GOPROXY=http://athens.gomods-cache…`.
#
# Enterprise pattern: https://docs.docker.com/build/building/variables/
# (Docker docs — Build args) + gomods/athens Dockerfile precedent.
ARG GOPROXY=direct
ENV GOPROXY=$GOPROXY
RUN mkdir -p /root/.ssh \
    # Alpine 3.22 (via golang:1.26-alpine) bumped openssh-client to 10.x,
    # which now exits non-zero when ssh-keyscan returns no keys (DNS race,
    # TCP reset on first connect, etc.). Under kaniko that kills the whole
    # build. Use StrictHostKeyChecking=accept-new on first connection
    # instead — pins the host key on first git fetch, verifies on
    # subsequent ones, and never short-circuits the build on a transient
    # keyscan failure. Same fix landed in the CI .gitlab-ci.yml template
    # earlier (commits 8fd5d0f / ae8e902); the Dockerfile needed it too.
    && printf 'Host github.com\n  HostName %s\n  Port 22\n  StrictHostKeyChecking accept-new\n  UserKnownHostsFile /root/.ssh/known_hosts\n' "$GITLAB_SSH_HOST" > /root/.ssh/config \
    && chmod 600 /root/.ssh/config \
    && if [ -n "$GITLAB_DEPLOY_KEY" ]; then \
         echo "$GITLAB_DEPLOY_KEY" > /root/.ssh/id_ed25519 && chmod 600 /root/.ssh/id_ed25519; \
       fi \
    # Direct github.com modules (post-cohort-split — module path
    # matches repo path under hexxlock/platform-* + hexxlock/keystone +
    # hexxlock/falcon-id). Two auth paths, mirrored from .gitlab-ci.yml's
    # `.setup-private-modules` anchor:
    #
    #   1. Prefer PRIVATE_MODULES_RO_PAT (group-level RO PAT). It can read
    #      every private module under the hexxlock group, including
    #      platform-shared / cohort repos. Login is always `oauth2`.
    #
    #   2. Fall back to KEYSTONE_RO_PAT (legacy keystone-only project
    #      variable). Sufficient when go.mod only imports keystone; will
    #      404 the moment go.mod imports platform-shared or any cohort
    #      module — keep only for environments still on the old PAT.
    #
    #   3. Last resort: rewrite HTTPS to SCP-style SSH so the deploy key
    #      attempts to clone via the in-cluster gitlab-ssh service.
    && if [ -n "$PRIVATE_MODULES_RO_PAT" ]; then \
         { echo "machine github.com login oauth2 password ${PRIVATE_MODULES_RO_PAT}"; \
           echo "machine github.com login oauth2 password ${PRIVATE_MODULES_RO_PAT}"; } > /root/.netrc && chmod 600 /root/.netrc; \
       elif [ -n "$KEYSTONE_RO_PAT" ]; then \
         { echo "machine github.com login ${KEYSTONE_RO_USER:-oauth2} password ${KEYSTONE_RO_PAT}"; \
           echo "machine github.com login ${KEYSTONE_RO_USER:-oauth2} password ${KEYSTONE_RO_PAT}"; } > /root/.netrc && chmod 600 /root/.netrc; \
       else \
       fi

# Copy go mod files for layer caching
COPY --chown=root:root go.mod go.sum ./
# The vendored go-grpc-middleware (a local `replace` target — see
# third_party/go-grpc-middleware/go.mod) must be present BEFORE `go mod
# download` so the module graph resolves. It is tiny and frozen, so adding it
# to this layer does not meaningfully change go.mod-layer cache behaviour.
COPY --chown=root:root third_party/ ./third_party/
RUN go mod download

# Remove the deploy key before copying any source (defence in depth — the
# final production image is a separate stage so the key never reaches it,
# but cleaning up the builder intermediate layer is belt-and-suspenders).
RUN rm -f /root/.ssh/id_ed25519

# Copy all falcon-id source (sensitive files excluded via .dockerignore)
COPY --chown=root:root . .

# Build the main service binary AND the sibling CLIs that live under
# cmd/<name>/main.go (resetpw, migrate-spicedb, verify-spicedb,
# backfill-spicedb, migrate-user-realm). The operator runbooks reference
# these binaries for one-off data corrections (seeding the bootstrap
# admin user, fixing realm assignments per Sprint-1 #5, etc.); without
# building them alongside the main service, the kubectl-exec path is
# stat-not-found.  Building all CLIs alongside the main binary keeps
# them versioned in lock-step with the running service.
ENV GOTOOLCHAIN=auto
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o falcon-id ./cmd/ \
 && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o resetpw            ./cmd/resetpw \
 && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o migrate-spicedb    ./cmd/migrate-spicedb \
 && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o verify-spicedb     ./cmd/verify-spicedb \
 && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o backfill-spicedb   ./cmd/backfill-spicedb \
 && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o migrate-user-realm ./cmd/migrate-user-realm \
 && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o keystone-migration-gate ./cmd/keystone-migration-gate

# Final stage
FROM mirror.gcr.io/library/alpine:3.21 AS production

WORKDIR /app

# Upgrade all Alpine packages first (patches OS-level CVEs).
# Then add only what the service needs at runtime:
#   ca-certificates — TLS root CAs
#   tzdata          — timezone data for time.LoadLocation
#
# kubectl: pinned to v1.34.6 (compiled with Go 1.24.13) rather than v1.35.3
# (compiled with Go 1.25.7). The 1.25.7 toolchain carries CVE-2026-25679
# (HIGH — url.Parse host validation bypass, fixed in 1.25.8/1.26.1). There is
# no 1.35.x patch release built with Go ≥ 1.25.8 at this time. Go 1.24.x is
# unaffected by any of the Go 1.25.x/1.26.x stdlib CVE series.
# Resume 1.35.x when a build with Go ≥ 1.25.8 is published.
RUN apk upgrade --no-cache \
    && apk --no-cache add ca-certificates tzdata curl \
    && addgroup -g 1000 appuser \
    && adduser -D -u 1000 -G appuser appuser

COPY --from=builder --chown=appuser:appuser --chmod=555 /app/falcon-id          .
COPY --from=builder --chown=appuser:appuser --chmod=555 /app/resetpw            .
COPY --from=builder --chown=appuser:appuser --chmod=555 /app/migrate-spicedb    .
COPY --from=builder --chown=appuser:appuser --chmod=555 /app/verify-spicedb     .
COPY --from=builder --chown=appuser:appuser --chmod=555 /app/backfill-spicedb   .
COPY --from=builder --chown=appuser:appuser --chmod=555 /app/migrate-user-realm .
COPY --from=builder --chown=appuser:appuser --chmod=555 /app/keystone-migration-gate .

# Copy resource directories. Do NOT use --chmod=444 here: docker's COPY
# --chmod applies the same mode to directories as to files, so 0444 on
# a directory strips the +x (traversal) bit and breaks lstat/readdir on
# files inside it. That's how we got
#   lstat policies/abac_rules.rego: permission denied
# at OPA LoadPolicies time. Instead, chown+copy (inheriting safe dir
# perms from the builder stage) and then normalise permissions with
# `chmod -R a+rX` — capital X only sets +x on directories and on files
# that already have +x, so .rego/.sql/.zed files stay non-executable
# while directories stay traversable.
#
# Note that internal/templates/ contents are ALSO embedded into the
# Go binary via //go:embed directives, so the filesystem copy of
# those dirs is only relied on by the standalone CLIs
# (cmd/migrate-spicedb, cmd/verify-spicedb, cmd/resetpw). The main
# service reads from the embed.FS and is unaffected by on-disk
# permissions.
#
# Phase-2b MR4 (2026-05-04) deleted migrations/ from the source tree
# entirely — realm DB schema now comes from the Keystone-managed
# `falcon-id-tenant-desired` SchemaDefinition rather than embedded
# *.up.sql files. Dropped the corresponding `COPY .../migrations` +
# `chmod` lines that referenced the now-gone directory; kaniko was
# failing with `lstat /kaniko/0/app/migrations: no such file or
# directory` on master pipeline 4913.
COPY --from=builder --chown=appuser:appuser /app/policies ./policies
COPY --from=builder --chown=appuser:appuser /app/schema ./schema
RUN chmod -R a+rX /app/policies /app/schema

USER 1000

# SERVICE_PORT per .env.production.example and the main config is 8010.
# The old 8005 was a stale value from an earlier refactor.
EXPOSE 8010

# wget is not installed in this image (only curl is, from the apk add
# above). Switching the healthcheck to curl and matching the real
# service port.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl --silent --fail --max-time 5 http://localhost:8010/health || exit 1

CMD ["./falcon-id"]
