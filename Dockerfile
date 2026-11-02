# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.27-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git ca-certificates

# Module files first, for layer caching. third_party/ holds a vendored
# module that go.mod points at with a local replace directive, so it has to
# be present before `go mod download`.
COPY go.mod go.sum ./
COPY third_party/ ./third_party/
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked go mod download

COPY . .

# The main service plus the small operator CLIs under cmd/.
ENV GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o falcon-id ./cmd/ \
 && go build -o resetpw            ./cmd/resetpw \
 && go build -o migrate-spicedb    ./cmd/migrate-spicedb \
 && go build -o verify-spicedb     ./cmd/verify-spicedb \
 && go build -o backfill-spicedb   ./cmd/backfill-spicedb \
 && go build -o migrate-user-realm ./cmd/migrate-user-realm \
 && go build -o schema-writer      ./schema

# Final stage
FROM alpine:3.24 AS production

WORKDIR /app
RUN apk upgrade --no-cache \
    && apk --no-cache add ca-certificates tzdata curl \
    && addgroup -g 1000 appuser \
    && adduser -D -u 1000 -G appuser appuser

COPY --from=builder --chown=appuser:appuser --chmod=555 /app/falcon-id /app/resetpw /app/migrate-spicedb /app/verify-spicedb /app/backfill-spicedb /app/migrate-user-realm /app/schema-writer ./

# OPA policies are read from disk at start-up; the SpiceDB schema file is the
# default input of schema-writer. `chmod a+rX` keeps directories traversable
# without making the files executable.
COPY --from=builder --chown=appuser:appuser /app/policies ./policies
COPY --from=builder --chown=appuser:appuser /app/schema ./schema
COPY --from=builder --chown=appuser:appuser /app/deploy/helm/spicedb-schema/files/spicedb.zed ./deploy/helm/spicedb-schema/files/spicedb.zed
RUN chmod -R a+rX /app/policies /app/schema /app/deploy

USER 1000
EXPOSE 8010

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl --silent --fail --max-time 5 http://localhost:8010/health || exit 1

CMD ["./falcon-id"]
