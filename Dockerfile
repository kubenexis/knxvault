# syntax=docker/dockerfile:1
# Multi-stage hardened image. Runtime stage uses debian:bookworm-slim for OpenSSL.
# For distroless (no shell), swap the runtime stage with:
#   FROM gcr.io/distroless/static-debian12:nonroot
# and copy only the static knxvault binary (PKI/OpenSSL exec requires a shell stage today).

FROM golang:1.26-bookworm AS builder

ARG VERSION=0.4.5
ARG COMMIT=unknown
ARG BUILD_ID=0

ENV GOTOOLCHAIN=go1.26.4
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN ldflags="-s -w \
    -X github.com/kubenexis/knxvault/internal/version.Version=${VERSION} \
    -X github.com/kubenexis/knxvault/internal/version.Commit=${COMMIT} \
    -X github.com/kubenexis/knxvault/internal/version.BuildID=${BUILD_ID}" \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="${ldflags}" -o /out/knxvault ./cmd/knxvault \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="${ldflags}" -o /out/knxvault-csi ./cmd/knxvault-csi \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="${ldflags}" -o /out/knxvault-webhook ./cmd/knxvault-webhook \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="${ldflags}" -o /out/knxvault-eso ./cmd/knxvault-eso

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 65532 -g nogroup knxvault

COPY --from=builder /out/knxvault /usr/local/bin/knxvault
COPY --from=builder /out/knxvault-csi /usr/local/bin/knxvault-csi
COPY --from=builder /out/knxvault-webhook /usr/local/bin/knxvault-webhook
COPY --from=builder /out/knxvault-eso /usr/local/bin/knxvault-eso

USER 65532:65532
EXPOSE 8200

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/knxvault", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/knxvault"]
CMD ["serve"]