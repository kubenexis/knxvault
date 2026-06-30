# syntax=docker/dockerfile:1
# Multi-stage hardened image. Runtime stage uses debian:bookworm-slim for OpenSSL.
# For distroless (no shell), swap the runtime stage with:
#   FROM gcr.io/distroless/static-debian12:nonroot
# and copy only the static knxvault binary (PKI/OpenSSL exec requires a shell stage today).

FROM golang:1.25-bookworm AS builder

ENV GOTOOLCHAIN=go1.25.11
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/knxvault ./cmd/knxvault \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/knxvault-csi ./cmd/knxvault-csi \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/knxvault-webhook ./cmd/knxvault-webhook

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 65532 -g nogroup knxvault

COPY --from=builder /out/knxvault /usr/local/bin/knxvault
COPY --from=builder /out/knxvault-csi /usr/local/bin/knxvault-csi
COPY --from=builder /out/knxvault-webhook /usr/local/bin/knxvault-webhook

USER 65532:65532
EXPOSE 8200

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/knxvault", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/knxvault"]