# syntax=docker/dockerfile:1
# =============================================================================
# KNXVault — production container image (only supported path)
#
# Runtime: gcr.io/distroless/static-debian13:nonroot (Debian 13 / Trixie)
# Builder: golang:1.26-bookworm (static CGO_ENABLED=0 binaries)
#
# Policy: knxvault is ALWAYS built as this distroless image. There is no
# bookworm-slim/OpenSSL runtime. PKI is always in-process Go crypto/x509
# (OpenSSL CLI backend removed from the product).
# =============================================================================

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

# Debian 13–based distroless (static, nonroot uid 65532). No shell, no openssl.
FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=builder /out/knxvault /usr/local/bin/knxvault
COPY --from=builder /out/knxvault-csi /usr/local/bin/knxvault-csi
COPY --from=builder /out/knxvault-webhook /usr/local/bin/knxvault-webhook
COPY --from=builder /out/knxvault-eso /usr/local/bin/knxvault-eso

# PKI is always in-process Go crypto/x509 (no openssl binary in the image).

EXPOSE 8200

# Exec-form healthcheck (no shell in distroless).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/knxvault", "-healthcheck"]

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/knxvault"]
CMD ["serve"]
