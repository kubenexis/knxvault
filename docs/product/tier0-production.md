<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Tier 0 production features (W37 / W38-14 / W39-05)

This document describes production-hardening features shipped in v0.4.4+.

## W37-01 — Server TLS and mTLS

| Variable | Description |
|----------|-------------|
| `KNXVAULT_TLS_CERT` | Server certificate PEM path |
| `KNXVAULT_TLS_KEY` | Server private key PEM path |
| `KNXVAULT_MTLS_REQUIRED` | Require client certificates |
| `KNXVAULT_MTLS_CA` | Client CA bundle for mTLS |

When mTLS is enabled, `POST /secrets/kv/*` write routes require a valid client certificate.

YAML (`security:` block in `config/knxvault.example.yaml`):

```yaml
security:
  tls_cert: /etc/knxvault/tls/server.pem
  tls_key: /etc/knxvault/tls/server.key
  mtls_required: true
  mtls_ca: /etc/knxvault/tls/client-ca.pem
```

## W37-02 — OIDC/JWT auth

`POST /auth/oidc/:role` exchanges an OIDC JWT for a short-lived client token.

Configure per-role OIDC settings on the RBAC role (`auth_method: oidc`, `oidc` block) via `PUT /sys/roles/:name`.

| Role field | Description |
|------------|-------------|
| `auth_method` | `oidc` |
| `oidc.issuer` | Expected JWT `iss` |
| `oidc.audience` | Expected JWT `aud` |
| `oidc.jwks_url` | JWKS endpoint |
| `oidc.max_ttl_seconds` | Cap on issued token TTL |

Global default TTL: `KNXVAULT_OIDC_DEFAULT_TTL` (default `1h`).

## W37-03 — Machine identity registry (NHI)

Non-human identities are recorded on K8s and OIDC login:

- `GET /sys/machine-identities` — list identities
- `DELETE /sys/machine-identities/:id` — revoke (blocks future logins)

Audit action: `nhi.login`, `nhi.revoke`.

## W37-05 — Scheduled KV rotation

| API | Description |
|-----|-------------|
| `PUT /sys/kv-rotation` | Enable rotation policy (`path` in JSON body) |
| `DELETE /sys/kv-rotation?path=` | Disable rotation |

Leader job interval: `KNXVAULT_JOB_KV_ROTATION_INTERVAL` (default `5m`).

Generators: `random_password` (shipped), `script_ref` (deferred).

Webhook on rotation: `KNXVAULT_ROTATION_WEBHOOK_URL`.

## W37-07 — Exposure hooks

See [exposure detection integration](../integration/exposure-detection.md).

## W38-14 — Raft peer mTLS

| Variable | Description |
|----------|-------------|
| `KNXVAULT_RAFT_MTLS_CERT` | Raft node certificate |
| `KNXVAULT_RAFT_MTLS_KEY` | Raft node key |
| `KNXVAULT_RAFT_MTLS_CA` | Raft peer CA |

All three are required together. Metric: `knxvault_raft_tls_enabled`.

## W39-05 — CSI rotation

CSI provider detects KV version changes on remount. Metric: `knxvault_csi_mount_rotations_total`.

Enable upstream driver rotation (`enableSecretRotation=true`) and configure poll interval on `SecretProviderClass` — see `deployments/csi/secretproviderclass-example.yaml`.