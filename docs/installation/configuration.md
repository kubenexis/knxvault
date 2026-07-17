<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Configuration Reference

KNXVault accepts a YAML v3 base configuration file for daemon mode. By default, `knxvault serve` loads `/etc/knxvault.conf` when that file exists. Override the path with `-c` / `--config` on the root command (e.g. `knxvault -c /path/to/knxvault.conf serve`). Environment variables override file values — use the file for static settings and env/Secrets for credentials and per-pod overrides.

Running `./knxvault` without arguments prints usage. Start the server with `knxvault serve` (default file or env-only) or `knxvault -c config.yaml serve`.

See [`config/knxvault.example.yaml`](../../config/knxvault.example.yaml) for the file schema.

**Environment-only settings** (not in the YAML schema today): `KNXVAULT_MASTER_KEY`, `KNXVAULT_MASTER_KEY_FILE`, `KNXVAULT_UNSEAL_KEY`, `KNXVAULT_OIDC_DEFAULT_TTL`, `KNXVAULT_JOB_MASTER_KEY_REENCRYPT_INTERVAL`. Use environment variables or Kubernetes Secrets for these values.

## Core

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `KNXVAULT_HTTP_ADDR` | `:8200` | No | HTTP listen address |
| `KNXVAULT_LOG_LEVEL` | `info` | No | `debug`, `info`, `warn`, `error` |
| `KNXVAULT_VERSION` | `0.5.1` | No | Version string in metrics and health (build metadata when unset) |
| `KNXVAULT_SHUTDOWN_GRACE` | `10s` | No | Graceful shutdown timeout |

## Cryptography

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `KNXVAULT_MASTER_KEY` | — | **Yes** (prod) | Base64-encoded 32-byte master key |
| `KNXVAULT_MASTER_KEY_FILE` | — | Alt. to above | Path to base64 key file (takes priority) |
| `KNXVAULT_UNSEAL_KEY` | — | **Yes when Raft enabled** | Base64 unseal key for seal/unseal; **must differ from master key** when `KNXVAULT_RAFT_ENABLED=true` (startup fails if unset or equal). Not used for envelope encryption. |
| `KNXVAULT_UNSEAL_THRESHOLD` | `1` | No | Shamir threshold **t** (shares required to unseal). `1` = single full key; `t>1` requires `POST /sys/unseal` with successive `share` values. Offline split: `go run ./scripts/shamir-split`. Lab E2E uses `t=2` — [e2e-and-lab-tests.md](../engineering/e2e-and-lab-tests.md) |
| `KNXVAULT_JOB_MASTER_KEY_REENCRYPT_INTERVAL` | `1m` | No | Leader job interval for DEK re-encryption after rotation |
| _(PKI)_ | native only | — | Issuance always uses Go `crypto/x509`. `KNXVAULT_PKI_BACKEND` / `KNXVAULT_OPENSSL_*` are rejected if set to OpenSSL values. |

## Authentication

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `KNXVAULT_ROOT_TOKEN` | — | Bootstrap | Initial admin token |
| `KNXVAULT_JWT_SECRET` | — | Dev K8s auth | HS256 secret for local ServiceAccount JWT login (dev only; not used when TokenReview is available) |
| `KNXVAULT_K8S_AUTH_INSECURE` | `false` | Dev only | When `KNXVAULT_RAFT_ENABLED=false`, parse JWT structure without signature verification (still requires a valid `sub` service-account claim; never enable in production) |
| `KNXVAULT_TOKEN_TTL` | `24h` | No | Issued client token lifetime |

## Dragonboat Raft (production storage)

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `KNXVAULT_RAFT_ENABLED` | `false` | Prod: **Yes** | Enable Dragonboat backend |
| `KNXVAULT_RAFT_NODE_ID` | — (see below) | **Yes** when enabled | Unique Raft node ID; must be **> 0** or startup fails with `KNXVAULT_RAFT_NODE_ID must be > 0 when raft is enabled` |
| `KNXVAULT_RAFT_ADDRESS` | `127.0.0.1:63001` | When enabled | Advertised Raft address |
| `KNXVAULT_RAFT_LISTEN_ADDRESS` | — | No | Bind address override |
| `KNXVAULT_RAFT_DATA_DIR` | `/var/lib/knxvault/raft` | When enabled | Pebble WAL + snapshot directory |
| `KNXVAULT_RAFT_INITIAL_MEMBERS` | — | New cluster | `id=host:port,...` peer map |
| `KNXVAULT_RAFT_JOIN` | `false` | No | Join existing cluster |
| `KNXVAULT_RAFT_ELECTION_RTT` | `10` | No | Election interval (RTT ticks) |
| `KNXVAULT_RAFT_HEARTBEAT_RTT` | `1` | No | Heartbeat interval (RTT ticks) |
| `KNXVAULT_RAFT_RTT_MILLISECOND` | `1` | No | Logical RTT milliseconds |
| `KNXVAULT_POD_NAME` | — | K8s | StatefulSet pod name (`knxvault-0` → node ID `1`) when `KNXVAULT_RAFT_NODE_ID` is unset |
| `KNXVAULT_RAFT_MTLS_CERT` | — | No | Raft peer TLS certificate (all three required together) |
| `KNXVAULT_RAFT_MTLS_KEY` | — | No | Raft peer TLS private key |
| `KNXVAULT_RAFT_MTLS_CA` | — | No | Raft peer CA bundle for mutual TLS |
| `KNXVAULT_RAFT_LEADER_WAIT` | `10s` | No | Max wait for a Raft leader during startup before failing |

**Node ID:** Assign a stable integer > 0 per replica (not randomly generated). Set `KNXVAULT_RAFT_NODE_ID` explicitly for bare-metal, Docker, and local dev. On Kubernetes, omit it and let the StatefulSet derive from `KNXVAULT_POD_NAME` (`knxvault-0` → `1`). The ID must match the left-hand key in `KNXVAULT_RAFT_INITIAL_MEMBERS`.

See [Raft node IDs — how to choose and assign](../storage/dragonboat.md#raft-node-ids--how-to-choose-and-assign) for planning tables and examples.

## Background jobs

Jobs run on the **Raft leader** when Raft is enabled.

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_JOB_LEASE_CLEANUP_INTERVAL` | `1m` | Expired lease cleanup |
| `KNXVAULT_JOB_CRL_REFRESH_INTERVAL` | `15m` | CRL pre-generation |
| `KNXVAULT_JOB_CERT_RENEW_INTERVAL` | `1h` | Auto-renewal scan |
| `KNXVAULT_RENEW_GRACE` | `72h` | Renew certs expiring within window |

## Security hardening

| Variable | Default | Description |
|----------|---------|-------------|
| **`KNXVAULT_SECURITY_PROFILE`** | `lab` | **`lab`** (default) or **`production`**. Production is **fail-closed** at startup (M-PRODSEC-1 A1). YAML: `security.profile`. See [production security posture](../design/production-security-posture.md) and `config/knxvault.production.yaml`. |
| **`KNXVAULT_TLS_TERMINATION`** | `server` under production | `server` = process TLS via cert/key; `ingress` = edge TLS (process may listen plain HTTP). YAML: `security.tls_termination`. |
| `KNXVAULT_AUDIT_SIGNING_KEY` | — | HMAC key for audit export and per-entry signatures (**required** when profile=`production`) |
| `KNXVAULT_AUDIT_FORWARD_URL` | — | HTTP sink for async audit entry forwarding |
| `KNXVAULT_METRICS_BEARER_TOKEN` | — | Require `Authorization: Bearer` on `GET /metrics` (**required** when profile=`production`). YAML: `security.metrics_bearer_token`. |
| `KNXVAULT_METRICS_ADDR` | — | Dedicated metrics listen address (e.g. `:8201`). When set, `/metrics` is **not** on the API listener (W75-03). |
| `KNXVAULT_UNSEAL_ALLOW_CIDRS` | — | Comma-separated CIDRs/IPs allowed for `POST /sys/unseal` (W75-04). Empty = allow all (lab). |
| `KNXVAULT_AUTO_UNSEAL` | `false` | Enable auto-unseal on start (W63/P3). |
| `KNXVAULT_AUTO_UNSEAL_PROVIDER` | — | `aes-kek` (AES-256-GCM with injected KEK; cloud KMS supplies KEK via CSI). |
| `KNXVAULT_AUTO_UNSEAL_CIPHERTEXT` | — | Base64 sealed unseal key. |
| `KNXVAULT_AUTO_UNSEAL_KEK` / `_FILE` | — | Base64 32-byte KEK or file path. |
| `KNXVAULT_CORS_ALLOWED_ORIGINS` | — | Comma-separated origins for CORS (e.g. `https://app.example.com`) |
| `KNXVAULT_RATE_LIMIT_ENABLED` | `true` | Per-token/IP rate limiting (W52-05); **forced on** in production profile |
| `KNXVAULT_RATE_LIMIT_RPM` | `300` | Requests per minute per client |
| `KNXVAULT_VALKEY_CACHE_URL` | — | Valkey URL for KV cache + **cluster-shared** rate limit and auth lockout (W53). In **production**, if set must be `rediss://` / `valkeys://` or include credentials |
| `KNXVAULT_TENANT_MODE` | `false` | Tenant namespace scoping for KV + DB/SSH/PKI resources (W32-04 / W53) |
| `KNXVAULT_REQUEST_SIGNING_KEY` | — | HMAC key for `X-KNX-Signature` header |
| `KNXVAULT_REQUEST_SIGNING_REQUIRED` | `false` | Reject unsigned requests when true |
| `KNXVAULT_TLS_CERT` | — | HTTPS server certificate PEM path (**required** in production unless `TLS_TERMINATION=ingress`) |
| `KNXVAULT_TLS_KEY` | — | HTTPS server private key PEM path |
| `KNXVAULT_MTLS_REQUIRED` | `false` | Require client certificates on KV write routes (also enables peer certs for `POST /auth/cert`) |
| `KNXVAULT_MTLS_CA` | — | Client CA bundle when mTLS is enabled |
| `KNXVAULT_ROOT_TOKEN_TTL` | `72h` lab / **≤4h** production | Bootstrap root lifetime; production profile **caps at 4h** |
| `KNXVAULT_RAFT_ALLOW_INSECURE` | `false` | Lab-only: skip multi-node Raft mTLS and allow `k8s_auth_insecure`. **Rejected** when profile=`production` |
| `KNXVAULT_OIDC_DEFAULT_TTL` | `1h` | Default OIDC-issued client token TTL |
| `KNXVAULT_LDAP_URL` | — | Optional native LDAP URL (`ldap://` / `ldaps://`) for `POST /auth/ldap` (W70) |
| `KNXVAULT_LDAP_USER_DN_TEMPLATE` | — | DN template with `%s` username (e.g. `uid=%s,ou=people,dc=example,dc=com`) |
| `KNXVAULT_LDAP_DEFAULT_POLICIES` | — | Comma-separated policies after successful LDAP bind |
| `KNXVAULT_LDAP_INSECURE_SKIP_VERIFY` | `false` | Lab-only TLS skip for ldaps |
| `KNXVAULT_JOB_KV_ROTATION_INTERVAL` | `5m` | Leader job for scheduled KV rotation |
| `KNXVAULT_ROTATION_WEBHOOK_URL` | — | Webhook on successful KV rotation |
| `KNXVAULT_EXPOSURE_SIGNING_KEY` | — | HMAC key for `POST /sys/exposure/report` |
| `KNXVAULT_EXPOSURE_AUTO_REVOKE` | `false` | Auto-revoke leases / rotate KV on exposure report |
| `KNXVAULT_EXPOSURE_WEBHOOK_URL` | — | Webhook on exposure reports |

### Production profile (`KNXVAULT_SECURITY_PROFILE=production`)

Startup **fails** unless:

| Requirement | Notes |
|-------------|--------|
| No lab auth | No `KNXVAULT_JWT_SECRET`, no `k8s_auth_insecure`, no `RAFT_ALLOW_INSECURE` |
| Audit signing key | `KNXVAULT_AUDIT_SIGNING_KEY` |
| Metrics bearer | `KNXVAULT_METRICS_BEARER_TOKEN` |
| TLS | Server cert+key **or** `KNXVAULT_TLS_TERMINATION=ingress` |
| Rate limit / HTTPS clients / RBAC fail-closed | Forced or required on |
| Multi-node Raft | Peer mTLS cert/key/CA required |
| Root token TTL | Capped at **4h** |
| Valkey (optional) | TLS or credentials in URL |

Example file: [`config/knxvault.production.yaml`](../../config/knxvault.production.yaml). Design: [production security posture](../design/production-security-posture.md).

See [Tier 0 production features](../product/tier0-production.md) and [exposure detection](../integration/exposure-detection.md).

## Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_TRACING_ENABLED` | `false` | Enable OpenTelemetry HTTP tracing |
| `KNXVAULT_OTLP_ENDPOINT` | collector default | OTLP HTTP endpoint |
| `KNXVAULT_TRACING_SAMPLE_RATIO` | `0` (effective `1` when tracing enabled) | Trace sampling ratio (0–1) |

## Configuration profiles

### Development (in-memory)

```bash
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_ROOT_TOKEN=dev-root-token
# KNXVAULT_RAFT_ENABLED unset → in-memory
```

### Development (single-node Raft)

Requires `KNXVAULT_RAFT_NODE_ID` (and `KNXVAULT_MASTER_KEY`) — auto-derivation does not apply on a generic host:

```bash
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_UNSEAL_KEY=$(openssl rand -base64 32)   # required; must differ from master
export KNXVAULT_ROOT_TOKEN=dev-root-token
export KNXVAULT_RAFT_ENABLED=true
export KNXVAULT_RAFT_NODE_ID=1
export KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001
export KNXVAULT_RAFT_DATA_DIR=/tmp/knxvault-raft
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001
```

### Production (3-node Raft)

Set in ConfigMap / StatefulSet:

```yaml
KNXVAULT_RAFT_ENABLED: "true"
KNXVAULT_RAFT_DATA_DIR: "/var/lib/knxvault/raft"
KNXVAULT_RAFT_INITIAL_MEMBERS: "1=knxvault-0.knxvault-raft:63001,2=knxvault-1.knxvault-raft:63001,3=knxvault-2.knxvault-raft:63001"
# Node IDs: derived from KNXVAULT_POD_NAME in the StatefulSet (knxvault-0 → 1, etc.)
```

Secrets (never in ConfigMap) — see also [`deployments/k8s/secret.yaml`](../../deployments/k8s/secret.yaml):

```yaml
KNXVAULT_MASTER_KEY: "<base64-32-bytes>"
KNXVAULT_UNSEAL_KEY: "<base64-32-bytes-distinct-from-master>"  # required with Raft
KNXVAULT_ROOT_TOKEN: "<bootstrap-token>"
KNXVAULT_AUDIT_SIGNING_KEY: "<audit-hmac>"
```

Kubernetes auth uses in-cluster **TokenReview** automatically — do not set `KNXVAULT_JWT_SECRET` or `KNXVAULT_K8S_AUTH_INSECURE` in production.

## Operator security notes

| Variable | Guidance |
|----------|----------|
| `KNXVAULT_MASTER_KEY` | Never commit to git; use K8s Secret or KMS |
| `KNXVAULT_UNSEAL_KEY` | **Required when Raft is enabled**; generate separately from master; same custody as master; not for envelope encryption |
| `KNXVAULT_ROOT_TOKEN` | Rotate after bootstrap; replace with scoped tokens |
| `KNXVAULT_JWT_SECRET` | Dev-only HS256 K8s auth; production uses in-cluster TokenReview |
| `KNXVAULT_K8S_AUTH_INSECURE` | Never enable when Raft/production is on |
| `KNXVAULT_AUDIT_SIGNING_KEY` | Enable in production for tamper-evident audit export |

Do not store database admin passwords in database role `config` — use KV paths. See [Operator security](../operations/operator-security.md).

## knxvault-operator (TLS CRD automation)

Environment for the **separate** `knxvault-operator` process (not the vault server). Full guide: [Replace cert-manager](../operations/pki-replace-cert-manager.md).

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_ADDR` | — | Vault API base URL |
| `KNXVAULT_TOKEN` / `KNXVAULT_TOKEN_FILE` | — | Bootstrap / lab token (prefer SA auth in cluster) |
| `KNXVAULT_K8S_ROLE` | `knxvault-operator` | Role for ServiceAccount JWT login |
| `KNXVAULT_SA_TOKEN_FILE` | in-cluster path | Path to projected SA token |
| `KNXVAULT_OPERATOR_LEADER_ELECT` | `true` | Single-writer HA for controllers |
| `KNXVAULT_OPERATOR_LEADER_ELECT_NAMESPACE` | `knxvault` | Lease namespace |
| `KNXVAULT_OPERATOR_INGRESS_SHIM` | `false` | Create Certificate CRs from Ingress annotations |
| Metrics / probe bind | `:8080` / `:8081` | Prometheus + healthz |

AppRole credentials for **cert-manager** (server-side) are registered via admin API `POST /sys/auth/approle`, not env vars.

## Legacy Kubernetes Lease HA (non-Raft)

When `KNXVAULT_RAFT_ENABLED=false`, optional background-job leader election uses a Kubernetes `coordination.k8s.io/v1` Lease:

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_HA_ENABLED` | `false` | Enable K8s Lease elector for background jobs |
| `KNXVAULT_HA_NAMESPACE` | `knxvault` | Lease namespace |
| `KNXVAULT_HA_LEASE_NAME` | `knxvault-leader` | Lease object name |
| `KNXVAULT_HA_IDENTITY` | pod hostname | Holder identity (defaults to `KNXVAULT_POD_NAME`) |

Production HA should use **Dragonboat Raft** (`KNXVAULT_RAFT_ENABLED=true`) instead of Lease-only mode. Lease HA does not replicate vault data.

## Related documents

- [Operator security](../operations/operator-security.md)
- [Replace cert-manager](../operations/pki-replace-cert-manager.md)
- [cert-manager Vault profile](../recipes/cert-manager-integration.md)
- [Kubernetes deployment](../deploy/kubernetes.md)
- [Metrics](../metrics.md)
- [Tracing](../observability/tracing.md)