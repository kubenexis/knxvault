<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Getting Started

A hands-on introduction to KNXVault secrets, PKI, access control, **Transit**, **wrapping**, and **leases**.

## Prerequisites

A running KNXVault instance. See [Installation guide](../installation/install.md).

**Production topology (Distributed Trust Platform):** high-assurance installs use **base only** (core secrets + private PKI). CSI, External Secrets, webhooks, and public OIDC/ACME are **add-ons** on platform/public-edge instances — see [base Day-0/Day-1](../operations/base-day0-day1.md) and [platform-edge Day-0/Day-1](../operations/platform-edge-day0-day1.md). Product rules: [`AGENTS.md`](../../AGENTS.md).

```bash
export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=dev-root-token   # bootstrap token
```

## 0. Verify the deployment

Before writing secrets, confirm the server is healthy. Prefer `doctor` as the single gate used in lab and production smoke tests.

```bash
./build/bin/knxvault-cli health          # liveness → status healthy
./build/bin/knxvault-cli status          # readiness → status ready
./build/bin/knxvault-cli doctor --json   # full report
```

Expect `"healthy": true` and `"fail": 0`. Common checks:

| Check | Meaning |
|-------|---------|
| `server.health` / `server.readiness` | API is up and accepting traffic |
| `server.sealed` | Vault is unsealed (writes allowed) |
| `server.raft` | Raft ready when HA/persistent Raft is enabled |
| `auth.token` | Your token is valid |
| `cli.config.tls` **warn** | API is plain HTTP — expected in local lab; use HTTPS in production |

HTTP equivalents:

```bash
curl -s "$KNXVAULT_ADDR/health"
curl -s "$KNXVAULT_ADDR/ready"
# With Raft, expect sealed:false, raft_ready:true, and leader:true on the leader node
```

## Core concepts

| Concept | Description |
|---------|-------------|
| **Secrets engine** | Backend for secret types (KVv2, database, SSH, cubbyhole, Transit) |
| **Path** | Hierarchical identifier (e.g. `app/database/password`) |
| **Policy** | RBAC document granting capabilities on path prefixes |
| **Token** | Opaque credential presented as `Authorization: Bearer` |
| **Lease** | Time-bounded dynamic credential; unified renew/revoke/tidy under `/sys/leases` |
| **Cubbyhole** | Per-token private KV; wiped on token revoke |
| **Wrapping** | Single-use token that carries a secret payload once |
| **Transit** | Encryption-as-a-Service (encrypt/decrypt/sign without storing app data) |
| **CA hierarchy** | Root → intermediate → leaf certificate chain |

More recipes: [response wrapping](../recipes/response-wrapping.md), [Transit](../recipes/transit-eaas.md), [leases](../operations/lease-management.md), [secret sync](../integration/secret-sync.md).

## 1. Authenticate

```bash
curl -s -X POST $KNXVAULT_ADDR/auth/token \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$KNXVAULT_TOKEN\"}"
```

Or:

```bash
./build/bin/knxvault-cli auth login --token "$KNXVAULT_TOKEN"
```

Kubernetes workloads use `POST /auth/kubernetes` with a ServiceAccount JWT. In-cluster **TokenReview** is used automatically in production. `KNXVAULT_JWT_SECRET` is for local dev only.

## 2. Store and read a secret

**CLI:**

```bash
./build/bin/knxvault-cli kv put app/db password=s3cret host=db.internal

# Default: secret values are redacted (safe for terminals and logs)
./build/bin/knxvault-cli kv get app/db
# stdout → "password": "[REDACTED]"
# stderr → note: secret values redacted; use --show-secrets to reveal

# Reveal plaintext only when you need it
./build/bin/knxvault-cli kv get app/db --show-secrets
# → "password": "s3cret"
```

> **CLI redaction:** `kv get` without `--show-secrets` returns `[REDACTED]` for values and prints a one-line **stderr** hint. This is intentional. Use `--show-secrets` for automation that needs real values; avoid piping that output into shared logs. The HTTP API still returns plaintext (protect the channel).

**API:**

```bash
# Write
curl -s -X POST $KNXVAULT_ADDR/secrets/kv/app/db \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"password":"s3cret"},"options":{"ttl":"24h"}}'

# Read latest version (API returns plaintext data; protect the response channel)
curl -s $KNXVAULT_ADDR/secrets/kv/app/db \
  -H "Authorization: Bearer $KNXVAULT_TOKEN"
```

KVv2 supports versioning, TTL expiration, and check-and-set via the `options` block.

## 3. Create a PKI hierarchy

The **issue role** is usually the **CA name** you created (for example `dev-root` or an intermediate). Optional persisted PKI roles can map a role name to a different CA.

### Dev: root → leaf

```bash
# Root CA (self-signed trust anchor)
curl -s -X POST $KNXVAULT_ADDR/pki/root \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"dev-root","common_name":"KNXVault Root CA","ttl":"8760h"}'

# Issue a leaf certificate — role is the CA name
curl -s -X POST $KNXVAULT_ADDR/pki/issue \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "role": "dev-root",
    "common_name": "api.example.com",
    "dns_names": ["api.example.com"],
    "ttl": "720h",
    "auto_renew": true
  }'
```

CLI equivalent:

```bash
./build/bin/knxvault-cli pki root --name dev-root --common-name "KNXVault Root CA" --ttl 8760h
./build/bin/knxvault-cli pki issue --role dev-root --common-name api.example.com --dns api.example.com --ttl 720h
```

### Production-shaped: root → intermediate → leaf

```bash
# Long-lived root (sign intermediates only)
curl -s -X POST $KNXVAULT_ADDR/pki/root \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"prod-root","common_name":"Prod Root CA","ttl":"87600h"}'

# Operational intermediate
curl -s -X POST $KNXVAULT_ADDR/pki/intermediate \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "prod-intermediate",
    "parent_name": "prod-root",
    "common_name": "Prod Intermediate CA",
    "ttl": "43800h"
  }'

# Leaves signed by the intermediate
curl -s -X POST $KNXVAULT_ADDR/pki/issue \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "role": "prod-intermediate",
    "common_name": "api.example.com",
    "dns_names": ["api.example.com"],
    "ttl": "720h",
    "auto_renew": true
  }'
```

Set `"auto_renew": true` to track the certificate for background renewal by the Raft leader.

### Kubernetes TLS (preferred — no cert-manager)

Use **knxvault-operator** multi-issuer CRDs so workloads get `kubernetes.io/tls` Secrets **without cert-manager**:

```bash
kubectl apply -f deployments/operator/crds/
# Private CA path
kubectl apply -f deployments/operator/samples/certificate-example.yaml
# Or self-signed lab certs
kubectl apply -f deployments/operator/samples/selfsigned-certificate.yaml
# ACME / Let's Encrypt:
#   K8s: operator samples — deployments/operator/samples/acme-clusterissuer-example.yaml
#   Standalone/host: knxvault-cli acme --config examples/acme/edge-staging.yaml
#   Design: docs/design/acme-letsencrypt-unified.md
```

Guides: [Replace cert-manager](../operations/pki-replace-cert-manager.md), [support matrix](../operations/certificate-support-matrix.md).

Detailed recipes (trust bundles, CRL/OCSP): [PKI administration](../operations/pki-administration.md).

## 4. Define access control

```bash
# Policy: read-only access to app secrets
curl -s -X PUT $KNXVAULT_ADDR/sys/policies/app-reader \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "paths": {
      "secrets/kv/app/*": {"capabilities": ["read"]},
      "inject/render": {"capabilities": ["read"]}
    }
  }'

# Role binding
curl -s -X PUT $KNXVAULT_ADDR/sys/roles/app-sa \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "policies": ["app-reader"],
    "bound_service_account_names": ["my-app"],
    "bound_service_account_namespaces": ["production"]
  }'
```

Check effective capabilities:

```bash
curl -s $KNXVAULT_ADDR/sys/capabilities \
  -H "Authorization: Bearer $KNXVAULT_TOKEN"
```

## 5. Dynamic database credentials

KNXVault generates credentials and SQL statements; **your tooling runs the SQL** using admin credentials stored outside the role (typically in KV). See [Database credentials guide](../deploy/database-credentials.md).

```bash
# Store admin DB credentials in KV (encrypted before Raft)
curl -s -X POST $KNXVAULT_ADDR/secrets/kv/database/admin/prod-db \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"username":"vault_admin","password":"admin-pass","host":"db.internal"}}'

# Configure role (no credentials in config)
curl -s -X PUT $KNXVAULT_ADDR/secrets/database/roles/readonly \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "ttl_seconds": 3600,
    "username_prefix": "v-",
    "admin_credentials_path": "database/admin/prod-db",
    "creation_statements": ["CREATE USER '\''{{username}}'\''@'\''%'\'' IDENTIFIED BY '\''{{password}}'\'';"],
    "config": {"db_type": "mysql"}
  }'

# Generate ephemeral credentials + SQL statements
curl -s -X POST $KNXVAULT_ADDR/secrets/database/creds/readonly \
  -H "Authorization: Bearer $KNXVAULT_TOKEN"
```

Renew with `POST /secrets/database/renew/:lease_id`; revoke with `PUT /secrets/database/revoke/:lease_id`.

## 6. Inject secrets into pods

Use `POST /inject/render` from an init container or sidecar. See [Secrets injection](../deploy/secrets-injection.md).

## Next steps

- [Dummies guide](dummies-guide.md) — concepts, Kubernetes use cases, and security overview
- [Operator runbook (Day-0 + Day-2)](../operations/operator-runbook.md) — bring-up from empty cluster through first cert/secret, then ongoing ops
- [Installation guide](../installation/install.md) — local, Docker, Kubernetes; Raft unseal requirements
- [Replace cert-manager](../operations/pki-replace-cert-manager.md) — operator CRDs for TLS Secrets
- [cert-manager Vault profile](../recipes/cert-manager-integration.md) — optional legacy path
- [Recipes index](../recipes/README.md) — step-by-step guides for production tasks
- [CLI reference](../cli/reference.md)
- [API reference](../api/reference.md)
- [Integration overview](../integration/overview.md)
- [PKI administration](../operations/pki-administration.md)
- [Day-2 operations](../operations/day2.md)
