<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# API Reference

KNXVault exposes a REST API on port **8200** (configurable via `KNXVAULT_HTTP_ADDR` or `http_addr` in the config file).

## Interactive documentation

| Resource | URL |
|----------|-----|
| Swagger UI | `http://<host>:8200/swagger` |
| OpenAPI 3.1 spec | `http://<host>:8200/openapi.yaml` |
| Source spec | [`api/openapi.yaml`](../../api/openapi.yaml) |

## Authentication

Secured endpoints require:

```
Authorization: Bearer <token>
```

Optional request signing (when `KNXVAULT_REQUEST_SIGNING_REQUIRED=true`):

```
X-KNX-Timestamp: <RFC3339>
X-KNX-Signature: <HMAC-SHA256 of method+path+body+timestamp>
```

When the vault is **sealed**, mutating secured routes return `503`; reads and `POST /sys/unseal` remain available.

## Response envelope

Successful responses:

```json
{
  "data": { ... },
  "request_id": "uuid"
}
```

Errors:

```json
{
  "error_code": "not_found",
  "message": "secret not found",
  "request_id": "uuid",
  "timestamp": "2026-06-30T12:00:00Z"
}
```

## Error codes

| Code | HTTP status | Meaning |
|------|-------------|---------|
| `validation_error` | 400 | Invalid request payload or parameters |
| `unauthorized` | 401 | Missing or invalid token |
| `forbidden` | 403 | Token lacks required capability |
| `not_found` | 404 | Resource does not exist |
| `internal_error` | 500 | Unexpected server error |

## Endpoint catalog

### Health & observability

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Liveness |
| GET | `/ready` | No | Readiness (storage, Raft leader, seal state) |
| GET | `/metrics` | No | Prometheus metrics |
| GET | `/openapi.yaml` | No | OpenAPI spec |
| GET | `/swagger` | No | Swagger UI |

### System

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/sys/capabilities` | Yes | Token capabilities |
| POST | `/sys/init` | Yes | Bootstrap initialization |
| POST | `/sys/tls/issue-listener` | Yes | Issue listener TLS certificate |
| POST | `/sys/rotation/run` | Yes | Orchestrate KV rotation, DB lease renewal, PKI renewal |
| POST | `/sys/rotate-master-key` | Yes | Rotate envelope master key |
| POST | `/sys/seal` | Yes | Seal vault (block mutating operations) |
| POST | `/sys/unseal` | No | Unseal vault (`{"key":"<base64>"}` full key, or `{"share":"<base64>"}` Shamir share with progress) |
| POST | `/sys/generate-unseal-shares` | Yes | Split unseal key into Shamir shares (`shares`, `threshold`) |
| POST | `/sys/raft/add-node` | Yes | Add Raft member (when Raft enabled) |
| POST | `/sys/raft/remove-node` | Yes | Remove Raft member |
| PUT | `/sys/kv-rotation` | Yes | Configure scheduled KV rotation |
| DELETE | `/sys/kv-rotation` | Yes | Remove KV rotation schedule |
| GET | `/sys/machine-identities` | Yes | List machine identities |
| DELETE | `/sys/machine-identities/:id` | Yes | Revoke machine identity |
| POST | `/sys/exposure/report` | HMAC | Report credential exposure (when signing key configured) |
| POST | `/sys/backup` | Yes | Export encrypted snapshot |
| POST | `/sys/restore` | Yes | Restore from encrypted snapshot |

### RBAC policies & roles

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/sys/policies/:name` | Yes | Create/update policy |
| GET | `/sys/policies` | Yes | List policies |
| GET | `/sys/policies/:name` | Yes | Get policy |
| DELETE | `/sys/policies/:name` | Yes | Delete policy |
| PUT | `/sys/roles/:name` | Yes | Create/update role binding |
| GET | `/sys/roles/:name` | Yes | Get role |

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/kubernetes` | No | K8s SA JWT → client token |
| POST | `/auth/oidc/:role` | No | OIDC login |
| POST | `/auth/cert` | No | mTLS client certificate → client token (CN/DNS SAN → role policies) |
| POST | `/auth/token` | No | Validate opaque token |
| POST | `/auth/token/create` | Yes | Issue scoped client token |
| POST | `/auth/token/renew` | Yes | Renew client token |
| DELETE | `/auth/token/self` | Yes | Revoke current token |

### Secrets (KVv2)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/secrets/kv/*path` | Yes | Write secret version |
| GET | `/secrets/kv/*path` | Yes | Read latest version |
| DELETE | `/secrets/kv/*path` | Yes | Delete secret path |

### Dynamic database credentials

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/secrets/database/roles/:name` | Yes | Configure DB role |
| GET | `/secrets/database/roles/:name` | Yes | Get DB role |
| POST | `/secrets/database/creds/:role` | Yes | Generate credentials |
| POST | `/secrets/database/renew/:lease_id` | Yes | Renew lease |
| PUT | `/secrets/database/revoke/:lease_id` | Yes | Revoke lease |

### PKI

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/pki/root` | Yes | Create root CA |
| POST | `/pki/intermediate` | Yes | Create intermediate CA |
| POST | `/pki/issue` | Yes | Issue leaf certificate |
| POST | `/pki/renew` | Yes | Renew tracked certificate |
| POST | `/pki/revoke` | Yes | Revoke serial |
| POST | `/pki/ca/import` | Yes | Import CA material |
| POST | `/pki/ca/:id/rotate` | Yes | Rotate CA keys |
| GET | `/pki/ca/:id` | Yes | Get CA by ID |
| GET | `/pki/ca/:id/export` | Yes | Export CA PEM bundle |
| GET | `/pki/crl/:id` | Yes | Generate CRL |
| POST | `/pki/ocsp/:id` | No | OCSP responder (DER) |

### Injection & audit

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/inject/render` | Yes | Render secrets for injection |
| GET | `/audit/export` | Yes | Export audit log + chain head |
| POST | `/audit/verify` | Yes | Verify audit hash chain |

### Vault compatibility (cert-manager)

Thin **Vault product profile** for cert-manager's Vault issuer (`internal/compat/vault` + `vaultcompat` handlers). Not a full Vault API.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/sys/health` | No | Vault health (200/429/503); cert-manager Ready probe |
| POST | `/v1/auth/kubernetes/login` | No | Kubernetes SA JWT login |
| POST | `/v1/auth/approle/login` | No | AppRole `role_id` + `secret_id` login |
| POST | `/v1/auth/:mount/login` | No | Custom auth mounts (dispatches by body) |
| POST | `/v1/pki/sign/:role` | Yes | CSR / CN sign (default mount) |
| POST | `/v1/:mount/sign/:role` | Yes | Custom PKI mount (Issuer `path: <mount>/sign/<role>`) |
| POST | `/sys/auth/approle` | Yes (sudo) | Register AppRole credentials (admin) |

Authenticated sign routes accept `X-Vault-Token` or `Authorization: Bearer`.

Sign body accepts Vault fields used by cert-manager: `csr`, `common_name`, `alt_names`, `ip_sans`, `uri_sans`, `ttl`, `exclude_cn_from_sans`. Response `data` includes `certificate`, `issuing_ca`, `ca_chain`, `serial_number`, `expiration`.

## Leases (M-LEASE-1)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/sys/leases` | `sys/leases` read | List/filter leases |
| GET | `/sys/leases/:id` | `sys/leases` read | Lookup |
| POST | `/sys/leases/renew` | `sys/leases` write | Renew |
| POST | `/sys/leases/revoke/:id` | `sys/leases` write | Revoke one |
| PUT | `/sys/leases/revoke` | `sys/leases` write | Bulk revoke |
| POST | `/sys/leases/revoke-prefix` | `sys/leases` write | Prefix revoke |
| POST | `/sys/leases/tidy` | `sys/leases` write | Expire cleanup |

## Cubbyhole & wrapping (M-WRAP-1)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| PUT/GET/DELETE | `/cubbyhole/*path` | `cubbyhole` | Per-token private KV |
| POST | `/sys/wrapping/wrap` | `sys/wrapping` write | Mint wrapping token |
| POST | `/sys/wrapping/unwrap` | `sys/wrapping` write | Single-use unwrap |
| POST | `/sys/wrapping/lookup` | `sys/wrapping` read | Wrap metadata |

## Transit (M-TRANSIT-1)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| POST | `/transit/keys/:name` | `transit/keys` write | Create key |
| GET | `/transit/keys/:name` | `transit/keys` read | Key metadata |
| POST | `/transit/keys/:name/rotate` | `transit/keys` write | Rotate |
| POST | `/transit/encrypt|decrypt|rewrap/:name` | encrypt/decrypt write | Crypto ops |
| POST | `/transit/sign|verify|hmac/:name` | sign/hmac | Integrity ops |

## Identity (M-IDENT-1)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| POST/GET | `/identity/entity` | identity sudo/read | Create/list entities |
| GET | `/identity/entity/:id` | identity read | Get entity |
| POST | `/identity/entity/:id/disable` | identity sudo | Disable entity |
| POST | `/identity/alias` | identity sudo | Create alias |
| POST/GET | `/identity/group` | identity sudo/read | Groups |

## LDAP auth (W70)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/ldap` | No | Username/password bind; server LDAP env config |

## Go client

```go
c := client.New("http://localhost:8200", token)
resp, err := c.KVGet(ctx, "app/db")
```

Package: [`pkg/client`](../../pkg/client/).

## Related documents

- [Getting started](../user/getting-started.md)
- [Configuration reference](../installation/configuration.md)
- [Security model](../architecture/security-model.md)
- [Lease management](../operations/lease-management.md)
- [Vault-class capability plan](../design/vault-class-capability-plan.md)