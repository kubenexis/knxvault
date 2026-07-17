<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: Response wrapping and cubbyhole (M-WRAP-1)

Securely bootstrap a secret to another party without leaving it in chat logs or CI output for long.

## Cubbyhole (per-token private KV)

```bash
# Store
curl -sS -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"data":{"password":"s3cr3t"}}' \
  "$KNXVAULT_ADDR/cubbyhole/bootstrap"

# Read (same token only)
curl -sS -H "Authorization: Bearer $TOKEN" \
  "$KNXVAULT_ADDR/cubbyhole/bootstrap"

# Delete
curl -sS -X DELETE -H "Authorization: Bearer $TOKEN" \
  "$KNXVAULT_ADDR/cubbyhole/bootstrap"
```

Cubbyhole paths are wiped when the owning token is revoked.

## Response wrapping

```bash
# Wrap a payload (returns wrapping token only)
curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"data":{"api_key":"ak_xxx"},"ttl":"5m"}' \
  "$KNXVAULT_ADDR/sys/wrapping/wrap"
# → {"token":"knxw_...","ttl_seconds":300,...}

# Recipient unwraps once (needs sys/wrapping *read* + wrap token possession)
curl -sS -X POST -H "Authorization: Bearer $READER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"token":"knxw_..."}' \
  "$KNXVAULT_ADDR/sys/wrapping/unwrap"
# Second unwrap fails

# Metadata only
curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"token":"knxw_..."}' \
  "$KNXVAULT_ADDR/sys/wrapping/lookup"
```

**Permissions:** `cubbyhole` read/write/delete; wrap create needs `sys/wrapping` **write**; unwrap/lookup need `sys/wrapping` **read**.

**Limits:** wrapping TTL max 1h; single-use; wrap **metadata is sealed in storage** (`sys/wrapping/meta/*`) for multi-node HA (W74-04); audit `wrapping.wrap` / `wrapping.unwrap`.
