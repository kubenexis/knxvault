<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Secret exposure detection integration

KNXVault accepts signed exposure reports from external scanners (Gitleaks, TruffleHog, GitGuardian, etc.) and can auto-remediate when configured.

## Endpoint

`POST /sys/exposure/report`

Authentication uses HMAC signing (not bearer tokens):

| Header | Description |
|--------|-------------|
| `X-KNXVault-Exposure-Signature` | HMAC-SHA256 hex digest of the raw request body |

Configure the signing key with `KNXVAULT_EXPOSURE_SIGNING_KEY`.

## Request body

```json
{
  "detector": "gitleaks",
  "fingerprint": "abc123",
  "secret_path": "app/db",
  "lease_id": "lease-optional",
  "severity": "high"
}
```

## Auto-remediation

When `KNXVAULT_EXPOSURE_AUTO_REVOKE=true`:

- `lease_id` → database lease revoked via `DatabaseService`
- `secret_path` → KV rotation triggered when a rotation policy exists

Optional webhook: `KNXVAULT_EXPOSURE_WEBHOOK_URL` receives `exposure.reported` events.

## Pairing with scanners

1. Configure the scanner to POST findings to KNXVault.
2. Sign the exact JSON body with the shared HMAC key.
3. Map scanner metadata to `secret_path` or `lease_id` when known.

See also [configuration](../installation/configuration.md) for TLS and mTLS settings.