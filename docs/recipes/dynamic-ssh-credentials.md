<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: Dynamic SSH credentials

Issue short-lived OpenSSH user certificates signed by a CA key stored in KNXVault KV.

## What you will learn

- Storing an SSH CA private key in KV (envelope encrypted)
- Configuring SSH roles with `allowed_users`
- Generating signed certs and validating with `ssh-keygen`

## Prerequisites

- KNXVault with SSH secrets engine enabled
- `ssh-keygen` on your workstation
- Optional: OpenSSH server configured to trust your CA public key

## Concepts

| Component | Location |
|-----------|----------|
| **CA private key** | KV path (e.g. `ssh/ca/root`) — encrypted at rest |
| **SSH role** | `PUT /secrets/ssh/roles/:name` |
| **Output** | Ephemeral key pair + `signed_key` (certificate) |
| **Lease** | TTL-bound; renew via `POST /secrets/ssh/renew/:lease_id` |

## Step 1 — Generate SSH CA keypair

```bash
ssh-keygen -t ed25519 -f ./ssh-ca -N "" -C "knxvault-ssh-ca"
# ssh-ca      — private (store in KV)
# ssh-ca.pub  — public (configure on sshd)
```

## Step 2 — Store CA private key in KV

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

knxvault-cli kv put ssh/ca/root \
  private_key="$(cat ./ssh-ca)" \
  public_key="$(cat ./ssh-ca.pub)"
```

## Step 3 — Configure SSH role

```bash
curl -s -X PUT "$KNXVAULT_ADDR/secrets/ssh/roles/ops" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "ttl_seconds": 600,
    "ca_key_path": "ssh/ca/root",
    "allowed_users": ["deploy", "ubuntu"],
    "default_user": "deploy",
    "key_type": "ed25519"
  }'
```

CLI:

```bash
knxvault-cli ssh roles put ops -f - <<'EOF'
{
  "ttl_seconds": 600,
  "ca_key_path": "ssh/ca/root",
  "allowed_users": ["deploy"],
  "default_user": "deploy"
}
EOF
```

## Step 4 — Generate credentials

```bash
curl -s -X POST "$KNXVAULT_ADDR/secrets/ssh/creds/ops" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username": "deploy", "ttl_seconds": 600}' | jq . > ssh-creds.json

knxvault-cli ssh creds ops --username deploy --ttl 600
```

Response fields:

| Field | Use |
|-------|-----|
| `private_key` | Client authentication key |
| `signed_key` | OpenSSH certificate |
| `lease_id` | Renew/revoke reference |
| `expires_at` | Cert validity end |

## Step 5 — Validate certificate locally

```bash
jq -r .signed_key ssh-creds.json > cert.pub
jq -r .private_key ssh-creds.json > id_key

chmod 600 id_key
ssh-keygen -L -f cert.pub
ssh-keygen -Y check -n user -s ./ssh-ca.pub -I "$(ssh-keygen -L -f cert.pub | awk '/Signing CA/ {print $3}')" -f cert.pub
```

## Step 6 — Configure OpenSSH server (target host)

Add to `/etc/ssh/sshd_config`:

```text
TrustedUserCAKeys /etc/ssh/knxvault_ca.pub
```

```bash
sudo cp ./ssh-ca.pub /etc/ssh/knxvault_ca.pub
sudo systemctl reload sshd
```

## Step 7 — Connect with certificate

```bash
ssh -i id_key -o CertificateFile=cert.pub deploy@target-host.example.com
```

## Step 8 — Renew lease

```bash
LEASE=$(jq -r .lease_id ssh-creds.json)

curl -s -X POST "$KNXVAULT_ADDR/secrets/ssh/renew/$LEASE" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ttl_seconds": 1200}' | jq .
```

## RBAC for SSH engine

```json
{
  "paths": {
    "secrets/ssh/creds/*": {"capabilities": ["create"]},
    "secrets/ssh/roles/*": {"capabilities": ["read"]}
  }
}
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `requires CA` error | `ca_key_path` KV secret missing `private_key` field |
| Wrong user rejected | Username not in `allowed_users` |
| Server rejects cert | `TrustedUserCAKeys` not loaded; principals mismatch |

## Related recipes

- [KV secrets lifecycle](kv-secrets-lifecycle.md)
- [RBAC policies](rbac-policies.md)
- [Orchestrated rotation](orchestrated-rotation.md)

## See also

- [API reference — SSH](../api/reference.md)
- `cmd/knxvault-cli/cmd/ssh.go`