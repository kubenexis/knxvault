<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: Master key rotation without data loss

Rotate the envelope master key and re-encrypt existing data in place — secrets remain readable throughout.

## What you will learn

- How envelope encryption uses a master key and DEKs
- The `rotate-master-key` API and background re-encrypt job
- Operational safeguards (backup first, store new key securely)

## Prerequisites

- Healthy KNXVault cluster (quorum intact)
- Current `KNXVAULT_MASTER_KEY` available
- Admin token
- Maintenance window recommended (re-encrypt is CPU/IO intensive on leader)

## Concepts

```
Plaintext secret
    → encrypted with random DEK (AES-256-GCM)
    → DEK wrapped with master key (KeyRing version N)
    → only ciphertext + wrapped DEK stored in Raft
```

**Master key rotation:**

1. Add new master key version to the in-memory KeyRing.
2. New writes use the new version immediately.
3. Leader background job re-wraps existing DEKs with the new key version.
4. Old master key version remains in KeyRing until re-encrypt completes (needed to read legacy DEKs).

Secrets are **never** decrypted to plaintext during re-encrypt — only DEK blobs are re-wrapped.

## Step 1 — Backup before rotation

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

knxvault-cli backup create -o pre-master-key-rotate.json
```

## Step 2 — Seed test data

```bash
knxvault-cli kv put rotate-test/before value=must-survive-rotation
knxvault-cli kv get rotate-test/before --show-secrets
```

## Step 3 — Generate and apply new master key

```bash
NEW_MASTER_KEY=$(openssl rand -base64 32)
echo "Store NEW_MASTER_KEY in your secrets manager: $NEW_MASTER_KEY"

# CLI
knxvault-cli sys rotate-master-key --key "$NEW_MASTER_KEY"

# Or API
curl -s -X POST "$KNXVAULT_ADDR/sys/rotate-master-key" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$NEW_MASTER_KEY\"}" | jq .
```

## Step 4 — Update deployment configuration

After rotation succeeds, update the cluster secret for **future restarts**:

```bash
# Edit deployments/k8s/secret.yaml — set KNXVAULT_MASTER_KEY to NEW_MASTER_KEY
kubectl -n knxvault apply -f deployments/k8s/secret.yaml
```

> Running pods keep the old key in memory until restarted. Complete re-encrypt before rolling restart, or briefly run with both key versions available via the in-memory KeyRing during the transition.

## Step 5 — Monitor re-encrypt on leader

```bash
# Find leader pod
for i in 0 1 2; do
  kubectl -n knxvault exec knxvault-$i -- wget -qO- http://localhost:8200/ready 2>/dev/null | jq -c '{pod:"knxvault-'$i'",leader}'
done

kubectl -n knxvault logs <leader-pod> --tail=100 | grep -i reencrypt
```

Wait until re-encrypt completes (typically seconds to minutes depending on data volume).

## Step 6 — Verify data integrity

```bash
# Pre-rotation secret still readable
knxvault-cli kv get rotate-test/before --show-secrets

# New write after rotation
knxvault-cli kv put rotate-test/after value=post-rotation-write
knxvault-cli kv get rotate-test/after --show-secrets

# Backup with new key
knxvault-cli backup create -o post-master-key-rotate.json
```

Read from each replica (port-forward per pod) to confirm cluster-wide consistency.

## Step 7 — Rolling restart (optional)

Once re-encrypt completes and `secret.yaml` is updated:

```bash
for i in 2 1 0; do
  kubectl -n knxvault delete pod knxvault-$i --wait=true
  kubectl -n knxvault wait --for=condition=ready pod/knxvault-$i --timeout=300s
done
knxvault-cli doctor
```

## Verify

| Check | Expected |
|-------|----------|
| `rotate-test/before` readable | Same plaintext as before rotation |
| New writes succeed | All replicas accept KV PUT |
| Backup/restores | `backup restore` works with `NEW_MASTER_KEY` |
| Logs | No plaintext secrets in pod logs |

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Read fails after rotation | Re-encrypt incomplete; wait for leader job; ensure old key still in KeyRing |
| Restore fails | Backup was taken with different master key — use matching key |
| Rotation API 403 | Token needs `sys` write capability |

## Related recipes

- [Backup and restore](backup-and-restore.md)
- [Deploy 3-node cluster](deploy-3-node-cluster.md)

## See also

- [Envelope encryption](../architecture/envelope-encryption.md)
- [ADR-0004: Encrypt before replication](../adr/0004-encrypt-before-replication.md)