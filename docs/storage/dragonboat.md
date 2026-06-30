# Dragonboat Raft Storage

KNXVault persists all vault state in a single Dragonboat Raft cluster (cluster ID `1`). Repository interfaces delegate to a replicated state machine backed by in-memory stores snapshotted as portable JSON.

**Encryption invariant:** Secret payloads and private keys are encrypted by the engine layer (AES-256-GCM envelope) *before* `Propose`. Raft logs, Pebble WAL entries, and on-disk snapshots therefore contain ciphertext for sensitive fields — not plaintext secrets. See [ADR-0004](../adr/0004-encrypt-before-replication.md).

## Topology

| Mode | Nodes | Use case |
|------|-------|----------|
| Single-node | `KNXVAULT_RAFT_NODE_ID=1` | Dev / CI |
| 3-node StatefulSet | `0,1,2` pod indices + headless Service | Production HA |

Raft addresses use `host:63001` by default. HTTP remains on `:8200`.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_RAFT_ENABLED` | `false` | Enable Dragonboat backend |
| `KNXVAULT_RAFT_NODE_ID` | — | Raft node ID (required when enabled) |
| `KNXVAULT_RAFT_ADDRESS` | `127.0.0.1:63001` | Public Raft address |
| `KNXVAULT_RAFT_LISTEN_ADDRESS` | _(empty)_ | Optional bind address |
| `KNXVAULT_RAFT_DATA_DIR` | `/var/lib/knxvault/raft` | Pebble/WAL data directory |
| `KNXVAULT_RAFT_INITIAL_MEMBERS` | — | `id=host:port,...` for new clusters |
| `KNXVAULT_RAFT_ELECTION_RTT` | `10` | Election interval in RTT ticks |
| `KNXVAULT_RAFT_HEARTBEAT_RTT` | `1` | Heartbeat interval in RTT ticks |
| `KNXVAULT_RAFT_RTT_MILLISECOND` | `1` | Logical RTT milliseconds |
| `KNXVAULT_RAFT_JOIN` | `false` | Join an existing cluster |

Readiness (`GET /ready`) returns `raft_enabled` and `raft_ready` when Raft is active. Background jobs run only on the Raft leader (`knxvault_raft_leader`).

## Command catalog

Commands are JSON envelopes `{ "op": "<name>", "payload": { ... } }`.

| Op | Type | Description |
|----|------|-------------|
| `ca.save` | write | Persist CA |
| `ca.get_by_id` | read | Fetch CA by ID |
| `ca.get_by_name` | read | Fetch CA by name |
| `ca.list` | read | List CAs |
| `secret.save_version` | write | Save secret version |
| `secret.get_latest` | read | Latest secret version |
| `secret.get_version` | read | Specific secret version |
| `secret.list_by_path` | read | List by prefix |
| `secret.next_version` | read | Next version number |
| `audit.append` | write | Append audit entry |
| `audit.list` | read | Query audit log |
| `audit.latest_hash` | read | Hash-chain tip |
| `revoke.save` | write | Revoke certificate |
| `revoke.is` | read | Revocation check |
| `revoke.list_by_ca` | read | Revocations by CA |
| `lease.save` | write | Save lease |
| `lease.get` | read | Get lease |
| `lease.list` | read | List leases |
| `lease.list_expired` | read | Expired leases |
| `lease.revoke` | write | Revoke lease |
| `policy.save` | write | Save policy |
| `policy.get_by_name` | read | Get policy |
| `policy.list` | read | List policies |
| `policy.delete` | write | Delete policy |
| `role.save` | write | Save role |
| `role.get` | read | Get role |
| `role.list` | read | List roles |
| `role.delete` | write | Delete role |
| `db_role.save` | write | Save database role |
| `db_role.get` | read | Get database role |
| `db_role.list` | read | List database roles |
| `db_role.delete` | write | Delete database role |
| `issued.save` | write | Track issued certificate |
| `issued.get_by_serial` | read | Lookup issued cert |
| `issued.list` | read | List issued certs |
| `issued.list_expiring` | read | Expiring issued certs |
| `snapshot.import` | write | Replace state from backup snapshot |

## Snapshots

Dragonboat `SaveSnapshot` / `RecoverFromSnapshot` use the same JSON format as `internal/backup.Snapshot`. `POST /sys/backup` exports via repositories and triggers an on-disk Raft snapshot; restore proposes `snapshot.import`.

## Kubernetes

Use [`deployments/k8s/statefulset.yaml`](../../deployments/k8s/statefulset.yaml) with headless Service [`service-raft.yaml`](../../deployments/k8s/service-raft.yaml). Set `KNXVAULT_RAFT_INITIAL_MEMBERS` in the ConfigMap to the stable DNS names of all replicas.