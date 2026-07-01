# Dragonboat Raft Storage

KNXVault persists all vault state in a single Dragonboat Raft cluster (cluster ID `1`). Repository interfaces delegate to a replicated state machine backed by in-memory stores snapshotted as portable JSON.

**Encryption invariant:** Secret payloads and private keys are encrypted by the engine layer (AES-256-GCM envelope) *before* `Propose`. Raft logs, Pebble WAL entries, and on-disk snapshots therefore contain ciphertext for sensitive fields — not plaintext secrets. See [ADR-0004](../adr/0004-encrypt-before-replication.md).

## Topology

| Mode | Nodes | Use case |
|------|-------|----------|
| Single-node | `KNXVAULT_RAFT_NODE_ID=1` | Dev / CI |
| 3-node StatefulSet | pod ordinals `0,1,2` → node IDs `1,2,3` | Production HA |

Raft addresses use `host:63001` by default. HTTP remains on `:8200`.

## Raft node IDs — how to choose and assign

A **Raft node ID** is a stable numeric member identifier in the Dragonboat cluster. It is **not** generated randomly at runtime — you **assign** it when planning the cluster, then reference the same ID in `KNXVAULT_RAFT_INITIAL_MEMBERS`.

### Rules

| Rule | Detail |
|------|--------|
| Must be > 0 | `KNXVAULT_RAFT_NODE_ID=0` or unset (with no auto-derivation) fails startup |
| Unique per replica | Each running member needs a distinct ID |
| Stable for life of member | Reusing an ID on a different host corrupts quorum semantics — treat IDs like server names |
| Must match `INITIAL_MEMBERS` | The ID in `KNXVAULT_RAFT_INITIAL_MEMBERS` must equal this node's configured/derived ID |

There is no `knxvault raft gen-node-id` command. Pick integers `1`, `2`, `3`, … when designing the cluster.

### Option 1 — Set explicitly (recommended for dev, bare metal, Docker)

Choose the next free integer and set it on **that** process only:

```bash
# Single-node laptop / CI
export KNXVAULT_RAFT_NODE_ID=1
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001

# Three VMs (example)
# host-a: KNXVAULT_RAFT_NODE_ID=1  KNXVAULT_RAFT_ADDRESS=10.0.0.1:63001
# host-b: KNXVAULT_RAFT_NODE_ID=2  KNXVAULT_RAFT_ADDRESS=10.0.0.2:63001
# host-c: KNXVAULT_RAFT_NODE_ID=3  KNXVAULT_RAFT_ADDRESS=10.0.0.3:63001
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=10.0.0.1:63001,2=10.0.0.2:63001,3=10.0.0.3:63001
```

**Planning tip:** Use contiguous IDs starting at `1`. The left-hand side of `INITIAL_MEMBERS` is the node ID; the right-hand side is the **reachable** Raft address for that ID.

### Option 2 — Kubernetes auto-derivation (production StatefulSet)

When `KNXVAULT_RAFT_NODE_ID` is **unset**, KNXVault derives the ID from `KNXVAULT_POD_NAME` (or `HOSTNAME` / OS hostname):

```
node_id = <trailing_numeric_ordinal> + 1
```

| Pod / host name | Derived node ID |
|-----------------|-----------------|
| `knxvault-0` | `1` |
| `knxvault-1` | `2` |
| `knxvault-2` | `3` |
| `myhost-0` | `1` |

The StatefulSet injects `KNXVAULT_POD_NAME` from `metadata.name` and sets `KNXVAULT_RAFT_ADDRESS` to the headless Service DNS name. Your ConfigMap `KNXVAULT_RAFT_INITIAL_MEMBERS` must use the **same** IDs:

```text
1=knxvault-0.knxvault-raft.knxvault.svc.cluster.local:63001,
2=knxvault-1.knxvault-raft.knxvault.svc.cluster.local:63001,
3=knxvault-2.knxvault-raft.knxvault.svc.cluster.local:63001
```

**Naming requirement:** Auto-derivation only works when the hostname ends with `-<ordinal>` where `<ordinal>` is a non-negative integer. Names like `knxvault` or `server01` do **not** auto-derive — set `KNXVAULT_RAFT_NODE_ID` explicitly instead.

### Option 3 — Override on Kubernetes

You may set `KNXVAULT_RAFT_NODE_ID` in the ConfigMap or per-pod env to override derivation. If you do, update `KNXVAULT_RAFT_INITIAL_MEMBERS` so the same numeric ID maps to that pod's Raft address.

### Verify after startup

```bash
curl -s http://localhost:8200/ready | jq
# expect: raft_enabled=true, raft_ready=true, leader=true|false
```

Prometheus gauge `knxvault_raft_leader` is `1` only on the elected leader replica.

### Common mistakes

| Mistake | Symptom |
|---------|---------|
| Raft enabled without node ID on a generic host | `KNXVAULT_RAFT_NODE_ID must be > 0 when raft is enabled` |
| Node ID `2` but `INITIAL_MEMBERS` only lists ID `1` | Peer cannot join quorum / readiness stuck |
| Two pods both derive ID `1` (duplicate ordinals) | Split-brain / Raft startup failure |
| Changing a pod's ID after data was written | Treat as a **new** member — use [`docs/operations/runbooks/scaling.md`](../operations/runbooks/scaling.md) |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_RAFT_ENABLED` | `false` | Enable Dragonboat backend |
| `KNXVAULT_RAFT_NODE_ID` | — | Raft node ID (**required** when enabled; must be > 0). Set explicitly for local dev; on K8s derived from `KNXVAULT_POD_NAME` ordinal (`knxvault-0` → `1`) when unset |
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
| `snapshot.export` | read | Atomic full-state export for consistent backup |

## Snapshots

Dragonboat `SaveSnapshot` / `RecoverFromSnapshot` use the same JSON format as `internal/backup.Snapshot`. **Audit entries are included** in on-disk snapshots (`ExportSnapshot(true)`). `POST /sys/backup` uses the atomic `snapshot.export` read when Raft is enabled, then triggers an on-disk Raft snapshot; restore proposes `snapshot.import`.

Dynamic membership: `POST /sys/raft/add-node` and `POST /sys/raft/remove-node` (leader only). See [`docs/operations/runbooks/scaling.md`](../operations/runbooks/scaling.md).

For snapshot correctness, quorum recovery, disaster recovery, bootstrap, and network partitions, see [Raft HA & recovery](raft-ha-and-recovery.md).

## Kubernetes

Use [`deployments/k8s/statefulset.yaml`](../../deployments/k8s/statefulset.yaml) with headless Service [`service-raft.yaml`](../../deployments/k8s/service-raft.yaml). Set `KNXVAULT_RAFT_INITIAL_MEMBERS` in the ConfigMap to the stable DNS names of all replicas.