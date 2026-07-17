<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Raft HA, Snapshots, and Recovery

Technical reference for how KNXVault uses [Dragonboat](https://github.com/lni/dragonboat) for quorum, snapshots, membership, bootstrap, and disaster recovery. Operational runbooks live in [Raft failover](../operations/runbooks/raft-failover.md) and [Scaling](../operations/runbooks/scaling.md).

## Architecture summary

| Concept | Implementation |
|---------|----------------|
| Cluster ID | `1` (`internal/raft/client.go`) |
| State machine | `VaultStateMachine` — in-memory `Store` snapshotted as JSON |
| Writes | `SyncPropose` — linearizable, majority ack required |
| Reads (export) | `SyncRead` on read-only ops (e.g. `snapshot.export`) |
| Leader jobs | Gated by `LeaderElector` + live `IsLeader()` probe |
| Data dir | `KNXVAULT_RAFT_DATA_DIR` — Pebble WAL + Dragonboat snapshots |

```
                    ┌─────────────────────────────────────┐
                    │  HTTP API (any replica)              │
                    └──────────────┬──────────────────────┘
                                   │ Propose / SyncRead
                    ┌──────────────▼──────────────────────┐
                    │  Dragonboat NodeHost (per process)     │
                    │  Raft log → committed entries        │
                    └──────────────┬──────────────────────┘
                                   │ Update / Lookup
                    ┌──────────────▼──────────────────────┐
                    │  VaultStateMachine → Store           │
                    │  (memory repos: CA, secrets, …)      │
                    └─────────────────────────────────────┘
```

Sensitive fields are encrypted **before** `Propose` — snapshots and Raft logs hold ciphertext only ([ADR-0004](../adr/0004-encrypt-before-replication.md)).

---

## Snapshot correctness

KNXVault uses **two related snapshot mechanisms** that share the same JSON schema (`internal/backup.Snapshot`).

### 1. Dragonboat on-disk snapshots

Dragonboat periodically compacts the Raft log by calling the state machine snapshot hooks.

| Hook | Behavior |
|------|----------|
| `SaveSnapshot` | `ExportSnapshot(true)` — **includes audit** — JSON-encode to writer |
| `RecoverFromSnapshot` | JSON decode → `ValidateSnapshot` → **replace entire** `Store` |

Configuration (`internal/raft/nodehost.go`):

- `SnapshotEntries: 1000` — snapshot after 1000 committed entries (Dragonboat tuning).

On recovery, a follower or restarted node can catch up from a snapshot plus subsequent log entries instead of replaying the full history.

**Correctness guarantees:**

- Snapshot content is a **point-in-time** view of the in-memory store at the commit index when Dragonboat invoked `SaveSnapshot`.
- `ImportSnapshot` builds a **fresh** `Store`, restores into it, then swaps pointers — no merge with prior state (`internal/raft/store.go`).
- Round-trip tests: `TestVaultStateMachineSnapshotRoundTrip`, `TestVaultStateMachineSnapshotPreservesAudit` in `internal/raft/statemachine_test.go`.

### 2. Portable backup export (`snapshot.export`)

For operator backups, KNXVault must avoid torn reads across multiple repositories.

| Path | Mechanism |
|------|-----------|
| **Raft enabled** | `Client.ExportSnapshot` → linearizable `SyncRead` of `snapshot.export` on the leader’s state machine |
| **In-memory dev** | `backup.Export` walks repos directly (no Raft) |

`POST /sys/backup` (`internal/service/backup.go`):

1. Atomic export via Raft read (when configured).
2. `RequestSnapshot` — triggers Dragonboat `SyncRequestSnapshot` on the leader (persists on-disk snapshot).
3. `backup.Seal` — master-key-encrypt the portable JSON for off-site storage.

`TestExportSnapshotConsistentGraph` in `internal/raft/store_import_test.go` asserts CA + secret appear together in one export.

### 3. Validation before import

`snapshot.import` and restore paths call `backup.ValidateSnapshot` **before** replacing state:

| Check | Purpose |
|-------|---------|
| `Version == 1` | Format compatibility |
| CA graph | Unique IDs/names; `ParentID` references exist |
| RBAC | Role policy names resolve |
| PKI roles | `CAName` references exist |
| Issued certs | `CAID` references exist; no duplicate serials per CA |
| Audit chain | Hash chain integrity when hashes present |

Invalid snapshots are rejected — the live cluster state is unchanged.

### 4. Restore semantics

| Mode | Behavior |
|------|----------|
| Raft | `SnapshotImporter.ImportSnapshot` → `Propose(snapshot.import)` — **full state replacement** on all replicas via Raft |
| In-memory | `backup.Restore` replaces repo contents directly |

Restore is **not** a merge. Stale entities not in the snapshot are dropped (`TestRestoreReplacesExistingState`).

After restore, RBAC policies are reloaded into the in-memory evaluator (`BackupService.SetPolicyReloader`).

---

## Membership changes

Static bootstrap uses `KNXVAULT_RAFT_INITIAL_MEMBERS`. **Runtime** membership changes use Dragonboat’s config-change API (W36-23).

### Bootstrap vs join

On first start (`internal/raft/nodehost.go`):

```text
if cluster not already running on this NodeHost:
    StartCluster(members, join, CreateStateMachine, config)
```

| Flag / input | Meaning |
|--------------|---------|
| `KNXVAULT_RAFT_INITIAL_MEMBERS` | `id=host:port,...` — expected voter set |
| `KNXVAULT_RAFT_JOIN=true` | This node joins an **existing** cluster (empty local data dir) |
| `join=false` (default) | Form or re-form cluster from `INITIAL_MEMBERS` |

If `INITIAL_MEMBERS` is empty, the node bootstraps as a **single-member** cluster containing only itself.

**Rule:** Node IDs are stable identifiers — never reuse an ID on a different host without treating it as disaster recovery. See [node ID assignment](dragonboat.md#raft-node-ids--how-to-choose-and-assign).

### Add / remove voting members

| API | Permission | Implementation |
|-----|------------|----------------|
| `POST /sys/raft/add-node` | `sys/raft:write` | `SyncRequestAddNode(clusterID, nodeID, address, 0)` |
| `POST /sys/raft/remove-node` | `sys/raft:write` | `SyncRequestDeleteNode(clusterID, nodeID, 0)` |

Constraints (`internal/raft/membership.go`, `internal/api/handlers/sys.go`):

- **Leader only** — handler checks `raft.IsLeader()`; followers return validation error.
- **30s timeout** per Dragonboat sync call.
- **Cannot remove local node** via API — shut down the process instead.
- New member must be listening on its `RaftAddress` before `add-node`.

Recommended flow: provision new node with `KNXVAULT_RAFT_JOIN=true` and updated `INITIAL_MEMBERS`, start process, then call `add-node` from the leader. See [Scaling runbook](../operations/runbooks/scaling.md).

Membership changes are **Raft configuration entries** — they replicate like normal writes and require quorum.

---

## Quorum recovery

### Quorum model

Production expects **3 voting nodes**. Raft requires a **majority** for commits:

| Nodes up | Quorum | Writes |
|----------|--------|--------|
| 3/3 | yes | normal |
| 2/3 | yes | normal (tolerates 1 failure) |
| 1/3 | no | **blocked** |

Dragonboat config sets `CheckQuorum: true` (`internal/raft/nodehost.go`) so leaders step down when they cannot reach a majority.

### How KNXVault surfaces quorum loss

| Signal | Behavior |
|--------|----------|
| `GET /ready` | **503** when `raft cluster has no leader` (`Dependencies.Ready`) |
| `raft_ready: false` | Exposed in readiness JSON |
| `knxvault_raft_leader` | 0 on all nodes during election or partition |
| Writes via API | Fail when proposals cannot achieve majority |

Background jobs (lease cleanup, CRL refresh, master-key re-encrypt) run **only on the leader** (`LeaderElector`). Followers do not execute jobs.

### Recovery procedure (quorum intact on minority)

1. Restore failed nodes with **intact PVCs** — they replay Raft log / snapshot and rejoin.
2. Delete crashed pods — StatefulSet recreates them; no restore needed if disk survived.
3. Wait for `/ready` 200 on all replicas and exactly one `knxvault_raft_leader = 1`.

### Recovery procedure (quorum lost)

When 2+ nodes are down **and** data is corrupted or missing:

1. Restore **at least 2 of 3** nodes with good PVCs, **or**
2. Stand up a recovery node and `POST /sys/restore` from encrypted backup (see Disaster recovery).
3. Re-expand membership after state is verified.

Do **not** start independent clusters with the same `INITIAL_MEMBERS` and divergent data — that risks operator confusion and split deployments.

---

## Disaster recovery

### Recovery tiers

| Tier | Scenario | Approach |
|------|----------|----------|
| **A** | Single pod / node loss, PVC intact | Delete pod; automatic rejoin |
| **B** | One PVC corrupted, 2/3 healthy | Replace node; optional restore from backup if peer sync insufficient |
| **C** | All PVCs lost | New cluster + **encrypted backup restore** |
| **D** | Master key lost | **Unrecoverable** ciphertext — backups useless without key |

### Encrypted backup restore flow

Prerequisites:

- `KNXVAULT_MASTER_KEY` matches the key used when backup was created.
- Backup file: JSON archive `format: knxvault-backup` with master-key-sealed payload.

```bash
# CLI
export KNXVAULT_ADDR=http://leader:8200
export KNXVAULT_TOKEN=<admin-token>
./build/bin/knxvault-cli backup restore -f knxvault-backup.json
```

Raft path (`internal/service/backup.go`):

1. `backup.Open` — decrypt archive with master key.
2. `ValidateSnapshot` — structural checks.
3. `ImportSnapshot` — single `snapshot.import` Raft command replaces global state.
4. RBAC reload from restored policies.

Run restore against a **leader** during a maintenance window. All replicas converge via Raft replication.

### What restore does not rewind

- **Raft peer config** on disk — membership in Dragonboat’s local state may still reflect old nodes; reconcile with `add-node` / `remove-node` after restore.
- **Certificates issued after backup timestamp** — re-issue or accept loss.
- **Client tokens created after backup** — restore token hashes from snapshot only.
- **Dragonboat data dir on other nodes** — may need wipe + rejoin if restore replaced logical state divergently; prefer maintenance window with coordinated restore to a fresh cluster or rolling reconcile per runbook.

### Cross-cluster DR (LT-35)

Automated cross-region replication is **not implemented**. Operators copy encrypted backups off-site (`scripts/backup.sh`) and follow [Backup & restore](../deploy/backup-restore.md).

---

## Bootstrap process

Bootstrap spans **process startup** (infrastructure) and **vault initialization** (application).

### Phase 1 — Process startup (`knxvault serve`)

Executed in `app.New` / `NewDependencies`:

```
1. Load config (file + env)
2. masterkey.Load() — required when KNXVAULT_RAFT_ENABLED=true
3. crypto.NewService(masterKey)
4. raft.StartNodeHost(cfg)
      ├── Mkdir data dir (0700)
      ├── dragonboat.NewNodeHost
      └── StartCluster if cluster not running
5. dragonboat.NewRepos → all repository interfaces
6. Wire engines, auth, JobRunner, LeaderElector
7. HTTP server start
```

Kubernetes: set `KNXVAULT_MASTER_KEY`, `KNXVAULT_UNSEAL_KEY` (≠ master key), `KNXVAULT_ROOT_TOKEN` in Secret; ConfigMap carries `KNXVAULT_RAFT_*`. See [Kubernetes deployment](../deploy/kubernetes.md).

### Phase 2 — Raft cluster formation

**New 3-node cluster (production):**

1. All pods share the same `KNXVAULT_RAFT_INITIAL_MEMBERS` in ConfigMap.
2. Each pod gets a unique derived or explicit `KNXVAULT_RAFT_NODE_ID`.
3. `KNXVAULT_RAFT_JOIN=false` on initial rollout.
4. Pods start concurrently; Dragonboat elects a leader once a majority is reachable.
5. `GET /ready` returns 200 when a leader is known.

**Joining a new member later:** `KNXVAULT_RAFT_JOIN=true` on the new node only, then `POST /sys/raft/add-node`.

### Phase 3 — Vault initialization (`POST /sys/init`)

One-time application bootstrap (`internal/api/handlers/sys.go`):

| Step | Action |
|------|--------|
| Guard | `sys.MarkInitialized` — rejects second call (`ErrAlreadyInitialized`) |
| Fingerprint | SHA-256 first 8 bytes of master key → `master_key_fingerprint` |
| Optional | `create_root_ca: true` → creates initial PKI root via `PKIEngine.CreateRoot` |

`POST /sys/init` does **not** configure Raft membership or load secrets — it marks logical init and optionally creates the root CA.

### Phase 4 — Operator hardening

After init:

1. Authenticate with bootstrap `KNXVAULT_ROOT_TOKEN`.
2. Create scoped policies and roles.
3. Issue workload tokens / configure Kubernetes auth.
4. Rotate off bootstrap root token.
5. Schedule encrypted backups.

See [Installation — post-install bootstrap](../installation/install.md#post-install-bootstrap).

---

## Network partition handling

KNXVault relies on **standard Raft majority rules** — there is no custom partition resolver beyond Dragonboat + `CheckQuorum`.

### Majority partition (2 of 3 nodes)

- Continues to elect a leader among reachable members.
- Accepts writes and replicates to in-partition followers.
- `knxvault_raft_leader` = 1 on the leader replica.

### Minority partition (1 of 3 nodes)

- Cannot commit new entries (no quorum).
- Leader on minority steps down; `/ready` → 503 on isolated node.
- API writes fail until partition heals.

### When connectivity returns

- Minority node catches up from leader’s log / snapshot.
- Dragonboat reconciles terms; stale leaders abdicate on seeing higher terms.
- No operator action required if data dirs are intact.

### What KNXVault does not do

| Limitation | Detail |
|------------|--------|
| Asymmetric quorum | Cannot run with 1-of-3 as writable “degraded mode” |
| Witness / non-voter nodes | All members are voting peers in current API |
| Automatic split-brain merge | Divergent majorities from misconfiguration require manual DR |
| Network policy enforcement | Operators must ensure Raft TCP (`:63001`) between all replicas — see `networkpolicy.yaml` |

### Partition diagram

```
        Partition A (majority)              Partition B (minority)
   ┌─────────┐     ┌─────────┐              ┌─────────┐
   │ node 1  │◄───►│ node 2  │      ✕       │ node 3  │
   │ LEADER  │     │ follower│   network    │ isolated│
   └─────────┘     └─────────┘              └─────────┘
        │ writes OK                              │ writes FAIL
        └──────── replicated ────────────────► │ catches up on heal
```

### Observability during partitions

```bash
curl -s http://pod:8200/ready | jq    # raft_ready, leader
curl -s http://pod:8200/metrics | grep knxvault_raft
```

Alerts: `deployments/prometheus/knxvault-alerts.yaml` — leader loss, commit index stall.

Integration tests: `TestRaftLeaderFailover` (`test/integration/raft_test.go`), `test/chaos/raft-pod-kill.sh`.

---

## Quick reference

| Task | Document / API |
|------|----------------|
| Node ID planning | [dragonboat.md](dragonboat.md) |
| Add/remove peer | `POST /sys/raft/add-node`, `remove-node` |
| Backup | `POST /sys/backup` |
| Restore | `POST /sys/restore` |
| Init vault | `POST /sys/init` |
| Failover runbook | [raft-failover.md](../operations/runbooks/raft-failover.md) |
| Scale cluster | [scaling.md](../operations/runbooks/scaling.md) |
| Backup format | [backup-restore.md](../deploy/backup-restore.md) |

## Code map

| File | Responsibility |
|------|----------------|
| `internal/raft/nodehost.go` | NodeHost boot, `StartCluster`, snapshot entry threshold |
| `internal/raft/statemachine.go` | `SaveSnapshot` / `RecoverFromSnapshot` |
| `internal/raft/store.go` | Export/import snapshot, command dispatch |
| `internal/raft/membership.go` | `AddNode` / `RemoveNode` |
| `internal/raft/client.go` | Propose, SyncRead export, `RequestSnapshot` |
| `internal/raft/snapshot.go` | Raft-proposed `snapshot.import` |
| `internal/backup/import.go` | `ValidateSnapshot`, `Restore` |
| `internal/service/backup.go` | Encrypted backup orchestration |
| `internal/app/deps.go` | Readiness / quorum gating |
| `internal/raft/leader.go` | Leader election loop for jobs |