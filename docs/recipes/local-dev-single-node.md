<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: Local dev single-node

Run KNXVault on your laptop for development without Kubernetes.

## Prerequisites

- Go 1.22+ or release binary
- `openssl`, `curl`

## Quick start

```bash
cd /path/to/knxvault
make build

export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_ROOT_TOKEN=dev-root-token
export KNXVAULT_RAFT_ENABLED=false
export KNXVAULT_LISTEN_ADDR=:8200

./build/bin/knxvault serve
```

In another terminal:

```bash
export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=dev-root-token

./build/bin/knxvault-cli doctor --json   # healthy:true, fail:0
./build/bin/knxvault-cli kv put dev/hello value=world
./build/bin/knxvault-cli kv get dev/hello                 # [REDACTED]
./build/bin/knxvault-cli kv get dev/hello --show-secrets  # plaintext
```

## Optional: single-node Raft

When Raft is enabled, **`KNXVAULT_UNSEAL_KEY` is required** and must be a base64 32-byte key **different from** `KNXVAULT_MASTER_KEY`. Startup fails with `unseal key is required when raft is enabled` if it is unset.

```bash
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_UNSEAL_KEY=$(openssl rand -base64 32)   # must differ from master
export KNXVAULT_ROOT_TOKEN=dev-root-token
export KNXVAULT_RAFT_ENABLED=true
export KNXVAULT_RAFT_NODE_ID=1
export KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001
export KNXVAULT_RAFT_DATA_DIR=/tmp/knxvault-raft

./build/bin/knxvault serve
curl -s http://localhost:8200/ready | jq .
# expect: ready, sealed:false, raft_enabled:true, raft_ready:true, leader:true
```

Lab single-node E2E on bare metal (e.g. `192.168.137.131`): [lab-e2e-test01.md](../engineering/lab-e2e-test01.md). Post-install verify fields: [Installation](../installation/install.md#post-install-verify).

## Dev-only Kubernetes auth

```bash
export KNXVAULT_JWT_SECRET=$(openssl rand -hex 32)
# Or: export KNXVAULT_K8S_AUTH_INSECURE=true
```

**Never use these in production.**

## Next steps

- [KV secrets lifecycle](kv-secrets-lifecycle.md)
- [RBAC policies](rbac-policies.md)
- [Deploy 3-node cluster](deploy-3-node-cluster.md)

## See also

- [Installation guide](../installation/install.md)
- [Development guide](../engineering/development.md)