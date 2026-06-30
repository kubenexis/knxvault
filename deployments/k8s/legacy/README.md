# Legacy Kubernetes manifests

`deployment.yaml` in this directory is a **deprecated** single `Deployment` manifest for non-Raft, in-memory dev setups. Production HA uses the **StatefulSet** in the parent directory (`../statefulset.yaml`) with Dragonboat Raft.

Do not apply `deployment.yaml` for production clusters. Use `statefulset.yaml`, `service-raft.yaml`, and related manifests documented in [`docs/deploy/kubernetes.md`](../../../docs/deploy/kubernetes.md).