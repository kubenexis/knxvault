# LLD ↔ implementation traceability

Maps [`docs/lld.md`](../lld.md) sections to code paths and backlog status. Updated 2026-06.

| LLD § | Feature | Code path | Backlog | Status |
|-------|---------|-----------|---------|--------|
| §4.A.1 | OpenSSL sandboxed wrapper | `internal/crypto/openssl/wrapper.go` | W3-03 | ✅ Shipped |
| §4.A.1 | OpenSSL circuit breaker | `internal/crypto/openssl/breaker.go` | W38-17 | ✅ Shipped |
| §4.A.3 | PKI issuance roles | `internal/domain/pki/role.go`, engine validation | W38-03 | ✅ Minimal |
| §4.A.4 | Secure key zeroing | `internal/crypto/memzero/memzero.go` | W38-10 | ✅ Shipped |
| §4.B.1 | KVv2 versioned secrets | `internal/engine/secrets/kvv2.go` | W6-01 | ✅ Shipped |
| §4.B.1 | Atomic Raft KV put | `internal/raft/commands.go` `OpSecretPut` | W36-05 | ✅ Shipped |
| §4.B.1 | KV list/metadata/versions | `internal/api/handlers/secrets.go` | W38-01 | ✅ Shipped |
| §4.C.1 | Token create/renew/revoke | `internal/auth/token.go`, `handlers/auth.go` | W38-02 | ✅ Shipped |
| §4.C.1 | K8s fail-closed auth | `internal/auth/token.go` `LoginKubernetes` | W36-01 | ✅ Shipped |
| §4.C.1 | Kubernetes TokenReview | `internal/infra/k8s/tokenreview.go` | W36-02 | ✅ Shipped |
| §4.C.1 | SA role bindings | `domain/auth/role.go` bindings | W36-03 | ✅ Shipped |
| §4.C.1 | Master key required (Raft) | `internal/app/deps.go` | W36-04 | ✅ Shipped |
| §4.C.2 | RBAC policies | `internal/auth/rbac.go` | W7-01 | ✅ Shipped |
| §4.D | Dragonboat Raft storage | `internal/raft/` | W23–W29 | ✅ Shipped |
| §5.4 | CORS + security headers | `internal/api/middleware/securityheaders.go` | W38-20 | ✅ Shipped |
| §6.4 | CSI provider | `cmd/knxvault-csi/` | W39-01 | ✅ Shipped |
| §6.4 | Mutating webhook (CSI inject) | `cmd/knxvault-webhook/`, `internal/webhook/` | W38-07 | ✅ Shipped |
| §6.5 | NetworkPolicy + PDB | `deployments/k8s/networkpolicy.yaml`, `pdb.yaml` | W38-05 | ✅ Shipped |
| §6.5 | Startup probe + seccomp | `deployments/k8s/statefulset.yaml` | W38-21 | ✅ Shipped |
| §7.1 | Raft peer mTLS | `internal/raft/nodehost.go` | W38-14 | ✅ Shipped |
| §7.2 | CA rotation workflow | `POST /pki/ca/:id/rotate` stub | W38-24 | 🔶 Stub |
| §7.3 | Audit hash chain | `internal/audit/service.go` | W7-04 | ✅ Shipped |
| §7.3 | Per-entry signatures | `domain/audit/entry.go` `Signature` | W38-09 | ✅ Shipped |
| §7.3 | Audit SIEM forward | `internal/audit/forward.go` | W38-08 | ✅ Shipped |
| §7.4 | API TLS from PKI | `POST /sys/tls/issue-listener` | W38-15 | ✅ Shipped |
| §7.7 | semgrep CI gate | `.semgrep/knxvault.yml`, `make semgrep` | W38-16 | ✅ Shipped |
| §8.4 | Prometheus alert rules | `deployments/prometheus/knxvault-alerts.yaml` | W38-22 | ✅ Shipped |
| §9.5 | Chaos raft pod-kill | `test/chaos/raft-pod-kill.sh` | W38-18 | ✅ Script |
| §9.5 | OpenSSL fuzz | `internal/crypto/openssl/wrapper_test.go` | W38-11 | ✅ Shipped |
| §11.2 | CLI Viper config | `cmd/knxvault-cli/cmd/root.go` | W38-13 | ✅ Shipped |
| §11.3 | Admin init API | `POST /sys/init` | W38-12 | ✅ Shipped |
| §11.3 | PKI CA import/export | `handlers/pki.go` | W38-04 | ✅ Shipped |
| §11.6 | CLI example scripts | `examples/cli/` | W38-23 | ✅ Shipped |

**Legend:** ✅ implemented · 🔶 partial/stub · 📋 backlog only

See [`docs/backlog.md`](../backlog.md) for remaining Tier 0 / Phase 5 items.