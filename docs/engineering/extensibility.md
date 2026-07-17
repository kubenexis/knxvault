<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Extensibility guide — engines, façades, and “plugins”

How KNXVault is built to be extended, and how to add new capability **without** HashiCorp Vault–style loadable plugins.

| Field | Value |
|-------|-------|
| **Audience** | Contributors, integrators, platform engineers, architects |
| **Status** | Current (reflects M-ACME-1; M-DNS01-1 planned) |
| **Related** | [HLD](../architecture/hld.md) · [Security model](../architecture/security-model.md) · [Contributing](contributing.md) · [DNS-01 design](../design/dns01-providers-and-webhooks.md) · [Phase 4–5 ecosystem](../design/phase4-ecosystem.md) |

---

## 1. Mental model

KNXVault is **extensible by design**, but **not** via binary plugins (`.so` / external Vault plugin processes).

| Extension style | Supported? | How |
|-----------------|------------|-----|
| In-tree Go secret engines | **Yes** | `engine.SecretEngine` + `engine.Registry` |
| Product-profile HTTP façades | **Yes** | `internal/compat/<profile>` |
| Operator multi-issuer modes | **Yes** (Vault / ACME / SelfSigned) | CRDs + reconciler |
| Out-of-tree DNS-01 providers | **Yes** | HTTP **webhook** (primary out-of-tree path) |
| Separate K8s delivery adapters | **Yes** | CSI / ESO / mutating webhook binaries |
| Loadable Vault-style plugins | **No** | Explicit non-goal (HLD + M-DNS01-1) |

```text
                    ┌─────────────────────────────────────┐
                    │  knxvault core (static binary)      │
                    │  engines · services · product profile│
                    └──────────────┬──────────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        ▼                          ▼                          ▼
  in-tree Go code           HTTP webhooks              K8s adapters
  (engines, issuers,        (DNS-01 today;             (CSI, ESO,
   compat façades)           registry planned)          operator)
```

**Rule of thumb**

- Need something **inside** the trust boundary (crypto, secret storage, RBAC): implement **in-tree**.
- Need a **DNS provider or external system** the core should not depend on: implement an **HTTP webhook** (or thin out-of-tree adapter).

---

## 2. What is intentionally *not* supported

From the [HLD out-of-scope](../architecture/hld.md) list and DNS-01 design non-goals:

- Full HashiCorp Vault feature parity (arbitrary `/v1` secret engines via plugins)
- Binary plugins (`.so`) — licensing and load complexity
- Third-party enterprise CAs (Venafi, AWS PCA, …) as a shipped plugin API — future “external issuer” work
- Drop-in cert-manager DNS webhook gRPC compatibility (optional later; HTTP first)

---

## 3. Extension map (quick choose)

| You want… | Mechanism | Rebuild knxvault? |
|-----------|-----------|-------------------|
| New DNS provider (Route53, PowerDNS, …) | DNS-01 **HTTP webhook** | **No** |
| First-party DNS provider | In-tree `DNS01Presenter` + `BuildSolvers` | **Yes** |
| New secret engine | `SecretEngine` + register + handlers | **Yes** |
| New foreign wire format (another client) | `internal/compat/<profile>` façade | **Yes** |
| New TLS issuer kind | Operator CRD + reconciler + issuer | **Yes** |
| New secrets delivery into pods | CSI / ESO / mutating webhook style | Separate binary |

---

## 4. Secret engines (in-tree)

### 4.1 Interfaces and registry

```go
// internal/engine/interfaces.go
type SecretEngine interface {
    Name() string
    Put(ctx context.Context, path string, data map[string]any) error
    Get(ctx context.Context, path string) (map[string]any, error)
}
```

`internal/engine.Registry` maps engine names → implementations (`Register`, `Get`, `List`, `Put`, `GetSecret`).

Startup wiring (`internal/app/deps.go`) registers:

| Name (typical) | Package | Notes |
|----------------|---------|--------|
| `kv` | `internal/engine/secrets` | KVv2 |
| database | `internal/engine/secrets/database` | Dynamic DB creds (adapter; real API is roles/leases) |
| ssh | `internal/engine/secrets/ssh` | SSH CA / signed keys |
| (PKI) | `internal/engine/pki` | Own engine surface; not only via thin Put/Get |

Adapters: `internal/engine/secrets/*/registry_adapter.go`.

### 4.2 How to add a secret engine

1. **Domain** — types/errors under `internal/domain/` if new entities are needed.
2. **Persistence** — repository interface + Dragonboat/memory implementation if state is replicated.
3. **Engine** — package under `internal/engine/<name>/` (or `secrets/<name>/`) with business logic.
4. **Registry adapter** — implement `engine.SecretEngine` (or wrap with `RegistryAdapter`).
5. **Wire-up** — in `internal/app/deps.go`:
   ```go
   deps.EngineRegistry.Register(myengine.NewRegistryAdapter(deps.MyEngine))
   ```
6. **API** — handlers + DTOs in `internal/api/`; update `api/openapi.yaml`.
7. **Tests** — unit tests next to code; integration where paths cross storage/auth.
8. **Docs** — recipe or deploy guide; update capability matrices if user-facing.

**Constraints**

- Domain packages must not import infrastructure.
- Direct dependencies must stay **Apache-2.0** (or similarly permissive) — see [licensing](../licensing.md).
- There is **no** runtime config key that loads external engine code.

### 4.3 Minimal adapter sketch

```go
package myengine

import (
    "context"
    "github.com/kubenexis/knxvault/internal/engine"
)

type RegistryAdapter struct{ *Engine }

func NewRegistryAdapter(e *Engine) RegistryAdapter {
    return RegistryAdapter{Engine: e}
}

func (a RegistryAdapter) Name() string { return "myengine" }

func (a RegistryAdapter) Put(ctx context.Context, path string, data map[string]any) error {
    return a.Engine.Put(ctx, path, data)
}

func (a RegistryAdapter) Get(ctx context.Context, path string) (map[string]any, error) {
    return a.Engine.Get(ctx, path)
}

// Compile-time check
var _ engine.SecretEngine = RegistryAdapter{}
```

---

## 5. Product profiles (`internal/compat/*`)

**Principle:** native services are authoritative. Product profiles only map **foreign wire formats** onto those services.

Shipped example: **Vault product profile** for optional cert-manager dual-run:

```text
Foreign client (cert-manager Vault issuer)
        │
        ▼
  HTTP /v1/*  (handlers)
        │
        ▼
  internal/compat/vault  (pure mapping)
        │
        ▼
  auth.Service + PKIService  (authoritative)
```

Package docs: `internal/compat/vault/doc.go`.

### How to add a profile

1. Create `internal/compat/<name>/` with pure request/response mapping.
2. Add thin handlers (no second PKI/secrets stack).
3. Register routes; document dual-run or migration path.
4. Tests: mapping unit tests + integration against native services.

Do **not** reimplement issuance or KV storage inside the profile.

---

## 6. Operator multi-issuer

TLS automation uses knxvault-operator CRDs (`KNXVaultIssuer` / `KNXVaultClusterIssuer`):

| Mode | Purpose |
|------|---------|
| `Vault` | Private CA via knxvault PKI |
| `ACME` | Public/private ACME (Let's Encrypt, Pebble, …) |
| `SelfSigned` | Leaf self-signed without external CA |

Factory helpers live in `internal/acme/issuer_factory.go` (`NewIssuerFromKind`, `BuildSolvers`).

### How to add an issuer kind (in-tree)

1. Extend CRD types under `internal/operator/apis/v1alpha1`.
2. Validate “exactly one of …” issuer mode rules.
3. Implement issue/renew path in reconciler + shared issuer interface.
4. Samples under `deployments/operator/samples/`.
5. Update [certificate support matrix](../operations/certificate-support-matrix.md) and operator docs.

Enterprise public CAs remain a **future external issuer** direction, not a plugin SDK yet.

---

## 7. ACME DNS-01 — primary out-of-tree “plugin” path

### 7.1 Today

| Piece | Status |
|-------|--------|
| `DNS01Presenter` (`Present` / `CleanUp`) | Yes |
| In-tree `cloudflare` | Yes |
| In-tree `memory` (tests) | Yes |
| Generic HTTP `webhook` | Yes (simple contract) |
| Multi-solver / domain selectors | Planned (**M-DNS01-1**) |
| Provider registry package | Planned (**M-DNS01-1**) |

Solver construction: `acme.BuildSolvers` — providers `memory` | `webhook` | `cloudflare`.

Operator sample comments: `deployments/operator/samples/acme-clusterissuer-example.yaml`.

Full roadmap: [DNS-01 providers and webhooks](../design/dns01-providers-and-webhooks.md).

### 7.2 Webhook contract (current)

**Request:** `POST` JSON

```json
{
  "action": "present",
  "domain": "app.example.com",
  "fqdn": "_acme-challenge.app.example.com.",
  "value": "<ACME DNS-01 TXT payload>"
}
```

| Field | Meaning |
|-------|---------|
| `action` | `present` (create TXT) or `cleanup` (delete TXT) |
| `domain` | Certificate / challenge domain |
| `fqdn` | Full challenge FQDN (usually `_acme-challenge.<domain>.`) |
| `value` | TXT record content |

**Response:** HTTP **2xx** = success. Non-2xx = failure; body text is logged.

**Security**

- Production URL validation uses SSRF checks (`ValidateOutboundURL`).
- Prefer cluster-internal Service URLs or private HTTPS with tight network policy.
- Do not expose an unauthenticated DNS-mutating webhook on the public internet.

### 7.3 Planned webhook v1 (M-DNS01-1, additive)

```json
{
  "apiVersion": "acme.knxvault.io/v1",
  "action": "present|cleanup",
  "domain": "app.example.com",
  "fqdn": "_acme-challenge.app.example.com.",
  "value": "<TXT payload>",
  "key": "<alias of value>",
  "uid": "<optional challenge id>",
  "config": { }
}
```

`config` is opaque JSON from the Issuer CR / CLI profile so out-of-tree providers receive settings without knxvault knowing provider details. Optional bearer/basic/mTLS auth is planned.

### 7.4 Configure knxvault to use your webhook

**Operator (ClusterIssuer sketch):**

```yaml
apiVersion: knxvault.kubenexis.dev/v1alpha1
kind: KNXVaultClusterIssuer
metadata:
  name: letsencrypt-dns-webhook
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: ops@example.com
    dns01:
      provider: webhook
      webhookURL: http://dns-webhook.knxvault.svc/present
```

**CLI / standalone profile:** set DNS provider to `webhook` and the same URL in the ACME profile used by `knxvault-cli acme` (see `examples/acme/` and ACME design docs).

### 7.5 Reference webhook skeleton (Go)

Minimal server you can run as a Deployment/sidecar. Replace the `// TODO` body with your DNS API.

```go
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
)

type body struct {
	Action string `json:"action"`
	Domain string `json:"domain"`
	FQDN   string `json:"fqdn"`
	Value  string `json:"value"`
	// Future v1 fields (ignore until knxvault sends them):
	// APIVersion string         `json:"apiVersion"`
	// Key        string         `json:"key"`
	// Config     json.RawMessage `json:"config"`
}

func main() {
	addr := env("LISTEN", ":8080")
	mux := http.NewServeMux()
	mux.HandleFunc("/present", handle) // knxvault posts here for present + cleanup
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	log.Printf("dns01 webhook listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var b body
	if err := json.Unmarshal(raw, &b); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	switch b.Action {
	case "present":
		// TODO: upsert TXT at b.FQDN = b.Value (your DNS API)
		log.Printf("present domain=%s fqdn=%s", b.Domain, b.FQDN)
	case "cleanup":
		// TODO: delete that TXT
		log.Printf("cleanup domain=%s fqdn=%s", b.Domain, b.FQDN)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
```

**Hardening checklist for production webhooks**

- [ ] Authenticate callers (shared bearer, mTLS, or NetworkPolicy to operator SA only)
- [ ] Idempotent `present` / `cleanup`
- [ ] Bound request body size; structured logs without leaking tokens
- [ ] Prefer HTTPS or mesh mTLS inside the cluster
- [ ] Apache-2.0 (or similarly permissive) dependencies if you ship a binary next to knxvault

### 7.6 Adding an **in-tree** DNS provider

1. Implement `DNS01Presenter` in `internal/acme/` (or future `internal/acme/providers/<name>/`).
2. Extend `SolverSpec` + `BuildSolvers` switch.
3. Wire operator CR fields + CLI profile parsing.
4. Unit tests with fake DNS API / `httptest`.
5. Document in certificate support matrix and design doc status table.

---

## 8. Kubernetes ecosystem adapters

These are **separate processes**, not secret-engine plugins:

| Binary | Role |
|--------|------|
| `knxvault-csi` | Secrets Store CSI provider |
| `knxvault-webhook` | Mutating admission → CSI volume injection |
| `knxvault-eso` | External Secrets Operator webhook adapter |
| `operator` (`cmd/operator`) | CA / Certificate / Issuer CRDs |

To add a new delivery path: ship a small binary that calls the **native** knxvault REST API (or uses `pkg/client`), plus deploy manifests under `deployments/`. Prefer reusing existing auth (K8s SA JWT, AppRole, tokens) and RBAC policies.

---

## 9. Do we need to split knxvault for extensibility?

### 9.1 Recommendation

**No — a core split is not required to improve extensibility.**

What knxvault already has matches a security-minded model:

| Layer | Shape today | Role |
|-------|-------------|------|
| **Trust core** | Single server binary + Raft cluster | Seal/unseal, master key, auth/RBAC, engines, PKI, audit |
| **Edge processes** | Operator, CSI, ESO, mutating webhook, CLI | High-privilege *cluster* surfaces; no master key in ideal deployments |
| **Out-of-tree extension** | HTTP (DNS-01 webhooks) | Third parties without loading code into the core process |
| **In-tree extension** | Interfaces, registries, product-profile façades | First-party / trusted code reviewed with the core |

That is **“hard core + soft plugins at the network edge”**, not a monorepo problem that needs microservices or Vault-style plugins.

Splitting *can* help later for **team scale**, **edge image size / dependency CVEs**, or **untrusted third-party engines** — but a naive split often **hurts** security and operability. Prefer stronger **contracts** (webhook v1, registries) over restructuring the sealed data plane.

### 9.2 What “split” might mean

| Kind of split | Already? | Helps extensibility? | Security impact |
|---------------|----------|----------------------|-----------------|
| **Separate binaries** (server / operator / CSI / ESO / webhook / CLI) | **Yes** | Medium — each surface deploys alone | **Good** if least privilege per binary |
| **Package boundaries** inside one module (`engine`, `compat`, `acme`, …) | **Yes** | High for contributors | Neutral; best ROI today |
| **Go multi-module monorepo** (`knxvault-core`, `-operator`, `-acme`) | No | Mild (build isolation) | Mild — smaller dep graphs if done well |
| **Process plugins** (Vault-style RPC / `.so` / external plugin) | Explicit non-goal | High for third parties | **High risk** without a full capability + attestation model |
| **Microservices core** (auth, KV, PKI, ACME as separate services) | No | Medium | **Often worse** for secrets systems |
| **Separate git repos** | No | Low–medium for open ecosystem | Version skew + supply-chain risk |

**Preferred order of investment**

1. Keep **one sealed data plane**
2. Harden **interfaces** (engine registry, issuer factory, DNS provider registry, webhook contracts)
3. Process-isolate **untrusted or high-noise edges** (already started)
4. Consider **multi-module** later if build/CI or image CVE drag appears — not for security theater

### 9.3 Why a core split is not needed for extensibility

**Extensibility is an interface problem, not a repo problem.**  
What unlocks “extend without forking” is a **stable contract** (DNS-01 webhook today; richer v1 under M-DNS01-1), not splitting `go.mod`. Vault’s plugin system exists so arbitrary engines can ship without recompiling. knxvault deliberately chose the opposite: **curated engines in-tree**, **webhooks out-of-tree**.

**The hard core should stay cohesive.** These belong in one process (or one tightly coupled HA cluster):

- Master key / unseal
- Envelope crypto
- Raft state machine
- Token store + RBAC
- CA private keys (decrypt → use → zero)
- Hash-chained audit integrity

Splitting “KV service” vs “PKI service” vs “auth service” without extreme care trades **one well-understood TCB** for **many trust boundaries**, each needing authn, authz, transport security, and correlated audit — usually for little extension benefit.

**The project already split the right things:**

| Component | Why separate is good |
|-----------|----------------------|
| Operator | Talks to K8s API + knxvault; holds issuer config, not the master key in ideal setups |
| CSI / ESO / inject webhook | High privilege in cluster; compromise ≠ vault master key if tokens are path-scoped |
| CLI | Host admin tool; not in the distroless server image |
| DNS webhook (out-of-tree) | Mutates DNS; must **not** hold vault master key |

### 9.4 Target shape (keep core, extend at the edge)

```text
┌──────────────────────────────────────────────────────────┐
│  knxvault-server (single TCB)                            │
│  seal · master key · Raft · auth/RBAC · engines · PKI    │
│  stable interfaces: SecretEngine, Issuer, DNS01Presenter │
└─────────────┬────────────────────────────┬───────────────┘
              │ native API / SA auth       │ DNS-01 HTTP only
              ▼                            ▼
     operator · CSI · ESO          out-of-tree DNS webhooks
     (already separate)            (third-party / per-cloud)
```

**Improve extensibility without a risky core split**

1. Finish **M-DNS01-1** — versioned webhook, opaque `config`, auth, provider registry  
2. Keep engines **in-tree** with clean packages + registration checklist (this guide §4)  
3. Optional **multi-module** later only for operator/CSI dep hygiene (smaller images)  
4. **Never** put master key / unseal path into operator, CSI, or webhooks  
5. **Capability-scoped tokens** for every edge binary (path-limited policies)  
6. Future external issuers (Venafi, etc.): **HTTP façade + short-lived credentials**, same pattern as DNS webhooks — not in-process plugins  

### 9.5 Security concerns by split approach

See also the [security model](../architecture/security-model.md) (threats, in-process PKI, seal/unseal).

#### A. Process plugins / external secret engines (Vault-like)

**Highest risk class for a secrets manager.**

| Concern | Why it matters |
|---------|----------------|
| **Master key / DEK exposure** | A plugin that can Put/Get secrets effectively needs plaintext or a decrypt oracle → near-full compromise |
| **Confused deputy** | Core calls plugin with high privilege; plugin tricks core into sign/issue/decrypt |
| **Plugin supply chain** | Third-party binary on the vault trust path (malware, stale CVEs, license risk) |
| **IPC attack surface** | Unix socket / gRPC: plugin identity, DoS, protocol bugs |
| **Side channels** | Timing, core dumps, plugin logs |
| **Audit gaps** | Actions inside plugin may not join the same hash-chained audit trail |
| **Crash / resource isolation** | Plugin OOM/panic can starve the host or core if poorly sandboxed |
| **Seal semantics** | When sealed, plugins must fail closed across restarts — easy to get wrong |

**If this path is ever chosen (requires ADR + threat model):** no master key in plugins; **capability tokens** for narrow paths only; mTLS + attested plugin identity; allowlisted plugin hashes; seccomp/user namespaces; audit events emitted **from core after policy check**; default deny.

Current product stance (no `.so` plugins) **avoids this class almost entirely**.

#### B. Microservices split of the core (auth / KV / PKI / ACME services)

| Concern | Detail |
|---------|--------|
| **Distributed TCB** | Attacker needs any weak service that can still move secrets or mint tokens |
| **Token sprawl** | Service-to-service credentials become a second secrets problem |
| **Network surface** | East-west APIs: SSRF, MITM if mTLS incomplete, RBAC drift |
| **Consistency** | Who owns leases, tokens, seal state vs Raft? |
| **Audit fragmentation** | Multi-service traces; harder non-repudiation |
| **Privilege concentration moves** | A “PKI microservice” still holds CA keys; compromise remains catastrophic |
| **Operational load** | More certs, NetworkPolicies, upgrades → more config mistakes |

**When it can be worth it:** multi-tenant SaaS with hard isolation, or a tiny FIPS/HSM-bound crypto module. That is **not** knxvault’s current product shape (self-hosted, single product, Raft HA).

#### C. Multi-module / multi-repo split (build-only)

Mostly **supply-chain and process** risk, not runtime crypto risk:

| Concern | Detail |
|---------|--------|
| **Version skew** | Operator `v0.5` against server `v0.4` → skipped checks or auth bugs |
| **Duplicate crypto** | Two modules reimplement envelope / token verification incorrectly |
| **Weaker review** | “Just the webhook repo” gets less scrutiny but still mutates DNS or issues certs |
| **Dependency fan-out** | More `go.mod` graphs to license-scan and CVE-track |

**Upside if careful:** operator/CSI do not pull Dragonboat; smaller images; clearer ownership.

#### D. Edge webhooks (DNS-01, ESO, admission) — preferred extension model

These improve extensibility **without** placing third-party code next to the master key — **if** contracts stay narrow:

| Concern | Mitigation |
|---------|------------|
| **SSRF** (operator → webhook URL) | URL validation / allowlist, block link-local and metadata, no redirects (`ValidateOutboundURL`) |
| **Webhook god-mode for DNS** | NetworkPolicy, bearer/mTLS, DNS credentials **only in the webhook** |
| **Issuer CR as attack surface** | Cluster RBAC: who may create ClusterIssuer / Issuer |
| **ACME account key storage** | Keep in knxvault/operator secrets — not in every webhook |
| **Admission webhook** | TLS required; careful fail policy; namespace selectors |
| **CSI provider** | Node-level privilege; only path-scoped vault tokens |

### 9.6 When a split *would* be justified

Consider a **deliberate** split only if several of these become true:

| Signal | Suggested split |
|--------|-----------------|
| Untrusted third parties must ship secret engines | Plugin **process** with capability API — large design + threat model (new ADR) |
| Operator/CSI image size or CVEs dominated by Raft/crypto deps | Multi-module: shared client API vs server |
| Regulatory “crypto boundary” / HSM module | Tiny crypto process or PKCS#11; still not a full microservice mesh |
| Independent release trains for operator vs server | Separate modules/repos with **strict API versioning + compatibility tests** |

None of those are required merely to “improve the architecture of extensibility” today.

### 9.7 Summary table

| Approach | Extensibility | Security posture for knxvault |
|----------|---------------|-------------------------------|
| **Status quo + stronger contracts** | Good → excellent with M-DNS01-1 | **Best default** — small TCB, in-process PKI, edges isolated |
| **Multi-module monorepo** | Slight | Neutral/positive if edge images and deps shrink |
| **Microservices core** | Mixed | Usually **worse** for secrets/PKI without heavy investment |
| **Loadable / process plugins for engines** | Excellent for ecosystem | **Highest risk** — avoid until formal plugin threat model exists |

**Bottom line:** Split for **privilege reduction at the edges** (already doing). Do **not** split the sealed core for extensibility theater. Prefer **versioned webhooks and in-tree registries** over plugins that share memory or master-key trust with the vault.

---

## 10. Contribution workflow for extensions

Follow [contributing](contributing.md) and [development](development.md):

1. Check [backlog](../backlog.md) for overlapping work (e.g. **W61-*** for DNS-01).
2. Large design changes → [ADR](../adr/README.md) (required before process plugins or core microservice splits).
3. `make quality` (pre-merge) / `make all` before PR.
4. Unit tests with the change; keep coverage gates.
5. Docs and OpenAPI in the **same** change set when APIs move.
6. License gate: no new copyleft direct dependencies.

---

## 11. FAQ

**Q: Can I drop a `.so` into a plugins directory?**  
A: No. Use in-tree Go code or an HTTP webhook.

**Q: Can I add a Vault-compatible secret engine under `/v1/...` without forking?**  
A: Not as a loadable plugin. Either contribute an in-tree engine + handlers, or run an external service and have apps call knxvault only for what it owns.

**Q: What’s the easiest third-party extension today?**  
A: A **DNS-01 webhook** for ACME (operator or CLI). No knxvault rebuild required.

**Q: Will there be a formal plugin SDK?**  
A: Not planned as binary plugins. The stable external contract is the **versioned DNS-01 webhook API** (v1 under M-DNS01-1). Future “external issuer” work may add another HTTP contract; that is not shipped yet.

**Q: Should we split knxvault into multiple services/repos to make plugins easier?**  
A: **No by default.** See [§9](#9-do-we-need-to-split-knxvault-for-extensibility). Harden interfaces and edge webhooks first; only split when release scale, image deps, or a formal external-engine threat model demand it.

**Q: Is the operator / CSI already a “split”?**  
A: Yes — a **good** one: edge processes with scoped vault credentials, not a split of the sealed crypto/Raft core.

---

## Related documents

| Document | Why |
|----------|-----|
| [HLD](../architecture/hld.md) | Scope, non-goals, product profiles |
| [Security model](../architecture/security-model.md) | Threats, crypto, auth, seal |
| [Security posture assessment](../architecture/security-posture-assessment.md) | Honest grades; set-and-forget / custody gaps |
| [Production security posture](../design/production-security-posture.md) | M-PRODSEC-1 / M-CUSTODY-1 programs (W62–W64) |
| [Vault-class capability plan](../design/vault-class-capability-plan.md) | Transit, wrap, leases, identity; no plugin framework |
| [DNS-01 providers and webhooks](../design/dns01-providers-and-webhooks.md) | M-DNS01-1 architecture |
| [Multi-issuer ACME](../design/multi-issuer-acme.md) | Operator ACME design |
| [ACME unified (LE)](../design/acme-letsencrypt-unified.md) | CLI + operator ACME |
| [Certificate support matrix](../operations/certificate-support-matrix.md) | What is claimed vs planned |
| [Replace cert-manager](../operations/pki-replace-cert-manager.md) | Operator multi-issuer ops |
| [Phase 4–5 ecosystem](../design/phase4-ecosystem.md) | Façade design principle |
| [Development](development.md) | Layout and make targets |
| [Contributing](contributing.md) | PR checklist |
