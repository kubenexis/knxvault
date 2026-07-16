# Crypto generations (g1 / g2 / g3)

Platform **contracts** for classical vs PQ-ready crypto. Generations hide algorithm churn from applications while supporting dual-stack.

## Verdict

**Good idea** if generations are **named contracts** (`g1`, `g2`, `g3`…) mapped by the platform to concrete profiles and issuers. Prefer not to use bare `gx` in production APIs (reserve “gx” for design language meaning “a future generation”).

## What a generation is

A generation is a **bundle**, not a single algorithm:

| Included in a generation | Example (illustrative) |
|--------------------------|-------------------------|
| Key / signature algorithms for issued certs | g1: RSA-2048 or ECDSA-P256 |
| TLS constraints for API (if bound) | g1: TLS 1.3 classical groups |
| Envelope expectations | Shared AES-256-GCM for all gens |
| Client support assumption | g1: Harbor, mainstream containerd, ingress |

| Generation | Contract (intent) | Typical users |
|------------|-------------------|---------------|
| **g1** | Works with today’s K8s/Harbor/legacy TLS clients | Harbor, default apps |
| **g2** | PQ-aware transit and/or hybrid identity | New services with capable stacks |
| **g3** | PQ signatures / stricter matrix | Explicit allow-list only |

Platform may strengthen **new** certs inside a generation carefully; **breaking** changes for existing consumers should introduce a **new** generation or a long dual-run.

## Why generations help

| Benefit | Detail |
|---------|--------|
| Stable app contract | Apps do not hard-code `ML-DSA-65` |
| Safe dual-stack | Harbor pinned to g1; others opt into g2+ |
| Clear default | Default = **g1** |
| Operable migration | “Move payments g1 → g2 in Q3” |
| Fits multi-issuer | `ClusterIssuer/platform-g1` vs `platform-g2` |

## Mapping chain

```text
cryptoGeneration (g1|g2|g3)
        │
        ▼
CryptoProfile (concrete algs + TLS)     ← platform-owned
        │
        ▼
Issuer / CA (platform-g1, platform-g2)
        │
        ▼
Certificate → Secret → workload (Harbor, Ingress, Pod)
```

Apps/GitOps set **generation or issuer name**. Platform maps generation → algorithms.

## Harbor never calls generations

**Harbor does not know about g1/g2/g3.**

Harbor only:

```yaml
expose:
  tls:
    certSource: secret
    secret:
      secretName: harbor-tls
```

The **platform** chooses generation when creating the cert that fills that Secret:

```yaml
apiVersion: knxvault.kubenexis.dev/v1alpha1
kind: KNXVaultCertificate
metadata:
  name: harbor-tls
  namespace: harbor
spec:
  secretName: harbor-tls          # only name Harbor is configured to use
  cryptoGeneration: g1            # platform decision (or implied by issuer)
  issuerRef:
    kind: KNXVaultClusterIssuer
    name: platform-g1
  commonName: harbor.example.local
  dnsNames: [harbor.example.local]
```

| Actor | Knows g1/g2/g3? |
|-------|-----------------|
| knxvault / operator / GitOps / knxctl | Yes |
| Harbor process | No — only PEM in Secret |
| docker/containerd pulling from Harbor | No — only trust store + server cert |

```text
Generation → Issuer/CA → Certificate CR → Secret → Harbor
 (platform)   (platform)    (platform)     (K8s)    (dumb consumer)
```

knxctl convention (target): Harbor component always provisions **g1** certificates.

## How PQ-capable apps “choose”

Not usually a runtime “call g2” from app code:

| Mechanism | Who sets it |
|-----------|-------------|
| `cryptoGeneration: g2` on Certificate | App Helm chart / platform template |
| `issuerRef: platform-g2` | Same |
| `certificateClassName: platform-tls-pq` | Same |
| CSI `vaultAddress` to hybrid Service | Platform CSI config for that tenant |
| Namespace allow-list for g2 | Cluster policy |

The app **image** must support the algorithms that generation implies; the **manifest** selects the generation.

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Vague `gx` in APIs | Use g1, g2, g3 with a published matrix |
| Silent breaking change inside g1 | New generation or dual-run; don’t break Harbor mid-flight |
| Too many live generations | Cap at few (g1 + g2); retire old when unused |
| Confusion with K8s `metadata.generation` | Field name `cryptoGeneration` or label `knxvault.kubenexis.dev/crypto-generation` |
| Two Raft crypto planes | Not required; one Raft |

## Policy examples

- Default Certificate / CertificateClass → **g1**.  
- Namespace `harbor` → **g1 only**.  
- Namespace `payments-pq` → allow **g1|g2**.  
- Role `knxvault-operator` may issue both if cluster policy allows.  

## Related

- [Dual crypto planes](dual-crypto-planes.md)  
- [Roadmap](roadmap.md)  
- [PQ backlog](backlog.md)  
