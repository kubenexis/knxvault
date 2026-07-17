<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# System Architecture Diagrams

Visual reference for KNXVault components and data flows. Diagrams use [Mermaid](https://mermaid.js.org/) syntax.

## Layered architecture

```mermaid
graph TD
    subgraph API["API layer (internal/api)"]
        Router[Gin router]
        Handlers[Native handlers]
        VaultH[Vault profile handlers]
        Middleware[Auth · RBAC · Rate limit · Signing · Logging]
        DTO[DTOs]
        Compat[internal/compat/vault mapping]
    end

    subgraph Service["Service layer (internal/service) — façade"]
        PKISvc[PKI service]
        SecSvc[Secrets service]
        AuthSvc[Auth service]
        AuditSvc[Audit service]
    end

    subgraph Engine["Engine layer (internal/engine)"]
        PKIEng[PKI engine]
        KVEng[KVv2 engine]
        DBEng[Database creds engine]
        SSHEng[SSH engine]
    end

    subgraph K8sProduct["Kubernetes products"]
        Operator[knxvault-operator]
        CSI[CSI provider]
        ESO[ESO webhook]
    end

    subgraph Infra["Infrastructure"]
        Crypto[Envelope crypto]
        NativePKI[Native Go crypto/x509 PKI]
        RaftSM[Raft state machine]
        Jobs[Background jobs]
    end

    Router --> Middleware --> Handlers & VaultH
    Handlers --> DTO
    VaultH --> Compat --> PKISvc & AuthSvc
    Handlers --> PKISvc & SecSvc & AuthSvc & AuditSvc
    Operator -->|native /pki/* + /auth/kubernetes| PKISvc
    CSI --> SecSvc
    ESO --> SecSvc
    PKISvc --> PKIEng
    SecSvc --> KVEng & DBEng & SSHEng
    PKIEng & KVEng --> Crypto
    PKIEng --> NativePKI
    PKISvc & SecSvc & AuditSvc --> RaftSM
    Jobs -.->|leader only| RaftSM
```

## Request path (authenticated write)

```mermaid
sequenceDiagram
    participant C as Client
    participant API as REST API
    participant Auth as Auth middleware
    participant Svc as Service
    participant Eng as Engine
    participant Raft as Raft cluster
    participant Audit as Audit

    C->>API: POST /secrets/kv/app/db
    API->>Auth: Validate Bearer token + policy
    Auth-->>API: Actor + capabilities
    API->>Svc: WriteSecret
    Svc->>Eng: Seal payload (DEK + master key)
    Eng-->>Svc: Encrypted version
    Svc->>Raft: Propose secret.save_version
    Raft-->>Svc: Committed
    Svc->>Audit: Append hash-chained entry
    Svc-->>API: Version metadata
    API-->>C: 200 JSON response
```

## PKI certificate issuance (native)

```mermaid
sequenceDiagram
    participant C as Client / Operator
    participant API as REST API
    participant PKI as PKI engine
    participant Native as Go crypto/x509
    participant Raft as Raft cluster

    C->>API: POST /pki/issue or /pki/sign or /pki/renew
    API->>PKI: IssueCertificate / SignCSR / Renew
    PKI->>Raft: ca.get_by_name (read)
    PKI->>Native: CreateRoot / Issue / SignCSR
    Native-->>PKI: PEM cert + key
    PKI->>PKI: Encrypt private key (envelope) when storing
    PKI->>Raft: issued.save (if auto_renew / tracked)
    PKI-->>API: Certificate bundle + ca_id when applicable
    API-->>C: 200 / 201 JSON response
```

## Operator TLS path (preferred — no cert-manager)

```mermaid
sequenceDiagram
    participant CR as KNXVaultCertificate
    participant Op as knxvault-operator
    participant Auth as POST /auth/kubernetes
    participant V as KNXVault PKI
    participant Sec as kubernetes.io/tls Secret

    CR->>Op: Reconcile
    Op->>Auth: SA JWT → client token
    Auth-->>Op: token
    Op->>V: GET CA by name (Issuer Ready)
    Op->>V: POST /pki/issue or /renew or /sign
    V-->>Op: cert + key + serial + caId
    alt delivery Secret
        Op->>Sec: Write tls.crt / tls.key + annotations
    else delivery None
        Op-->>CR: Status only (no key in etcd)
    end
    Op-->>CR: Ready + serial + caId
```

## cert-manager Vault profile (optional legacy)

```mermaid
sequenceDiagram
    participant CM as cert-manager Vault issuer
    participant V1 as /v1/* profile
    participant Map as internal/compat/vault
    participant Svc as Auth + PKI services

    CM->>V1: GET /v1/sys/health
    V1-->>CM: 200 / 429 / 503
    CM->>V1: POST /v1/auth/.../login or X-Vault-Token
    V1->>Map: auth envelope
    Map->>Svc: LoginKubernetes / LoginAppRole
    Svc-->>CM: client_token
    CM->>V1: POST /v1/pki/sign/role (CSR + SANs)
    V1->>Map: SignRequest → SignResult
    Map->>Svc: SignCSR
    Svc-->>CM: data.certificate + issuing_ca + ca_chain
```

## 3-node Raft topology (Kubernetes)

```mermaid
graph LR
    subgraph K8s["Namespace: knxvault"]
        S0[knxvault-0<br/>node 1]
        S1[knxvault-1<br/>node 2]
        S2[knxvault-2<br/>node 3]
        HSVC[knxvault-raft<br/>headless Service]
        HTTP[knxvault<br/>ClusterIP Service]
    end

    S0 --- HSVC
    S1 --- HSVC
    S2 --- HSVC
    HTTP --> S0 & S1 & S2

    S0 <-->|Raft :63001| S1
    S1 <-->|Raft :63001| S2
    S0 <-->|Raft :63001| S2
```

Only the **Raft leader** runs background jobs (lease cleanup, CRL refresh, cert renewal). Any replica can serve linearizable reads and propose writes.

## Secrets injection

**Primary:** Secrets Store CSI provider (`knxvault-csi`). Sidecar/init remain fallbacks.

```mermaid
graph LR
    subgraph Pod
        CSI[CSI volume]
        App[application]
    end

    SA[Pod ServiceAccount] -->|JWT| Auth[POST /auth/kubernetes]
    Auth --> KNX[KNXVault]
    KNX -->|mount files| CSI
    CSI --> App
```

See [Secrets injection](../deploy/secrets-injection.md) and [CSI install](../deploy/csi-install.md).

## Observability path

```mermaid
graph LR
    KNX[KNXVault] -->|/metrics| Prom[Prometheus]
    KNX -->|structured logs| Loki[Loki / journald]
    KNX -->|OTLP HTTP| OTel[OpenTelemetry Collector]
    Prom --> Graf[Grafana dashboard]
    OTel --> Jaeger[Jaeger / Tempo]
```

Dashboard JSON: [`deployments/grafana/knxvault-overview.json`](../../deployments/grafana/knxvault-overview.json).