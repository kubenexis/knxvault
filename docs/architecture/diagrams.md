# System Architecture Diagrams

Visual reference for KNXVault components and data flows. Diagrams use [Mermaid](https://mermaid.js.org/) syntax.

## Layered architecture

```mermaid
graph TD
    subgraph API["API layer (internal/api)"]
        Router[Gin router]
        Handlers[Handlers]
        Middleware[Auth · RBAC · Rate limit · Signing · Logging]
        DTO[DTOs]
    end

    subgraph Service["Service layer (internal/service)"]
        PKISvc[PKI service]
        SecSvc[Secrets service]
        AuditSvc[Audit service]
    end

    subgraph Engine["Engine layer (internal/engine)"]
        PKIEng[PKI engine]
        KVEng[KVv2 engine]
        DBEng[Database creds engine]
    end

    subgraph Infra["Infrastructure"]
        Crypto[Envelope crypto]
        OpenSSL[OpenSSL wrapper]
        RaftSM[Raft state machine]
        Jobs[Background jobs]
    end

    Router --> Middleware --> Handlers --> DTO
    Handlers --> PKISvc & SecSvc & AuditSvc
    PKISvc --> PKIEng
    SecSvc --> KVEng & DBEng
    PKIEng & KVEng --> Crypto
    PKIEng --> OpenSSL
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

## PKI certificate issuance

```mermaid
sequenceDiagram
    participant C as Client
    participant API as REST API
    participant PKI as PKI engine
    participant SSL as OpenSSL
    participant Raft as Raft cluster

    C->>API: POST /pki/issue
    API->>PKI: IssueCertificate
    PKI->>Raft: ca.get_by_id (read)
    PKI->>SSL: genrsa + req + x509 (sandboxed temp dir)
    SSL-->>PKI: PEM cert + key
    PKI->>PKI: Encrypt private key (envelope)
    PKI->>Raft: issued.save (if auto_renew)
    PKI-->>API: Certificate bundle
    API-->>C: 200 JSON response
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

## Secrets injection (sidecar)

```mermaid
graph LR
    subgraph Pod
        Init[init container]
        Side[sidecar injector]
        App[application]
        Vol[emptyDir volume]
    end

    KNX[KNXVault API] -->|POST /inject/render| Init
    KNX -->|POST /inject/render| Side
    Init --> Vol
    Side --> Vol
    Vol --> App
```

See [Secrets injection](../deploy/secrets-injection.md) for manifest examples.

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