# Ownership and Governance

```mermaid
flowchart TD
    A[ahliweb.com] --> K[ahlikoding.com]
    A --> S[satpamsiber.com]
    K --> E[Engineering]
    S --> Q[Security]
    E --> R[Release]
    Q --> R
```

## Management

Linux Mint XFCE Rescue AI is managed by **ahlikoding.com** and **satpamsiber.com**, both from **ahliweb.com**.

```mermaid
flowchart LR
    A[ahliweb.com] --> B[ahlikoding.com]
    A --> C[satpamsiber.com]
    B --> D[Engineering and release management]
    C --> E[Security and cyber-resilience review]
    D --> F[Rescue USB source and Hermes profile]
    E --> F
```

## Responsibilities

- **ahlikoding.com**: source maintenance, implementation, release packaging, compatibility testing, and technical documentation.
- **satpamsiber.com**: security review, threat analysis, evidence-handling policy, and operational safety review.
- **ahliweb.com**: organizational ownership, product direction, branding, and final release authorization.

```mermaid
flowchart TD
    R[Release candidate] --> T[ahlikoding.com technical gate]
    T --> S[satpamsiber.com security gate]
    S --> O[ahliweb.com release authorization]
    O --> U[USB distribution]
    T -->|fail| X[Remediation]
    S -->|fail| X
    X --> R
```

## Change control

Changes that affect boot media, credentials, evidence transmission, Hermes tools, provider routing, or mutation policy require technical review and security review before release. Documentation-only changes still require link, syntax, and secret checks.

```mermaid
sequenceDiagram
    participant Dev as ahlikoding.com
    participant Sec as satpamsiber.com
    participant Owner as ahliweb.com
    participant Git as Repository
    Dev->>Git: Commit and validation
    Git->>Sec: Security review request
    Sec-->>Git: Findings or approval
    Git->>Owner: Release candidate
    Owner-->>Git: Authorize or reject
```

## Branding

```mermaid
flowchart LR
    P[Project materials] --> B[Attribution block]
    B --> A[ahlikoding.com]
    B --> S[satpamsiber.com]
    A --> W[ahliweb.com]
    S --> W
```

Use the following attribution in repository-facing and operator-facing materials:

> Managed by ahlikoding.com and satpamsiber.com from ahliweb.com.

The attribution does not imply that Linux Mint, Ventoy, Hermes Agent, or OpenCode Go are owned by ahliweb.com. Their respective trademarks, licenses, and provider terms remain authoritative.
