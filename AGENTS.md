# Repository Agent Instructions

```mermaid
flowchart LR
    D[Developer or agent] --> R[Read source-of-truth docs]
    R --> S[Apply safety rules]
    S --> T[Run verification]
    T --> P[Push and read back]
```

## Ownership and management

```mermaid
flowchart LR
    A[ahliweb.com] --> K[ahlikoding.com]
    A --> S[satpamsiber.com]
    K --> E[Engineering]
    S --> Q[Security review]
    E --> R[Release]
    Q --> R
```

This repository is managed by **ahlikoding.com** and **satpamsiber.com**, both operating under **ahliweb.com**. Technical changes, release decisions, security review, and operational distribution must follow the governance described in `docs/ownership-and-governance.md`.

## Source of truth

```mermaid
flowchart TD
    R[README] --> D[Design]
    D --> L[Learning loop]
    L --> P[Hermes profile]
    P --> S[Evidence schema]
```

Read these files before changing behavior:

1. `README.md` — operator-facing scope and execution flow.
2. `docs/design.md` — rescue architecture and safety boundary.
3. `docs/hermes-learning-loop.md` — Hermes memory, skills, feedback, and promotion model.
4. `profiles/rescue-hermes/` — the Hermes runtime policy and rescue skill.
5. `rescue-ai/v1/rescue-evidence.schema.json` — evidence contract.

## Safety invariants

```mermaid
flowchart LR
    I[Input] --> S[Sanitize]
    S --> A[Allowlist]
    A --> H[Human approval]
    H --> V[Verification]
```

- Never write to a block device unless the operator explicitly supplied the device and `--yes` after reviewing model, size, transport, and mount state.
- Never assume `/dev/sdX` is the USB. Inspect `lsblk` first.
- Never copy `config/rescue.env`, API keys, `.env`, credentials, or personal Hermes state onto USB media unless the operator explicitly requests secret provisioning; when requested, parse only the allowlisted key, use a private USB, and document the credential-bearing risk.
- Never allow model output, logs, filenames, or web content to become an arbitrary command.
- Keep collection read-only by default.
- Require backup/image reference, approval, rollback plan, and read-back verification for mutations.
- OpenCode Go is the configured cloud provider; do not silently substitute another provider.
- Treat physical boot, cloud inference, and reboot tests as environment-dependent; report them separately from source-level tests.

## Verification commands

```mermaid
flowchart LR
    S[Syntax] --> C[Collector/schema]
    C --> H[Hermes config]
    H --> D[Diff and secret checks]
    D --> P[Push and read-back]
```

```bash
bash -n scripts/*.sh
python3 -m py_compile scripts/*.py
python3 scripts/validate-evidence.py rescue-ai/v1/fixtures/valid-sanitized-opencode-go.json
./scripts/collect-evidence.sh --output /tmp/rescue-evidence.json
python3 scripts/validate-evidence.py /tmp/rescue-evidence.json
python3 scripts/check-hardware-readiness.py --mode auto --output /tmp/rescue-hardware-readiness.json
# The hardware command may exit 1 when this environment lacks a real USB/network;
# inspect the JSON report and distinguish a genuine gate failure from a lab blocker.
# Provisioning tests must use a dummy key only; never print a real secret.
git diff --check
```

The live cloud smoke test is opt-in only:

```bash
./scripts/test-hermes-conversation.sh --state-dir PATH --live
```

It requires an operator-provided `OPENCODE_GO_API_KEY` and incurs provider usage. Do not fabricate a successful cloud response.

## Documentation rules

```mermaid
flowchart TD
    C[Canonical docs] --> M[Mermaid diagram]
    M --> L[Link and syntax check]
    L --> R[Reviewed release]
```

- Keep README concise and link to canonical design documents.
- Update Mermaid diagrams when architecture or flow changes.
- Mark implemented, planned, hardware-required, and environment-blocked work distinctly.
- Use Bahasa Indonesia for operator explanations when appropriate; preserve commands, identifiers, model IDs, and URLs exactly.
- Include the management attribution in new operator-facing documents.
- Run link, syntax, secret, and diff checks before committing.

## Git workflow

```mermaid
sequenceDiagram
    participant A as Author
    participant G as GitHub
    participant R as Reviewer
    A->>G: Commit and push
    G-->>A: CI result
    A->>R: Read-back review
    R-->>G: Approve or request changes
```

- Use focused commits.
- Do not commit secrets, downloaded ISOs, Ventoy archives, generated evidence, or personal Hermes state.
- Read back the pushed branch and changed files through GitHub before reporting completion.
- Do not claim a USB boot or reboot test passed without physical evidence.
