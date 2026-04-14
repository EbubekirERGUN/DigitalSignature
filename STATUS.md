# DigitalSignature Status

## Current mission

Baseline-T rollout for the ETSI-facing formats in this order:

1. CAdES-T
2. ASiC-S-T
3. PAdES-T
4. XAdES-T
5. JAdES-T

Primary done criteria for each format:

- local tests pass
- runtime artifact is produced
- ETSI checker parses the artifact
- T-related checks pass
- no visible error / warning / failure regressions

## Layered operating model

### Layer 1. Orchestration

Owner: main agent session

Responsibilities:

- choose sequence and scope
- keep architecture coherent across formats
- own branch / PR / merge decisions
- decide when work is ready to move to the next format

### Layer 2. Specialized execution

Used only for narrow tasks when it improves speed or confidence.

Examples:

- ETSI checker behavior research
- one-off standards lookup
- isolated prototype for a single format problem

Rule: shared code and final integration still come back through Layer 1.

### Layer 3. Verification

Every slice must clear these checkpoints:

- format-specific unit tests
- runtime smoke tests
- runtime artifact generation under `artifacts/runtime-demo`
- ETSI checker validation when applicable

### Layer 4. Release / merge gate

Policy:

- work accumulates on `issue-baseline-t-suite`
- merge to `main` only after a meaningful T block is complete
- prefer fewer, larger, reviewable merges over many tiny merges to `main`

## Active tracking

- Active branch: `issue-baseline-t-suite`
- Active PR: #29
- Samples remain local-only
- Current merge policy: hold on feature branch until the current T block is solid

## Format matrix

| Format | Baseline-B | Baseline-T | Local | ETSI checker | Notes |
|---|---|---:|---:|---:|---|
| CAdES | Done | Done | Pass | Pass | `sample-cades-t.p7m` |
| ASiC-S | Done | Done | Pass | Pass | `sample-asic-t.asics` with inner timestamped CAdES |
| PAdES | Done | Done | Pass | Pass | `sample-pades-t.pdf` |
| XAdES | Done | Done | Pass | Pass | `sample-xades-t.xml` |
| JAdES | Done | Queued | Pending | Pending | next active target |

## Current focus

- implement JAdES-T while preserving the checker-compatible general JSON serialization
- keep existing B/T formats green while extending the suite

## Next checkpoints

1. JAdES-T local test and runtime artifact
2. JAdES-T ETSI validation
3. branch-wide regression pass across all T formats
4. re-evaluate merge to `main`

## Update rule

Update this file whenever one of these happens:

- a format changes state
- a checker validation is completed
- the active target changes
- merge policy changes
