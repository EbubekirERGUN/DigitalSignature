# DigitalSignature Workflow

This file defines the lightweight operating model for the project.

## Why this exists

The project spans multiple ETSI formats, repeated checker validation, timestamp logic, and interoperability-focused debugging. We need:

- visible progress
- controlled sequencing
- durable continuity
- safe integration points

## Workflow layers

### 1. Main integration lane

Used for:

- architecture decisions
- shared abstraction changes
- final code integration
- merge readiness decisions
- repo hygiene and release state

This lane is the source of truth.

### 2. Narrow investigation lane

Used only for focused research or debugging.

Good fits:

- ETSI checker behavior
- standards interpretation for one specific rule
- isolated prototype for a hard format-specific problem

Outputs from this lane are inputs, not final truth, until integrated back into the main lane.

### 3. Verification lane

Every meaningful change should be checked in this order:

1. targeted unit tests
2. runtime smoke tests
3. runtime artifact generation
4. ETSI checker upload

If a slice fails at any stage, it is not done.

### 4. Repository lane

Current repo policy:

- keep `main` current
- avoid stale feature branches and PR clutter
- prefer a clean branch list
- use larger meaningful merges instead of noisy tiny PR history when possible

## Communication policy

Short updates should be sent when:

- a format reaches done state
- a checker result lands
- work is blocked by a concrete technical issue
- repo status meaningfully changes

## Tracking sources

Use these together:

- `STATUS.md` for live state
- `ROADMAP.md` for technical direction
- git history for shipped slices
- `artifacts/runtime-demo` for generated proof artifacts

## Definition of done for one T slice

A format is not done until all of these are true:

- implementation exists
- tests pass
- runtime artifact exists
- checker parses the artifact
- timestamp-specific checks are visible in the report
- no visible error / warning / failure regressions remain

## Current effective order

Completed:

1. CAdES-T
2. ASiC-S-T
3. PAdES-T
4. XAdES-T

Open / parked:

5. JAdES-T

## Current note on JAdES-T

JAdES-T is currently the only unresolved part of the Baseline-T rollout.

The known challenge is not simple timestamp embedding alone, but final alignment between:

- JSON serialization semantics
- protected header expectations
- signature verification input
- ETSI checker interpretation

Resume only with a cleaner refactor path, not with more ad hoc patches.
