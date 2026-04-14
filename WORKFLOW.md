# DigitalSignature Workflow

This file defines the lightweight operating system for the project.

## Why this exists

The project now spans multiple ETSI formats, repeated checker validation, and cross-cutting timestamp logic. A simple code-only workflow is no longer enough. We need:

- visible progress
- controlled sequencing
- durable continuity
- safe integration points

## Workflow layers

### 1. Main agent lane

Used for:

- architecture decisions
- shared abstraction changes
- final code integration
- branch / PR ownership
- release readiness decisions

This lane is the source of truth.

### 2. Specialist lane

Used for narrow investigations only.

Good fits:

- ETSI checker behavior
- standards interpretation for one rule
- isolated prototype for a hard format-specific problem

Outputs from this lane are inputs, not final truth, until integrated in the main lane.

### 3. Verification lane

Every meaningful change should be checked in this order:

1. targeted unit tests
2. runtime smoke tests
3. runtime artifact generation
4. ETSI checker upload

If a slice fails at any stage, the next format does not start.

### 4. Merge lane

Current branch policy:

- do active work on `issue-baseline-t-suite`
- merge to `main` only when a substantial T block is complete and stable

## Communication policy

Short user updates should be sent when:

- a format reaches done state
- a checker result lands
- progress is blocked by a concrete technical issue
- merge readiness changes

## Tracking sources

Use these together:

- `STATUS.md` for live state
- PR #29 for review context and checklist
- git history for concrete shipped slices
- `artifacts/runtime-demo` for generated proof artifacts

## Definition of done for one T slice

A format is not considered done until all of these are true:

- implementation exists
- tests pass
- runtime artifact exists
- checker parses the artifact
- timestamp-specific checks are visible in the report
- no visible error / warning / failure regressions remain

## Current format order

1. CAdES-T
2. ASiC-S-T
3. PAdES-T
4. XAdES-T
5. JAdES-T

Do not reorder unless a blocker forces it.
