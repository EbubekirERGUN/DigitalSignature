# DigitalSignature Status

## Current repository state

- Active branch: `main`
- Remote branch state: clean
- Open PR requirement: none
- Samples: local-only

## Current format matrix

| Format | Baseline-B | Baseline-T | Local | ETSI checker | Notes |
|---|---|---:|---:|---:|---|
| CAdES | Done | Done | Pass | Pass | `sample-cades-t.p7m` |
| ASiC-S | Done | Done | Pass | Pass | `sample-asic-t.asics` |
| PAdES | Done | Done | Pass | Pass | `sample-pades-t.pdf` |
| XAdES | Done | Done | Pass | Pass | `sample-xades-t.xml` |
| JAdES | Done | In progress / parked | Mixed | In progress | JAdES-T still needs serialization / verification alignment |

## Current focus

Primary completed set:

1. CAdES-T
2. ASiC-S-T
3. PAdES-T
4. XAdES-T

Current exception:

5. JAdES-T -> partially explored, currently parked until a cleaner signing / verification refactor is resumed

## What is true right now

- `main` already contains the successful Baseline-T rollout except JAdES-T completion
- no active feature branch is required at the moment
- no active PR is required at the moment
- GitHub branch state is already clean

## JAdES-T note

JAdES-T is the only remaining major open item in the current T matrix.

Known state:

- JAdES Baseline-B is working
- ETSI checker can parse the JAdES-T shape under current experiments
- timestamp structure and signature parsing were partially validated
- remaining problem area is the final serialization / protected-header / verification alignment for a clean ETSI pass

## Recommended next checkpoint when resumed

1. refactor JAdES-T signing and verification around real JSON serialization semantics
2. restore local test green state
3. regenerate runtime artifact
4. rerun ETSI checker validation
5. close JAdES-T only after clean pass

## Update rule

Update this file whenever one of these happens:

- a format changes state
- checker validation completes
- repo branch / PR policy changes
- JAdES-T resumes or completes
