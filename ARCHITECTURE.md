# Architecture

## Project layout

DigitalSignature is organized as a multi-project .NET 10 solution.

### Current projects

- `DigitalSignature.Abstractions`
  - format-independent contracts and shared domain primitives
- `DigitalSignature.Core`
  - common cryptographic and workflow foundations
- `DigitalSignature.Validation`
  - format-independent validation pipeline
- `DigitalSignature.CAdES`
  - first concrete AdES format adaptor

### Test projects

- `DigitalSignature.Core.Tests`
- `DigitalSignature.Validation.Tests`
- `DigitalSignature.CAdES.Tests`

## Planned projects

- `DigitalSignature.PAdES`
- `DigitalSignature.XAdES`
- `DigitalSignature.JAdES`
- later CLI / API delivery projects

## Dependency direction

Allowed dependency direction:

- `DigitalSignature.Abstractions` -> no project dependency
- `DigitalSignature.Core` -> `DigitalSignature.Abstractions`
- `DigitalSignature.Validation` -> `DigitalSignature.Abstractions`, `DigitalSignature.Core`
- `DigitalSignature.CAdES` -> `DigitalSignature.Abstractions`, `DigitalSignature.Core`, `DigitalSignature.Validation`
- format-specific test projects -> only the project under test plus shared lower-level projects when needed

Forbidden direction:

- `Abstractions` depending on any implementation project
- `Core` depending on format projects
- `Validation` depending on format-specific serialization details
- one format adaptor depending on another format adaptor

## Architectural intent

The solution is designed around a shared AdES center instead of four disconnected implementations.

### Shared center

The shared center owns:

- baseline signature level model
- validation result and failure model
- crypto policy abstractions
- trust / revocation abstractions
- timestamp abstractions
- augmentation workflow model

### Format adaptors

Format adaptors are responsible only for mapping the shared model into concrete representations:

- CMS for CAdES
- PDF binding for PAdES
- XML DSIG/XAdES representation for XAdES
- JOSE/JAdES representation for JAdES

## Repository structure conventions

- `src/` contains production code
- `tests/` contains unit/integration tests
- future interoperability corpus should live under a dedicated `testdata/` or `fixtures/` folder
- standards and roadmap docs stay at repository root unless a dedicated `docs/` structure becomes necessary

## Initial implementation order

1. shared abstractions
2. common core
3. validation engine
4. CAdES baseline
5. PAdES
6. XAdES
7. JAdES
8. augmentation and standardized reporting
