# DigitalSignature Roadmap

## Product scope

DigitalSignature is a .NET 10 open source electronic signature platform focused on:

- XAdES
- CAdES
- PAdES
- JAdES
- signature validation
- augmentation (B-B -> B-T -> B-LT -> B-LTA)
- timestamp integration
- long-term validation material
- standards-aligned validation reporting

## Scope boundary

V1 hedefi ETSI uyumlu imza formatları üretmek ve doğrulamaktır.

Out of scope for v1:

- qualified trust service provider olmak
- eIDAS altında hukuki qualified sonuç vaat etmek
- tam ulusal trust list varyasyon desteği
- tüm PDF viewer davranışlarını garanti etmek

## Core standards reference

- ETSI TS 119 102-1 -> validation procedures
- ETSI TS 119 102-2 -> validation report structure
- ETSI TS 119 312 -> crypto policy
- ETSI EN 319 122-* -> CAdES
- ETSI EN 319 132-* -> XAdES
- ETSI EN 319 142-* -> PAdES
- ETSI TS 119 182-* -> JAdES
- RFC 3161 -> timestamp
- RFC 7515 -> JWS
- RFC 8785 -> JSON canonicalization

## Target architecture

### 1. Core Crypto Layer

Responsibilities:

- hashing
- signature algorithm execution
- certificate chain processing
- OCSP / CRL integration
- TSA client
- trust anchor handling
- configurable crypto policy

### 2. AdES Common Model

Shared concepts:

- signature level
- signing certificate
- signing time
- timestamp token
- revocation information
- validation material
- archive material
- validation conclusion

### 3. Format Adaptors

- XAdES adaptor
- CAdES adaptor
- PAdES adaptor
- JAdES adaptor

### 4. Validation Engine

- ETSI TS 119 102-1 aligned validation flow
- format-independent validation result model
- deterministic error/conclusion model

### 5. Augmentation Engine

- B-T
- B-LT
- B-LTA
- validation material embedding
- timestamp renewal / archive material extension

### 6. Delivery Layer

- class library
- CLI
- ASP.NET Core Web API
- later: NuGet packaging

## Recommended interfaces

- `ISignatureFormatter`
- `ISignatureValidator`
- `ISignatureAugmentor`
- `ITimestampProvider`
- `IRevocationDataProvider`
- `ITrustAnchorProvider`
- `ISigningKeyProvider`
- `ICryptoPolicyProvider`

## Format strategy

### Phase priority

1. CAdES core + validation core
2. PAdES baseline
3. XAdES baseline
4. JAdES baseline
5. LT/LTA augmentation + crypto policy engine
6. TS 119 102-2 style standardized reports

Reasoning:

- CAdES gives the best reusable cryptographic base
- PAdES can reuse CMS/CAdES core and has high practical value
- XAdES and JAdES need dedicated canonicalization work

## Technical risks

### Highest risk

1. Canonicalization mismatches
   - XML canonicalization for XAdES
   - JSON canonicalization for JAdES
2. Incorrect temporal validation model
   - validation must consider signing time, not just current time
3. Treating PAdES as only a PDF + CMS blob
4. Treating JAdES as plain JWS without ETSI semantic layers

## Functional requirements

- produce signatures in XAdES, CAdES, PAdES, JAdES
- validate signatures
- augment signatures to higher baseline levels
- support timestamp integration
- support OCSP / CRL revocation data
- support trust anchor and trust source configuration
- produce detailed validation conclusions and machine-readable errors
- support multiple signatures / countersignatures where format allows

## Non-functional requirements

- interoperability first
- deterministic output where possible
- detailed and explainable validation failures
- pluggable key provider model
- low-allocation / GC-friendly implementation on hot paths
- testability by format-independent and format-specific suites

## Initial engineering order

### Milestone 0 - Foundation

- establish solution structure
- add shared abstractions project
- add common result/error model
- add crypto policy model
- define test strategy and sample corpus layout

### Milestone 1 - Common core

- implement crypto abstractions
- certificate chain model
- timestamp token abstraction
- validation material model
- baseline level enum and workflow model

### Milestone 2 - CAdES baseline

- SignedData creation
- detached baseline signing
- signature verification
- basic validation result

### Milestone 3 - Validation core

- format-independent validation pipeline
- chain building
- OCSP/CRL hooks
- report model aligned with TS 119 102-1/102-2 concepts

### Milestone 4 - PAdES baseline

- PDF binding layer
- ByteRange handling
- incremental update support
- DSS/VRI roadmap preparation

### Milestone 5 - XAdES baseline

- XML DSIG integration
- SignedProperties model
- canonicalization layer

### Milestone 6 - JAdES baseline

- JWS/JAdES binding layer
- JSON canonicalization strategy
- baseline profile support

### Milestone 7 - LT/LTA

- TSA integration
- revocation material embedding
- archival extension flow

## Immediate next step

Start with a multi-project solution split like:

- `src/DigitalSignature.Abstractions`
- `src/DigitalSignature.Core`
- `src/DigitalSignature.CAdES`
- `src/DigitalSignature.Validation`
- `tests/DigitalSignature.Core.Tests`
- `tests/DigitalSignature.CAdES.Tests`
- `tests/DigitalSignature.Validation.Tests`

Then implement the common domain and error model before format-specific signing code.
