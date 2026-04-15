# DigitalSignature

DigitalSignature is a .NET 10 digital signature toolkit for CAdES, XAdES, PAdES, JAdES, and ASiC-S.

It focuses on practical ETSI-style signing and validation flows, with local verification and runtime-generated artifacts checked against the ETSI Conformance Checker.

## Highlights

- Baseline-B, Baseline-T, and Baseline-LT support across the main signature families
- Local signing and validation with `RSA` and `X509Certificate2`
- ETSI checker verified interoperability for the current runtime artifact set
- JAdES support built around JSON General Serialization
- Shared validation and augmentation foundations for cross-format workflows

## Validation status

The current runtime artifact set passes both local verification and a fresh ETSI Conformance Checker sweep for all formats and levels listed below.

| Format | Baseline-B | Baseline-T | Baseline-LT | Local Validation | ETSI Checker | Notes |
|---|---:|---:|---:|---|---|---|
| CAdES | Yes | Yes | Yes | Pass | Pass | Checker-facing attached `.p7m` artifacts |
| XAdES | Yes | Yes | Yes | Pass | Pass | XML signature generation and validation |
| PAdES | Yes | Yes | Yes | Pass | Pass | LT includes PDF DSS and VRI embedding |
| ASiC-S | Yes | Yes | Yes | Pass | Pass | Single-file container with embedded CAdES signature |
| JAdES | Yes | Yes | Yes | Pass | Pass | Primary artifact is JSON General Serialization |

## Build and test

```bash
dotnet restore DigitalSignature.slnx
dotnet build DigitalSignature.slnx
dotnet test DigitalSignature.slnx
```

## Quick example

```csharp
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;

byte[] payload = "hello"u8.ToArray();
using RSA rsa = RSA.Create(2048);

var certificateRequest = new CertificateRequest(
    "CN=DigitalSignature Demo",
    rsa,
    HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1);

using X509Certificate2 certificate = certificateRequest.CreateSelfSigned(
    DateTimeOffset.UtcNow.AddDays(-1),
    DateTimeOffset.UtcNow.AddYears(1));

var suite = new SignatureSuite(
    SignatureAlgorithmIdentifier.RsaPkcs1,
    HashAlgorithmIdentifier.Sha256,
    2048,
    IsRecommended: true);

var request = new SignatureRequest(
    SignatureFormat.CAdES,
    SignatureLevel.BaselineB,
    payload,
    MimeType: "text/plain");

var service = new CAdESBaselineBService();
var signature = service.CreateDetachedSignature(request, certificate, rsa, suite);
var validation = service.VerifyDetachedSignature(payload, signature.Data);

Console.WriteLine(validation.Conclusion);
```

## Repository layout

- `src/DigitalSignature.Abstractions` - shared contracts and signature models
- `src/DigitalSignature.Core` - shared signing, timestamp, and augmentation infrastructure
- `src/DigitalSignature.CAdES` - CMS/CAdES generation and validation helpers
- `src/DigitalSignature.XAdES` - XML/XAdES generation and validation helpers
- `src/DigitalSignature.PAdES` - PDF/PAdES generation, DSS, and verification helpers
- `src/DigitalSignature.JAdES` - JOSE/JAdES generation and validation helpers
- `src/DigitalSignature.ASiC` - ASiC-S container generation and validation helpers
- `src/DigitalSignature.Validation` - validation pipeline and reporting components
- `tests/` - unit, integration, and runtime smoke tests

## Current scope

DigitalSignature currently targets:

- local signing workflows based on `RSA` and `X509Certificate2`
- Baseline-B, Baseline-T, and Baseline-LT artifact generation
- local verification and ETSI-oriented interoperability checks

It is not yet positioned as a full production PKI platform for:

- HSM or KMS backed signing
- remote signing services
- trust-list distribution or full production trust management

## Notes

- For JAdES, the primary persisted artifact is JSON General Serialization.
- Compact JWS output is kept as a helper output for Baseline-B scenarios.
- ETSI checker results are conformance-oriented and should be interpreted separately from full trust-store policy decisions.
