using DigitalSignature.Abstractions;

namespace DigitalSignature.XAdES;

public sealed record XAdESVerificationResult(
    ValidationResult Validation,
    bool HasSignedPropertiesReference,
    bool HasCanonicalizationMethod,
    string? CanonicalizationMethod);
