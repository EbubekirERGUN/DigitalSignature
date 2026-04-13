using DigitalSignature.Abstractions;

namespace DigitalSignature.JAdES;

public sealed record JAdESVerificationResult(
    ValidationResult Validation,
    bool HasTypHeader,
    bool HasCanonicalizationClaim,
    string? Algorithm);
