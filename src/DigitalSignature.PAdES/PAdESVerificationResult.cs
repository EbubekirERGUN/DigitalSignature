using DigitalSignature.Abstractions;

namespace DigitalSignature.PAdES;

public sealed record PAdESVerificationResult(
    ValidationResult Validation,
    PdfSignaturePlaceholder? Placeholder,
    bool HasDetachedCAdESSignature);
