using DigitalSignature.Abstractions;

namespace DigitalSignature.ASiC;

public sealed record ASiCSBaselineBVerificationResult(
    ValidationResult Validation,
    bool HasMimeTypeFile,
    bool MimeTypeMatchesContainer,
    bool IsMimeTypeFileFirst,
    bool IsMimeTypeFileStored,
    bool HasSignatureFile,
    bool HasSinglePayloadFile,
    string? PayloadEntryName,
    string? SignatureEntryName);
