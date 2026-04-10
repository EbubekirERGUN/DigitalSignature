namespace DigitalSignature.Abstractions;

public sealed record SignatureDescriptor(
    SignatureFormat Format,
    SignatureLevel Level,
    SigningCertificateReference? SigningCertificate,
    DateTimeOffset? SigningTime,
    ValidationMaterial ValidationMaterial,
    string? SignatureAlgorithm = null,
    string? DigestAlgorithm = null);
