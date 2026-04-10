namespace DigitalSignature.Abstractions;

public sealed record SigningCertificateReference(
    string Subject,
    string Issuer,
    string SerialNumber,
    string Thumbprint,
    string? NotBefore = null,
    string? NotAfter = null);
