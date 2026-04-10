namespace DigitalSignature.Abstractions;

public sealed record CertificateTrustAnchor(
    string Subject,
    string Thumbprint,
    ReadOnlyMemory<byte> RawData,
    string? Source = null);
