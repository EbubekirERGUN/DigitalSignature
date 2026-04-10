namespace DigitalSignature.Abstractions;

public sealed record CertificateRevocationEvidence(
    CertificateRevocationSource Source,
    CertificateRevocationStatus Status,
    DateTimeOffset ProducedAt,
    DateTimeOffset? ThisUpdate,
    DateTimeOffset? NextUpdate,
    DateTimeOffset? RevokedAt,
    string? Responder = null,
    string? Reason = null,
    ReadOnlyMemory<byte> RawData = default);
