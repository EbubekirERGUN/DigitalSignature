namespace DigitalSignature.Abstractions;

public sealed record TimestampRequest(
    ReadOnlyMemory<byte> HashedMessage,
    string HashAlgorithm,
    string? PolicyOid = null,
    string? Nonce = null,
    bool RequireCertificate = true);
