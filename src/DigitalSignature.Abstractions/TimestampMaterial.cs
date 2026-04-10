namespace DigitalSignature.Abstractions;

public sealed record TimestampMaterial(
    ReadOnlyMemory<byte> Token,
    DateTimeOffset CreatedAt,
    string? PolicyOid = null,
    string? HashAlgorithm = null);
