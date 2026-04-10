namespace DigitalSignature.Abstractions;

public sealed record SignatureArtifact(
    SignatureFormat Format,
    SignatureLevel Level,
    ReadOnlyMemory<byte> Data,
    string? MediaType = null);
