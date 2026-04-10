namespace DigitalSignature.Abstractions;

public sealed record SignatureRequest(
    SignatureFormat Format,
    SignatureLevel Level,
    ReadOnlyMemory<byte> Payload,
    string? MimeType = null,
    string? ContentTypeHint = null);
