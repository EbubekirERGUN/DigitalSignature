namespace DigitalSignature.JAdES;

public sealed record JAdESJsonSignatureEntry(
    string Protected,
    string Signature,
    string? HeaderJson = null);
