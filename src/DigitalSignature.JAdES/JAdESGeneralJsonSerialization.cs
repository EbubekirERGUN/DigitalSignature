namespace DigitalSignature.JAdES;

public sealed record JAdESGeneralJsonSerialization(
    string Payload,
    IReadOnlyList<JAdESJsonSignatureEntry> Signatures);
