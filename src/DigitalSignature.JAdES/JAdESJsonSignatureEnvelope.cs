namespace DigitalSignature.JAdES;

public sealed record JAdESJsonSignatureEnvelope(
    string Payload,
    string Protected,
    string Signature,
    string JsonDocument,
    string CanonicalPayload,
    string SignatureMethod,
    string DigestMethod,
    string ProtectedHeaderJson);
