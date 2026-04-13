namespace DigitalSignature.JAdES;

public sealed record JAdESSignatureEnvelope(
    string ProtectedHeader,
    string Payload,
    string Signature,
    string CompactSerialization,
    string CanonicalPayload,
    string SignatureMethod,
    string DigestMethod);
