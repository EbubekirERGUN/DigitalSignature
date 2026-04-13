namespace DigitalSignature.Abstractions;

public enum ValidationFailureKind
{
    None = 0,
    HashMismatch = 1,
    SignatureValueInvalid = 2,
    CertificateChainIncomplete = 3,
    TrustAnchorMissing = 4,
    CertificateExpired = 5,
    CertificateRevoked = 6,
    RevocationStatusUnknown = 7,
    TimestampInvalid = 8,
    UnsupportedFormat = 9,
    UnsupportedAlgorithm = 10,
    MalformedSignature = 11,
    JsonCanonicalizationInvalid = 12,
    JwsMalformed = 13,
}
