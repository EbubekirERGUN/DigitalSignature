namespace DigitalSignature.Abstractions;

public static class ValidationErrorCodes
{
    public const string HashMismatch = "validation.hash_mismatch";
    public const string SignatureValueInvalid = "validation.signature_value_invalid";
    public const string CertificateChainIncomplete = "validation.certificate_chain_incomplete";
    public const string TrustAnchorMissing = "validation.trust_anchor_missing";
    public const string CertificateExpired = "validation.certificate_expired";
    public const string CertificateRevoked = "validation.certificate_revoked";
    public const string RevocationStatusUnknown = "validation.revocation_status_unknown";
    public const string TimestampInvalid = "validation.timestamp_invalid";
    public const string UnsupportedFormat = "validation.unsupported_format";
    public const string UnsupportedAlgorithm = "validation.unsupported_algorithm";
    public const string MalformedSignature = "validation.malformed_signature";
    public const string CanonicalizationInvalid = "validation.canonicalization_invalid";
    public const string ReferenceResolutionFailed = "validation.reference_resolution_failed";
    public const string JsonCanonicalizationInvalid = "validation.json_canonicalization_invalid";
    public const string JwsMalformed = "validation.jws_malformed";
}
