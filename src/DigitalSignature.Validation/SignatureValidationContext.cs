using DigitalSignature.Abstractions;

namespace DigitalSignature.Validation;

public sealed record SignatureValidationContext(
    SignatureValidationInput Input,
    IReadOnlyList<CertificateTrustAnchor> TrustAnchors,
    IReadOnlyList<RevocationInfo> EffectiveRevocationInfo,
    CertificateChainValidationResult? ChainResult)
{
    public static SignatureValidationContext Create(
        SignatureValidationInput input,
        IReadOnlyList<CertificateTrustAnchor>? trustAnchors = null,
        IReadOnlyList<RevocationInfo>? effectiveRevocationInfo = null,
        CertificateChainValidationResult? chainResult = null)
    {
        return new(
            input,
            trustAnchors ?? Array.Empty<CertificateTrustAnchor>(),
            effectiveRevocationInfo ?? Array.Empty<RevocationInfo>(),
            chainResult);
    }
}
