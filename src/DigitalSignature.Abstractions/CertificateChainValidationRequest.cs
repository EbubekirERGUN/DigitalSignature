namespace DigitalSignature.Abstractions;

public sealed record CertificateChainValidationRequest(
    SigningCertificateReference SigningCertificate,
    IReadOnlyList<SigningCertificateReference> IntermediateCertificates,
    IReadOnlyList<CertificateTrustAnchor> TrustAnchors,
    DateTimeOffset ValidationTime,
    bool UseSigningTime,
    IReadOnlyList<CertificateRevocationEvidence> RevocationEvidence)
{
    public static CertificateChainValidationRequest Create(
        SigningCertificateReference signingCertificate,
        DateTimeOffset validationTime,
        bool useSigningTime,
        IReadOnlyList<SigningCertificateReference>? intermediateCertificates = null,
        IReadOnlyList<CertificateTrustAnchor>? trustAnchors = null,
        IReadOnlyList<CertificateRevocationEvidence>? revocationEvidence = null)
    {
        return new(
            signingCertificate,
            intermediateCertificates ?? Array.Empty<SigningCertificateReference>(),
            trustAnchors ?? Array.Empty<CertificateTrustAnchor>(),
            validationTime,
            useSigningTime,
            revocationEvidence ?? Array.Empty<CertificateRevocationEvidence>());
    }
}
