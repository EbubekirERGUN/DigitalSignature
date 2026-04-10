namespace DigitalSignature.Abstractions;

public sealed record CertificateChainValidationResult(
    bool IsTrusted,
    IReadOnlyList<SigningCertificateReference> Chain,
    CertificateTrustAnchor? TrustAnchor,
    IReadOnlyList<ValidationFailure> Failures)
{
    public static CertificateChainValidationResult Success(
        IReadOnlyList<SigningCertificateReference> chain,
        CertificateTrustAnchor trustAnchor)
    {
        return new(true, chain, trustAnchor, Array.Empty<ValidationFailure>());
    }

    public static CertificateChainValidationResult Failure(params ValidationFailure[] failures)
    {
        return new(false, Array.Empty<SigningCertificateReference>(), null, failures);
    }
}
