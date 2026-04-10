using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public interface ICrlProvider
{
    ValueTask<IReadOnlyList<CertificateRevocationEvidence>> GetRevocationEvidenceAsync(
        SigningCertificateReference certificate,
        SigningCertificateReference? issuer,
        TemporalValidationContext temporalContext,
        CancellationToken cancellationToken = default);
}
