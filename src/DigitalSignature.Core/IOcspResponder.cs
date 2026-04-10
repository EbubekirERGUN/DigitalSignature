using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public interface IOcspResponder
{
    ValueTask<CertificateRevocationEvidence?> GetRevocationEvidenceAsync(
        SigningCertificateReference certificate,
        SigningCertificateReference? issuer,
        TemporalValidationContext temporalContext,
        CancellationToken cancellationToken = default);
}
