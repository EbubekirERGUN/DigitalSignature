using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.Validation;

public sealed class RevocationEvidenceCollector(
    IOcspResponder? ocspResponder = null,
    ICrlProvider? crlProvider = null)
{
    public async ValueTask<IReadOnlyList<CertificateRevocationEvidence>> CollectAsync(
        SigningCertificateReference certificate,
        SigningCertificateReference? issuer,
        TemporalValidationContext temporalContext,
        CancellationToken cancellationToken = default)
    {
        var evidence = new List<CertificateRevocationEvidence>();

        if (ocspResponder is not null)
        {
            var ocsp = await ocspResponder.GetRevocationEvidenceAsync(certificate, issuer, temporalContext, cancellationToken).ConfigureAwait(false);
            if (ocsp is not null)
            {
                evidence.Add(ocsp);
            }
        }

        if (crlProvider is not null)
        {
            var crlEvidence = await crlProvider.GetRevocationEvidenceAsync(certificate, issuer, temporalContext, cancellationToken).ConfigureAwait(false);
            if (crlEvidence.Count > 0)
            {
                evidence.AddRange(crlEvidence);
            }
        }

        return evidence;
    }
}
