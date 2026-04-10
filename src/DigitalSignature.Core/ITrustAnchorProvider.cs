using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public interface ITrustAnchorProvider
{
    ValueTask<IReadOnlyList<CertificateTrustAnchor>> GetTrustAnchorsAsync(
        SignatureFormat format,
        TemporalValidationContext temporalContext,
        CancellationToken cancellationToken = default);
}
