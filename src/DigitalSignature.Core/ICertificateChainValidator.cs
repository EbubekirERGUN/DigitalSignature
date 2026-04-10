using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public interface ICertificateChainValidator
{
    ValueTask<CertificateChainValidationResult> ValidateAsync(
        CertificateChainValidationRequest request,
        CancellationToken cancellationToken = default);
}
