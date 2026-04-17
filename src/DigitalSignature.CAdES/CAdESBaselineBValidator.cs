using DigitalSignature.Abstractions;
using DigitalSignature.Validation;

namespace DigitalSignature.CAdES;

public sealed class CAdESBaselineBValidator(
    CAdESBaselineBService cadesService,
    SignatureValidationEngine validationEngine)
{
    public async ValueTask<ValidationResult> ValidateDetachedAsync(
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signature,
        TemporalValidationContext temporalContext,
        SignatureValidationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var integrityResult = cadesService.VerifyDetachedSignature(payload, signature);
        if (integrityResult.Conclusion != ValidationConclusion.Valid || integrityResult.Signature is null)
        {
            return integrityResult;
        }

        var input = SignatureValidationInput.Create(payload, integrityResult.Signature, integrityResult, temporalContext);
        return await validationEngine.ValidateAsync(input, options, cancellationToken).ConfigureAwait(false);
    }
}
