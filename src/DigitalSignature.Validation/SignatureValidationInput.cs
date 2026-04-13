using DigitalSignature.Abstractions;

namespace DigitalSignature.Validation;

public sealed record SignatureValidationInput(
    ReadOnlyMemory<byte> Payload,
    SignatureDescriptor Signature,
    ValidationResult IntegrityResult,
    TemporalValidationContext TemporalContext)
{
    public static SignatureValidationInput Create(
        ReadOnlyMemory<byte> payload,
        SignatureDescriptor signature,
        ValidationResult integrityResult,
        TemporalValidationContext temporalContext)
    {
        return new(payload, signature, integrityResult, temporalContext);
    }
}
