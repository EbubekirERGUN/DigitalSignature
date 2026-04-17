using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public sealed record AugmentationResult(
    SignatureDescriptor Signature,
    TimestampAttachmentPlan TimestampPlan,
    bool HasEmbeddedValidationData,
    bool HasArchiveEvidence)
{
    public static AugmentationResult Unchanged(SignatureDescriptor signature, SignatureLevel targetLevel)
    {
        ArgumentNullException.ThrowIfNull(signature);

        return new(signature, TimestampAttachmentPlan.Empty(signature.Format, signature.Level, targetLevel), false, false);
    }
}
