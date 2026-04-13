using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public sealed record TimestampAttachmentPlan(
    SignatureFormat Format,
    SignatureLevel CurrentLevel,
    SignatureLevel TargetLevel,
    IReadOnlyList<TimestampAttachment> Attachments)
{
    public static TimestampAttachmentPlan Empty(SignatureFormat format, SignatureLevel currentLevel, SignatureLevel targetLevel) =>
        new(format, currentLevel, targetLevel, Array.Empty<TimestampAttachment>());
}
