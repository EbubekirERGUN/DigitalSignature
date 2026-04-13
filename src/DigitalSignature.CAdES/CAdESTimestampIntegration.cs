using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.CAdES;

public static class CAdESTimestampIntegration
{
    public static TimestampAttachmentPlan PlanBaselineT(
        SignatureDescriptor signature,
        TimestampMaterial timestamp)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(timestamp);

        return new TimestampAttachmentPlan(
            SignatureFormat.CAdES,
            signature.Level,
            SignatureLevel.BaselineT,
            [new TimestampAttachment(SignatureLevel.BaselineT, timestamp, "RFC 3161 signature timestamp token")]);
    }
}
