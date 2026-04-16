using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.CAdES;

public sealed class CAdESAugmenter : ISignatureAugmenter
{
    public SignatureAugmentationProfile Profile { get; } = new(
        SignatureFormat.CAdES,
        SupportsBaselineT: true,
        SupportsBaselineLT: true,
        SupportsBaselineLTA: true);

    public ValueTask<AugmentationResult> AugmentAsync(
        AugmentationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var signature = request.Signature;
        var timestamps = signature.ValidationMaterial.Timestamps.ToList();
        var archiveTimestamps = signature.ValidationMaterial.ArchiveTimestamps.ToList();
        var revocationInfo = signature.ValidationMaterial.RevocationInfo.ToList();
        var attachments = new List<TimestampAttachment>();

        if (request.TargetLevel >= SignatureLevel.BaselineT)
        {
            var timestamp = request.EffectiveTimestamps.FirstOrDefault()
                ?? throw new InvalidOperationException("Baseline-T augmentation requires at least one timestamp token.");

            if (!timestamps.Contains(timestamp))
            {
                timestamps.Add(timestamp);
            }

            attachments.Add(new TimestampAttachment(SignatureLevel.BaselineT, timestamp, "RFC 3161 signature timestamp token"));
            signature = signature with
            {
                Level = SignatureLevel.BaselineT,
                ValidationMaterial = signature.ValidationMaterial with { Timestamps = timestamps }
            };
        }

        if (request.TargetLevel >= SignatureLevel.BaselineLT)
        {
            revocationInfo = request.EffectiveRevocationInfo.Count > 0
                ? request.EffectiveRevocationInfo.ToList()
                : revocationInfo;

            signature = signature with
            {
                Level = SignatureLevel.BaselineLT,
                ValidationMaterial = signature.ValidationMaterial with
                {
                    RevocationInfo = revocationInfo,
                    Timestamps = timestamps
                }
            };
        }

        if (request.TargetLevel >= SignatureLevel.BaselineLTA)
        {
            var archiveTimestamp = request.EffectiveArchiveTimestamps.FirstOrDefault()
                ?? throw new InvalidOperationException("Baseline-LTA augmentation requires at least one archive timestamp token.");

            if (!archiveTimestamps.Contains(archiveTimestamp))
            {
                archiveTimestamps.Add(archiveTimestamp);
            }

            attachments.Add(new TimestampAttachment(SignatureLevel.BaselineLTA, archiveTimestamp, "RFC 3161 archive timestamp token"));

            signature = signature with
            {
                Level = SignatureLevel.BaselineLTA,
                ValidationMaterial = signature.ValidationMaterial with
                {
                    RevocationInfo = revocationInfo,
                    Timestamps = timestamps,
                    ArchiveTimestamps = archiveTimestamps
                }
            };
        }

        var result = new AugmentationResult(
            signature,
            attachments.Count == 0
                ? TimestampAttachmentPlan.Empty(SignatureFormat.CAdES, request.Signature.Level, request.TargetLevel)
                : new TimestampAttachmentPlan(SignatureFormat.CAdES, request.Signature.Level, request.TargetLevel, attachments),
            HasEmbeddedValidationData: signature.ValidationMaterial.RevocationInfo.Count > 0,
            HasArchiveEvidence: signature.ValidationMaterial.ArchiveTimestamps.Count > 0);

        return ValueTask.FromResult(result);
    }
}
