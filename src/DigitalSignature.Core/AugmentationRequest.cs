using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public sealed record AugmentationRequest(
    SignatureDescriptor Signature,
    SignatureLevel TargetLevel,
    TemporalValidationContext TemporalContext,
    IReadOnlyList<RevocationInfo>? RevocationInfo = null,
    IReadOnlyList<TimestampMaterial>? Timestamps = null,
    IReadOnlyList<ReadOnlyMemory<byte>>? EvidenceRecords = null)
{
    public IReadOnlyList<RevocationInfo> EffectiveRevocationInfo => RevocationInfo ?? Array.Empty<RevocationInfo>();
    public IReadOnlyList<TimestampMaterial> EffectiveTimestamps => Timestamps ?? Array.Empty<TimestampMaterial>();
    public IReadOnlyList<ReadOnlyMemory<byte>> EffectiveEvidenceRecords => EvidenceRecords ?? Array.Empty<ReadOnlyMemory<byte>>();
}
