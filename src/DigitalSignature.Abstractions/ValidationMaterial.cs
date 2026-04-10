namespace DigitalSignature.Abstractions;

public sealed record ValidationMaterial(
    SigningCertificateReference? SigningCertificate,
    IReadOnlyList<SigningCertificateReference> CertificateChain,
    IReadOnlyList<RevocationInfo> RevocationInfo,
    IReadOnlyList<TimestampMaterial> Timestamps,
    IReadOnlyList<ReadOnlyMemory<byte>> EvidenceRecords)
{
    public static ValidationMaterial Empty { get; } = new(
        SigningCertificate: null,
        CertificateChain: Array.Empty<SigningCertificateReference>(),
        RevocationInfo: Array.Empty<RevocationInfo>(),
        Timestamps: Array.Empty<TimestampMaterial>(),
        EvidenceRecords: Array.Empty<ReadOnlyMemory<byte>>());
}
