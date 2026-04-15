namespace DigitalSignature.Abstractions;

public sealed record ValidationMaterial(
    SigningCertificateReference? SigningCertificate,
    IReadOnlyList<SigningCertificateReference> CertificateChain,
    IReadOnlyList<RevocationInfo> RevocationInfo,
    IReadOnlyList<TimestampMaterial> Timestamps,
    IReadOnlyList<ReadOnlyMemory<byte>> EvidenceRecords)
{
    public IReadOnlyList<ReadOnlyMemory<byte>> CertificateValues { get; init; } = Array.Empty<ReadOnlyMemory<byte>>();
    public IReadOnlyList<ReadOnlyMemory<byte>> RevocationValues { get; init; } = Array.Empty<ReadOnlyMemory<byte>>();

    public static ValidationMaterial Empty { get; } = new(
        SigningCertificate: null,
        CertificateChain: Array.Empty<SigningCertificateReference>(),
        RevocationInfo: Array.Empty<RevocationInfo>(),
        Timestamps: Array.Empty<TimestampMaterial>(),
        EvidenceRecords: Array.Empty<ReadOnlyMemory<byte>>())
    {
        CertificateValues = Array.Empty<ReadOnlyMemory<byte>>(),
        RevocationValues = Array.Empty<ReadOnlyMemory<byte>>()
    };
}
