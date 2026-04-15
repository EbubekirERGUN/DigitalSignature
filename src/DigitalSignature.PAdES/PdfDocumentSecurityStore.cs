using DigitalSignature.Abstractions;

namespace DigitalSignature.PAdES;

internal sealed record PdfDocumentSecurityStore(
    IReadOnlyList<ReadOnlyMemory<byte>> CertificateValues,
    IReadOnlyList<ReadOnlyMemory<byte>> CrlValues,
    IReadOnlyList<ReadOnlyMemory<byte>> OcspValues,
    IReadOnlyList<ReadOnlyMemory<byte>> RevocationValues,
    IReadOnlyList<RevocationInfo> RevocationInfo,
    bool HasVri)
{
    public static PdfDocumentSecurityStore Empty { get; } = new(
        Array.Empty<ReadOnlyMemory<byte>>(),
        Array.Empty<ReadOnlyMemory<byte>>(),
        Array.Empty<ReadOnlyMemory<byte>>(),
        Array.Empty<ReadOnlyMemory<byte>>(),
        Array.Empty<RevocationInfo>(),
        false);

    public bool HasEmbeddedValidationData => CertificateValues.Count > 0 && RevocationValues.Count > 0;
}
