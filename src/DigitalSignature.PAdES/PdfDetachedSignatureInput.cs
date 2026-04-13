namespace DigitalSignature.PAdES;

public sealed record PdfDetachedSignatureInput(
    ReadOnlyMemory<byte> Document,
    ReadOnlyMemory<byte> SignedBytes,
    PdfSignaturePlaceholder Placeholder);
