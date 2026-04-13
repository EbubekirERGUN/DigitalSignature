namespace DigitalSignature.PAdES;

public sealed record PdfSignaturePlaceholder(
    int ContentsOffset,
    int ContentsLength,
    PdfSignatureByteRange ByteRange);
