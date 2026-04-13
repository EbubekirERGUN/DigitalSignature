namespace DigitalSignature.PAdES;

public sealed record PdfSignatureBindingResult(
    ReadOnlyMemory<byte> Document,
    PdfSignaturePlaceholder Placeholder,
    string DictionaryText);
