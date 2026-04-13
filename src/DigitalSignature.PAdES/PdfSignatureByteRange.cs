namespace DigitalSignature.PAdES;

public sealed record PdfSignatureByteRange(
    int StartOffset,
    int FirstLength,
    int SecondOffset,
    int SecondLength)
{
    public int SignedLength => FirstLength + SecondLength;
}
