namespace DigitalSignature.PAdES;

internal static class PdfByteRangeFormatter
{
    public static string Format(PdfSignatureByteRange byteRange)
        => $"[0 {byteRange.FirstLength} {byteRange.SecondOffset} {byteRange.SecondLength}]";
}
