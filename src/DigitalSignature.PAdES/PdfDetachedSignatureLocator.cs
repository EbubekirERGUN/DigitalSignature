using System.Formats.Asn1;
using System.Text;

namespace DigitalSignature.PAdES;

internal static class PdfDetachedSignatureLocator
{
    public static string Render(ReadOnlyMemory<byte> pdfDocument) => Encoding.Latin1.GetString(pdfDocument.Span);

    public static bool HasDetachedCadesSubFilter(string text) =>
        text.Contains("/SubFilter /ETSI.CAdES.detached", StringComparison.Ordinal);

    public static PdfSignaturePlaceholder? TryLocatePlaceholder(string text)
    {
        var contentsMarker = "/Contents <";
        var start = text.IndexOf(contentsMarker, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        var contentsOffset = start + contentsMarker.Length;
        var end = text.IndexOf('>', contentsOffset);
        if (end < 0)
        {
            return null;
        }

        var contentsLength = end - contentsOffset;
        var byteRange = new PdfSignatureByteRange(0, contentsOffset, end + 1, text.Length - (end + 1));
        return new PdfSignaturePlaceholder(contentsOffset, contentsLength, byteRange);
    }

    public static ReadOnlyMemory<byte> TryExtractRawContentsBytes(string text, PdfSignaturePlaceholder placeholder)
    {
        var hexSignature = text.Substring(placeholder.ContentsOffset, placeholder.ContentsLength);
        if (string.IsNullOrWhiteSpace(hexSignature) || hexSignature.Length < 2)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        if ((hexSignature.Length & 1) == 1)
        {
            hexSignature = hexSignature[..^1];
        }

        try
        {
            return Convert.FromHexString(hexSignature);
        }
        catch (FormatException)
        {
            return ReadOnlyMemory<byte>.Empty;
        }
    }

    public static ReadOnlyMemory<byte> TryExtractCmsSignature(string text, PdfSignaturePlaceholder placeholder)
    {
        try
        {
            var raw = TryExtractRawContentsBytes(text, placeholder);
            if (raw.IsEmpty)
            {
                return ReadOnlyMemory<byte>.Empty;
            }

            if (AsnDecoder.TryReadEncodedValue(raw.Span, AsnEncodingRules.BER, out _, out _, out _, out var bytesConsumed) && bytesConsumed > 0)
            {
                return raw[..bytesConsumed];
            }

            return ReadOnlyMemory<byte>.Empty;
        }
        catch (AsnContentException)
        {
            return ReadOnlyMemory<byte>.Empty;
        }
    }
}
