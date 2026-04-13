using System.Text;

namespace DigitalSignature.PAdES;

internal static class PdfSignedDocumentBuilder
{
    public static (byte[] Document, PdfSignaturePlaceholder Placeholder) CreatePlaceholder(int estimatedContentsHexLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(estimatedContentsHexLength);

        var objects = new List<(int Number, string Content)>
        {
            (1, "<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>"),
            (2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
            (3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 7 0 R /Annots [6 0 R] >>"),
            (4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
            (5, "<< /SigFlags 3 /Fields [6 0 R] >>"),
            (6, "<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [72 640 240 700] /T (Signature1) /F 4 /P 3 0 R /V 8 0 R >>"),
            (7, "<< /Length 44 >>\nstream\nBT\n/F1 12 Tf\n72 720 Td\n(Runtime Demo PDF) Tj\nET\nendstream"),
            (8, BuildSignatureDictionary(estimatedContentsHexLength))
        };

        var builder = new StringBuilder();
        builder.AppendLine("%PDF-1.7");
        builder.AppendLine("%PDFSIGNED");

        var offsets = new List<PdfObjectOffset>();
        foreach (var (number, content) in objects)
        {
            offsets.Add(new PdfObjectOffset(number, Encoding.ASCII.GetByteCount(builder.ToString())));
            builder.Append(number).AppendLine(" 0 obj");
            builder.Append(content);
            if (!content.EndsWith("\n", StringComparison.Ordinal))
            {
                builder.AppendLine();
            }
            builder.AppendLine("endobj");
        }

        var xrefOffset = Encoding.ASCII.GetByteCount(builder.ToString());
        builder.AppendLine("xref");
        builder.AppendLine("0 9");
        builder.AppendLine("0000000000 65535 f ");
        for (var i = 1; i <= 8; i++)
        {
            var offset = offsets.Single(x => x.Number == i).Offset;
            builder.Append(offset.ToString("D10")).AppendLine(" 00000 n ");
        }

        builder.AppendLine("trailer");
        builder.AppendLine("<< /Size 9 /Root 1 0 R >>");
        builder.AppendLine("startxref");
        builder.AppendLine(xrefOffset.ToString());
        builder.Append("%%EOF");

        var bytes = Encoding.ASCII.GetBytes(builder.ToString());
        var rendered = Encoding.ASCII.GetString(bytes);
        var contentsMarker = "/Contents <";
        var contentsOffset = rendered.IndexOf(contentsMarker, StringComparison.Ordinal) + contentsMarker.Length;
        var placeholder = new PdfSignaturePlaceholder(
            contentsOffset,
            estimatedContentsHexLength,
            new PdfSignatureByteRange(
                0,
                contentsOffset,
                contentsOffset + estimatedContentsHexLength + 1,
                bytes.Length - (contentsOffset + estimatedContentsHexLength + 1)));

        return (bytes, placeholder);
    }

    private static string BuildSignatureDictionary(int estimatedContentsHexLength)
    {
        var placeholder = new string('0', estimatedContentsHexLength);
        return $"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [0 ********** ********** **********] /Contents <{placeholder}> /M (D:20260413120000Z) /Reason (DigitalSignature Runtime Demo) >>";
    }
}
