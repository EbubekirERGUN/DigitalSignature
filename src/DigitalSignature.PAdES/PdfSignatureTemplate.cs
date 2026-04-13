namespace DigitalSignature.PAdES;

internal static class PdfSignatureTemplate
{
    public static byte[] CreatePlaceholderDocument(int estimatedContentsHexLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(estimatedContentsHexLength);

        var builder = new PdfDocumentBuilder();
        builder.AddObject(1, "<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>");
        builder.AddObject(2, "<< /Type /Pages /Count 1 /Kids [3 0 R] >>");
        builder.AddObject(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 7 0 R >> >> /Contents 4 0 R /Annots [6 0 R] >>");
        builder.AddObject(4, $"<< /Length 44 >>\nstream\nBT\n/F1 12 Tf\n72 720 Td\n(Runtime Demo PDF) Tj\nET\nendstream");
        builder.AddObject(5, "<< /SigFlags 3 /Fields [6 0 R] >>");
        builder.AddObject(6, $"<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [72 640 240 700] /T (Signature1) /F 4 /P 3 0 R /V 8 0 R >>");
        builder.AddObject(7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
        builder.AddObject(8, BuildSignatureObject(estimatedContentsHexLength));
        return builder.Build(1);
    }

    private static string BuildSignatureObject(int estimatedContentsHexLength)
    {
        var placeholder = new string('0', estimatedContentsHexLength);
        return $"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [0 ********** ********** **********] /Contents <{placeholder}> /M (D:20260413120000Z) /Reason (DigitalSignature Runtime Demo) >>";
    }
}
