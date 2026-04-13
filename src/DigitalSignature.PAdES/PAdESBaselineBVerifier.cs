using System.Text;
using DigitalSignature.Abstractions;

namespace DigitalSignature.PAdES;

public sealed class PAdESBaselineBVerifier
{
    public PAdESVerificationResult Verify(ReadOnlyMemory<byte> signedPdf)
    {
        var text = Encoding.ASCII.GetString(signedPdf.Span);
        var placeholder = TryLocatePlaceholder(text);

        if (placeholder is null)
        {
            return new PAdESVerificationResult(
                ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.MalformedSignature,
                    ValidationErrorCodes.MalformedSignature,
                    "PDF signature placeholder was not found.")),
                null,
                false);
        }

        var hasDetachedCades = text.Contains("/SubFilter /ETSI.CAdES.detached", StringComparison.Ordinal);
        var result = hasDetachedCades
            ? ValidationResult.Success(new SignatureDescriptor(
                SignatureFormat.PAdES,
                SignatureLevel.BaselineB,
                null,
                null,
                ValidationMaterial.Empty))
            : ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.UnsupportedFormat,
                ValidationErrorCodes.UnsupportedFormat,
                "PDF signature dictionary does not declare ETSI.CAdES.detached subfilter."));

        return new PAdESVerificationResult(result, placeholder, hasDetachedCades);
    }

    private static PdfSignaturePlaceholder? TryLocatePlaceholder(string text)
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
}
