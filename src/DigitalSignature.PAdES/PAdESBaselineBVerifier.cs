using System.Formats.Asn1;
using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;

namespace DigitalSignature.PAdES;

public sealed class PAdESBaselineBVerifier
{
    private readonly CAdESBaselineBService _cadesService = new();

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
        if (!hasDetachedCades)
        {
            return new PAdESVerificationResult(
                ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.UnsupportedFormat,
                    ValidationErrorCodes.UnsupportedFormat,
                    "PDF signature dictionary does not declare ETSI.CAdES.detached subfilter.")),
                placeholder,
                false);
        }

        var detachedCmsSignature = TryExtractCmsSignature(text, placeholder);
        if (detachedCmsSignature.IsEmpty)
        {
            return new PAdESVerificationResult(
                ValidationResult.Success(new SignatureDescriptor(
                    SignatureFormat.PAdES,
                    SignatureLevel.BaselineB,
                    null,
                    null,
                    ValidationMaterial.Empty)),
                placeholder,
                true);
        }

        var cadesDescriptor = _cadesService.ReadSignature(detachedCmsSignature);
        var padesDescriptor = new SignatureDescriptor(
            SignatureFormat.PAdES,
            cadesDescriptor.Level,
            cadesDescriptor.SigningCertificate,
            cadesDescriptor.SigningTime,
            cadesDescriptor.ValidationMaterial,
            cadesDescriptor.SignatureAlgorithm,
            cadesDescriptor.DigestAlgorithm);

        return new PAdESVerificationResult(ValidationResult.Success(padesDescriptor), placeholder, true);
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

    private static ReadOnlyMemory<byte> TryExtractCmsSignature(string text, PdfSignaturePlaceholder placeholder)
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
            var raw = Convert.FromHexString(hexSignature);
            if (AsnDecoder.TryReadEncodedValue(raw, AsnEncodingRules.BER, out _, out _, out _, out var bytesConsumed) && bytesConsumed > 0)
            {
                return raw.AsMemory(0, bytesConsumed);
            }

            return ReadOnlyMemory<byte>.Empty;
        }
        catch (FormatException)
        {
            return ReadOnlyMemory<byte>.Empty;
        }
        catch (AsnContentException)
        {
            return ReadOnlyMemory<byte>.Empty;
        }
    }
}
