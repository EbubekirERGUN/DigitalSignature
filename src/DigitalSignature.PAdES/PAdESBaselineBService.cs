using System.Text;
using DigitalSignature.Abstractions;

namespace DigitalSignature.PAdES;

public sealed class PAdESBaselineBService
{
    public PdfSignatureBindingResult PrepareDetachedSignaturePlaceholder(
        ReadOnlyMemory<byte> pdfDocument,
        int estimatedContentsHexLength = 16384)
    {
        byte[] combined;
        if (LooksLikeMinimalPdf(pdfDocument.Span))
        {
            var built = PdfSignedDocumentBuilder.CreatePlaceholder(estimatedContentsHexLength);
            combined = built.Document;
            return new PdfSignatureBindingResult(combined, built.Placeholder, Encoding.ASCII.GetString(combined));
        }

        var dictionaryText = PdfSignatureDictionaryBuilder.BuildPlaceholderDictionary(estimatedContentsHexLength);
        var dictionaryBytes = Encoding.ASCII.GetBytes(dictionaryText);
        combined = pdfDocument.ToArray().Concat(dictionaryBytes).ToArray();

        var rendered = Encoding.ASCII.GetString(combined);
        var contentsMarker = "/Contents <";
        var contentsOffset = rendered.IndexOf(contentsMarker, StringComparison.Ordinal) + contentsMarker.Length;
        var contentsLength = estimatedContentsHexLength;

        var byteRange = new PdfSignatureByteRange(
            0,
            contentsOffset,
            contentsOffset + contentsLength + 1,
            combined.Length - (contentsOffset + contentsLength + 1));

        return new PdfSignatureBindingResult(
            combined,
            new PdfSignaturePlaceholder(contentsOffset, contentsLength, byteRange),
            rendered);
    }

    public PdfDetachedSignatureInput PrepareDetachedSignatureInput(PdfSignatureBindingResult binding)
    {
        var byteRangeToken = "[0 ********** ********** **********]";
        var renderedByteRange = PdfByteRangeFormatter.Format(binding.Placeholder.ByteRange).PadRight(byteRangeToken.Length, ' ');
        var renderedText = Encoding.ASCII.GetString(binding.Document.Span).Replace(byteRangeToken, renderedByteRange, StringComparison.Ordinal);
        var preparedDocument = Encoding.ASCII.GetBytes(renderedText);

        var firstLength = binding.Placeholder.ByteRange.FirstLength;
        var secondOffset = binding.Placeholder.ByteRange.SecondOffset;
        var secondLength = preparedDocument.Length - secondOffset;
        var effectivePlaceholder = binding.Placeholder with
        {
            ByteRange = new PdfSignatureByteRange(0, firstLength, secondOffset, secondLength)
        };

        var signedBytes = preparedDocument.AsSpan(0, firstLength)
            .ToArray()
            .Concat(preparedDocument.AsSpan(secondOffset, secondLength).ToArray())
            .ToArray();

        return new PdfDetachedSignatureInput(preparedDocument, signedBytes, effectivePlaceholder);
    }

    public ReadOnlyMemory<byte> ApplyDetachedSignature(
        PdfDetachedSignatureInput input,
        ReadOnlyMemory<byte> detachedCmsSignature)
    {
        var document = input.Document.ToArray();
        var hexSignature = Convert.ToHexString(detachedCmsSignature.Span);

        if (hexSignature.Length > input.Placeholder.ContentsLength)
        {
            throw new ArgumentException("Detached CMS signature does not fit inside the reserved PDF Contents placeholder.", nameof(detachedCmsSignature));
        }

        var paddedSignature = hexSignature.PadRight(input.Placeholder.ContentsLength, '0');
        Encoding.ASCII.GetBytes(paddedSignature, document.AsSpan(input.Placeholder.ContentsOffset, input.Placeholder.ContentsLength));
        return document;
    }

    public ReadOnlyMemory<byte> ApplyDetachedSignature(
        PdfSignatureBindingResult binding,
        ReadOnlyMemory<byte> detachedCmsSignature)
        => ApplyDetachedSignature(PrepareDetachedSignatureInput(binding), detachedCmsSignature);

    private static bool LooksLikeMinimalPdf(ReadOnlySpan<byte> pdfDocument)
    {
        var text = Encoding.ASCII.GetString(pdfDocument);
        return text.StartsWith("%PDF-", StringComparison.Ordinal) && text.Contains("%%EOF", StringComparison.Ordinal);
    }

    public SignatureDescriptor CreateSignatureDescriptor()
    {
        return new SignatureDescriptor(
            SignatureFormat.PAdES,
            SignatureLevel.BaselineB,
            null,
            null,
            ValidationMaterial.Empty,
            SignatureAlgorithm: null,
            DigestAlgorithm: null);
    }
}
