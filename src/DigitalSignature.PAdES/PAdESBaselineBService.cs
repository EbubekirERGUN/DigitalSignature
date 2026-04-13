using System.Text;
using DigitalSignature.Abstractions;

namespace DigitalSignature.PAdES;

public sealed class PAdESBaselineBService
{
    public PdfSignatureBindingResult PrepareDetachedSignaturePlaceholder(
        ReadOnlyMemory<byte> pdfDocument,
        int estimatedContentsHexLength = 16384)
    {
        var dictionaryText = PdfSignatureDictionaryBuilder.BuildPlaceholderDictionary(estimatedContentsHexLength);
        var dictionaryBytes = Encoding.ASCII.GetBytes(dictionaryText);
        var combined = pdfDocument.ToArray().Concat(dictionaryBytes).ToArray();

        var contentsMarker = "/Contents <";
        var contentsMarkerIndex = dictionaryText.IndexOf(contentsMarker, StringComparison.Ordinal);
        var contentsOffset = pdfDocument.Length + contentsMarkerIndex + contentsMarker.Length;
        var contentsLength = estimatedContentsHexLength;

        var byteRange = new PdfSignatureByteRange(
            0,
            contentsOffset,
            contentsOffset + contentsLength + 1,
            combined.Length - (contentsOffset + contentsLength + 1));

        return new PdfSignatureBindingResult(
            combined,
            new PdfSignaturePlaceholder(contentsOffset, contentsLength, byteRange),
            dictionaryText);
    }

    public ReadOnlyMemory<byte> ApplyDetachedSignature(
        PdfSignatureBindingResult binding,
        ReadOnlyMemory<byte> detachedCmsSignature)
    {
        var document = binding.Document.ToArray();
        var hexSignature = Convert.ToHexString(detachedCmsSignature.Span);

        if (hexSignature.Length > binding.Placeholder.ContentsLength)
        {
            throw new ArgumentException("Detached CMS signature does not fit inside the reserved PDF Contents placeholder.", nameof(detachedCmsSignature));
        }

        var paddedSignature = hexSignature.PadRight(binding.Placeholder.ContentsLength, '0');
        Encoding.ASCII.GetBytes(paddedSignature, document.AsSpan(binding.Placeholder.ContentsOffset, binding.Placeholder.ContentsLength));

        var byteRangeToken = "[0 ********** ********** **********]";
        var renderedByteRange = PdfByteRangeFormatter.Format(binding.Placeholder.ByteRange);
        var renderedText = Encoding.ASCII.GetString(document).Replace(byteRangeToken, renderedByteRange, StringComparison.Ordinal);

        return Encoding.ASCII.GetBytes(renderedText);
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
