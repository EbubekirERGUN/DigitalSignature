using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;

namespace DigitalSignature.PAdES;

public sealed class PAdESBaselineBService
{
    private readonly CAdESBaselineBService _cadesService = new();

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

    public ReadOnlyMemory<byte> AugmentToBaselineLT(
        ReadOnlyMemory<byte> signedPdf,
        IReadOnlyList<RevocationInfo> revocationInfo,
        IReadOnlyList<X509Certificate2>? validationCertificates = null)
    {
        var text = PdfDetachedSignatureLocator.Render(signedPdf);
        var placeholder = PdfDetachedSignatureLocator.TryLocatePlaceholder(text)
            ?? throw new InvalidOperationException("PDF signature placeholder was not found.");

        if (!PdfDetachedSignatureLocator.HasDetachedCadesSubFilter(text))
        {
            throw new InvalidOperationException("PDF signature dictionary does not declare ETSI.CAdES.detached subfilter.");
        }

        var detachedCmsSignature = PdfDetachedSignatureLocator.TryExtractCmsSignature(text, placeholder);
        if (detachedCmsSignature.IsEmpty)
        {
            throw new InvalidOperationException("Detached CMS signature could not be extracted from the PDF contents placeholder.");
        }

        var cadesDescriptor = _cadesService.ReadSignature(detachedCmsSignature);
        if (cadesDescriptor.Level < SignatureLevel.BaselineT)
        {
            throw new InvalidOperationException("PAdES Baseline-LT augmentation requires an existing Baseline-T detached CAdES signature.");
        }

        var certificateValues = CollectCertificateValues(detachedCmsSignature, cadesDescriptor.ValidationMaterial, validationCertificates);
        var (crlValues, ocspValues) = CollectRevocationValues(revocationInfo, cadesDescriptor.ValidationMaterial.RevocationValues);

        return PdfDocumentSecurityStoreBuilder.Embed(
            signedPdf,
            detachedCmsSignature,
            certificateValues,
            crlValues,
            ocspValues);
    }

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

    private static IReadOnlyList<ReadOnlyMemory<byte>> CollectCertificateValues(
        ReadOnlyMemory<byte> detachedCmsSignature,
        ValidationMaterial validationMaterial,
        IReadOnlyList<X509Certificate2>? validationCertificates)
    {
        var values = new List<ReadOnlyMemory<byte>>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void AddValue(ReadOnlyMemory<byte> value)
        {
            if (value.IsEmpty)
            {
                return;
            }

            if (seen.Add(Convert.ToBase64String(value.Span)))
            {
                values.Add(value);
            }
        }

        var signedCms = new SignedCms();
        signedCms.Decode(detachedCmsSignature.ToArray());
        foreach (var certificate in signedCms.Certificates)
        {
            AddValue(certificate.RawData);
        }

        foreach (var value in validationMaterial.CertificateValues)
        {
            AddValue(value);
        }

        if (validationCertificates is not null)
        {
            foreach (var certificate in validationCertificates)
            {
                AddValue(certificate.RawData);
            }
        }

        foreach (var timestamp in validationMaterial.Timestamps)
        {
            var token = new TimeStampToken(new CmsSignedData(timestamp.Token.ToArray()));
            foreach (var certificate in token.GetCertificates().EnumerateMatches(null))
            {
                AddValue(certificate.GetEncoded());
            }
        }

        return values;
    }

    private static (IReadOnlyList<ReadOnlyMemory<byte>> CrlValues, IReadOnlyList<ReadOnlyMemory<byte>> OcspValues) CollectRevocationValues(
        IReadOnlyList<RevocationInfo> revocationInfo,
        IReadOnlyList<ReadOnlyMemory<byte>> validationRevocationValues)
    {
        var crlValues = new List<ReadOnlyMemory<byte>>();
        var ocspValues = new List<ReadOnlyMemory<byte>>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void AddValue(ReadOnlyMemory<byte> value, bool isCrl)
        {
            if (value.IsEmpty)
            {
                return;
            }

            if (!seen.Add(Convert.ToBase64String(value.Span)))
            {
                return;
            }

            if (isCrl)
            {
                crlValues.Add(value);
                return;
            }

            ocspValues.Add(value);
        }

        foreach (var info in revocationInfo)
        {
            if (info.EncodedValue.IsEmpty)
            {
                continue;
            }

            AddValue(info.EncodedValue, info.Source.Contains("CRL", StringComparison.OrdinalIgnoreCase));
        }

        foreach (var value in validationRevocationValues)
        {
            AddValue(value, isCrl: true);
        }

        return (crlValues, ocspValues);
    }
}
