using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;

namespace DigitalSignature.PAdES;

public sealed class PAdESBaselineBService
{
    private const string ByteRangeToken = "[0 ********** ********** **********]";
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
        var renderedByteRange = PdfByteRangeFormatter.Format(binding.Placeholder.ByteRange).PadRight(ByteRangeToken.Length, ' ');
        var renderedText = Encoding.ASCII.GetString(binding.Document.Span).Replace(ByteRangeToken, renderedByteRange, StringComparison.Ordinal);
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

    public PdfDetachedSignatureInput PrepareDocumentTimestampInput(
        ReadOnlyMemory<byte> signedPdf,
        int estimatedContentsHexLength = 16384)
    {
        EnsureCanAugmentToBaselineLTA(signedPdf);

        var text = PdfDetachedSignatureLocator.Render(signedPdf);
        var (rootObjectNumber, size, previousXrefOffset) = ReadLatestTrailer(text);
        var rootObject = ReadLatestObjectBody(text, rootObjectNumber);
        var acroFormObjectNumber = TryReadObjectReference(rootObject, "/AcroForm")
            ?? throw new InvalidOperationException("PDF root object does not declare an AcroForm required for document timestamp augmentation.");
        var pagesObjectNumber = TryReadObjectReference(rootObject, "/Pages")
            ?? throw new InvalidOperationException("PDF root object does not declare /Pages.");
        var acroFormObject = ReadLatestObjectBody(text, acroFormObjectNumber);
        var pagesObject = ReadLatestObjectBody(text, pagesObjectNumber);
        var pageObjectNumber = ReadFirstPageObjectNumber(pagesObject);
        var pageObject = ReadLatestObjectBody(text, pageObjectNumber);

        var timestampFieldObjectNumber = size;
        var timestampDictionaryObjectNumber = size + 1;
        var newSize = size + 2;

        var appended = new StringBuilder();
        appended.AppendLine();
        var offsets = new Dictionary<int, int>();

        AddObject(pageObjectNumber, AppendReferenceToArray(pageObject, "/Annots", $"{timestampFieldObjectNumber} 0 R"));
        AddObject(acroFormObjectNumber, AppendReferenceToArray(acroFormObject, "/Fields", $"{timestampFieldObjectNumber} 0 R"));
        AddObject(timestampFieldObjectNumber, BuildDocumentTimestampField(pageObjectNumber, timestampDictionaryObjectNumber));
        AddObject(timestampDictionaryObjectNumber, BuildDocumentTimestampDictionary(estimatedContentsHexLength));

        var xrefOffset = signedPdf.Length + Encoding.ASCII.GetByteCount(appended.ToString());
        appended.AppendLine("xref");
        foreach (var group in GroupAdjacent(offsets.Keys.Order()))
        {
            appended.Append(group.Start).Append(' ').Append(group.Count).AppendLine();
            foreach (var objectNumber in group.ObjectNumbers)
            {
                appended.Append(offsets[objectNumber].ToString("D10", CultureInfo.InvariantCulture)).AppendLine(" 00000 n ");
            }
        }

        appended.AppendLine("trailer");
        appended.Append("<< /Size ").Append(newSize)
            .Append(" /Root ").Append(rootObjectNumber).Append(" 0 R")
            .Append(" /Prev ").Append(previousXrefOffset)
            .AppendLine(" >>");
        appended.AppendLine("startxref");
        appended.AppendLine(xrefOffset.ToString(CultureInfo.InvariantCulture));
        appended.Append("%%EOF");

        var combined = signedPdf.ToArray().Concat(Encoding.ASCII.GetBytes(appended.ToString())).ToArray();
        var rendered = Encoding.ASCII.GetString(combined);
        var subFilterOffset = rendered.LastIndexOf("/SubFilter /ETSI.RFC3161", StringComparison.Ordinal);
        if (subFilterOffset < 0)
        {
            throw new InvalidOperationException("Document timestamp placeholder could not be located after augmentation preparation.");
        }

        var contentsMarker = "/Contents <";
        var contentsOffset = rendered.IndexOf(contentsMarker, subFilterOffset, StringComparison.Ordinal);
        if (contentsOffset < 0)
        {
            throw new InvalidOperationException("Document timestamp contents placeholder could not be located.");
        }

        contentsOffset += contentsMarker.Length;
        var contentsEnd = rendered.IndexOf('>', contentsOffset);
        if (contentsEnd < 0)
        {
            throw new InvalidOperationException("Document timestamp contents placeholder could not be completed.");
        }

        var placeholder = new PdfSignaturePlaceholder(
            contentsOffset,
            contentsEnd - contentsOffset,
            new PdfSignatureByteRange(
                0,
                contentsOffset,
                contentsEnd + 1,
                combined.Length - (contentsEnd + 1)));

        return PrepareDetachedSignatureInput(new PdfSignatureBindingResult(combined, placeholder, rendered));

        void AddObject(int objectNumber, string content)
        {
            offsets[objectNumber] = signedPdf.Length + Encoding.ASCII.GetByteCount(appended.ToString());
            appended.Append(objectNumber).AppendLine(" 0 obj");
            appended.Append(content);
            if (!content.EndsWith('\n'))
            {
                appended.AppendLine();
            }

            appended.AppendLine("endobj");
        }
    }

    public TimestampRequest CreateDocumentTimestampRequest(
        PdfDetachedSignatureInput input,
        HashAlgorithmIdentifier hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(input);
        return new TimestampRequest(HashData(input.SignedBytes.Span, hashAlgorithm), GetDigestOid(hashAlgorithm));
    }

    public ReadOnlyMemory<byte> ApplyDocumentTimestamp(
        PdfDetachedSignatureInput input,
        TimestampMaterial documentTimestamp)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (documentTimestamp.Token.IsEmpty)
        {
            throw new InvalidOperationException("Document timestamp token cannot be empty.");
        }

        try
        {
            _ = new TimeStampToken(new CmsSignedData(documentTimestamp.Token.ToArray()));
        }
        catch (Exception ex) when (ex is CmsException or TspException)
        {
            throw new InvalidOperationException("Document timestamp token must be a decodable RFC 3161 token.", ex);
        }

        return ApplyDetachedSignature(input, documentTimestamp.Token);
    }

    public ReadOnlyMemory<byte> AugmentToBaselineLTA(
        ReadOnlyMemory<byte> baselineLtPdf,
        TimestampMaterial documentTimestamp,
        int estimatedContentsHexLength = 16384)
    {
        var input = PrepareDocumentTimestampInput(baselineLtPdf, estimatedContentsHexLength);
        return ApplyDocumentTimestamp(input, documentTimestamp);
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

    private void EnsureCanAugmentToBaselineLTA(ReadOnlyMemory<byte> signedPdf)
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
        var dss = PdfDocumentSecurityStoreBuilder.Read(signedPdf);
        if (cadesDescriptor.Level < SignatureLevel.BaselineT || !dss.HasEmbeddedValidationData || !dss.HasVri)
        {
            throw new InvalidOperationException("PAdES Baseline-LTA augmentation requires an existing Baseline-LT PDF with DSS and VRI data.");
        }
    }

    private static string BuildDocumentTimestampField(int pageObjectNumber, int documentTimestampObjectNumber) =>
        $"<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [0 0 0 0] /T (DocTimeStamp1) /F 132 /P {pageObjectNumber} 0 R /V {documentTimestampObjectNumber} 0 R >>";

    private static string BuildDocumentTimestampDictionary(int estimatedContentsHexLength)
    {
        var placeholder = new string('0', estimatedContentsHexLength);
        return $"<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 /ByteRange {ByteRangeToken} /Contents <{placeholder}> >>";
    }

    private static string AppendReferenceToArray(string objectBody, string key, string reference)
    {
        var arrayPattern = $@"{Regex.Escape(key)}\s*\[(.*?)\]";
        var arrayMatch = Regex.Match(objectBody, arrayPattern, RegexOptions.Singleline | RegexOptions.CultureInvariant);
        if (arrayMatch.Success)
        {
            var current = arrayMatch.Groups[1].Value.Trim();
            var updated = string.IsNullOrWhiteSpace(current)
                ? $"{key} [{reference}]"
                : $"{key} [{current} {reference}]";
            return Regex.Replace(objectBody, arrayPattern, updated, RegexOptions.Singleline | RegexOptions.CultureInvariant);
        }

        var end = objectBody.LastIndexOf(">>", StringComparison.Ordinal);
        if (end < 0)
        {
            throw new InvalidOperationException($"PDF object could not be rewritten with {key} reference.");
        }

        return objectBody.Insert(end, $" {key} [{reference}]");
    }

    private static int ReadFirstPageObjectNumber(string pagesObject)
    {
        var kidsMatch = Regex.Match(pagesObject, @"/Kids\s*\[(\d+)\s+0\s+R", RegexOptions.CultureInvariant);
        if (!kidsMatch.Success)
        {
            throw new InvalidOperationException("PDF pages tree does not declare a first page reference.");
        }

        return int.Parse(kidsMatch.Groups[1].Value, CultureInfo.InvariantCulture);
    }

    private static (int RootObjectNumber, int Size, int StartXrefOffset) ReadLatestTrailer(string text)
    {
        var matches = Regex.Matches(text, @"(?s)trailer\s*<<(.*?)>>\s*startxref\s*(\d+)", RegexOptions.CultureInvariant);
        if (matches.Count == 0)
        {
            throw new InvalidOperationException("PDF trailer could not be located.");
        }

        var last = matches[^1];
        var dictionary = last.Groups[1].Value;
        var startXrefOffset = int.Parse(last.Groups[2].Value, CultureInfo.InvariantCulture);
        var rootObjectNumber = TryReadObjectReference(dictionary, "/Root")
            ?? throw new InvalidOperationException("PDF trailer does not declare a root object.");
        var sizeMatch = Regex.Match(dictionary, @"/Size\s+(\d+)", RegexOptions.CultureInvariant);
        if (!sizeMatch.Success)
        {
            throw new InvalidOperationException("PDF trailer does not declare /Size.");
        }

        return (rootObjectNumber, int.Parse(sizeMatch.Groups[1].Value, CultureInfo.InvariantCulture), startXrefOffset);
    }

    private static string ReadLatestObjectBody(string text, int objectNumber)
    {
        var matches = Regex.Matches(text, $@"(?s)(?<!\d){objectNumber}\s+0\s+obj\s*(.*?)\s*endobj", RegexOptions.CultureInvariant);
        if (matches.Count == 0)
        {
            throw new InvalidOperationException($"PDF object '{objectNumber} 0 obj' could not be located.");
        }

        return matches[^1].Groups[1].Value;
    }

    private static int? TryReadObjectReference(string text, string key)
    {
        var match = Regex.Match(text, $@"{Regex.Escape(key)}\s+(\d+)\s+0\s+R", RegexOptions.CultureInvariant);
        return match.Success
            ? int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture)
            : null;
    }

    private static byte[] HashData(ReadOnlySpan<byte> data, HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => SHA256.HashData(data),
        HashAlgorithmIdentifier.Sha384 => SHA384.HashData(data),
        HashAlgorithmIdentifier.Sha512 => SHA512.HashData(data),
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private static string GetDigestOid(HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => "2.16.840.1.101.3.4.2.1",
        HashAlgorithmIdentifier.Sha384 => "2.16.840.1.101.3.4.2.2",
        HashAlgorithmIdentifier.Sha512 => "2.16.840.1.101.3.4.2.3",
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private sealed record ObjectNumberGroup(int Start, int Count, IReadOnlyList<int> ObjectNumbers);

    private static IEnumerable<ObjectNumberGroup> GroupAdjacent(IEnumerable<int> objectNumbers)
    {
        List<int>? current = null;
        foreach (var objectNumber in objectNumbers)
        {
            if (current is null || objectNumber != current[^1] + 1)
            {
                if (current is not null)
                {
                    yield return new ObjectNumberGroup(current[0], current.Count, current);
                }

                current = [objectNumber];
                continue;
            }

            current.Add(objectNumber);
        }

        if (current is not null)
        {
            yield return new ObjectNumberGroup(current[0], current.Count, current);
        }
    }
}
