using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using DigitalSignature.Abstractions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.X509;

namespace DigitalSignature.PAdES;

internal static class PdfDocumentSecurityStoreBuilder
{
    public static ReadOnlyMemory<byte> Embed(
        ReadOnlyMemory<byte> signedPdf,
        ReadOnlyMemory<byte> detachedCmsSignature,
        IReadOnlyList<ReadOnlyMemory<byte>> certificateValues,
        IReadOnlyList<ReadOnlyMemory<byte>> crlValues,
        IReadOnlyList<ReadOnlyMemory<byte>> ocspValues)
    {
        var distinctCertificates = Distinct(certificateValues);
        var distinctCrls = Distinct(crlValues);
        var distinctOcsps = Distinct(ocspValues);

        if (distinctCertificates.Count == 0)
        {
            throw new InvalidOperationException("PAdES Baseline-LT augmentation requires at least one certificate value.");
        }

        if (distinctCrls.Count == 0 && distinctOcsps.Count == 0)
        {
            throw new InvalidOperationException("PAdES Baseline-LT augmentation requires at least one revocation value.");
        }

        var text = PdfDetachedSignatureLocator.Render(signedPdf);
        var (rootObjectNumber, size, previousXrefOffset) = ReadLatestTrailer(text);
        var rootObject = ReadLatestObjectBody(text, rootObjectNumber);

        var nextObjectNumber = size;
        var certObjectNumbers = AllocateObjectNumbers(nextObjectNumber, distinctCertificates.Count, out nextObjectNumber);
        var crlObjectNumbers = AllocateObjectNumbers(nextObjectNumber, distinctCrls.Count, out nextObjectNumber);
        var ocspObjectNumbers = AllocateObjectNumbers(nextObjectNumber, distinctOcsps.Count, out nextObjectNumber);
        var vriEntryObjectNumber = nextObjectNumber++;
        var vriMapObjectNumber = nextObjectNumber++;
        var dssObjectNumber = nextObjectNumber++;
        var newSize = nextObjectNumber;

        var appended = new StringBuilder();
        appended.AppendLine();
        var offsets = new Dictionary<int, int>();

        AddObject(rootObjectNumber, InjectDssReference(rootObject, dssObjectNumber));

        for (var i = 0; i < certObjectNumbers.Count; i++)
        {
            AddObject(certObjectNumbers[i], BuildAsciiHexStream(distinctCertificates[i]));
        }

        for (var i = 0; i < crlObjectNumbers.Count; i++)
        {
            AddObject(crlObjectNumbers[i], BuildAsciiHexStream(distinctCrls[i]));
        }

        for (var i = 0; i < ocspObjectNumbers.Count; i++)
        {
            AddObject(ocspObjectNumbers[i], BuildAsciiHexStream(distinctOcsps[i]));
        }

        var vriKey = Convert.ToHexString(SHA1.HashData(detachedCmsSignature.Span));
        AddObject(vriEntryObjectNumber, BuildVriEntry(certObjectNumbers, crlObjectNumbers, ocspObjectNumbers));
        AddObject(vriMapObjectNumber, $"<< /{vriKey} {vriEntryObjectNumber} 0 R >>");
        AddObject(dssObjectNumber, BuildDssDictionary(certObjectNumbers, crlObjectNumbers, ocspObjectNumbers, vriMapObjectNumber));

        var xrefOffset = signedPdf.Length + Encoding.ASCII.GetByteCount(appended.ToString());
        appended.AppendLine("xref");
        foreach (var group in offsets.Keys.Order().GroupAdjacent())
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

        return signedPdf.ToArray().Concat(Encoding.ASCII.GetBytes(appended.ToString())).ToArray();

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

    public static PdfDocumentSecurityStore Read(ReadOnlyMemory<byte> signedPdf, X509Certificate2? signingCertificate = null)
    {
        var text = PdfDetachedSignatureLocator.Render(signedPdf);
        var (rootObjectNumber, _, _) = ReadLatestTrailer(text);
        var rootObject = ReadLatestObjectBody(text, rootObjectNumber);
        var dssObjectNumber = TryReadObjectReference(rootObject, "/DSS");
        if (dssObjectNumber is null)
        {
            return PdfDocumentSecurityStore.Empty;
        }

        var dssObject = ReadLatestObjectBody(text, dssObjectNumber.Value);
        var certificateValues = ReadStreamArray(text, dssObject, "/Certs");
        var crlValues = ReadStreamArray(text, dssObject, "/CRLs");
        var ocspValues = ReadStreamArray(text, dssObject, "/OCSPs");
        var revocationValues = crlValues.Concat(ocspValues).ToArray();
        var revocationInfo = crlValues.Select(raw => MapCrl(raw, signingCertificate))
            .Concat(ocspValues.Select(MapOcsp))
            .ToArray();
        var hasVri = TryReadObjectReference(dssObject, "/VRI") is not null;

        return new PdfDocumentSecurityStore(
            certificateValues,
            crlValues,
            ocspValues,
            revocationValues,
            revocationInfo,
            hasVri);
    }

    private static List<ReadOnlyMemory<byte>> Distinct(IEnumerable<ReadOnlyMemory<byte>> values) => values
        .Where(value => !value.IsEmpty)
        .GroupBy(value => Convert.ToBase64String(value.Span), StringComparer.Ordinal)
        .Select(group => group.First())
        .ToList();

    private static List<int> AllocateObjectNumbers(int startObjectNumber, int count, out int nextObjectNumber)
    {
        var objectNumbers = Enumerable.Range(startObjectNumber, count).ToList();
        nextObjectNumber = startObjectNumber + count;
        return objectNumbers;
    }

    private static string BuildAsciiHexStream(ReadOnlyMemory<byte> value)
    {
        var hex = Convert.ToHexString(value.Span);
        return $"<< /Length {hex.Length + 1} /Filter /ASCIIHexDecode >>\nstream\n{hex}>\nendstream";
    }

    private static string BuildVriEntry(IReadOnlyList<int> certObjectNumbers, IReadOnlyList<int> crlObjectNumbers, IReadOnlyList<int> ocspObjectNumbers)
    {
        var builder = new StringBuilder("<< /Type /VRI");
        if (certObjectNumbers.Count > 0)
        {
            builder.Append(" /Cert ").Append(BuildReferenceArray(certObjectNumbers));
        }
        if (crlObjectNumbers.Count > 0)
        {
            builder.Append(" /CRL ").Append(BuildReferenceArray(crlObjectNumbers));
        }
        if (ocspObjectNumbers.Count > 0)
        {
            builder.Append(" /OCSP ").Append(BuildReferenceArray(ocspObjectNumbers));
        }
        builder.Append(" >>");
        return builder.ToString();
    }

    private static string BuildDssDictionary(
        IReadOnlyList<int> certObjectNumbers,
        IReadOnlyList<int> crlObjectNumbers,
        IReadOnlyList<int> ocspObjectNumbers,
        int vriMapObjectNumber)
    {
        var builder = new StringBuilder("<< /Type /DSS");
        if (certObjectNumbers.Count > 0)
        {
            builder.Append(" /Certs ").Append(BuildReferenceArray(certObjectNumbers));
        }
        if (crlObjectNumbers.Count > 0)
        {
            builder.Append(" /CRLs ").Append(BuildReferenceArray(crlObjectNumbers));
        }
        if (ocspObjectNumbers.Count > 0)
        {
            builder.Append(" /OCSPs ").Append(BuildReferenceArray(ocspObjectNumbers));
        }
        builder.Append(" /VRI ").Append(vriMapObjectNumber).Append(" 0 R >>");
        return builder.ToString();
    }

    private static string BuildReferenceArray(IEnumerable<int> objectNumbers) =>
        $"[{string.Join(' ', objectNumbers.Select(objectNumber => $"{objectNumber} 0 R"))}]";

    private static string InjectDssReference(string rootObject, int dssObjectNumber)
    {
        if (Regex.IsMatch(rootObject, @"/DSS\s+\d+\s+0\s+R", RegexOptions.CultureInvariant))
        {
            return Regex.Replace(rootObject, @"/DSS\s+\d+\s+0\s+R", $"/DSS {dssObjectNumber} 0 R", RegexOptions.CultureInvariant);
        }

        var end = rootObject.LastIndexOf(">>", StringComparison.Ordinal);
        if (end < 0)
        {
            throw new InvalidOperationException("PDF root object could not be rewritten with DSS reference.");
        }

        return rootObject.Insert(end, $" /DSS {dssObjectNumber} 0 R");
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
        var matches = Regex.Matches(
            text,
            $@"(?s)(?<!\d){objectNumber}\s+0\s+obj\s*(.*?)\s*endobj",
            RegexOptions.CultureInvariant);
        if (matches.Count == 0)
        {
            throw new InvalidOperationException($"PDF object '{objectNumber} 0 obj' could not be located.");
        }

        return matches[^1].Groups[1].Value.Trim();
    }

    private static int? TryReadObjectReference(string text, string key)
    {
        var match = Regex.Match(text, Regex.Escape(key) + @"\s+(\d+)\s+0\s+R", RegexOptions.CultureInvariant);
        return match.Success
            ? int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture)
            : null;
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> ReadStreamArray(string text, string dictionary, string key)
    {
        var match = Regex.Match(dictionary, Regex.Escape(key) + @"\s*\[(.*?)\]", RegexOptions.CultureInvariant | RegexOptions.Singleline);
        if (!match.Success)
        {
            return Array.Empty<ReadOnlyMemory<byte>>();
        }

        var objectNumbers = Regex.Matches(match.Groups[1].Value, @"(\d+)\s+0\s+R", RegexOptions.CultureInvariant)
            .Select(result => int.Parse(result.Groups[1].Value, CultureInfo.InvariantCulture))
            .ToArray();

        return objectNumbers.Select(objectNumber => ReadStreamObject(text, objectNumber)).ToArray();
    }

    private static ReadOnlyMemory<byte> ReadStreamObject(string text, int objectNumber)
    {
        var objectBody = ReadLatestObjectBody(text, objectNumber);
        var streamMatch = Regex.Match(objectBody, @"(?s)<<(.*?)>>\s*stream\r?\n(.*?)\r?\nendstream", RegexOptions.CultureInvariant);
        if (!streamMatch.Success)
        {
            throw new InvalidOperationException($"PDF DSS object '{objectNumber} 0 obj' does not contain a readable stream.");
        }

        var dictionary = streamMatch.Groups[1].Value;
        var streamData = streamMatch.Groups[2].Value;
        if (dictionary.Contains("/ASCIIHexDecode", StringComparison.Ordinal))
        {
            var hex = new string(streamData.Where(ch => !char.IsWhiteSpace(ch)).ToArray()).TrimEnd('>');
            return Convert.FromHexString(hex);
        }

        return Encoding.Latin1.GetBytes(streamData);
    }

    private static RevocationInfo MapCrl(ReadOnlyMemory<byte> rawValue, X509Certificate2? signingCertificate)
    {
        var crl = new X509CrlParser().ReadCrl(rawValue.ToArray());
        bool? isRevoked = null;

        if (signingCertificate is not null)
        {
            var bcCertificate = new X509CertificateParser().ReadCertificate(signingCertificate.RawData);
            if (StringComparer.OrdinalIgnoreCase.Equals(crl.IssuerDN.ToString(), bcCertificate.IssuerDN.ToString()))
            {
                isRevoked = crl.IsRevoked(bcCertificate);
            }
        }

        return new RevocationInfo(
            "CRL",
            new DateTimeOffset(crl.ThisUpdate.ToUniversalTime()),
            crl.NextUpdate is null ? null : new DateTimeOffset(crl.NextUpdate.Value.ToUniversalTime()),
            isRevoked,
            null)
        {
            EncodedValue = rawValue
        };
    }

    private static RevocationInfo MapOcsp(ReadOnlyMemory<byte> rawValue)
    {
        var response = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(rawValue.ToArray()));
        return new RevocationInfo(
            "OCSP",
            new DateTimeOffset(response.TbsResponseData.ProducedAt.ToDateTime().ToUniversalTime()),
            null,
            null,
            null)
        {
            EncodedValue = rawValue
        };
    }

    private sealed record ObjectNumberGroup(int Start, int Count, IReadOnlyList<int> ObjectNumbers);

    private static IEnumerable<ObjectNumberGroup> GroupAdjacent(this IEnumerable<int> objectNumbers)
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
