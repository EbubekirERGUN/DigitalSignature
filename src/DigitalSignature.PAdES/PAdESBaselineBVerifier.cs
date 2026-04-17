using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;

namespace DigitalSignature.PAdES;

public sealed class PAdESBaselineBVerifier
{
    private readonly CAdESBaselineBService _cadesService = new();

    public PAdESVerificationResult Verify(ReadOnlyMemory<byte> signedPdf)
    {
        var text = PdfDetachedSignatureLocator.Render(signedPdf);
        var placeholder = PdfDetachedSignatureLocator.TryLocatePlaceholder(text);

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

        var hasDetachedCades = PdfDetachedSignatureLocator.HasDetachedCadesSubFilter(text);
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

        var detachedCmsSignature = PdfDetachedSignatureLocator.TryExtractCmsSignature(text, placeholder);
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

        try
        {
            var cadesDescriptor = _cadesService.ReadSignature(detachedCmsSignature);
            using var signingCertificate = ReadSigningCertificate(detachedCmsSignature);
            var dss = PdfDocumentSecurityStoreBuilder.Read(signedPdf, signingCertificate);
            var documentTimestamp = ReadDocumentTimestamp(signedPdf);
            if (documentTimestamp.Failure is not null)
            {
                return new PAdESVerificationResult(ValidationResult.Failure(documentTimestamp.Failure), placeholder, true);
            }

            var level = DetermineLevel(cadesDescriptor.Level, dss, documentTimestamp.Timestamp is not null);
            var validationMaterial = MergeValidationMaterial(cadesDescriptor.ValidationMaterial, dss, cadesDescriptor.SigningCertificate, documentTimestamp.Timestamp);

            var padesDescriptor = new SignatureDescriptor(
                SignatureFormat.PAdES,
                level,
                cadesDescriptor.SigningCertificate,
                cadesDescriptor.SigningTime,
                validationMaterial,
                cadesDescriptor.SignatureAlgorithm,
                cadesDescriptor.DigestAlgorithm);

            return new PAdESVerificationResult(ValidationResult.Success(padesDescriptor), placeholder, true);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException or FormatException)
        {
            return new PAdESVerificationResult(
                ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.MalformedSignature,
                    ValidationErrorCodes.MalformedSignature,
                    ex.Message)),
                placeholder,
                true);
        }
    }

    private static X509Certificate2? ReadSigningCertificate(ReadOnlyMemory<byte> detachedCmsSignature)
    {
        var signedCms = new System.Security.Cryptography.Pkcs.SignedCms();
        signedCms.Decode(detachedCmsSignature.ToArray());
        return signedCms.SignerInfos.Count > 0
            ? signedCms.SignerInfos[0].Certificate
            : signedCms.Certificates.Cast<X509Certificate2>().FirstOrDefault();
    }

    private static SignatureLevel DetermineLevel(SignatureLevel cadesLevel, PdfDocumentSecurityStore dss)
    {
        if (cadesLevel >= SignatureLevel.BaselineT && dss.HasEmbeddedValidationData && dss.HasVri)
        {
            return SignatureLevel.BaselineLT;
        }

        return cadesLevel;
    }

    private static SignatureLevel DetermineLevel(SignatureLevel cadesLevel, PdfDocumentSecurityStore dss, bool hasDocumentTimestamp)
    {
        if (hasDocumentTimestamp && cadesLevel >= SignatureLevel.BaselineT && dss.HasEmbeddedValidationData && dss.HasVri)
        {
            return SignatureLevel.BaselineLTA;
        }

        if (cadesLevel >= SignatureLevel.BaselineT && dss.HasEmbeddedValidationData && dss.HasVri)
        {
            return SignatureLevel.BaselineLT;
        }

        return cadesLevel;
    }

    private static ValidationMaterial MergeValidationMaterial(
        ValidationMaterial cadesValidationMaterial,
        PdfDocumentSecurityStore dss,
        SigningCertificateReference? signingCertificate,
        TimestampMaterial? archiveTimestamp)
    {
        var certificateValues = dss.CertificateValues.Count > 0
            ? dss.CertificateValues
            : cadesValidationMaterial.CertificateValues;
        var revocationValues = dss.RevocationValues.Count > 0
            ? dss.RevocationValues
            : cadesValidationMaterial.RevocationValues;
        var revocationInfo = dss.RevocationInfo.Count > 0
            ? dss.RevocationInfo
            : cadesValidationMaterial.RevocationInfo;

        return cadesValidationMaterial with
        {
            CertificateChain = BuildCertificateChainReferences(signingCertificate, cadesValidationMaterial.CertificateChain, certificateValues),
            RevocationInfo = revocationInfo,
            CertificateValues = certificateValues,
            RevocationValues = revocationValues,
            ArchiveTimestamps = archiveTimestamp is null
                ? cadesValidationMaterial.ArchiveTimestamps
                : [.. cadesValidationMaterial.ArchiveTimestamps, archiveTimestamp]
        };
    }

    private static DocumentTimestampReadResult ReadDocumentTimestamp(ReadOnlyMemory<byte> signedPdf)
    {
        var text = PdfDetachedSignatureLocator.Render(signedPdf);
        var match = Regex.Matches(
            text,
            @"(?s)<<(?:(?!>>).)*?(?:/Type\s*/DocTimeStamp\s*)?/Filter\s*/Adobe\.PPKLite\s*/SubFilter\s*/ETSI\.RFC3161(?:(?!>>).)*?/ByteRange\s*\[(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\](?:(?!>>).)*?/Contents\s*<([0-9A-Fa-f\s]+)>",
            RegexOptions.CultureInvariant);

        if (match.Count == 0)
        {
            return new DocumentTimestampReadResult(null, null);
        }

        var last = match[^1];
        try
        {
            var byteRange = new PdfSignatureByteRange(
                int.Parse(last.Groups[1].Value, CultureInfo.InvariantCulture),
                int.Parse(last.Groups[2].Value, CultureInfo.InvariantCulture),
                int.Parse(last.Groups[3].Value, CultureInfo.InvariantCulture),
                int.Parse(last.Groups[4].Value, CultureInfo.InvariantCulture));

            var contentsHex = Regex.Replace(last.Groups[5].Value, "\\s+", string.Empty, RegexOptions.CultureInvariant);
            if ((contentsHex.Length & 1) == 1)
            {
                contentsHex = contentsHex[..^1];
            }

            var raw = Convert.FromHexString(contentsHex);
            if (AsnDecoder.TryReadEncodedValue(raw, System.Formats.Asn1.AsnEncodingRules.BER, out _, out _, out _, out var bytesConsumed) && bytesConsumed > 0)
            {
                raw = raw[..bytesConsumed];
            }

            var signedBytes = signedPdf.Span.Slice(byteRange.StartOffset, byteRange.FirstLength).ToArray()
                .Concat(signedPdf.Span.Slice(byteRange.SecondOffset, byteRange.SecondLength).ToArray())
                .ToArray();

            var token = new TimeStampToken(new CmsSignedData(raw));
            var validationFailure = ValidateTimestampToken(token, signedBytes);
            if (validationFailure is not null)
            {
                return new DocumentTimestampReadResult(null, validationFailure);
            }

            return new DocumentTimestampReadResult(
                new TimestampMaterial(
                    token.GetEncoded("DER"),
                    new DateTimeOffset(token.TimeStampInfo.GenTime.ToUniversalTime()),
                    token.TimeStampInfo.Policy,
                    GetDigestFromOid(token.TimeStampInfo.MessageImprintAlgOid)),
                null);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or CmsException or TspException or InvalidOperationException or ArgumentOutOfRangeException)
        {
            return new DocumentTimestampReadResult(
                null,
                new ValidationFailure(
                    ValidationFailureKind.TimestampInvalid,
                    ValidationErrorCodes.TimestampInvalid,
                    $"PAdES document timestamp verification failed: {ex.Message}"));
        }
    }

    private static ValidationFailure? ValidateTimestampToken(TimeStampToken token, ReadOnlySpan<byte> signedBytes)
    {
        var certificate = token.GetCertificates().EnumerateMatches(token.SignerID).SingleOrDefault();
        if (certificate is null)
        {
            return new ValidationFailure(
                ValidationFailureKind.TimestampInvalid,
                ValidationErrorCodes.TimestampInvalid,
                "PAdES document timestamp token does not include a matching TSA certificate.");
        }

        var signer = token.ToCmsSignedData().GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
        if (!signer.Verify(certificate))
        {
            return new ValidationFailure(
                ValidationFailureKind.TimestampInvalid,
                ValidationErrorCodes.TimestampInvalid,
                "PAdES document timestamp token signature verification failed.");
        }

        var hashAlgorithm = GetDigestAlgorithmFromOid(token.TimeStampInfo.MessageImprintAlgOid);
        var digest = HashData(signedBytes, hashAlgorithm);
        if (!digest.SequenceEqual(token.TimeStampInfo.GetMessageImprintDigest()))
        {
            return new ValidationFailure(
                ValidationFailureKind.TimestampInvalid,
                ValidationErrorCodes.TimestampInvalid,
                "PAdES document timestamp token message imprint verification failed.");
        }

        return null;
    }

    private static byte[] HashData(ReadOnlySpan<byte> data, HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => SHA256.HashData(data),
        HashAlgorithmIdentifier.Sha384 => SHA384.HashData(data),
        HashAlgorithmIdentifier.Sha512 => SHA512.HashData(data),
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private static HashAlgorithmIdentifier GetDigestAlgorithmFromOid(string oid) => oid switch
    {
        "2.16.840.1.101.3.4.2.1" => HashAlgorithmIdentifier.Sha256,
        "2.16.840.1.101.3.4.2.2" => HashAlgorithmIdentifier.Sha384,
        "2.16.840.1.101.3.4.2.3" => HashAlgorithmIdentifier.Sha512,
        _ => throw new NotSupportedException($"Unsupported digest algorithm OID: {oid}.")
    };

    private static string? GetDigestFromOid(string? oid) => oid switch
    {
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        _ => oid
    };

    private sealed record DocumentTimestampReadResult(
        TimestampMaterial? Timestamp,
        ValidationFailure? Failure);

    private static IReadOnlyList<SigningCertificateReference> BuildCertificateChainReferences(
        SigningCertificateReference? signingCertificate,
        IReadOnlyList<SigningCertificateReference> existingChain,
        IReadOnlyList<ReadOnlyMemory<byte>> certificateValues)
    {
        var chain = new List<SigningCertificateReference>();
        var seenThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (signingCertificate is not null && seenThumbprints.Add(signingCertificate.Thumbprint))
        {
            chain.Add(signingCertificate);
        }

        foreach (var certificate in existingChain)
        {
            if (seenThumbprints.Add(certificate.Thumbprint))
            {
                chain.Add(certificate);
            }
        }

        foreach (var rawValue in certificateValues)
        {
            using var certificate = X509CertificateLoader.LoadCertificate(rawValue.Span);
            var reference = new SigningCertificateReference(
                certificate.Subject,
                certificate.Issuer,
                certificate.SerialNumber,
                certificate.Thumbprint,
                certificate.NotBefore.ToUniversalTime().ToString("O"),
                certificate.NotAfter.ToUniversalTime().ToString("O"));

            if (seenThumbprints.Add(reference.Thumbprint))
            {
                chain.Add(reference);
            }
        }

        return chain;
    }
}
