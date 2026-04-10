using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.CAdES;

public sealed class CAdESBaselineBService
{
    public SignatureArtifact CreateDetachedSignature(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        DateTimeOffset? signingTime = null)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(suite);

        if (request.Format != SignatureFormat.CAdES)
        {
            throw new ArgumentException("CAdES service only accepts CAdES requests.", nameof(request));
        }

        if (request.Level != SignatureLevel.BaselineB)
        {
            throw new ArgumentException("CAdES Baseline-B signing requires SignatureLevel.BaselineB.", nameof(request));
        }

        if (!suite.IsRsa)
        {
            throw new NotSupportedException("Only RSA signature suites are supported for CAdES Baseline-B in the current implementation.");
        }

        var content = request.Payload.ToArray();
        var digestOid = GetDigestOid(suite.HashAlgorithm);
        var digest = HashData(content, suite.HashAlgorithm);
        var signedAttributes = BuildSignedAttributes(digest, digestOid, signingTime ?? DateTimeOffset.UtcNow);
        var signatureValue = SignSignedAttributes(signedAttributes, privateKey, suite);
        var signature = BuildSignedData(signingCertificate, digestOid, signedAttributes, signatureValue, suite, detached: true);

        return new SignatureArtifact(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            signature,
            "application/pkcs7-signature");
    }

    public SignatureDescriptor ReadSignature(ReadOnlyMemory<byte> signature)
    {
        var parsed = ParseSignedData(signature.Span);

        return new SignatureDescriptor(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            CreateCertificateReference(parsed.Certificate),
            parsed.SigningTime,
            new ValidationMaterial(
                CreateCertificateReference(parsed.Certificate),
                new[] { CreateCertificateReference(parsed.Certificate) },
                Array.Empty<RevocationInfo>(),
                Array.Empty<TimestampMaterial>(),
                Array.Empty<ReadOnlyMemory<byte>>()),
            SignatureAlgorithm: parsed.SignatureAlgorithm,
            DigestAlgorithm: parsed.DigestAlgorithm);
    }

    public ValidationResult VerifyDetachedSignature(ReadOnlyMemory<byte> payload, ReadOnlyMemory<byte> signature)
    {
        ParsedSignedData parsed;

        try
        {
            parsed = ParseSignedData(signature.Span);
        }
        catch (CryptographicException ex)
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                ex.Message));
        }

        var recomputedDigest = HashData(payload.ToArray(), parsed.HashAlgorithm);
        if (!CryptographicOperations.FixedTimeEquals(recomputedDigest, parsed.MessageDigest))
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.HashMismatch,
                ValidationErrorCodes.HashMismatch,
                "Detached content digest does not match the signed message-digest attribute."));
        }

        using var rsa = parsed.Certificate.GetRSAPublicKey();
        if (rsa is null)
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.UnsupportedAlgorithm,
                ValidationErrorCodes.UnsupportedAlgorithm,
                "Signing certificate does not expose an RSA public key."));
        }

        var verified = parsed.UsePss
            ? rsa.VerifyData(parsed.SignedAttributes, parsed.SignatureValue, parsed.HashAlgorithmName, RSASignaturePadding.Pss)
            : rsa.VerifyData(parsed.SignedAttributes, parsed.SignatureValue, parsed.HashAlgorithmName, RSASignaturePadding.Pkcs1);

        if (!verified)
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.SignatureValueInvalid,
                ValidationErrorCodes.SignatureValueInvalid,
                "CMS SignerInfo signature verification failed."));
        }

        return ValidationResult.Success(ReadSignature(signature));
    }

    private static byte[] BuildSignedData(
        X509Certificate2 certificate,
        string digestOid,
        byte[] signedAttributesDer,
        byte[] signatureValue,
        SignatureSuite suite,
        bool detached)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
        writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        writer.PushSequence();
        writer.WriteInteger(1);

        writer.PushSetOf();
        writer.PushSequence();
        writer.WriteObjectIdentifier(digestOid);
        writer.WriteNull();
        writer.PopSequence();
        writer.PopSetOf();

        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.7.1");
        if (!detached)
        {
            throw new NotSupportedException("Encapsulated content is not implemented in detached mode service.");
        }
        writer.PopSequence();

        writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        writer.WriteEncodedValue(certificate.RawData);
        writer.PopSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));

        writer.PushSetOf();
        writer.PushSequence();
        writer.WriteInteger(1);

        writer.PushSequence();
        WriteIssuerAndSerialNumber(writer, certificate);
        writer.PopSequence();

        writer.PushSequence();
        writer.WriteObjectIdentifier(digestOid);
        writer.WriteNull();
        writer.PopSequence();

        writer.WriteEncodedValue(signedAttributesDer);

        writer.PushSequence();
        writer.WriteObjectIdentifier(suite.SignatureAlgorithm == SignatureAlgorithmIdentifier.RsaPss ? "1.2.840.113549.1.1.10" : "1.2.840.113549.1.1.1");
        writer.WriteNull();
        writer.PopSequence();

        writer.WriteOctetString(signatureValue);
        writer.PopSequence();
        writer.PopSetOf();

        writer.PopSequence();
        writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        writer.PopSequence();

        return writer.Encode();
    }

    private static void WriteIssuerAndSerialNumber(AsnWriter writer, X509Certificate2 certificate)
    {
        var issuerName = certificate.IssuerName.RawData;
        var serialBytes = certificate.SerialNumberBytes.Span;
        var serial = serialBytes.Length > 0 && (serialBytes[0] & 0x80) != 0
            ? [0, .. serialBytes.ToArray()]
            : serialBytes.ToArray();

        writer.WriteEncodedValue(issuerName);
        writer.WriteIntegerUnsigned(serial);
    }

    private static byte[] BuildSignedAttributes(byte[] digest, string digestOid, DateTimeOffset signingTime)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSetOf();

        WriteAttribute(writer, "1.2.840.113549.1.9.3", valueWriter =>
        {
            valueWriter.WriteObjectIdentifier("1.2.840.113549.1.7.1");
        });

        WriteAttribute(writer, "1.2.840.113549.1.9.5", valueWriter =>
        {
            valueWriter.WriteUtcTime(signingTime.UtcDateTime);
        });

        WriteAttribute(writer, "1.2.840.113549.1.9.4", valueWriter =>
        {
            valueWriter.WriteOctetString(digest);
        });

        WriteAttribute(writer, "1.2.840.113549.1.9.16.2.47", valueWriter =>
        {
            valueWriter.PushSequence();
            valueWriter.PushSequence();
            valueWriter.WriteObjectIdentifier(digestOid);
            valueWriter.WriteNull();
            valueWriter.PopSequence();
            valueWriter.WriteOctetString(digest);
            valueWriter.PopSequence();
        });

        writer.PopSetOf();
        return writer.Encode();
    }

    private static void WriteAttribute(AsnWriter parent, string oid, Action<AsnWriter> valueFactory)
    {
        parent.PushSequence();
        parent.WriteObjectIdentifier(oid);
        parent.PushSetOf();
        var valueWriter = new AsnWriter(AsnEncodingRules.DER);
        valueFactory(valueWriter);
        parent.WriteEncodedValue(valueWriter.Encode());
        parent.PopSetOf();
        parent.PopSequence();
    }

    private static byte[] SignSignedAttributes(byte[] signedAttributes, RSA privateKey, SignatureSuite suite)
    {
        var hashAlgorithmName = ToHashAlgorithmName(suite.HashAlgorithm);
        var padding = suite.SignatureAlgorithm == SignatureAlgorithmIdentifier.RsaPss
            ? RSASignaturePadding.Pss
            : RSASignaturePadding.Pkcs1;

        return privateKey.SignData(signedAttributes, hashAlgorithmName, padding);
    }

    private static byte[] HashData(byte[] data, HashAlgorithmIdentifier algorithm) => algorithm switch
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

    private static HashAlgorithmIdentifier ParseHashAlgorithm(string oid) => oid switch
    {
        "2.16.840.1.101.3.4.2.1" => HashAlgorithmIdentifier.Sha256,
        "2.16.840.1.101.3.4.2.2" => HashAlgorithmIdentifier.Sha384,
        "2.16.840.1.101.3.4.2.3" => HashAlgorithmIdentifier.Sha512,
        _ => throw new CryptographicException($"Unsupported digest algorithm OID: {oid}.")
    };

    private static HashAlgorithmName ToHashAlgorithmName(HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => HashAlgorithmName.SHA256,
        HashAlgorithmIdentifier.Sha384 => HashAlgorithmName.SHA384,
        HashAlgorithmIdentifier.Sha512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private static ParsedSignedData ParseSignedData(ReadOnlySpan<byte> signature)
    {
        try
        {
            var reader = new AsnReader(signature.ToArray(), AsnEncodingRules.DER);
            var contentInfo = reader.ReadSequence();
            var contentType = contentInfo.ReadObjectIdentifier();
            if (contentType != "1.2.840.113549.1.7.2")
            {
                throw new CryptographicException("ContentInfo does not contain CMS SignedData.");
            }

            var signedDataReader = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadSequence();
            _ = signedDataReader.ReadInteger();

            var digestAlgorithms = signedDataReader.ReadSetOf();
            var digestAlgorithm = digestAlgorithms.ReadSequence();
            var digestOid = digestAlgorithm.ReadObjectIdentifier();
            if (digestAlgorithm.HasData)
            {
                digestAlgorithm.ReadNull();
            }

            var hashAlgorithm = ParseHashAlgorithm(digestOid);
            signedDataReader.ReadSequence();

            var certificateSet = signedDataReader.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
            var certificateBytes = certificateSet.PeekEncodedValue().ToArray();
            var certificate = X509CertificateLoader.LoadCertificate(certificateBytes);
            certificateSet.ReadEncodedValue();

            var signerInfos = signedDataReader.ReadSetOf();
            var signerInfo = signerInfos.ReadSequence();
            _ = signerInfo.ReadInteger();
            signerInfo.ReadSequence();

            var signerDigestAlgorithm = signerInfo.ReadSequence();
            var signerDigestOid = signerDigestAlgorithm.ReadObjectIdentifier();
            if (signerDigestAlgorithm.HasData)
            {
                signerDigestAlgorithm.ReadNull();
            }

            if (signerDigestOid != digestOid)
            {
                throw new CryptographicException("SignerInfo digest algorithm does not match SignedData digest algorithm.");
            }

            var signedAttributes = signerInfo.ReadEncodedValue().ToArray();

            var signatureAlgorithm = signerInfo.ReadSequence();
            var signatureOid = signatureAlgorithm.ReadObjectIdentifier();
            if (signatureAlgorithm.HasData)
            {
                signatureAlgorithm.ReadEncodedValue();
            }

            var signatureValue = signerInfo.ReadOctetString();

            var attrsReader = new AsnReader(signedAttributes, AsnEncodingRules.DER);
            var attrSet = attrsReader.ReadSetOf();

            byte[]? messageDigest = null;
            DateTimeOffset? signingTime = null;

            while (attrSet.HasData)
            {
                var attr = attrSet.ReadSequence();
                var oid = attr.ReadObjectIdentifier();
                var values = attr.ReadSetOf();

                switch (oid)
                {
                    case "1.2.840.113549.1.9.4":
                        messageDigest = values.ReadOctetString();
                        break;
                    case "1.2.840.113549.1.9.5":
                        signingTime = values.PeekTag().TagValue == (int)UniversalTagNumber.UtcTime
                            ? values.ReadUtcTime()
                            : values.ReadGeneralizedTime();
                        break;
                    default:
                        while (values.HasData)
                        {
                            values.ReadEncodedValue();
                        }
                        break;
                }
            }

            if (messageDigest is null)
            {
                throw new CryptographicException("SignerInfo is missing the message-digest signed attribute.");
            }

            return new ParsedSignedData(
                certificate,
                hashAlgorithm,
                ToHashAlgorithmName(hashAlgorithm),
                messageDigest,
                signedAttributes,
                signatureValue,
                signingTime,
                SignatureAlgorithm: signatureOid,
                DigestAlgorithm: digestOid,
                UsePss: signatureOid == "1.2.840.113549.1.1.10");
        }
        catch (AsnContentException ex)
        {
            throw new CryptographicException("Malformed CMS/CAdES signature payload.", ex);
        }
    }

    private static SigningCertificateReference CreateCertificateReference(X509Certificate2 certificate) => new(
        certificate.Subject,
        certificate.Issuer,
        certificate.SerialNumber,
        certificate.Thumbprint,
        certificate.NotBefore.ToUniversalTime().ToString("O"),
        certificate.NotAfter.ToUniversalTime().ToString("O"));

    private sealed record ParsedSignedData(
        X509Certificate2 Certificate,
        HashAlgorithmIdentifier HashAlgorithm,
        HashAlgorithmName HashAlgorithmName,
        byte[] MessageDigest,
        byte[] SignedAttributes,
        byte[] SignatureValue,
        DateTimeOffset? SigningTime,
        string SignatureAlgorithm,
        string DigestAlgorithm,
        bool UsePss);
}
