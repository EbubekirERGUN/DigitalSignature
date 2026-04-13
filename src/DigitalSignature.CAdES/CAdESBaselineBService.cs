using System.Collections;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;

namespace DigitalSignature.CAdES;

public sealed class CAdESBaselineBService
{
    private const string SignatureTimeStampTokenOid = "1.2.840.113549.1.9.16.2.14";

    public SignatureArtifact CreateDetachedSignature(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        DateTimeOffset? signingTime = null,
        TimestampMaterial? signatureTimestamp = null)
    {
        ValidateSigningInputs(request, signingCertificate, privateKey, suite);
        return CreateSignature(request, signingCertificate, privateKey, suite, detached: true, signingTime, signatureTimestamp);
    }

    public SignatureArtifact CreateAttachedSignature(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        DateTimeOffset? signingTime = null,
        TimestampMaterial? signatureTimestamp = null)
    {
        ValidateSigningInputs(request, signingCertificate, privateKey, suite);
        return CreateSignature(request, signingCertificate, privateKey, suite, detached: false, signingTime, signatureTimestamp);
    }

    public SignatureDescriptor ReadSignature(ReadOnlyMemory<byte> signature)
    {
        var parsed = Decode(signature);
        var signer = parsed.SignerInfos[0];
        var certificate = signer.Certificate ?? parsed.Certificates[0];
        var timestamps = ReadSignatureTimestamps(signer);
        var level = timestamps.Count > 0 ? SignatureLevel.BaselineT : SignatureLevel.BaselineB;

        return new SignatureDescriptor(
            SignatureFormat.CAdES,
            level,
            certificate is null ? null : CreateCertificateReference(certificate),
            TryGetSigningTime(signer),
            new ValidationMaterial(
                certificate is null ? null : CreateCertificateReference(certificate),
                certificate is null ? Array.Empty<SigningCertificateReference>() : [CreateCertificateReference(certificate)],
                Array.Empty<RevocationInfo>(),
                timestamps,
                Array.Empty<ReadOnlyMemory<byte>>()),
            SignatureAlgorithm: signer.SignatureAlgorithm?.Value,
            DigestAlgorithm: signer.DigestAlgorithm?.Value);
    }

    public ValidationResult VerifyDetachedSignature(ReadOnlyMemory<byte> payload, ReadOnlyMemory<byte> signature)
    {
        SignedCms signedCms;
        try
        {
            signedCms = Decode(signature, payload);
            signedCms.CheckSignature(verifySignatureOnly: true);
        }
        catch (CryptographicException ex)
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                ex.Message));
        }

        if (signedCms.SignerInfos.Count == 0)
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                "CMS/CAdES signature does not contain a SignerInfo."));
        }

        var timestampValidation = ValidateSignatureTimestamps(signedCms.SignerInfos[0]);
        if (timestampValidation is not null)
        {
            return ValidationResult.Failure(timestampValidation);
        }

        return ValidationResult.Success(ReadSignature(signature));
    }

    public ValidationResult VerifyAttachedSignature(ReadOnlyMemory<byte> signature)
    {
        try
        {
            var signedCms = Decode(signature);
            signedCms.CheckSignature(verifySignatureOnly: true);

            if (signedCms.SignerInfos.Count == 0)
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.MalformedSignature,
                    ValidationErrorCodes.MalformedSignature,
                    "CMS/CAdES signature does not contain a SignerInfo."));
            }

            var timestampValidation = ValidateSignatureTimestamps(signedCms.SignerInfos[0]);
            if (timestampValidation is not null)
            {
                return ValidationResult.Failure(timestampValidation);
            }

            return ValidationResult.Success(ReadSignature(signature));
        }
        catch (CryptographicException ex)
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                ex.Message));
        }
    }

    private static SignatureArtifact CreateSignature(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        bool detached,
        DateTimeOffset? signingTime,
        TimestampMaterial? signatureTimestamp)
    {
        EnsureSupportedLevel(request.Level);

        if (request.Level == SignatureLevel.BaselineT && signatureTimestamp is null)
        {
            throw new InvalidOperationException("CAdES Baseline-T signing requires a signature timestamp token.");
        }

        var contentInfo = new System.Security.Cryptography.Pkcs.ContentInfo(request.Payload.ToArray());
        var signedCms = new SignedCms(contentInfo, detached);
        var signerCertificate = signingCertificate.HasPrivateKey ? signingCertificate : signingCertificate.CopyWithPrivateKey(privateKey);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, signerCertificate)
        {
            IncludeOption = X509IncludeOption.EndCertOnly,
            DigestAlgorithm = new Oid(GetDigestOid(suite.HashAlgorithm))
        };

        signer.SignedAttributes.Add(new Pkcs9SigningTime((signingTime ?? DateTimeOffset.UtcNow).UtcDateTime));
        signer.SignedAttributes.Add(CreateSigningCertificateV2Attribute(signingCertificate, suite.HashAlgorithm));

        signedCms.ComputeSignature(signer, silent: true);

        var encodedSignature = signedCms.Encode();
        if (request.Level == SignatureLevel.BaselineT)
        {
            encodedSignature = AttachSignatureTimestamp(encodedSignature, signatureTimestamp!);
        }

        return new SignatureArtifact(
            SignatureFormat.CAdES,
            request.Level,
            encodedSignature,
            detached ? "application/pkcs7-signature" : "application/pkcs7-mime");
    }

    private static void ValidateSigningInputs(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(suite);

        if (request.Format != SignatureFormat.CAdES)
        {
            throw new ArgumentException("CAdES service only accepts CAdES requests.", nameof(request));
        }

        EnsureSupportedLevel(request.Level);

        if (!suite.IsRsa)
        {
            throw new NotSupportedException("Only RSA signature suites are supported for CAdES Baseline signatures in the current implementation.");
        }
    }

    private static void EnsureSupportedLevel(SignatureLevel level)
    {
        if (level is not SignatureLevel.BaselineB and not SignatureLevel.BaselineT)
        {
            throw new ArgumentException("CAdES signing currently supports only Baseline-B and Baseline-T requests.");
        }
    }

    private static byte[] AttachSignatureTimestamp(ReadOnlyMemory<byte> signature, TimestampMaterial timestamp)
    {
        if (timestamp.Token.IsEmpty)
        {
            throw new InvalidOperationException("Signature timestamp token cannot be empty.");
        }

        if (!Rfc3161TimestampToken.TryDecode(timestamp.Token, out _, out _))
        {
            throw new InvalidOperationException("Signature timestamp token must be a decodable RFC 3161 token.");
        }

        var cms = new CmsSignedData(signature.ToArray());
        var signer = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
        var unsignedAttributes = signer.UnsignedAttributes?.ToDictionary() ?? new Dictionary<DerObjectIdentifier, object>();
        unsignedAttributes[new DerObjectIdentifier(SignatureTimeStampTokenOid)] = new Org.BouncyCastle.Asn1.Cms.Attribute(
            new DerObjectIdentifier(SignatureTimeStampTokenOid),
            new DerSet(Asn1Object.FromByteArray(timestamp.Token.ToArray())));

        var updatedSigner = SignerInformation.ReplaceUnsignedAttributes(signer, new AttributeTable(unsignedAttributes));
        var signerStore = new SignerInformationStore([updatedSigner]);
        return CmsSignedData.ReplaceSigners(cms, signerStore).GetEncoded();
    }

    private static IReadOnlyList<TimestampMaterial> ReadSignatureTimestamps(System.Security.Cryptography.Pkcs.SignerInfo signer)
    {
        var timestamps = new List<TimestampMaterial>();

        foreach (CryptographicAttributeObject attribute in signer.UnsignedAttributes)
        {
            if (attribute.Oid?.Value != SignatureTimeStampTokenOid)
            {
                continue;
            }

            foreach (AsnEncodedData value in attribute.Values)
            {
                if (!Rfc3161TimestampToken.TryDecode(value.RawData, out var timestampToken, out _))
                {
                    continue;
                }

                timestamps.Add(new TimestampMaterial(
                    value.RawData,
                    timestampToken!.TokenInfo.Timestamp,
                    timestampToken.TokenInfo.PolicyId?.Value,
                    GetDigestFromOid(timestampToken.TokenInfo.HashAlgorithmId?.Value)));
            }
        }

        return timestamps;
    }

    private static ValidationFailure? ValidateSignatureTimestamps(System.Security.Cryptography.Pkcs.SignerInfo signer)
    {
        foreach (CryptographicAttributeObject attribute in signer.UnsignedAttributes)
        {
            if (attribute.Oid?.Value != SignatureTimeStampTokenOid)
            {
                continue;
            }

            foreach (AsnEncodedData value in attribute.Values)
            {
                if (!Rfc3161TimestampToken.TryDecode(value.RawData, out var timestampToken, out _))
                {
                    return new ValidationFailure(
                        ValidationFailureKind.TimestampInvalid,
                        ValidationErrorCodes.TimestampInvalid,
                        "Signature timestamp token could not be decoded as an RFC 3161 token.");
                }

                if (!timestampToken!.VerifySignatureForSignerInfo(signer, out _, null))
                {
                    return new ValidationFailure(
                        ValidationFailureKind.TimestampInvalid,
                        ValidationErrorCodes.TimestampInvalid,
                        "Signature timestamp token verification failed for the CAdES SignerInfo.");
                }
            }
        }

        return null;
    }

    private static SignedCms Decode(ReadOnlyMemory<byte> signature)
    {
        var signedCms = new SignedCms();
        signedCms.Decode(signature.ToArray());
        return signedCms;
    }

    private static SignedCms Decode(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> payload)
    {
        var signedCms = new SignedCms(new System.Security.Cryptography.Pkcs.ContentInfo(payload.ToArray()), detached: true);
        signedCms.Decode(signature.ToArray());
        return signedCms;
    }

    private static DateTimeOffset? TryGetSigningTime(System.Security.Cryptography.Pkcs.SignerInfo signer)
    {
        foreach (CryptographicAttributeObject attribute in signer.SignedAttributes)
        {
            if (attribute.Oid?.Value != "1.2.840.113549.1.9.5")
            {
                continue;
            }

            foreach (var value in attribute.Values)
            {
                if (value is Pkcs9SigningTime signingTime)
                {
                    return signingTime.SigningTime;
                }
            }
        }

        return null;
    }

    private static Pkcs9AttributeObject CreateSigningCertificateV2Attribute(X509Certificate2 certificate, HashAlgorithmIdentifier hashAlgorithm)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier(GetDigestOid(hashAlgorithm));
        writer.PopSequence();
        writer.WriteOctetString(HashCertificate(certificate.RawData, hashAlgorithm));
        writer.PopSequence();
        writer.PopSequence();
        writer.PopSequence();

        return new Pkcs9AttributeObject("1.2.840.113549.1.9.16.2.47", writer.Encode());
    }

    private static SigningCertificateReference CreateCertificateReference(X509Certificate2 certificate) => new(
        certificate.Subject,
        certificate.Issuer,
        certificate.SerialNumber,
        certificate.Thumbprint,
        certificate.NotBefore.ToUniversalTime().ToString("O"),
        certificate.NotAfter.ToUniversalTime().ToString("O"));

    private static byte[] HashCertificate(byte[] rawData, HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => SHA256.HashData(rawData),
        HashAlgorithmIdentifier.Sha384 => SHA384.HashData(rawData),
        HashAlgorithmIdentifier.Sha512 => SHA512.HashData(rawData),
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private static string GetDigestOid(HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => "2.16.840.1.101.3.4.2.1",
        HashAlgorithmIdentifier.Sha384 => "2.16.840.1.101.3.4.2.2",
        HashAlgorithmIdentifier.Sha512 => "2.16.840.1.101.3.4.2.3",
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private static string? GetDigestFromOid(string? oid) => oid switch
    {
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        _ => oid
    };
}
