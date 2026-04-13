using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
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
        ArgumentNullException.ThrowIfNull(request);
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

        return CreateSignature(request, signingCertificate, privateKey, suite, detached: true);
    }

    public SignatureArtifact CreateAttachedSignature(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        DateTimeOffset? signingTime = null)
    {
        ArgumentNullException.ThrowIfNull(request);
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

        return CreateSignature(request, signingCertificate, privateKey, suite, detached: false);
    }

    public SignatureDescriptor ReadSignature(ReadOnlyMemory<byte> signature)
    {
        var parsed = Decode(signature);
        var signer = parsed.SignerInfos[0];
        var certificate = signer.Certificate ?? parsed.Certificates[0];

        return new SignatureDescriptor(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            certificate is null ? null : CreateCertificateReference(certificate),
            TryGetSigningTime(signer),
            new ValidationMaterial(
                certificate is null ? null : CreateCertificateReference(certificate),
                certificate is null ? Array.Empty<SigningCertificateReference>() : [CreateCertificateReference(certificate)],
                Array.Empty<RevocationInfo>(),
                Array.Empty<TimestampMaterial>(),
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
        bool detached)
    {
        var contentInfo = new ContentInfo(request.Payload.ToArray());
        var signedCms = new SignedCms(contentInfo, detached);
        var signerCertificate = signingCertificate.HasPrivateKey ? signingCertificate : signingCertificate.CopyWithPrivateKey(privateKey);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, signerCertificate)
        {
            IncludeOption = X509IncludeOption.EndCertOnly,
            DigestAlgorithm = new Oid(GetDigestOid(suite.HashAlgorithm))
        };

        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
        signer.SignedAttributes.Add(CreateSigningCertificateV2Attribute(signingCertificate, suite.HashAlgorithm));

        signedCms.ComputeSignature(signer, silent: true);
        return new SignatureArtifact(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            signedCms.Encode(),
            detached ? "application/pkcs7-signature" : "application/pkcs7-mime");
    }

    private static SignedCms Decode(ReadOnlyMemory<byte> signature)
    {
        var signedCms = new SignedCms();
        signedCms.Decode(signature.ToArray());
        return signedCms;
    }

    private static SignedCms Decode(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> payload)
    {
        var signedCms = new SignedCms(new ContentInfo(payload.ToArray()), detached: true);
        signedCms.Decode(signature.ToArray());
        return signedCms;
    }

    private static DateTimeOffset? TryGetSigningTime(SignerInfo signer)
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
}
