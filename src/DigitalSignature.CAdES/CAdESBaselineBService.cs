using System.Collections;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

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
        TimestampMaterial? signatureTimestamp = null,
        IReadOnlyList<X509Certificate2>? validationCertificates = null,
        IReadOnlyList<RevocationInfo>? revocationInfo = null,
        bool includeSigningTime = true)
    {
        ValidateSigningInputs(request, signingCertificate, privateKey, suite);
        return CreateSignature(request, signingCertificate, privateKey, suite, detached: true, signingTime, signatureTimestamp, validationCertificates, revocationInfo, includeSigningTime);
    }

    public SignatureArtifact CreateAttachedSignature(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        DateTimeOffset? signingTime = null,
        TimestampMaterial? signatureTimestamp = null,
        IReadOnlyList<X509Certificate2>? validationCertificates = null,
        IReadOnlyList<RevocationInfo>? revocationInfo = null,
        bool includeSigningTime = true)
    {
        ValidateSigningInputs(request, signingCertificate, privateKey, suite);
        return CreateSignature(request, signingCertificate, privateKey, suite, detached: false, signingTime, signatureTimestamp, validationCertificates, revocationInfo, includeSigningTime);
    }

    public SignatureDescriptor ReadSignature(ReadOnlyMemory<byte> signature)
    {
        var parsed = Decode(signature);
        var signer = parsed.SignerInfos[0];
        var certificate = signer.Certificate ?? parsed.Certificates[0];
        var timestamps = ReadSignatureTimestamps(signature);
        var embeddedValidationData = ReadEmbeddedValidationData(signature, certificate);
        var level = DetermineLevel(timestamps, embeddedValidationData);

        return new SignatureDescriptor(
            SignatureFormat.CAdES,
            level,
            certificate is null ? null : CreateCertificateReference(certificate),
            TryGetSigningTime(signer),
            new ValidationMaterial(
                certificate is null ? null : CreateCertificateReference(certificate),
                BuildCertificateChainReferences(certificate, parsed.Certificates, embeddedValidationData.CertificateValues),
                embeddedValidationData.RevocationInfo,
                timestamps,
                Array.Empty<ReadOnlyMemory<byte>>())
            {
                CertificateValues = embeddedValidationData.CertificateValues,
                RevocationValues = embeddedValidationData.RevocationValues
            },
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

        var signer = signedCms.SignerInfos[0];
        var timestampValidation = ValidateSignatureTimestamps(signature);
        if (timestampValidation is not null)
        {
            return ValidationResult.Failure(timestampValidation);
        }

        var validationDataFailure = ValidateEmbeddedValidationData(signature, signer.Certificate ?? signedCms.Certificates[0]);
        if (validationDataFailure is not null)
        {
            return ValidationResult.Failure(validationDataFailure);
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

            var signer = signedCms.SignerInfos[0];
            var timestampValidation = ValidateSignatureTimestamps(signature);
            if (timestampValidation is not null)
            {
                return ValidationResult.Failure(timestampValidation);
            }

            var validationDataFailure = ValidateEmbeddedValidationData(signature, signer.Certificate ?? signedCms.Certificates[0]);
            if (validationDataFailure is not null)
            {
                return ValidationResult.Failure(validationDataFailure);
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
        TimestampMaterial? signatureTimestamp,
        IReadOnlyList<X509Certificate2>? validationCertificates,
        IReadOnlyList<RevocationInfo>? revocationInfo,
        bool includeSigningTime)
    {
        EnsureSupportedLevel(request.Level);

        if (request.Level is SignatureLevel.BaselineT or SignatureLevel.BaselineLT && signatureTimestamp is null)
        {
            throw new InvalidOperationException($"CAdES {request.Level} signing requires a signature timestamp token.");
        }

        if (request.Level == SignatureLevel.BaselineLT && (revocationInfo is null || revocationInfo.Count == 0 || revocationInfo.All(info => info.EncodedValue.IsEmpty)))
        {
            throw new InvalidOperationException("CAdES Baseline-LT signing requires embedded revocation values.");
        }

        var contentInfo = new System.Security.Cryptography.Pkcs.ContentInfo(request.Payload.ToArray());
        var signedCms = new SignedCms(contentInfo, detached);
        var signerCertificate = signingCertificate.HasPrivateKey ? signingCertificate : signingCertificate.CopyWithPrivateKey(privateKey);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, signerCertificate)
        {
            IncludeOption = X509IncludeOption.EndCertOnly,
            DigestAlgorithm = new Oid(GetDigestOid(suite.HashAlgorithm))
        };

        if (includeSigningTime)
        {
            signer.SignedAttributes.Add(new Pkcs9SigningTime((signingTime ?? DateTimeOffset.UtcNow).UtcDateTime));
        }

        signer.SignedAttributes.Add(CreateSigningCertificateV2Attribute(signingCertificate, suite.HashAlgorithm));

        signedCms.ComputeSignature(signer, silent: true);

        var encodedSignature = signedCms.Encode();
        if (request.Level is SignatureLevel.BaselineT or SignatureLevel.BaselineLT)
        {
            encodedSignature = AttachSignatureTimestamp(encodedSignature, signatureTimestamp!);
        }

        if (request.Level == SignatureLevel.BaselineLT)
        {
            encodedSignature = AttachEmbeddedValidationData(
                encodedSignature,
                NormalizeValidationCertificates(signingCertificate, validationCertificates),
                revocationInfo!,
                suite.HashAlgorithm);
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
        if (level is not SignatureLevel.BaselineB and not SignatureLevel.BaselineT and not SignatureLevel.BaselineLT)
        {
            throw new ArgumentException("CAdES signing currently supports only Baseline-B, Baseline-T and Baseline-LT requests.");
        }
    }

    private static byte[] AttachSignatureTimestamp(ReadOnlyMemory<byte> signature, TimestampMaterial timestamp)
    {
        if (timestamp.Token.IsEmpty)
        {
            throw new InvalidOperationException("Signature timestamp token cannot be empty.");
        }

        try
        {
            _ = new TimeStampToken(new CmsSignedData(timestamp.Token.ToArray()));
        }
        catch (Exception ex) when (ex is CmsException or TspException)
        {
            throw new InvalidOperationException("Signature timestamp token must be a decodable RFC 3161 token.", ex);
        }

        var cms = new CmsSignedData(signature.ToArray());
        var signer = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
        var unsignedAttributes = signer.UnsignedAttributes?.ToDictionary() ?? new Dictionary<DerObjectIdentifier, object>();
        unsignedAttributes[new DerObjectIdentifier(SignatureTimeStampTokenOid)] = new Org.BouncyCastle.Asn1.Cms.Attribute(
            new DerObjectIdentifier(SignatureTimeStampTokenOid),
            new DerSet(Asn1Object.FromByteArray(timestamp.Token.ToArray())));

        var updatedSigner = SignerInformation.ReplaceUnsignedAttributes(signer, new Org.BouncyCastle.Asn1.Cms.AttributeTable(unsignedAttributes));
        var signerStore = new SignerInformationStore([updatedSigner]);
        return CmsSignedData.ReplaceSigners(cms, signerStore).GetEncoded();
    }

    private static byte[] AttachEmbeddedValidationData(
        ReadOnlyMemory<byte> signature,
        IReadOnlyList<X509Certificate2> validationCertificates,
        IReadOnlyList<RevocationInfo> revocationInfo,
        HashAlgorithmIdentifier hashAlgorithm)
    {
        var cms = new CmsSignedData(signature.ToArray());
        var signer = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
        var unsignedAttributes = signer.UnsignedAttributes?.ToDictionary() ?? new Dictionary<DerObjectIdentifier, object>();

        unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertValues] = new Org.BouncyCastle.Asn1.Cms.Attribute(
            PkcsObjectIdentifiers.IdAAEtsCertValues,
            new DerSet(BuildCertificateValues(validationCertificates)));
        unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationValues] = new Org.BouncyCastle.Asn1.Cms.Attribute(
            PkcsObjectIdentifiers.IdAAEtsRevocationValues,
            new DerSet(BuildRevocationValues(revocationInfo)));

        var updatedSigner = SignerInformation.ReplaceUnsignedAttributes(signer, new Org.BouncyCastle.Asn1.Cms.AttributeTable(unsignedAttributes));
        var cmsWithSigner = CmsSignedData.ReplaceSigners(cms, new SignerInformationStore([updatedSigner]));

        var certificates = cmsWithSigner.GetCertificates().EnumerateMatches(null).ToList();
        certificates.AddRange(validationCertificates.Select(DotNetUtilities.FromX509Certificate));
        certificates = certificates
            .GroupBy(certificate => Convert.ToBase64String(certificate.GetEncoded()))
            .Select(group => group.First())
            .ToList();

        var crls = cmsWithSigner.GetCrls().EnumerateMatches(null).ToList();
        crls.AddRange(
            revocationInfo
                .Where(info => !info.EncodedValue.IsEmpty && IsCrlSource(info.Source))
                .Select(info => new X509CrlParser().ReadCrl(info.EncodedValue.ToArray()))
                .Where(crl => crl is not null)!);
        crls = crls
            .GroupBy(crl => Convert.ToBase64String(crl.GetEncoded()))
            .Select(group => group.First())
            .ToList();

        return CmsSignedData.ReplaceCertificatesAndCrls(
            cmsWithSigner,
            CollectionUtilities.CreateStore(certificates),
            CollectionUtilities.CreateStore(crls))
            .GetEncoded();
    }

    private static CertificateValues BuildCertificateValues(IEnumerable<X509Certificate2> certificates)
    {
        var values = certificates
            .Select(certificate => X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(certificate.RawData)))
            .ToArray();

        return new CertificateValues(values);
    }

    private static RevocationValues BuildRevocationValues(IEnumerable<RevocationInfo> revocationInfo)
    {
        var crls = new List<CertificateList>();
        var ocspResponses = new List<BasicOcspResponse>();

        foreach (var info in revocationInfo.Where(info => !info.EncodedValue.IsEmpty))
        {
            var rawValue = info.EncodedValue.ToArray();
            if (IsCrlSource(info.Source))
            {
                crls.Add(CertificateList.GetInstance(Asn1Object.FromByteArray(rawValue)));
                continue;
            }

            if (IsOcspSource(info.Source))
            {
                ocspResponses.Add(BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(rawValue)));
                continue;
            }

            throw new InvalidOperationException($"Unsupported revocation source '{info.Source}' for CAdES Baseline-LT embedding.");
        }

        return new RevocationValues(crls, ocspResponses, null);
    }

    private static EmbeddedValidationData ReadEmbeddedValidationData(ReadOnlyMemory<byte> signature, X509Certificate2? signingCertificate)
    {
        var cms = new CmsSignedData(signature.ToArray());
        var signer = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
        var unsignedAttributes = signer.UnsignedAttributes;
        var certificateValues = new List<ReadOnlyMemory<byte>>();
        var revocationValues = new List<ReadOnlyMemory<byte>>();
        var revocationInfo = new List<RevocationInfo>();

        var certificateValuesAttribute = unsignedAttributes?[PkcsObjectIdentifiers.IdAAEtsCertValues];
        if (certificateValuesAttribute is not null)
        {
            foreach (Asn1Encodable attributeValue in certificateValuesAttribute.AttrValues)
            {
                var values = CertificateValues.GetInstance(attributeValue);
                certificateValues.AddRange(values.GetCertificates().Select(certificate => (ReadOnlyMemory<byte>)certificate.GetEncoded()));
            }
        }

        var revocationValuesAttribute = unsignedAttributes?[PkcsObjectIdentifiers.IdAAEtsRevocationValues];
        if (revocationValuesAttribute is not null)
        {
            foreach (Asn1Encodable attributeValue in revocationValuesAttribute.AttrValues)
            {
                var values = RevocationValues.GetInstance(attributeValue);

                foreach (var crl in values.GetCrlVals() ?? Array.Empty<CertificateList>())
                {
                    var rawValue = crl.GetEncoded();
                    revocationValues.Add(rawValue);
                    revocationInfo.Add(MapCrlRevocationInfo(rawValue, signingCertificate));
                }

                foreach (var ocsp in values.GetOcspVals() ?? Array.Empty<BasicOcspResponse>())
                {
                    var rawValue = ocsp.GetEncoded();
                    revocationValues.Add(rawValue);
                    revocationInfo.Add(MapOcspRevocationInfo(rawValue));
                }
            }
        }

        return new EmbeddedValidationData(certificateValues, revocationInfo, revocationValues);
    }

    private static ValidationFailure? ValidateEmbeddedValidationData(ReadOnlyMemory<byte> signature, X509Certificate2? signingCertificate)
    {
        EmbeddedValidationData validationData;
        try
        {
            validationData = ReadEmbeddedValidationData(signature, signingCertificate);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidCastException or InvalidOperationException or ArgumentException)
        {
            return new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                $"Embedded CAdES-LT validation material could not be decoded: {ex.Message}");
        }

        var hasCertificateValues = validationData.CertificateValues.Count > 0;
        var hasRevocationValues = validationData.RevocationValues.Count > 0;
        if (hasCertificateValues != hasRevocationValues)
        {
            return new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                "CAdES embedded validation material must contain both CertificateValues and RevocationValues.");
        }

        return null;
    }

    private static IReadOnlyList<TimestampMaterial> ReadSignatureTimestamps(ReadOnlyMemory<byte> signature)
    {
        var signedCms = Decode(signature);
        var timestamps = new List<TimestampMaterial>();

        foreach (CryptographicAttributeObject attribute in signedCms.SignerInfos[0].UnsignedAttributes)
        {
            if (attribute.Oid?.Value != SignatureTimeStampTokenOid)
            {
                continue;
            }

            foreach (AsnEncodedData value in attribute.Values)
            {
                try
                {
                    var token = new TimeStampToken(new CmsSignedData(value.RawData));
                    timestamps.Add(new TimestampMaterial(
                        token.GetEncoded("DER"),
                        new DateTimeOffset(token.TimeStampInfo.GenTime.ToUniversalTime()),
                        token.TimeStampInfo.Policy,
                        GetDigestFromOid(token.TimeStampInfo.MessageImprintAlgOid)));
                }
                catch
                {
                    // Ignore malformed timestamp attributes during read; verification will surface them.
                }
            }
        }

        return timestamps;
    }

    private static ValidationFailure? ValidateSignatureTimestamps(ReadOnlyMemory<byte> signature)
    {
        try
        {
            var cms = new CmsSignedData(signature.ToArray());
            var signer = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
            var timestamps = TspUtil.GetSignatureTimestamps(signer).Cast<TimeStampToken>().ToArray();

            foreach (var timestamp in timestamps)
            {
                var certificate = timestamp.GetCertificates().EnumerateMatches(timestamp.SignerID).SingleOrDefault();
                if (certificate is null)
                {
                    return new ValidationFailure(
                        ValidationFailureKind.TimestampInvalid,
                        ValidationErrorCodes.TimestampInvalid,
                        "Signature timestamp token does not include a matching TSA certificate.");
                }

                var timestampSigner = timestamp.ToCmsSignedData().GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
                if (!timestampSigner.Verify(certificate))
                {
                    return new ValidationFailure(
                        ValidationFailureKind.TimestampInvalid,
                        ValidationErrorCodes.TimestampInvalid,
                        "Signature timestamp token signature verification failed.");
                }
            }

            return null;
        }
        catch (Exception ex) when (ex is CmsException or TspException or InvalidOperationException)
        {
            return new ValidationFailure(
                ValidationFailureKind.TimestampInvalid,
                ValidationErrorCodes.TimestampInvalid,
                $"Signature timestamp token verification failed: {ex.Message}");
        }
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

    private static IReadOnlyList<SigningCertificateReference> BuildCertificateChainReferences(
        X509Certificate2? signingCertificate,
        X509Certificate2Collection cmsCertificates,
        IReadOnlyList<ReadOnlyMemory<byte>> certificateValues)
    {
        var chain = new List<SigningCertificateReference>();
        var seenThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (signingCertificate is not null)
        {
            AddCertificateReference(chain, seenThumbprints, signingCertificate);
        }

        foreach (var certificate in cmsCertificates)
        {
            AddCertificateReference(chain, seenThumbprints, certificate);
        }

        foreach (var rawValue in certificateValues)
        {
            using var certificate = X509CertificateLoader.LoadCertificate(rawValue.Span);
            AddCertificateReference(chain, seenThumbprints, certificate);
        }

        return chain;
    }

    private static void AddCertificateReference(
        ICollection<SigningCertificateReference> chain,
        ISet<string> seenThumbprints,
        X509Certificate2 certificate)
    {
        if (!seenThumbprints.Add(certificate.Thumbprint))
        {
            return;
        }

        chain.Add(CreateCertificateReference(certificate));
    }

    private static IReadOnlyList<X509Certificate2> NormalizeValidationCertificates(
        X509Certificate2 signingCertificate,
        IReadOnlyList<X509Certificate2>? validationCertificates)
    {
        var certificates = new List<X509Certificate2> { signingCertificate };
        if (validationCertificates is not null)
        {
            certificates.AddRange(validationCertificates);
        }

        return certificates
            .GroupBy(certificate => certificate.Thumbprint, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToArray();
    }

    private static RevocationInfo MapCrlRevocationInfo(byte[] rawValue, X509Certificate2? signingCertificate)
    {
        var crl = new X509CrlParser().ReadCrl(rawValue);
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

    private static RevocationInfo MapOcspRevocationInfo(byte[] rawValue)
    {
        var response = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(rawValue));
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

    private static SignatureLevel DetermineLevel(
        IReadOnlyList<TimestampMaterial> timestamps,
        EmbeddedValidationData validationData)
    {
        if (timestamps.Count > 0 && validationData.CertificateValues.Count > 0 && validationData.RevocationValues.Count > 0)
        {
            return SignatureLevel.BaselineLT;
        }

        return timestamps.Count > 0
            ? SignatureLevel.BaselineT
            : SignatureLevel.BaselineB;
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

    private static bool IsCrlSource(string source) => source.Contains("CRL", StringComparison.OrdinalIgnoreCase);
    private static bool IsOcspSource(string source) => source.Contains("OCSP", StringComparison.OrdinalIgnoreCase);

    private sealed record EmbeddedValidationData(
        IReadOnlyList<ReadOnlyMemory<byte>> CertificateValues,
        IReadOnlyList<RevocationInfo> RevocationInfo,
        IReadOnlyList<ReadOnlyMemory<byte>> RevocationValues);
}
