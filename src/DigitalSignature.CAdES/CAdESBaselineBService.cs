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
    private const string ArchiveTimeStampV2Oid = "1.2.840.113549.1.9.16.2.48";
    private const string ArchiveTimeStampV3Oid = "0.4.0.1733.2.4";
    private const string AtsHashIndexV3Oid = "0.4.0.19122.1.5";

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

    public TimestampRequest CreateArchiveTimestampRequest(
        ReadOnlyMemory<byte> signature,
        HashAlgorithmIdentifier hashAlgorithm,
        ReadOnlyMemory<byte> detachedPayload = default)
    {
        var digest = ComputeArchiveTimestampV3Digest(signature, detachedPayload, hashAlgorithm, referenceTimestamp: null);
        return new TimestampRequest(digest, GetDigestOid(hashAlgorithm));
    }

    public bool IsDetachedSignature(ReadOnlyMemory<byte> signature)
        => ReadCmsStructure(signature).IsDetached;

    public byte[]? ReadEncapsulatedContent(ReadOnlyMemory<byte> signature)
    {
        var contentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo.GetInstance(Asn1Object.FromByteArray(signature.ToArray()));
        var signedData = Org.BouncyCastle.Asn1.Cms.SignedData.GetInstance(contentInfo.Content);
        var encapsulatedContent = signedData.EncapContentInfo.Content;
        return encapsulatedContent is null ? null : Asn1OctetString.GetInstance(encapsulatedContent).GetOctets();
    }

    public byte[] EncapsulateDetachedContent(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> payload)
    {
        if (payload.IsEmpty)
        {
            throw new InvalidOperationException("Detached CAdES content cannot be encapsulated with an empty payload.");
        }

        var existingContent = ReadEncapsulatedContent(signature);
        if (existingContent is not null)
        {
            if (!existingContent.AsSpan().SequenceEqual(payload.Span))
            {
                throw new InvalidOperationException("The CAdES signature already contains encapsulated content that does not match the requested payload.");
            }

            return signature.ToArray();
        }

        var contentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo.GetInstance(Asn1Object.FromByteArray(signature.ToArray()));
        var signedData = Org.BouncyCastle.Asn1.Cms.SignedData.GetInstance(contentInfo.Content);
        var updatedSignedData = new Org.BouncyCastle.Asn1.Cms.SignedData(
            signedData.DigestAlgorithms,
            new Org.BouncyCastle.Asn1.Cms.ContentInfo(signedData.EncapContentInfo.ContentType, new BerOctetString(payload.ToArray())),
            signedData.Certificates,
            signedData.CRLs,
            signedData.SignerInfos);

        return new Org.BouncyCastle.Asn1.Cms.ContentInfo(contentInfo.ContentType, updatedSignedData).GetEncoded();
    }

    public SignatureArtifact AttachArchiveTimestamp(
        SignatureArtifact artifact,
        TimestampMaterial archiveTimestamp)
    {
        ArgumentNullException.ThrowIfNull(artifact);

        if (artifact.Format != SignatureFormat.CAdES)
        {
            throw new ArgumentException("CAdES archive timestamps can only be attached to CAdES artifacts.", nameof(artifact));
        }

        var descriptor = ReadSignature(artifact.Data);
        if (descriptor.Level < SignatureLevel.BaselineLT)
        {
            throw new InvalidOperationException("CAdES Baseline-LTA requires a Baseline-LT artifact before attaching an archive timestamp.");
        }

        return artifact with
        {
            Level = SignatureLevel.BaselineLTA,
            Data = AttachArchiveTimestampAttribute(artifact.Data, archiveTimestamp)
        };
    }

    public SignatureDescriptor ReadSignature(ReadOnlyMemory<byte> signature)
    {
        var parsed = Decode(signature);
        var signer = parsed.SignerInfos[0];
        var certificate = signer.Certificate ?? parsed.Certificates[0];
        var timestamps = ReadSignatureTimestamps(signature);
        var archiveTimestamps = ReadArchiveTimestamps(signature);
        var embeddedValidationData = ReadEmbeddedValidationData(signature, certificate);
        var level = DetermineLevel(timestamps, embeddedValidationData, archiveTimestamps);

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
                ArchiveTimestamps = archiveTimestamps,
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

        var archiveTimestampValidation = ValidateArchiveTimestamps(signature, payload);
        if (archiveTimestampValidation is not null)
        {
            return ValidationResult.Failure(archiveTimestampValidation);
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

            var archiveTimestampValidation = ValidateArchiveTimestamps(signature);
            if (archiveTimestampValidation is not null)
            {
                return ValidationResult.Failure(archiveTimestampValidation);
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

    private static byte[] AttachArchiveTimestampAttribute(ReadOnlyMemory<byte> signature, TimestampMaterial timestamp)
    {
        if (timestamp.Token.IsEmpty)
        {
            throw new InvalidOperationException("Archive timestamp token cannot be empty.");
        }

        TimeStampToken timeStampToken;
        try
        {
            timeStampToken = new TimeStampToken(new CmsSignedData(timestamp.Token.ToArray()));
        }
        catch (Exception ex) when (ex is CmsException or TspException)
        {
            throw new InvalidOperationException("Archive timestamp token must be a decodable RFC 3161 token.", ex);
        }

        var hashAlgorithm = GetDigestAlgorithmFromOid(timeStampToken.TimeStampInfo.MessageImprintAlgOid);
        var atsHashIndexAttribute = BuildAtsHashIndexV3Attribute(signature, hashAlgorithm, referenceTimestamp: null);
        var timestampWithHashIndex = AttachUnsignedAttributesToTimestampToken(timeStampToken, atsHashIndexAttribute);

        var cms = new CmsSignedData(signature.ToArray());
        var signer = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
        var unsignedAttributes = signer.UnsignedAttributes?.ToDictionary() ?? new Dictionary<DerObjectIdentifier, object>();
        unsignedAttributes[new DerObjectIdentifier(ArchiveTimeStampV3Oid)] = new Org.BouncyCastle.Asn1.Cms.Attribute(
            new DerObjectIdentifier(ArchiveTimeStampV3Oid),
            new DerSet(Asn1Object.FromByteArray(timestampWithHashIndex)));

        var updatedSigner = SignerInformation.ReplaceUnsignedAttributes(signer, new Org.BouncyCastle.Asn1.Cms.AttributeTable(unsignedAttributes));
        var signerStore = new SignerInformationStore([updatedSigner]);
        return CmsSignedData.ReplaceSigners(cms, signerStore).GetEncoded();
    }

    private static byte[] AttachUnsignedAttributesToTimestampToken(
        TimeStampToken timestampToken,
        params Org.BouncyCastle.Asn1.Cms.Attribute[] attributes)
    {
        var cms = timestampToken.ToCmsSignedData();
        var signer = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
        var unsignedAttributes = signer.UnsignedAttributes?.ToDictionary() ?? new Dictionary<DerObjectIdentifier, object>();

        foreach (var attribute in attributes)
        {
            unsignedAttributes[attribute.AttrType] = attribute;
        }

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
        _ = hashAlgorithm;

        var contentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo.GetInstance(Asn1Object.FromByteArray(signature.ToArray()));
        var signedData = Org.BouncyCastle.Asn1.Cms.SignedData.GetInstance(contentInfo.Content);

        var certificateEntries = CreateDistinctAsn1EntryMap(signedData.Certificates);
        foreach (var certificate in validationCertificates)
        {
            AddDistinctAsn1Entry(
                certificateEntries,
                X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(certificate.RawData)));
        }

        var revocationEntries = CreateDistinctAsn1EntryMap(signedData.CRLs);
        foreach (var info in revocationInfo.Where(info => !info.EncodedValue.IsEmpty))
        {
            var rawValue = info.EncodedValue.ToArray();
            if (IsCrlSource(info.Source))
            {
                AddDistinctAsn1Entry(revocationEntries, CertificateList.GetInstance(Asn1Object.FromByteArray(rawValue)));
                continue;
            }

            if (IsOcspSource(info.Source))
            {
                AddDistinctAsn1Entry(
                    revocationEntries,
                    new DerTaggedObject(
                        false,
                        1,
                        new OtherRevocationInfoFormat(CmsObjectIdentifiers.id_ri_ocsp_response, BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(rawValue)))));
                continue;
            }

            throw new InvalidOperationException($"Unsupported revocation source '{info.Source}' for CAdES Baseline-LT embedding.");
        }

        var updatedSignedData = new Org.BouncyCastle.Asn1.Cms.SignedData(
            signedData.DigestAlgorithms,
            signedData.EncapContentInfo,
            new DerSet(certificateEntries.Values.ToArray()),
            revocationEntries.Count == 0 ? null : new DerSet(revocationEntries.Values.ToArray()),
            signedData.SignerInfos);

        return new Org.BouncyCastle.Asn1.Cms.ContentInfo(contentInfo.ContentType, updatedSignedData).GetEncoded();
    }

    private static EmbeddedValidationData ReadEmbeddedValidationData(ReadOnlyMemory<byte> signature, X509Certificate2? signingCertificate)
    {
        var modernValidationData = ReadSignedDataValidationData(signature, signingCertificate);
        var legacyValidationData = ReadLegacyValidationData(signature, signingCertificate);

        return MergeValidationData(modernValidationData, legacyValidationData);
    }

    private static EmbeddedValidationData ReadSignedDataValidationData(ReadOnlyMemory<byte> signature, X509Certificate2? signingCertificate)
    {
        var cms = new CmsSignedData(signature.ToArray());
        var certificateValues = new List<ReadOnlyMemory<byte>>();
        var revocationValues = new List<ReadOnlyMemory<byte>>();
        var revocationInfo = new List<RevocationInfo>();

        var signingCertificateThumbprint = signingCertificate?.Thumbprint;
        foreach (var certificate in cms.GetCertificates().EnumerateMatches(null))
        {
            var rawValue = certificate.GetEncoded();
            using var parsedCertificate = X509CertificateLoader.LoadCertificate(rawValue);
            if (signingCertificateThumbprint is not null &&
                StringComparer.OrdinalIgnoreCase.Equals(parsedCertificate.Thumbprint, signingCertificateThumbprint))
            {
                continue;
            }

            certificateValues.Add(rawValue);
        }

        var contentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo.GetInstance(Asn1Object.FromByteArray(signature.ToArray()));
        var signedData = Org.BouncyCastle.Asn1.Cms.SignedData.GetInstance(contentInfo.Content);
        foreach (var entry in EnumerateSet(signedData.CRLs))
        {
            var primitive = entry.ToAsn1Object();
            if (primitive is Asn1Sequence)
            {
                var rawValue = primitive.GetEncoded();
                revocationValues.Add(rawValue);
                revocationInfo.Add(MapCrlRevocationInfo(rawValue, signingCertificate));
                continue;
            }

            if (primitive is Asn1TaggedObject taggedObject && taggedObject.TagNo == 1)
            {
                var otherRevocationInfo = OtherRevocationInfoFormat.GetInstance(taggedObject, false);
                var rawValue = otherRevocationInfo.Info.ToAsn1Object().GetEncoded();
                revocationValues.Add(rawValue);
                revocationInfo.Add(MapOcspRevocationInfo(rawValue));
            }
        }

        return new EmbeddedValidationData(certificateValues, revocationInfo, revocationValues);
    }

    private static EmbeddedValidationData ReadLegacyValidationData(ReadOnlyMemory<byte> signature, X509Certificate2? signingCertificate)
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

    private static EmbeddedValidationData MergeValidationData(EmbeddedValidationData primary, EmbeddedValidationData secondary)
    {
        var certificateValues = MergeDistinct(primary.CertificateValues, secondary.CertificateValues);
        var revocationValues = MergeDistinct(primary.RevocationValues, secondary.RevocationValues);
        var revocationInfo = MergeDistinctRevocationInfo(primary.RevocationInfo, secondary.RevocationInfo);

        return new EmbeddedValidationData(certificateValues, revocationInfo, revocationValues);
    }

    private static ValidationFailure? ValidateEmbeddedValidationData(ReadOnlyMemory<byte> signature, X509Certificate2? signingCertificate)
    {
        try
        {
            _ = ReadEmbeddedValidationData(signature, signingCertificate);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidCastException or InvalidOperationException or ArgumentException)
        {
            return new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                $"Embedded CAdES-LT validation material could not be decoded: {ex.Message}");
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

    private static IReadOnlyList<TimestampMaterial> ReadArchiveTimestamps(ReadOnlyMemory<byte> signature)
        => ReadArchiveTimestampEntries(signature)
            .Select(entry => entry.Timestamp)
            .ToArray();

    private static ValidationFailure? ValidateSignatureTimestamps(ReadOnlyMemory<byte> signature)
    {
        try
        {
            var cms = new CmsSignedData(signature.ToArray());
            var signer = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
            var timestamps = TspUtil.GetSignatureTimestamps(signer).Cast<TimeStampToken>().ToArray();

            foreach (var timestamp in timestamps)
            {
                var timestampValidation = ValidateTimestampToken(timestamp, "Signature timestamp token");
                if (timestampValidation is not null)
                {
                    return timestampValidation;
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

    private static ValidationFailure? ValidateArchiveTimestamps(
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> detachedPayload = default)
    {
        try
        {
            var archiveTimestamps = ReadArchiveTimestampEntries(signature);
            foreach (var archiveTimestamp in archiveTimestamps)
            {
                var timestampValidation = ValidateTimestampToken(archiveTimestamp.Token, "Archive timestamp token");
                if (timestampValidation is not null)
                {
                    return timestampValidation;
                }

                var hashAlgorithm = GetDigestAlgorithmFromOid(archiveTimestamp.Token.TimeStampInfo.MessageImprintAlgOid);
                if (string.Equals(archiveTimestamp.AttributeOid, ArchiveTimeStampV3Oid, StringComparison.Ordinal))
                {
                    var actualAtsHashIndex = ReadAtsHashIndexAttribute(archiveTimestamp.Token);
                    if (actualAtsHashIndex is null)
                    {
                        return new ValidationFailure(
                            ValidationFailureKind.TimestampInvalid,
                            ValidationErrorCodes.TimestampInvalid,
                            "Archive timestamp token is missing ATSHashIndexV3.");
                    }

                    var expectedAtsHashIndex = BuildAtsHashIndexV3Attribute(signature, hashAlgorithm, archiveTimestamp.GeneratedAt);
                    if (!GetSingleAttributeValueEncoding(actualAtsHashIndex).SequenceEqual(GetSingleAttributeValueEncoding(expectedAtsHashIndex)))
                    {
                        return new ValidationFailure(
                            ValidationFailureKind.TimestampInvalid,
                            ValidationErrorCodes.TimestampInvalid,
                            "Archive timestamp token ATSHashIndexV3 does not match the signed data state.");
                    }

                    var expectedV3Digest = ComputeArchiveTimestampV3Digest(
                        signature,
                        detachedPayload,
                        hashAlgorithm,
                        archiveTimestamp.GeneratedAt,
                        actualAtsHashIndex);

                    if (!archiveTimestamp.Token.TimeStampInfo.GetMessageImprintDigest().SequenceEqual(expectedV3Digest))
                    {
                        return new ValidationFailure(
                            ValidationFailureKind.TimestampInvalid,
                            ValidationErrorCodes.TimestampInvalid,
                            "Archive timestamp token message imprint verification failed.");
                    }

                    continue;
                }

                var expectedDigest = ComputeArchiveTimestampV2Digest(
                    signature,
                    detachedPayload,
                    hashAlgorithm,
                    archiveTimestamp.GeneratedAt,
                    includeUnsignedAttrsTagAndLength: true);

                if (!archiveTimestamp.Token.TimeStampInfo.GetMessageImprintDigest().SequenceEqual(expectedDigest))
                {
                    var compatibilityDigest = ComputeArchiveTimestampV2Digest(
                        signature,
                        detachedPayload,
                        hashAlgorithm,
                        archiveTimestamp.GeneratedAt,
                        includeUnsignedAttrsTagAndLength: false);

                    if (!archiveTimestamp.Token.TimeStampInfo.GetMessageImprintDigest().SequenceEqual(compatibilityDigest))
                    {
                        return new ValidationFailure(
                            ValidationFailureKind.TimestampInvalid,
                            ValidationErrorCodes.TimestampInvalid,
                            "Archive timestamp token message imprint verification failed.");
                    }
                }
            }

            return null;
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException or ArgumentException or AsnContentException)
        {
            return new ValidationFailure(
                ValidationFailureKind.TimestampInvalid,
                ValidationErrorCodes.TimestampInvalid,
                $"Archive timestamp token verification failed: {ex.Message}");
        }
    }

    private static ValidationFailure? ValidateTimestampToken(TimeStampToken timestamp, string label)
    {
        var certificate = timestamp.GetCertificates().EnumerateMatches(timestamp.SignerID).SingleOrDefault();
        if (certificate is null)
        {
            return new ValidationFailure(
                ValidationFailureKind.TimestampInvalid,
                ValidationErrorCodes.TimestampInvalid,
                $"{label} does not include a matching TSA certificate.");
        }

        var timestampSigner = timestamp.ToCmsSignedData().GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
        if (!timestampSigner.Verify(certificate))
        {
            return new ValidationFailure(
                ValidationFailureKind.TimestampInvalid,
                ValidationErrorCodes.TimestampInvalid,
                $"{label} signature verification failed.");
        }

        return null;
    }

    private static byte[] ComputeArchiveTimestampV2Digest(
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> detachedPayload,
        HashAlgorithmIdentifier hashAlgorithm,
        DateTimeOffset? referenceTimestamp,
        bool includeUnsignedAttrsTagAndLength)
    {
        var imprintInput = BuildArchiveTimestampV2ImprintInput(signature, detachedPayload, referenceTimestamp, includeUnsignedAttrsTagAndLength);
        return HashData(imprintInput.Span, hashAlgorithm);
    }

    private static byte[] ComputeArchiveTimestampV3Digest(
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> detachedPayload,
        HashAlgorithmIdentifier hashAlgorithm,
        DateTimeOffset? referenceTimestamp,
        Org.BouncyCastle.Asn1.Cms.Attribute? atsHashIndexAttribute = null)
    {
        var imprintInput = BuildArchiveTimestampV3ImprintInput(
            signature,
            detachedPayload,
            hashAlgorithm,
            referenceTimestamp,
            atsHashIndexAttribute ?? BuildAtsHashIndexV3Attribute(signature, hashAlgorithm, referenceTimestamp));

        return HashData(imprintInput.Span, hashAlgorithm);
    }

    private static ReadOnlyMemory<byte> BuildArchiveTimestampV2ImprintInput(
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> detachedPayload,
        DateTimeOffset? referenceTimestamp,
        bool includeUnsignedAttrsTagAndLength)
    {
        var cmsStructure = ReadCmsStructure(signature);
        using var buffer = new MemoryStream();

        buffer.Write(cmsStructure.EncapsulatedContentInfo.Span);

        if (cmsStructure.IsDetached)
        {
            if (detachedPayload.IsEmpty)
            {
                throw new InvalidOperationException("Detached CAdES archive timestamp validation requires the original payload bytes.");
            }

            buffer.Write(detachedPayload.Span);
        }

        if (!cmsStructure.Certificates.IsEmpty)
        {
            buffer.Write(cmsStructure.Certificates.Span);
        }

        if (!cmsStructure.Crls.IsEmpty)
        {
            buffer.Write(cmsStructure.Crls.Span);
        }

        var signerInfoStructure = ReadSignerInfoStructure(cmsStructure.SignerInfo, referenceTimestamp, includeUnsignedAttrsTagAndLength);
        buffer.Write(signerInfoStructure.Version.Span);
        buffer.Write(signerInfoStructure.SignerIdentifier.Span);
        buffer.Write(signerInfoStructure.DigestAlgorithm.Span);

        if (!signerInfoStructure.SignedAttributes.IsEmpty)
        {
            buffer.Write(signerInfoStructure.SignedAttributes.Span);
        }

        buffer.Write(signerInfoStructure.SignatureAlgorithm.Span);
        buffer.Write(signerInfoStructure.SignatureValue.Span);

        if (!signerInfoStructure.UnsignedAttributes.IsEmpty)
        {
            buffer.Write(signerInfoStructure.UnsignedAttributes.Span);
        }

        return buffer.ToArray();
    }

    private static ReadOnlyMemory<byte> BuildArchiveTimestampV3ImprintInput(
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> detachedPayload,
        HashAlgorithmIdentifier hashAlgorithm,
        DateTimeOffset? referenceTimestamp,
        Org.BouncyCastle.Asn1.Cms.Attribute atsHashIndexAttribute)
    {
        var cmsStructure = ReadCmsStructure(signature);
        var signerInfoStructure = ReadSignerInfoStructure(cmsStructure.SignerInfo, referenceTimestamp, includeUnsignedAttrsTagAndLength: false);
        using var buffer = new MemoryStream();

        buffer.Write(ReadEncodedContentType(cmsStructure.EncapsulatedContentInfo));
        buffer.Write(ComputeSignedDataDigest(signature, cmsStructure.IsDetached, detachedPayload, hashAlgorithm));
        buffer.Write(signerInfoStructure.Version.Span);
        buffer.Write(signerInfoStructure.SignerIdentifier.Span);
        buffer.Write(signerInfoStructure.DigestAlgorithm.Span);

        if (!signerInfoStructure.SignedAttributes.IsEmpty)
        {
            buffer.Write(signerInfoStructure.SignedAttributes.Span);
        }

        buffer.Write(signerInfoStructure.SignatureAlgorithm.Span);
        buffer.Write(signerInfoStructure.SignatureValue.Span);
        buffer.Write(GetSingleAttributeValueEncoding(atsHashIndexAttribute));
        return buffer.ToArray();
    }

    private static byte[] ReadEncodedContentType(ReadOnlyMemory<byte> encapsulatedContentInfo)
    {
        var contentReader = new AsnReader(encapsulatedContentInfo, AsnEncodingRules.BER);
        var contentSequence = contentReader.ReadSequence();
        return contentSequence.ReadEncodedValue().ToArray();
    }

    private static byte[] ComputeSignedDataDigest(
        ReadOnlyMemory<byte> signature,
        bool isDetached,
        ReadOnlyMemory<byte> detachedPayload,
        HashAlgorithmIdentifier hashAlgorithm)
    {
        if (isDetached)
        {
            if (detachedPayload.IsEmpty)
            {
                throw new InvalidOperationException("Detached CAdES archive timestamp validation requires the original payload bytes.");
            }

            return HashData(detachedPayload.Span, hashAlgorithm);
        }

        var signedCms = Decode(signature);
        return HashData(signedCms.ContentInfo.Content, hashAlgorithm);
    }

    private static Org.BouncyCastle.Asn1.Cms.Attribute BuildAtsHashIndexV3Attribute(
        ReadOnlyMemory<byte> signature,
        HashAlgorithmIdentifier hashAlgorithm,
        DateTimeOffset? referenceTimestamp)
    {
        var cmsStructure = ReadCmsStructure(signature);
        var certificateHashes = ReadTaggedEntries(cmsStructure.Certificates, new Asn1Tag(TagClass.ContextSpecific, 0))
            .Select(entry => new DerOctetString(HashData(GetDerEncoded(entry), hashAlgorithm)))
            .Cast<Asn1Encodable>()
            .ToArray();

        var crlHashes = ReadTaggedEntries(cmsStructure.Crls, new Asn1Tag(TagClass.ContextSpecific, 1))
            .Select(entry => new DerOctetString(HashData(GetDerEncoded(entry), hashAlgorithm)))
            .Cast<Asn1Encodable>()
            .ToArray();

        var unsignedAttributeHashes = ReadUnsignedAttributeHashEntries(cmsStructure.SignerInfo, hashAlgorithm, referenceTimestamp)
            .Select(hash => new DerOctetString(hash))
            .Cast<Asn1Encodable>()
            .ToArray();

        var value = new DerSequence(
            new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new DerObjectIdentifier(GetDigestOid(hashAlgorithm))),
            new DerSequence(certificateHashes),
            new DerSequence(crlHashes),
            new DerSequence(unsignedAttributeHashes));

        return new Org.BouncyCastle.Asn1.Cms.Attribute(
            new DerObjectIdentifier(AtsHashIndexV3Oid),
            new DerSet(value));
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> ReadTaggedEntries(ReadOnlyMemory<byte> taggedSet, Asn1Tag expectedTag)
    {
        if (taggedSet.IsEmpty)
        {
            return Array.Empty<ReadOnlyMemory<byte>>();
        }

        var reader = new AsnReader(taggedSet, AsnEncodingRules.BER);
        var set = reader.ReadSetOf(skipSortOrderValidation: true, expectedTag: expectedTag);
        var values = new List<ReadOnlyMemory<byte>>();

        while (set.HasData)
        {
            values.Add(set.ReadEncodedValue().ToArray());
        }

        return values;
    }

    private static IReadOnlyList<byte[]> ReadUnsignedAttributeHashEntries(
        ReadOnlyMemory<byte> signerInfoEncoding,
        HashAlgorithmIdentifier hashAlgorithm,
        DateTimeOffset? referenceTimestamp)
    {
        var signerReader = new AsnReader(signerInfoEncoding, AsnEncodingRules.BER);
        var signerSequence = signerReader.ReadSequence();
        _ = signerSequence.ReadEncodedValue();
        _ = signerSequence.ReadEncodedValue();
        _ = signerSequence.ReadEncodedValue();

        if (signerSequence.HasData && signerSequence.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            _ = signerSequence.ReadEncodedValue();
        }

        _ = signerSequence.ReadEncodedValue();
        _ = signerSequence.ReadEncodedValue();

        if (!signerSequence.HasData || !signerSequence.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            return Array.Empty<byte[]>();
        }

        var unsignedAttributeSet = signerSequence.ReadSetOf(true, new Asn1Tag(TagClass.ContextSpecific, 1));
        var hashes = new List<byte[]>();

        while (unsignedAttributeSet.HasData)
        {
            var attributeBytes = unsignedAttributeSet.ReadEncodedValue().ToArray();
            if (ShouldExcludeArchiveTimestampAttribute(attributeBytes, referenceTimestamp))
            {
                continue;
            }

            var attribute = Org.BouncyCastle.Asn1.Cms.Attribute.GetInstance(Asn1Object.FromByteArray(attributeBytes));
            var attributeTypeEncoding = attribute.AttrType.GetEncoded("DER");
            foreach (Asn1Encodable attributeValue in attribute.AttrValues)
            {
                hashes.Add(HashData(Concat(attributeTypeEncoding, attributeValue.ToAsn1Object().GetEncoded("DER")), hashAlgorithm));
            }
        }

        return hashes;
    }

    private static Org.BouncyCastle.Asn1.Cms.Attribute? ReadAtsHashIndexAttribute(TimeStampToken timestampToken)
        => timestampToken.UnsignedAttributes?[new DerObjectIdentifier(AtsHashIndexV3Oid)];

    private static byte[] GetSingleAttributeValueEncoding(Org.BouncyCastle.Asn1.Cms.Attribute attribute)
    {
        if (attribute.AttrValues.Count != 1)
        {
            throw new InvalidOperationException($"Attribute '{attribute.AttrType.Id}' must contain exactly one value.");
        }

        return attribute.AttrValues[0].ToAsn1Object().GetEncoded("DER");
    }

    private static byte[] GetDerEncoded(ReadOnlyMemory<byte> encoded)
        => Asn1Object.FromByteArray(encoded.ToArray()).GetEncoded("DER");

    private static byte[] Concat(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var buffer = new byte[left.Length + right.Length];
        left.CopyTo(buffer);
        right.CopyTo(buffer.AsSpan(left.Length));
        return buffer;
    }

    private static IReadOnlyList<ArchiveTimestampEntry> ReadArchiveTimestampEntries(ReadOnlyMemory<byte> signature)
    {
        var signerInfo = ReadCmsStructure(signature).SignerInfo;
        var signerReader = new AsnReader(signerInfo, AsnEncodingRules.BER);
        var signerSequence = signerReader.ReadSequence();

        _ = signerSequence.ReadEncodedValue();
        _ = signerSequence.ReadEncodedValue();
        _ = signerSequence.ReadEncodedValue();

        if (signerSequence.HasData && signerSequence.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            _ = signerSequence.ReadEncodedValue();
        }

        _ = signerSequence.ReadEncodedValue();
        _ = signerSequence.ReadEncodedValue();

        if (!signerSequence.HasData || !signerSequence.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            return Array.Empty<ArchiveTimestampEntry>();
        }

        var unsignedAttributes = signerSequence.ReadSetOf(true, new Asn1Tag(TagClass.ContextSpecific, 1));
        var archiveTimestamps = new List<ArchiveTimestampEntry>();

        while (unsignedAttributes.HasData)
        {
            var attributeBytes = unsignedAttributes.ReadEncodedValue().ToArray();
            if (!TryReadArchiveTimestampEntry(attributeBytes, out var entry))
            {
                continue;
            }

            archiveTimestamps.Add(entry!);
        }

        return archiveTimestamps;
    }

    private static bool TryReadArchiveTimestampEntry(
        ReadOnlyMemory<byte> attributeEncoding,
        out ArchiveTimestampEntry? entry)
    {
        var attributeReader = new AsnReader(attributeEncoding, AsnEncodingRules.BER);
        var attributeSequence = attributeReader.ReadSequence();
        var oid = attributeSequence.ReadObjectIdentifier();
        if (!string.Equals(oid, ArchiveTimeStampV2Oid, StringComparison.Ordinal) &&
            !string.Equals(oid, ArchiveTimeStampV3Oid, StringComparison.Ordinal))
        {
            entry = null;
            return false;
        }

        var values = attributeSequence.ReadSetOf(skipSortOrderValidation: true);
        if (!values.HasData)
        {
            throw new InvalidOperationException("Archive timestamp attribute does not contain a timestamp token value.");
        }

        var tokenEncoding = values.ReadEncodedValue().ToArray();
        var token = new TimeStampToken(new CmsSignedData(tokenEncoding));
        entry = new ArchiveTimestampEntry(
            new TimestampMaterial(
                token.GetEncoded("DER"),
                new DateTimeOffset(token.TimeStampInfo.GenTime.ToUniversalTime()),
                token.TimeStampInfo.Policy,
                GetDigestFromOid(token.TimeStampInfo.MessageImprintAlgOid)),
            token,
            new DateTimeOffset(token.TimeStampInfo.GenTime.ToUniversalTime()),
            oid);
        return true;
    }

    private static CmsStructure ReadCmsStructure(ReadOnlyMemory<byte> signature)
    {
        var contentReader = new AsnReader(signature, AsnEncodingRules.BER);
        var contentSequence = contentReader.ReadSequence();
        _ = contentSequence.ReadObjectIdentifier();

        var signedDataWrapper = contentSequence.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        var signedData = signedDataWrapper.ReadSequence();
        _ = signedData.ReadEncodedValue();
        _ = signedData.ReadEncodedValue();

        var encapsulatedContentInfo = signedData.ReadEncodedValue().ToArray();
        byte[] certificates = [];
        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            certificates = signedData.ReadEncodedValue().ToArray();
        }

        byte[] crls = [];
        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            crls = signedData.ReadEncodedValue().ToArray();
        }

        var signerInfos = signedData.ReadSetOf(skipSortOrderValidation: true);
        var signerInfo = signerInfos.ReadEncodedValue().ToArray();
        if (signerInfos.HasData)
        {
            throw new InvalidOperationException("Archive timestamp computation currently supports only a single SignerInfo.");
        }

        return new CmsStructure(encapsulatedContentInfo, certificates, crls, signerInfo, IsDetachedEncapsulatedContent(encapsulatedContentInfo));
    }

    private static SignerInfoStructure ReadSignerInfoStructure(
        ReadOnlyMemory<byte> signerInfoEncoding,
        DateTimeOffset? referenceTimestamp,
        bool includeUnsignedAttrsTagAndLength)
    {
        var signerReader = new AsnReader(signerInfoEncoding, AsnEncodingRules.BER);
        var signerSequence = signerReader.ReadSequence();

        var version = signerSequence.ReadEncodedValue().ToArray();
        var signerIdentifier = signerSequence.ReadEncodedValue().ToArray();
        var digestAlgorithm = signerSequence.ReadEncodedValue().ToArray();

        byte[] signedAttributes = [];
        if (signerSequence.HasData && signerSequence.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            signedAttributes = signerSequence.ReadEncodedValue().ToArray();
        }

        var signatureAlgorithm = signerSequence.ReadEncodedValue().ToArray();
        var signatureValue = signerSequence.ReadEncodedValue().ToArray();

        byte[] unsignedAttributes = [];
        if (signerSequence.HasData && signerSequence.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            var unsignedAttributeSet = signerSequence.ReadSetOf(true, new Asn1Tag(TagClass.ContextSpecific, 1));
            var filteredAttributes = new List<ReadOnlyMemory<byte>>();

            while (unsignedAttributeSet.HasData)
            {
                var attributeBytes = unsignedAttributeSet.ReadEncodedValue().ToArray();
                if (ShouldExcludeArchiveTimestampAttribute(attributeBytes, referenceTimestamp))
                {
                    continue;
                }

                filteredAttributes.Add(attributeBytes);
            }

            if (filteredAttributes.Count > 0)
            {
                unsignedAttributes = includeUnsignedAttrsTagAndLength
                    ? BuildTaggedUnsignedAttributes(filteredAttributes)
                    : filteredAttributes.SelectMany(bytes => bytes.ToArray()).ToArray();
            }
        }

        return new SignerInfoStructure(version, signerIdentifier, digestAlgorithm, signedAttributes, signatureAlgorithm, signatureValue, unsignedAttributes);
    }

    private static bool ShouldExcludeArchiveTimestampAttribute(ReadOnlyMemory<byte> attributeEncoding, DateTimeOffset? referenceTimestamp)
    {
        if (referenceTimestamp is null)
        {
            return false;
        }

        if (!TryReadArchiveTimestampEntry(attributeEncoding, out var archiveTimestamp))
        {
            return false;
        }

        return archiveTimestamp!.GeneratedAt >= referenceTimestamp.Value;
    }

    private static byte[] BuildTaggedUnsignedAttributes(IReadOnlyList<ReadOnlyMemory<byte>> attributes)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1));

        foreach (var attribute in attributes)
        {
            writer.WriteEncodedValue(attribute.Span);
        }

        writer.PopSetOf(new Asn1Tag(TagClass.ContextSpecific, 1));
        return writer.Encode();
    }

    private static bool IsDetachedEncapsulatedContent(ReadOnlyMemory<byte> encapsulatedContentInfo)
    {
        var contentReader = new AsnReader(encapsulatedContentInfo, AsnEncodingRules.BER);
        var contentSequence = contentReader.ReadSequence();
        _ = contentSequence.ReadObjectIdentifier();
        return !contentSequence.HasData;
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
        EmbeddedValidationData validationData,
        IReadOnlyList<TimestampMaterial> archiveTimestamps)
    {
        if (archiveTimestamps.Count > 0 && timestamps.Count > 0 && validationData.RevocationValues.Count > 0)
        {
            return SignatureLevel.BaselineLTA;
        }

        if (timestamps.Count > 0 && validationData.RevocationValues.Count > 0)
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

    private static string? GetDigestFromOid(string? oid) => oid switch
    {
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        _ => oid
    };

    private static HashAlgorithmIdentifier GetDigestAlgorithmFromOid(string? oid) => oid switch
    {
        "2.16.840.1.101.3.4.2.1" => HashAlgorithmIdentifier.Sha256,
        "2.16.840.1.101.3.4.2.2" => HashAlgorithmIdentifier.Sha384,
        "2.16.840.1.101.3.4.2.3" => HashAlgorithmIdentifier.Sha512,
        _ => throw new NotSupportedException($"Unsupported digest algorithm OID: {oid ?? "<null>"}.")
    };

    private static bool IsCrlSource(string source) => source.Contains("CRL", StringComparison.OrdinalIgnoreCase);
    private static bool IsOcspSource(string source) => source.Contains("OCSP", StringComparison.OrdinalIgnoreCase);

    private static Dictionary<string, Asn1Encodable> CreateDistinctAsn1EntryMap(Asn1Set? source)
    {
        var result = new Dictionary<string, Asn1Encodable>(StringComparer.Ordinal);
        foreach (var entry in EnumerateSet(source))
        {
            AddDistinctAsn1Entry(result, entry);
        }

        return result;
    }

    private static void AddDistinctAsn1Entry(IDictionary<string, Asn1Encodable> target, Asn1Encodable entry)
        => target[Convert.ToBase64String(entry.GetEncoded())] = entry;

    private static IEnumerable<Asn1Encodable> EnumerateSet(Asn1Set? set)
    {
        if (set is null)
        {
            yield break;
        }

        for (var index = 0; index < set.Count; index++)
        {
            yield return set[index];
        }
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> MergeDistinct(
        IReadOnlyList<ReadOnlyMemory<byte>> first,
        IReadOnlyList<ReadOnlyMemory<byte>> second)
    {
        var entries = new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal);
        foreach (var value in first)
        {
            entries[Convert.ToBase64String(value.ToArray())] = value;
        }

        foreach (var value in second)
        {
            entries[Convert.ToBase64String(value.ToArray())] = value;
        }

        return entries.Values.ToArray();
    }

    private static IReadOnlyList<RevocationInfo> MergeDistinctRevocationInfo(
        IReadOnlyList<RevocationInfo> first,
        IReadOnlyList<RevocationInfo> second)
    {
        var entries = new Dictionary<string, RevocationInfo>(StringComparer.Ordinal);
        foreach (var value in first)
        {
            entries[Convert.ToBase64String(value.EncodedValue.ToArray())] = value;
        }

        foreach (var value in second)
        {
            entries[Convert.ToBase64String(value.EncodedValue.ToArray())] = value;
        }

        return entries.Values.ToArray();
    }

    private sealed record CmsStructure(
        ReadOnlyMemory<byte> EncapsulatedContentInfo,
        ReadOnlyMemory<byte> Certificates,
        ReadOnlyMemory<byte> Crls,
        ReadOnlyMemory<byte> SignerInfo,
        bool IsDetached);

    private sealed record SignerInfoStructure(
        ReadOnlyMemory<byte> Version,
        ReadOnlyMemory<byte> SignerIdentifier,
        ReadOnlyMemory<byte> DigestAlgorithm,
        ReadOnlyMemory<byte> SignedAttributes,
        ReadOnlyMemory<byte> SignatureAlgorithm,
        ReadOnlyMemory<byte> SignatureValue,
        ReadOnlyMemory<byte> UnsignedAttributes);

    private sealed record ArchiveTimestampEntry(
        TimestampMaterial Timestamp,
        TimeStampToken Token,
        DateTimeOffset GeneratedAt,
        string AttributeOid);

    private sealed record EmbeddedValidationData(
        IReadOnlyList<ReadOnlyMemory<byte>> CertificateValues,
        IReadOnlyList<RevocationInfo> RevocationInfo,
        IReadOnlyList<ReadOnlyMemory<byte>> RevocationValues);
}
