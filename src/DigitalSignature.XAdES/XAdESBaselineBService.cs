using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.XAdES;

public sealed class XAdESBaselineBService(IXmlCanonicalizer canonicalizer)
{
    public XAdESBaselineBSignature CreateEnvelopedSignature(
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

        if (request.Format != SignatureFormat.XAdES)
        {
            throw new ArgumentException("XAdES service only accepts XAdES requests.", nameof(request));
        }

        if (request.Level != SignatureLevel.BaselineB)
        {
            throw new ArgumentException("XAdES Baseline-B signing requires SignatureLevel.BaselineB.", nameof(request));
        }

        if (!suite.IsRsa)
        {
            throw new NotSupportedException("Only RSA signature suites are supported for XAdES Baseline-B in the current implementation.");
        }

        var xml = new XmlDocument { PreserveWhitespace = true };
        xml.LoadXml(System.Text.Encoding.UTF8.GetString(request.Payload.Span));

        var signingMoment = signingTime ?? DateTimeOffset.UtcNow;
        var signatureId = $"Signature-{Guid.NewGuid():N}";
        var signedPropertiesId = $"SignedProperties-{Guid.NewGuid():N}";
        var dataObjectReferenceId = $"Reference-{Guid.NewGuid():N}";
        var digestAlgorithmUri = GetXmlDigestMethodUri(suite.HashAlgorithm);
        var certificateDigest = Convert.ToBase64String(HashCertificate(signingCertificate, suite.HashAlgorithm));

        var signedProperties = new XAdESSignedProperties(
            signingMoment.UtcDateTime.ToString("O"),
            digestAlgorithmUri,
            certificateDigest,
            signingCertificate.Issuer,
            NormalizeSerialNumber(signingCertificate.SerialNumber),
            $"#{dataObjectReferenceId}",
            request.MimeType ?? "application/xml",
            "Signed XML document");

        EnsureDocumentHasId(xml.DocumentElement!);

        var signatureElement = xml.CreateElement("ds", "Signature", XmlDsigNamespace);
        signatureElement.SetAttribute("Id", signatureId);

        var objectElement = xml.CreateElement("ds", "Object", XmlDsigNamespace);
        var qualifyingProperties = xml.CreateElement("xades", "QualifyingProperties", XAdESNamespace);
        qualifyingProperties.SetAttribute("Target", $"#{signatureId}");
        var signedPropertiesElement = CreateSignedPropertiesElement(xml, signedPropertiesId, signedProperties);
        qualifyingProperties.AppendChild(signedPropertiesElement);
        objectElement.AppendChild(qualifyingProperties);

        var signedInfoElement = xml.CreateElement("ds", "SignedInfo", XmlDsigNamespace);
        var canonicalizationMethod = xml.CreateElement("ds", "CanonicalizationMethod", XmlDsigNamespace);
        canonicalizationMethod.SetAttribute("Algorithm", XmlDsigExcC14NTransformUrl);
        signedInfoElement.AppendChild(canonicalizationMethod);

        var signatureMethod = xml.CreateElement("ds", "SignatureMethod", XmlDsigNamespace);
        signatureMethod.SetAttribute("Algorithm", GetXmlSignatureMethodUri(suite));
        signedInfoElement.AppendChild(signatureMethod);

        var documentReference = CreateDocumentReference(xml, digestAlgorithmUri, dataObjectReferenceId);
        signedInfoElement.AppendChild(documentReference);

        var signedPropertiesReference = CreateSignedPropertiesReference(xml, digestAlgorithmUri, signedPropertiesId);
        signedInfoElement.AppendChild(signedPropertiesReference);

        signatureElement.AppendChild(signedInfoElement);

        var signatureValueElement = xml.CreateElement("ds", "SignatureValue", XmlDsigNamespace);
        signatureElement.AppendChild(signatureValueElement);

        var keyInfo = xml.CreateElement("ds", "KeyInfo", XmlDsigNamespace);
        var x509Data = xml.CreateElement("ds", "X509Data", XmlDsigNamespace);
        var x509Certificate = xml.CreateElement("ds", "X509Certificate", XmlDsigNamespace);
        x509Certificate.InnerText = Convert.ToBase64String(signingCertificate.RawData);
        x509Data.AppendChild(x509Certificate);
        keyInfo.AppendChild(x509Data);
        signatureElement.AppendChild(keyInfo);

        signatureElement.AppendChild(objectElement);
        xml.DocumentElement!.AppendChild(signatureElement);

        SetReferenceDigest(documentReference, ComputeDocumentReferenceDigest(xml, suite));
        SetReferenceDigest(signedPropertiesReference, ComputeSignedPropertiesDigest(signedPropertiesElement, suite));

        var canonicalizedSignedInfo = canonicalizer.Canonicalize(signedInfoElement);
        var signatureValueBytes = privateKey.SignData(
            canonicalizedSignedInfo,
            ToHashAlgorithmName(suite.HashAlgorithm),
            suite.SignatureAlgorithm == SignatureAlgorithmIdentifier.RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);

        signatureValueElement.InnerText = Convert.ToBase64String(signatureValueBytes);

        return new XAdESBaselineBSignature(xml.OuterXml, signatureId, signedPropertiesId, dataObjectReferenceId, signedProperties);
    }

    public SignatureDescriptor ReadSignature(ReadOnlyMemory<byte> xmlSignature)
    {
        var xml = LoadXml(xmlSignature);
        var signedProperties = GetSignedProperties(xml);
        var signingCertificate = GetSigningCertificate(xml);

        return new SignatureDescriptor(
            SignatureFormat.XAdES,
            SignatureLevel.BaselineB,
            signingCertificate is null ? null : CreateCertificateReference(signingCertificate),
            DateTimeOffset.TryParse(signedProperties?.SigningTime, out var signingTime) ? signingTime : null,
            new ValidationMaterial(
                signingCertificate is null ? null : CreateCertificateReference(signingCertificate),
                signingCertificate is null ? Array.Empty<SigningCertificateReference>() : [CreateCertificateReference(signingCertificate)],
                Array.Empty<RevocationInfo>(),
                Array.Empty<TimestampMaterial>(),
                Array.Empty<ReadOnlyMemory<byte>>()));
    }

    public ValidationResult VerifyEnvelopedSignature(ReadOnlyMemory<byte> xmlSignature)
    {
        try
        {
            var xml = LoadXml(xmlSignature);
            var ns = CreateNamespaceManager(xml);
            var signature = xml.SelectSingleNode("/*/*[local-name()='Signature']", ns) as XmlElement;
            var signedInfo = signature?.SelectSingleNode("*[local-name()='SignedInfo']", ns) as XmlElement;
            if (signedInfo is null)
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.MalformedSignature,
                    ValidationErrorCodes.MalformedSignature,
                    "XML signature is missing SignedInfo."));
            }

            var references = signedInfo.SelectNodes("*[local-name()='Reference']")?.Cast<XmlElement>().ToArray() ?? Array.Empty<XmlElement>();
            var documentReference = references.FirstOrDefault(reference => string.IsNullOrEmpty(reference.GetAttribute("Type")));
            var signedPropertiesReference = references.FirstOrDefault(reference =>
                string.Equals(reference.GetAttribute("Type"), SignedPropertiesTypeUri, StringComparison.Ordinal));

            if (documentReference is null || signedPropertiesReference is null)
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.ReferenceResolutionFailed,
                    ValidationErrorCodes.ReferenceResolutionFailed,
                    "SignedInfo is missing required XAdES references."));
            }

            if (!ValidateReferenceDigest(documentReference, ComputeDocumentReferenceDigest(xml, ParseSuiteFromSignature(xml))))
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.HashMismatch,
                    ValidationErrorCodes.HashMismatch,
                    "Document reference digest does not match the canonicalized XML payload."));
            }

            var signedPropertiesElement = xml.SelectSingleNode("//*[local-name()='SignedProperties']", ns) as XmlElement;
            if (signedPropertiesElement is null)
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.ReferenceResolutionFailed,
                    ValidationErrorCodes.ReferenceResolutionFailed,
                    "XAdES SignedProperties element is missing."));
            }

            if (!ValidateReferenceDigest(signedPropertiesReference, ComputeSignedPropertiesDigest(signedPropertiesElement, ParseSuiteFromSignature(xml))))
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.HashMismatch,
                    ValidationErrorCodes.HashMismatch,
                    "SignedProperties reference digest does not match the canonicalized SignedProperties element."));
            }

            var signatureValue = signature.SelectSingleNode("*[local-name()='SignatureValue']", ns)?.InnerText;
            var certificate = GetSigningCertificate(xml);
            if (certificate is null || string.IsNullOrWhiteSpace(signatureValue))
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.MalformedSignature,
                    ValidationErrorCodes.MalformedSignature,
                    "Signature is missing SignatureValue or X509Certificate."));
            }

            using var rsa = certificate.GetRSAPublicKey();
            if (rsa is null)
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.UnsupportedAlgorithm,
                    ValidationErrorCodes.UnsupportedAlgorithm,
                    "Signing certificate does not expose an RSA public key."));
            }

            var suite = ParseSuiteFromSignature(xml);
            var verified = rsa.VerifyData(
                canonicalizer.Canonicalize(signedInfo),
                Convert.FromBase64String(signatureValue),
                ToHashAlgorithmName(suite.HashAlgorithm),
                suite.SignatureAlgorithm == SignatureAlgorithmIdentifier.RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);

            if (!verified)
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.SignatureValueInvalid,
                    ValidationErrorCodes.SignatureValueInvalid,
                    "XML SignatureValue verification failed."));
            }

            return ValidationResult.Success(ReadSignature(xmlSignature));
        }
        catch (XmlException ex)
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                ex.Message));
        }
    }

    private XmlElement CreateSignedPropertiesElement(XmlDocument xml, string id, XAdESSignedProperties signedProperties)
    {
        var signedPropertiesElement = xml.CreateElement("xades", "SignedProperties", XAdESNamespace);
        signedPropertiesElement.SetAttribute("Id", id);

        var signedSignatureProperties = xml.CreateElement("xades", "SignedSignatureProperties", XAdESNamespace);

        var signingTime = xml.CreateElement("xades", "SigningTime", XAdESNamespace);
        signingTime.InnerText = signedProperties.SigningTime;
        signedSignatureProperties.AppendChild(signingTime);

        var signingCertificate = xml.CreateElement("xades", "SigningCertificateV2", XAdESNamespace);
        var cert = xml.CreateElement("xades", "Cert", XAdESNamespace);
        var certDigest = xml.CreateElement("xades", "CertDigest", XAdESNamespace);
        var digestMethod = xml.CreateElement("ds", "DigestMethod", XmlDsigNamespace);
        digestMethod.SetAttribute("Algorithm", signedProperties.SigningCertificateDigestAlgorithm);
        var digestValue = xml.CreateElement("ds", "DigestValue", XmlDsigNamespace);
        digestValue.InnerText = signedProperties.SigningCertificateDigest;
        certDigest.AppendChild(digestMethod);
        certDigest.AppendChild(digestValue);
        cert.AppendChild(certDigest);

        var issuerSerial = xml.CreateElement("xades", "IssuerSerialV2", XAdESNamespace);
        issuerSerial.InnerText = $"{signedProperties.SigningCertificateIssuerName},{signedProperties.SigningCertificateSerialNumber}";
        cert.AppendChild(issuerSerial);

        signingCertificate.AppendChild(cert);
        signedSignatureProperties.AppendChild(signingCertificate);
        signedPropertiesElement.AppendChild(signedSignatureProperties);

        var signedDataObjectProperties = xml.CreateElement("xades", "SignedDataObjectProperties", XAdESNamespace);
        var dataObjectFormat = xml.CreateElement("xades", "DataObjectFormat", XAdESNamespace);
        dataObjectFormat.SetAttribute("ObjectReference", signedProperties.DataObjectReference);
        var description = xml.CreateElement("xades", "Description", XAdESNamespace);
        description.InnerText = signedProperties.DataObjectDescription;
        var mimeType = xml.CreateElement("xades", "MimeType", XAdESNamespace);
        mimeType.InnerText = signedProperties.DataObjectMimeType;
        dataObjectFormat.AppendChild(description);
        dataObjectFormat.AppendChild(mimeType);
        signedDataObjectProperties.AppendChild(dataObjectFormat);
        signedPropertiesElement.AppendChild(signedDataObjectProperties);

        return signedPropertiesElement;
    }

    private XmlElement CreateDocumentReference(XmlDocument xml, string digestMethodUri, string id)
    {
        var reference = xml.CreateElement("ds", "Reference", XmlDsigNamespace);
        reference.SetAttribute("Id", id);
        reference.SetAttribute("URI", string.Empty);

        var transforms = xml.CreateElement("ds", "Transforms", XmlDsigNamespace);
        var envelopedSignatureTransform = xml.CreateElement("ds", "Transform", XmlDsigNamespace);
        envelopedSignatureTransform.SetAttribute("Algorithm", XmlDsigEnvelopedSignatureTransformUrl);
        transforms.AppendChild(envelopedSignatureTransform);
        var canonicalizationTransform = xml.CreateElement("ds", "Transform", XmlDsigNamespace);
        canonicalizationTransform.SetAttribute("Algorithm", XmlDsigExcC14NTransformUrl);
        transforms.AppendChild(canonicalizationTransform);
        reference.AppendChild(transforms);

        var digestMethod = xml.CreateElement("ds", "DigestMethod", XmlDsigNamespace);
        digestMethod.SetAttribute("Algorithm", digestMethodUri);
        reference.AppendChild(digestMethod);

        var digestValue = xml.CreateElement("ds", "DigestValue", XmlDsigNamespace);
        reference.AppendChild(digestValue);
        return reference;
    }

    private XmlElement CreateSignedPropertiesReference(XmlDocument xml, string digestMethodUri, string signedPropertiesId)
    {
        var reference = xml.CreateElement("ds", "Reference", XmlDsigNamespace);
        reference.SetAttribute("Type", SignedPropertiesTypeUri);
        reference.SetAttribute("URI", $"#{signedPropertiesId}");

        var transforms = xml.CreateElement("ds", "Transforms", XmlDsigNamespace);
        var canonicalizationTransform = xml.CreateElement("ds", "Transform", XmlDsigNamespace);
        canonicalizationTransform.SetAttribute("Algorithm", XmlDsigExcC14NTransformUrl);
        transforms.AppendChild(canonicalizationTransform);
        reference.AppendChild(transforms);

        var digestMethod = xml.CreateElement("ds", "DigestMethod", XmlDsigNamespace);
        digestMethod.SetAttribute("Algorithm", digestMethodUri);
        reference.AppendChild(digestMethod);

        var digestValue = xml.CreateElement("ds", "DigestValue", XmlDsigNamespace);
        reference.AppendChild(digestValue);
        return reference;
    }

    private byte[] ComputeDocumentReferenceDigest(XmlDocument xml, SignatureSuite suite)
    {
        var clone = new XmlDocument { PreserveWhitespace = true };
        clone.LoadXml(xml.OuterXml);
        var signatureNode = clone.SelectSingleNode("/*/*[local-name()='Signature']");
        signatureNode?.ParentNode?.RemoveChild(signatureNode);
        var canonicalized = canonicalizer.Canonicalize(clone.DocumentElement!);
        return HashData(canonicalized, suite.HashAlgorithm);
    }

    private byte[] ComputeSignedPropertiesDigest(XmlElement signedPropertiesElement, SignatureSuite suite)
        => HashData(canonicalizer.Canonicalize(signedPropertiesElement), suite.HashAlgorithm);

    private static void SetReferenceDigest(XmlElement reference, byte[] digest)
    {
        var digestValue = reference.SelectSingleNode("*[local-name()='DigestValue']") as XmlElement;
        if (digestValue is not null)
        {
            digestValue.InnerText = Convert.ToBase64String(digest);
        }
    }

    private static bool ValidateReferenceDigest(XmlElement reference, byte[] expectedDigest)
    {
        var digestValue = reference.SelectSingleNode("*[local-name()='DigestValue']")?.InnerText;
        return string.Equals(digestValue, Convert.ToBase64String(expectedDigest), StringComparison.Ordinal);
    }

    private static void EnsureDocumentHasId(XmlElement documentElement)
    {
        if (!documentElement.HasAttribute("Id") && !documentElement.HasAttribute("ID") && !documentElement.HasAttribute("id"))
        {
            documentElement.SetAttribute("Id", $"Object-{Guid.NewGuid():N}");
        }
    }

    private static XmlDocument LoadXml(ReadOnlyMemory<byte> xmlBytes)
    {
        var xml = new XmlDocument { PreserveWhitespace = true };
        xml.LoadXml(System.Text.Encoding.UTF8.GetString(xmlBytes.Span));
        return xml;
    }

    private static XmlNamespaceManager CreateNamespaceManager(XmlDocument xml)
    {
        var ns = new XmlNamespaceManager(xml.NameTable);
        ns.AddNamespace("ds", XmlDsigNamespace);
        ns.AddNamespace("xades", XAdESNamespace);
        return ns;
    }

    private static XAdESSignedProperties? GetSignedProperties(XmlDocument xml)
    {
        var ns = CreateNamespaceManager(xml);
        var baseNode = xml.SelectSingleNode("//*[local-name()='SignedProperties']/*[local-name()='SignedSignatureProperties']", ns);
        if (baseNode is null)
        {
            return null;
        }

        var dataObjectFormat = xml.SelectSingleNode("//*[local-name()='SignedProperties']/*[local-name()='SignedDataObjectProperties']/*[local-name()='DataObjectFormat']", ns);

        return new XAdESSignedProperties(
            baseNode.SelectSingleNode("*[local-name()='SigningTime']", ns)?.InnerText ?? string.Empty,
            baseNode.SelectSingleNode("*[local-name()='SigningCertificateV2']/*[local-name()='Cert']/*[local-name()='CertDigest']/*[local-name()='DigestMethod']", ns)?.Attributes?["Algorithm"]?.Value ?? string.Empty,
            baseNode.SelectSingleNode("*[local-name()='SigningCertificateV2']/*[local-name()='Cert']/*[local-name()='CertDigest']/*[local-name()='DigestValue']", ns)?.InnerText ?? string.Empty,
            ExtractIssuerName(baseNode.SelectSingleNode("*[local-name()='SigningCertificateV2']/*[local-name()='Cert']/*[local-name()='IssuerSerialV2']", ns)?.InnerText),
            ExtractSerialNumber(baseNode.SelectSingleNode("*[local-name()='SigningCertificateV2']/*[local-name()='Cert']/*[local-name()='IssuerSerialV2']", ns)?.InnerText),
            dataObjectFormat?.Attributes?["ObjectReference"]?.Value ?? string.Empty,
            dataObjectFormat?.SelectSingleNode("*[local-name()='MimeType']", ns)?.InnerText ?? string.Empty,
            dataObjectFormat?.SelectSingleNode("*[local-name()='Description']", ns)?.InnerText ?? string.Empty);
    }

    private static X509Certificate2? GetSigningCertificate(XmlDocument xml)
    {
        var ns = CreateNamespaceManager(xml);
        var certificateText = xml.SelectSingleNode("//*[local-name()='X509Certificate']", ns)?.InnerText;
        return string.IsNullOrWhiteSpace(certificateText)
            ? null
            : X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certificateText));
    }

    private static SignatureSuite ParseSuiteFromSignature(XmlDocument xml)
    {
        var ns = CreateNamespaceManager(xml);
        var algorithm = (xml.SelectSingleNode("//*[local-name()='SignatureMethod']", ns) as XmlElement)?.GetAttribute("Algorithm");

        return algorithm switch
        {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, NamedCurve.None, true),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha384, 2048, NamedCurve.None, true),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha512, 2048, NamedCurve.None, true),
            "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1" => new SignatureSuite(SignatureAlgorithmIdentifier.RsaPss, HashAlgorithmIdentifier.Sha256, 2048, NamedCurve.None, true),
            "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1" => new SignatureSuite(SignatureAlgorithmIdentifier.RsaPss, HashAlgorithmIdentifier.Sha384, 2048, NamedCurve.None, true),
            "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1" => new SignatureSuite(SignatureAlgorithmIdentifier.RsaPss, HashAlgorithmIdentifier.Sha512, 2048, NamedCurve.None, true),
            _ => throw new NotSupportedException("Unsupported XML signature suite.")
        };
    }

    private static byte[] HashCertificate(X509Certificate2 certificate, HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => SHA256.HashData(certificate.RawData),
        HashAlgorithmIdentifier.Sha384 => SHA384.HashData(certificate.RawData),
        HashAlgorithmIdentifier.Sha512 => SHA512.HashData(certificate.RawData),
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private static byte[] HashData(byte[] data, HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => SHA256.HashData(data),
        HashAlgorithmIdentifier.Sha384 => SHA384.HashData(data),
        HashAlgorithmIdentifier.Sha512 => SHA512.HashData(data),
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private static SigningCertificateReference CreateCertificateReference(X509Certificate2 certificate) => new(
        certificate.Subject,
        certificate.Issuer,
        certificate.SerialNumber,
        certificate.Thumbprint,
        certificate.NotBefore.ToUniversalTime().ToString("O"),
        certificate.NotAfter.ToUniversalTime().ToString("O"));

    private static HashAlgorithmName ToHashAlgorithmName(HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => HashAlgorithmName.SHA256,
        HashAlgorithmIdentifier.Sha384 => HashAlgorithmName.SHA384,
        HashAlgorithmIdentifier.Sha512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private static string GetXmlDigestMethodUri(HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        HashAlgorithmIdentifier.Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        HashAlgorithmIdentifier.Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private static string GetXmlSignatureMethodUri(SignatureSuite suite) => suite.SignatureAlgorithm switch
    {
        SignatureAlgorithmIdentifier.RsaPkcs1 when suite.HashAlgorithm == HashAlgorithmIdentifier.Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        SignatureAlgorithmIdentifier.RsaPkcs1 when suite.HashAlgorithm == HashAlgorithmIdentifier.Sha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        SignatureAlgorithmIdentifier.RsaPkcs1 when suite.HashAlgorithm == HashAlgorithmIdentifier.Sha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        SignatureAlgorithmIdentifier.RsaPss when suite.HashAlgorithm == HashAlgorithmIdentifier.Sha256 => "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
        SignatureAlgorithmIdentifier.RsaPss when suite.HashAlgorithm == HashAlgorithmIdentifier.Sha384 => "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1",
        SignatureAlgorithmIdentifier.RsaPss when suite.HashAlgorithm == HashAlgorithmIdentifier.Sha512 => "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1",
        _ => throw new NotSupportedException("Unsupported XML signature suite.")
    };

    private static string NormalizeSerialNumber(string serialNumber)
        => string.IsNullOrWhiteSpace(serialNumber) ? string.Empty : System.Numerics.BigInteger.Parse($"00{serialNumber}", System.Globalization.NumberStyles.HexNumber).ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static string ExtractIssuerName(string? issuerSerialV2)
    {
        if (string.IsNullOrWhiteSpace(issuerSerialV2))
        {
            return string.Empty;
        }

        var separator = issuerSerialV2.LastIndexOf(',');
        return separator <= 0 ? issuerSerialV2 : issuerSerialV2[..separator];
    }

    private static string ExtractSerialNumber(string? issuerSerialV2)
    {
        if (string.IsNullOrWhiteSpace(issuerSerialV2))
        {
            return string.Empty;
        }

        var separator = issuerSerialV2.LastIndexOf(',');
        return separator < 0 || separator == issuerSerialV2.Length - 1 ? string.Empty : issuerSerialV2[(separator + 1)..];
    }

    private const string XmlDsigNamespace = "http://www.w3.org/2000/09/xmldsig#";
    private const string XAdESNamespace = "http://uri.etsi.org/01903/v1.3.2#";
    private const string SignedPropertiesTypeUri = "http://uri.etsi.org/01903#SignedProperties";
    private const string XmlDsigExcC14NTransformUrl = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private const string XmlDsigEnvelopedSignatureTransformUrl = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
}
