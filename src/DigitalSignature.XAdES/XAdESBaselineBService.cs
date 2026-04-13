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
        var signedPropertiesId = $"xades-props-{Guid.NewGuid():N}";
        var digestAlgorithmUri = GetXmlDigestMethodUri(suite.HashAlgorithm);
        var certificateDigest = Convert.ToBase64String(HashCertificate(signingCertificate, suite.HashAlgorithm));

        var signedProperties = new XAdESSignedProperties(
            signingMoment.UtcDateTime.ToString("O"),
            digestAlgorithmUri,
            certificateDigest,
            signingCertificate.Issuer,
            signingCertificate.SerialNumber);

        var signatureElement = xml.CreateElement("ds", "Signature", XmlDsigNamespace);
        var signedInfoElement = xml.CreateElement("ds", "SignedInfo", XmlDsigNamespace);
        var canonicalizationMethod = xml.CreateElement("ds", "CanonicalizationMethod", XmlDsigNamespace);
        canonicalizationMethod.SetAttribute("Algorithm", XmlDsigExcC14NTransformUrl);
        signedInfoElement.AppendChild(canonicalizationMethod);

        var signatureMethod = xml.CreateElement("ds", "SignatureMethod", XmlDsigNamespace);
        signatureMethod.SetAttribute("Algorithm", GetXmlSignatureMethodUri(suite));
        signedInfoElement.AppendChild(signatureMethod);

        signedInfoElement.AppendChild(CreateReference(xml, string.Empty, digestAlgorithmUri, "", enveloped: true));
        signedInfoElement.AppendChild(CreateReference(xml, $"#{signedPropertiesId}", digestAlgorithmUri, SignedPropertiesTypeUri, enveloped: false));

        signatureElement.AppendChild(signedInfoElement);

        var canonicalizedSignedInfo = canonicalizer.Canonicalize(signedInfoElement);
        var signatureValueBytes = privateKey.SignData(
            canonicalizedSignedInfo,
            ToHashAlgorithmName(suite.HashAlgorithm),
            suite.SignatureAlgorithm == SignatureAlgorithmIdentifier.RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);

        var signatureValueElement = xml.CreateElement("ds", "SignatureValue", XmlDsigNamespace);
        signatureValueElement.InnerText = Convert.ToBase64String(signatureValueBytes);
        signatureElement.AppendChild(signatureValueElement);

        var keyInfo = xml.CreateElement("ds", "KeyInfo", XmlDsigNamespace);
        var x509Data = xml.CreateElement("ds", "X509Data", XmlDsigNamespace);
        var x509Certificate = xml.CreateElement("ds", "X509Certificate", XmlDsigNamespace);
        x509Certificate.InnerText = Convert.ToBase64String(signingCertificate.RawData);
        x509Data.AppendChild(x509Certificate);
        keyInfo.AppendChild(x509Data);
        signatureElement.AppendChild(keyInfo);

        var objectElement = xml.CreateElement("ds", "Object", XmlDsigNamespace);
        var qualifyingProperties = xml.CreateElement("xades", "QualifyingProperties", XAdESNamespace);
        qualifyingProperties.SetAttribute("Target", "#Signature");
        var signedPropertiesElement = CreateSignedPropertiesElement(xml, signedPropertiesId, signedProperties);
        qualifyingProperties.AppendChild(signedPropertiesElement);
        objectElement.AppendChild(qualifyingProperties);
        signatureElement.AppendChild(objectElement);

        xml.DocumentElement!.AppendChild(signatureElement);

        return new XAdESBaselineBSignature(xml.OuterXml, signedPropertiesId, signedProperties);
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
            var signedInfo = (XmlElement?)xml.SelectSingleNode("/*/*[local-name()='Signature']/*[local-name()='SignedInfo']", ns);
            if (signedInfo is null)
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.MalformedSignature,
                    ValidationErrorCodes.MalformedSignature,
                    "XML signature is missing SignedInfo."));
            }

            var canonicalizationMethod = signedInfo.SelectSingleNode("*[local-name()='CanonicalizationMethod']") as XmlElement;
            if (canonicalizationMethod is null)
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.CanonicalizationInvalid,
                    ValidationErrorCodes.CanonicalizationInvalid,
                    "SignedInfo is missing CanonicalizationMethod."));
            }

            var references = signedInfo.SelectNodes("*[local-name()='Reference']")?.Cast<XmlElement>().ToArray() ?? Array.Empty<XmlElement>();
            var signedPropertiesReference = references.FirstOrDefault(reference =>
                string.Equals(reference.GetAttribute("Type"), SignedPropertiesTypeUri, StringComparison.Ordinal));

            if (signedPropertiesReference is null)
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.ReferenceResolutionFailed,
                    ValidationErrorCodes.ReferenceResolutionFailed,
                    "SignedInfo is missing the XAdES SignedProperties reference."));
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

        var signingCertificate = xml.CreateElement("xades", "SigningCertificate", XAdESNamespace);
        var cert = xml.CreateElement("xades", "Cert", XAdESNamespace);
        var certDigest = xml.CreateElement("xades", "CertDigest", XAdESNamespace);
        var digestMethod = xml.CreateElement("ds", "DigestMethod", XmlDsigNamespace);
        digestMethod.SetAttribute("Algorithm", signedProperties.SigningCertificateDigestAlgorithm);
        var digestValue = xml.CreateElement("ds", "DigestValue", XmlDsigNamespace);
        digestValue.InnerText = signedProperties.SigningCertificateDigest;
        certDigest.AppendChild(digestMethod);
        certDigest.AppendChild(digestValue);
        cert.AppendChild(certDigest);

        var issuerSerial = xml.CreateElement("xades", "IssuerSerial", XAdESNamespace);
        var issuerName = xml.CreateElement("ds", "X509IssuerName", XmlDsigNamespace);
        issuerName.InnerText = signedProperties.SigningCertificateIssuerName;
        var serialNumber = xml.CreateElement("ds", "X509SerialNumber", XmlDsigNamespace);
        serialNumber.InnerText = signedProperties.SigningCertificateSerialNumber;
        issuerSerial.AppendChild(issuerName);
        issuerSerial.AppendChild(serialNumber);
        cert.AppendChild(issuerSerial);

        signingCertificate.AppendChild(cert);
        signedSignatureProperties.AppendChild(signingCertificate);
        signedPropertiesElement.AppendChild(signedSignatureProperties);

        return signedPropertiesElement;
    }

    private XmlElement CreateReference(XmlDocument xml, string uri, string digestMethodUri, string type, bool enveloped)
    {
        var reference = xml.CreateElement("ds", "Reference", XmlDsigNamespace);
        if (!string.IsNullOrEmpty(uri))
        {
            reference.SetAttribute("URI", uri);
        }

        if (!string.IsNullOrEmpty(type))
        {
            reference.SetAttribute("Type", type);
        }

        var transforms = xml.CreateElement("ds", "Transforms", XmlDsigNamespace);
        if (enveloped)
        {
            var envelopedSignatureTransform = xml.CreateElement("ds", "Transform", XmlDsigNamespace);
            envelopedSignatureTransform.SetAttribute("Algorithm", XmlDsigEnvelopedSignatureTransformUrl);
            transforms.AppendChild(envelopedSignatureTransform);
        }

        var canonicalizationTransform = xml.CreateElement("ds", "Transform", XmlDsigNamespace);
        canonicalizationTransform.SetAttribute("Algorithm", XmlDsigExcC14NTransformUrl);
        transforms.AppendChild(canonicalizationTransform);
        reference.AppendChild(transforms);

        var digestMethod = xml.CreateElement("ds", "DigestMethod", XmlDsigNamespace);
        digestMethod.SetAttribute("Algorithm", digestMethodUri);
        reference.AppendChild(digestMethod);

        var digestValue = xml.CreateElement("ds", "DigestValue", XmlDsigNamespace);
        digestValue.InnerText = "PENDING";
        reference.AppendChild(digestValue);

        return reference;
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

        return new XAdESSignedProperties(
            baseNode.SelectSingleNode("*[local-name()='SigningTime']", ns)?.InnerText ?? string.Empty,
            baseNode.SelectSingleNode("*[local-name()='SigningCertificate']/*[local-name()='Cert']/*[local-name()='CertDigest']/*[local-name()='DigestMethod']", ns)?.Attributes?["Algorithm"]?.Value ?? string.Empty,
            baseNode.SelectSingleNode("*[local-name()='SigningCertificate']/*[local-name()='Cert']/*[local-name()='CertDigest']/*[local-name()='DigestValue']", ns)?.InnerText ?? string.Empty,
            baseNode.SelectSingleNode("*[local-name()='SigningCertificate']/*[local-name()='Cert']/*[local-name()='IssuerSerial']/*[local-name()='X509IssuerName']", ns)?.InnerText ?? string.Empty,
            baseNode.SelectSingleNode("*[local-name()='SigningCertificate']/*[local-name()='Cert']/*[local-name()='IssuerSerial']/*[local-name()='X509SerialNumber']", ns)?.InnerText ?? string.Empty);
    }

    private static X509Certificate2? GetSigningCertificate(XmlDocument xml)
    {
        var ns = CreateNamespaceManager(xml);
        var certificateText = xml.SelectSingleNode("//*[local-name()='X509Certificate']", ns)?.InnerText;
        return string.IsNullOrWhiteSpace(certificateText)
            ? null
            : X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certificateText));
    }

    private static byte[] HashCertificate(X509Certificate2 certificate, HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => SHA256.HashData(certificate.RawData),
        HashAlgorithmIdentifier.Sha384 => SHA384.HashData(certificate.RawData),
        HashAlgorithmIdentifier.Sha512 => SHA512.HashData(certificate.RawData),
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

    private const string XmlDsigNamespace = "http://www.w3.org/2000/09/xmldsig#";
    private const string XAdESNamespace = "http://uri.etsi.org/01903/v1.3.2#";
    private const string SignedPropertiesTypeUri = "http://uri.etsi.org/01903#SignedProperties";
    private const string XmlDsigExcC14NTransformUrl = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private const string XmlDsigEnvelopedSignatureTransformUrl = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
}
