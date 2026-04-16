using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using DigitalSignature.XAdES;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DigitalSignature.XAdES.Tests;

public class XAdESBaselineBServiceTests
{
    [Fact]
    public void CreateEnvelopedSignature_ShouldProduceSignedProperties_AndReadableDescriptor()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=XAdES Test Signer");

        var service = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
        var request = new SignatureRequest(
            SignatureFormat.XAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("<Invoice Id=\"doc-1\"><Total>42</Total></Invoice>"),
            MimeType: "application/xml");
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048,
            IsRecommended: true);

        var signature = service.CreateEnvelopedSignature(request, certificate, rsa, suite, DateTimeOffset.Parse("2026-04-13T11:00:00Z"));
        var descriptor = service.ReadSignature(Encoding.UTF8.GetBytes(signature.XmlDocument));
        var validation = service.VerifyEnvelopedSignature(Encoding.UTF8.GetBytes(signature.XmlDocument));

        Assert.Contains("SignedProperties", signature.XmlDocument);
        Assert.Contains("CanonicalizationMethod", signature.XmlDocument);
        Assert.Contains("SigningCertificateV2", signature.XmlDocument);
        Assert.Contains("SignedDataObjectProperties", signature.XmlDocument);
        Assert.Equal(SignatureFormat.XAdES, descriptor.Format);
        Assert.Equal(SignatureLevel.BaselineB, descriptor.Level);
        Assert.NotNull(descriptor.SigningCertificate);
        Assert.Equal(certificate.Subject, descriptor.SigningCertificate!.Subject);
        Assert.Equal(ValidationConclusion.Valid, validation.Conclusion);
    }

    [Fact]
    public async Task AttachSignatureTimestamp_ShouldProduceBaselineTDescriptor_AndValidVerification()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=XAdES Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=XAdES Test TSA");

        var service = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate);
        var request = new SignatureRequest(
            SignatureFormat.XAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("<Invoice Id=\"doc-2\"><Total>84</Total></Invoice>"),
            MimeType: "application/xml");
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048,
            IsRecommended: true);

        var baselineBSignature = service.CreateEnvelopedSignature(request, certificate, rsa, suite, DateTimeOffset.Parse("2026-04-13T11:30:00Z"));
        var timestampRequest = service.CreateSignatureTimestampRequest(
            Encoding.UTF8.GetBytes(baselineBSignature.XmlDocument),
            suite.HashAlgorithm);
        var timestampResponse = await timestampProvider.GetTimestampAsync(timestampRequest);
        var baselineTSignature = service.AttachSignatureTimestamp(baselineBSignature, timestampResponse.Timestamp!);
        var descriptor = service.ReadSignature(Encoding.UTF8.GetBytes(baselineTSignature.XmlDocument));
        var validation = service.VerifyEnvelopedSignature(Encoding.UTF8.GetBytes(baselineTSignature.XmlDocument));

        Assert.True(timestampResponse.IsSuccess);
        Assert.Contains("SignatureTimeStamp", baselineTSignature.XmlDocument);
        Assert.Contains("EncapsulatedTimeStamp", baselineTSignature.XmlDocument);
        Assert.Equal(SignatureLevel.BaselineT, descriptor.Level);
        Assert.Single(descriptor.ValidationMaterial.Timestamps);
        Assert.Equal(ValidationConclusion.Valid, validation.Conclusion);
    }

    [Fact]
    public async Task AttachValidationMaterial_ShouldProduceBaselineLTDescriptor_AndValidVerification()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=XAdES Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=XAdES Test TSA");

        var service = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate);
        var request = new SignatureRequest(
            SignatureFormat.XAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("<Invoice Id=\"doc-3\"><Total>126</Total></Invoice>"),
            MimeType: "application/xml");
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048,
            IsRecommended: true);

        var baselineBSignature = service.CreateEnvelopedSignature(request, certificate, rsa, suite, DateTimeOffset.Parse("2026-04-15T11:30:00Z"));
        var timestampRequest = service.CreateSignatureTimestampRequest(
            Encoding.UTF8.GetBytes(baselineBSignature.XmlDocument),
            suite.HashAlgorithm);
        var timestampResponse = await timestampProvider.GetTimestampAsync(timestampRequest);
        var baselineTSignature = service.AttachSignatureTimestamp(baselineBSignature, timestampResponse.Timestamp!);
        var baselineLTSignature = service.AttachValidationMaterial(
            baselineTSignature,
            [certificate, tsaCertificate],
            [
                CreateCrlRevocationInfo(certificate, rsa, DateTimeOffset.Parse("2026-04-15T11:35:00Z")),
                CreateCrlRevocationInfo(tsaCertificate, tsaKey, DateTimeOffset.Parse("2026-04-15T11:36:00Z"))
            ]);
        var descriptor = service.ReadSignature(Encoding.UTF8.GetBytes(baselineLTSignature.XmlDocument));
        var validation = service.VerifyEnvelopedSignature(Encoding.UTF8.GetBytes(baselineLTSignature.XmlDocument));

        Assert.True(timestampResponse.IsSuccess);
        Assert.Contains("CertificateValues", baselineLTSignature.XmlDocument);
        Assert.Contains("RevocationValues", baselineLTSignature.XmlDocument);
        Assert.Contains("EncapsulatedX509Certificate", baselineLTSignature.XmlDocument);
        Assert.Contains("EncapsulatedCRLValue", baselineLTSignature.XmlDocument);
        Assert.Equal(SignatureLevel.BaselineLT, descriptor.Level);
        Assert.Equal(2, descriptor.ValidationMaterial.CertificateValues.Count);
        Assert.Equal(2, descriptor.ValidationMaterial.RevocationValues.Count);
        Assert.Equal(2, descriptor.ValidationMaterial.RevocationInfo.Count);
        Assert.Equal(ValidationConclusion.Valid, validation.Conclusion);
    }

    [Fact]
    public async Task AttachArchiveTimestamp_ShouldProduceBaselineLTADescriptor_AndValidVerification()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=XAdES Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=XAdES Test TSA");

        var service = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate, fixedTimestamp: DateTimeOffset.Parse("2026-04-16T09:45:00Z"));
        var request = new SignatureRequest(
            SignatureFormat.XAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("<Invoice Id=\"doc-4\"><Total>168</Total></Invoice>"),
            MimeType: "application/xml");
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048,
            IsRecommended: true);

        var baselineBSignature = service.CreateEnvelopedSignature(request, certificate, rsa, suite, DateTimeOffset.Parse("2026-04-16T09:30:00Z"));
        var timestampRequest = service.CreateSignatureTimestampRequest(
            Encoding.UTF8.GetBytes(baselineBSignature.XmlDocument),
            suite.HashAlgorithm);
        var timestampResponse = await timestampProvider.GetTimestampAsync(timestampRequest);
        var baselineTSignature = service.AttachSignatureTimestamp(baselineBSignature, timestampResponse.Timestamp!);
        var baselineLTSignature = service.AttachValidationMaterial(
            baselineTSignature,
            [certificate, tsaCertificate],
            [
                CreateCrlRevocationInfo(certificate, rsa, DateTimeOffset.Parse("2026-04-16T09:35:00Z")),
                CreateCrlRevocationInfo(tsaCertificate, tsaKey, DateTimeOffset.Parse("2026-04-16T09:36:00Z"))
            ]);
        var archiveTimestampResponse = await timestampProvider.GetTimestampAsync(
            service.CreateArchiveTimestampRequest(
                Encoding.UTF8.GetBytes(baselineLTSignature.XmlDocument),
                suite.HashAlgorithm));
        var baselineLTASignature = service.AttachArchiveTimestamp(baselineLTSignature, archiveTimestampResponse.Timestamp!);
        var descriptor = service.ReadSignature(Encoding.UTF8.GetBytes(baselineLTASignature.XmlDocument));
        var validation = service.VerifyEnvelopedSignature(Encoding.UTF8.GetBytes(baselineLTASignature.XmlDocument));

        Assert.True(archiveTimestampResponse.IsSuccess);
        Assert.Contains("ArchiveTimeStamp", baselineLTASignature.XmlDocument);
        Assert.Contains("EncapsulatedTimeStamp", baselineLTASignature.XmlDocument);
        Assert.Equal(SignatureLevel.BaselineLTA, descriptor.Level);
        Assert.Single(descriptor.ValidationMaterial.ArchiveTimestamps);
        Assert.Equal(ValidationConclusion.Valid, validation.Conclusion);
    }

    [Fact]
    public void VerifyEnvelopedSignature_ShouldFail_WhenSignedPropertiesReferenceIsMissing()
    {
        var service = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
        const string xml = "<Invoice><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /><ds:Reference URI=\"\" /></ds:SignedInfo></ds:Signature></Invoice>";

        var validation = service.VerifyEnvelopedSignature(Encoding.UTF8.GetBytes(xml));

        Assert.Equal(ValidationConclusion.Invalid, validation.Conclusion);
        Assert.Contains(validation.Failures, failure => failure.Code == ValidationErrorCodes.ReferenceResolutionFailed);
    }

    private static X509Certificate2 CreateSelfSignedCertificate(RSA rsa, string subjectName)
    {
        var request = new CertificateRequest(
            subjectName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 CreateTsaCertificate(RSA rsa, string subjectName)
    {
        var request = new CertificateRequest(
            subjectName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.8") }, true));

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static RevocationInfo CreateCrlRevocationInfo(
        X509Certificate2 certificate,
        RSA issuerKey,
        DateTimeOffset thisUpdate)
    {
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(DotNetUtilities.FromX509Certificate(certificate).SubjectDN);
        generator.SetThisUpdate(thisUpdate.UtcDateTime);
        generator.SetNextUpdate(thisUpdate.AddDays(7).UtcDateTime);

        var crl = generator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", DotNetUtilities.GetRsaKeyPair(issuerKey).Private));
        return new RevocationInfo(
            "CRL",
            thisUpdate,
            thisUpdate.AddDays(7),
            false,
            null)
        {
            EncodedValue = crl.GetEncoded()
        };
    }
}
