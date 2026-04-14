using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using DigitalSignature.XAdES;

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
}
