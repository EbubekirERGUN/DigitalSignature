using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using DigitalSignature.JAdES;

namespace DigitalSignature.JAdES.Tests;

public class JAdESBaselineBServiceTests
{
    [Fact]
    public void Canonicalizer_ShouldSortObjectProperties()
    {
        var canonicalizer = new Rfc8785JsonCanonicalizer();
        var canonical = canonicalizer.Canonicalize(Encoding.UTF8.GetBytes("{\"b\":2,\"a\":1}"));

        Assert.Equal("{\"a\":1,\"b\":2}", canonical);
    }

    [Fact]
    public void CreateDetachedSignature_ShouldProduceCompactJws_AndReadableDescriptor()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=JAdES Test Signer");

        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var request = new SignatureRequest(
            SignatureFormat.JAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("{\"b\":2,\"a\":1}"),
            MimeType: "application/json");
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);

        var envelope = service.CreateDetachedSignature(request, certificate, rsa, suite, DateTimeOffset.Parse("2026-04-13T12:30:00Z"));
        var descriptor = service.ReadSignature(envelope.CompactSerialization);
        var validation = service.VerifyDetachedSignature(request.Payload, envelope.CompactSerialization, certificate);

        Assert.Contains('.', envelope.CompactSerialization);
        Assert.Equal("{\"a\":1,\"b\":2}", envelope.CanonicalPayload);
        Assert.Equal(SignatureFormat.JAdES, descriptor.Format);
        Assert.Equal(SignatureLevel.BaselineB, descriptor.Level);
        Assert.Equal(ValidationConclusion.Valid, validation.Conclusion);
    }

    [Fact]
    public void VerifyDetachedSignature_ShouldFail_WhenPayloadCanonicalizationDiffers()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=JAdES Test Signer");

        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var request = new SignatureRequest(
            SignatureFormat.JAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("{\"b\":2,\"a\":1}"));
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048);
        var envelope = service.CreateDetachedSignature(request, certificate, rsa, suite);

        var validation = service.VerifyDetachedSignature(Encoding.UTF8.GetBytes("{\"a\":9,\"b\":2}"), envelope.CompactSerialization, certificate);

        Assert.Equal(ValidationConclusion.Invalid, validation.Conclusion);
        Assert.Contains(validation.Failures, failure => failure.Code == ValidationErrorCodes.HashMismatch);
    }

    private static X509Certificate2 CreateSelfSignedCertificate(RSA rsa, string subjectName)
    {
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
