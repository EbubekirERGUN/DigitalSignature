using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;

namespace DigitalSignature.CAdES.Tests;

public class CAdESBaselineBServiceTests
{
    [Fact]
    public void CreateDetachedSignature_ShouldProduceCAdESArtifact_AndReadableDescriptor()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=CAdES Test Signer");

        var service = new CAdESBaselineBService();
        var request = new SignatureRequest(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            "Hello CAdES"u8.ToArray(),
            MimeType: "text/plain",
            ContentTypeHint: "detached");
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048,
            IsRecommended: true);

        var artifact = service.CreateDetachedSignature(request, certificate, rsa, suite, DateTimeOffset.Parse("2026-04-10T18:30:00Z"));
        var descriptor = service.ReadSignature(artifact.Data);
        var validation = service.VerifyDetachedSignature(request.Payload, artifact.Data);

        Assert.Equal(SignatureFormat.CAdES, artifact.Format);
        Assert.Equal(SignatureLevel.BaselineB, artifact.Level);
        Assert.Equal("application/pkcs7-signature", artifact.MediaType);
        Assert.NotEmpty(artifact.Data.ToArray());

        Assert.Equal(SignatureFormat.CAdES, descriptor.Format);
        Assert.Equal(SignatureLevel.BaselineB, descriptor.Level);
        Assert.NotNull(descriptor.SigningCertificate);
        Assert.Equal(certificate.Subject, descriptor.SigningCertificate!.Subject);
        Assert.Equal("1.2.840.113549.1.1.1", descriptor.SignatureAlgorithm);
        Assert.Equal("2.16.840.1.101.3.4.2.1", descriptor.DigestAlgorithm);
        Assert.Equal(ValidationConclusion.Valid, validation.Conclusion);
        Assert.Empty(validation.Failures);
    }

    [Fact]
    public void VerifyDetachedSignature_ShouldFail_WhenPayloadDigestDoesNotMatch()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=CAdES Test Signer");

        var service = new CAdESBaselineBService();
        var request = new SignatureRequest(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            "original payload"u8.ToArray());
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048);

        var artifact = service.CreateDetachedSignature(request, certificate, rsa, suite);
        var validation = service.VerifyDetachedSignature("tampered payload"u8.ToArray(), artifact.Data);

        Assert.Equal(ValidationConclusion.Invalid, validation.Conclusion);
        Assert.Contains(validation.Failures, failure =>
            failure.Code is ValidationErrorCodes.HashMismatch or ValidationErrorCodes.MalformedSignature);
    }

    [Fact]
    public void VerifyDetachedSignature_ShouldFail_WhenSignatureBytesAreModified()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=CAdES Test Signer");

        var service = new CAdESBaselineBService();
        var request = new SignatureRequest(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            "payload"u8.ToArray());
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048);

        var artifact = service.CreateDetachedSignature(request, certificate, rsa, suite);
        var corrupted = artifact.Data.ToArray();
        corrupted[^1] ^= 0xFF;

        var validation = service.VerifyDetachedSignature(request.Payload, corrupted);

        Assert.Equal(ValidationConclusion.Invalid, validation.Conclusion);
        Assert.Contains(validation.Failures, failure =>
            failure.Code is ValidationErrorCodes.MalformedSignature or ValidationErrorCodes.SignatureValueInvalid);
    }

    private static X509Certificate2 CreateSelfSignedCertificate(RSA rsa, string subjectName)
    {
        var request = new CertificateRequest(
            subjectName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));
    }
}
