using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

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
    public async Task CreateDetachedSignature_ShouldProduceCAdESBaselineTArtifact_WhenTimestampIsProvided()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=CAdES Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=CAdES Test TSA");

        var service = new CAdESBaselineBService();
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate, fixedTimestamp: DateTimeOffset.Parse("2026-04-13T18:45:00Z"));
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048,
            IsRecommended: true);
        var baselineBRequest = new SignatureRequest(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            "Hello CAdES-T"u8.ToArray(),
            MimeType: "text/plain",
            ContentTypeHint: "detached");

        var signingTime = DateTimeOffset.Parse("2026-04-13T18:30:00Z");
        var baselineBArtifact = service.CreateDetachedSignature(baselineBRequest, certificate, rsa, suite, signingTime);
        var timestampMaterial = await CreateTimestampForSignatureAsync(baselineBArtifact.Data, baselineBRequest.Payload, timestampProvider);

        var timestampedArtifact = service.CreateDetachedSignature(
            baselineBRequest with { Level = SignatureLevel.BaselineT },
            certificate,
            rsa,
            suite,
            signingTime,
            signatureTimestamp: timestampMaterial);

        var descriptor = service.ReadSignature(timestampedArtifact.Data);
        var validation = service.VerifyDetachedSignature(baselineBRequest.Payload, timestampedArtifact.Data);

        Assert.Equal(SignatureLevel.BaselineT, timestampedArtifact.Level);
        Assert.Equal(SignatureLevel.BaselineT, descriptor.Level);
        Assert.Single(descriptor.ValidationMaterial.Timestamps);
        Assert.Equal(ValidationConclusion.Valid, validation.Conclusion);
    }

    [Fact]
    public async Task CreateAttachedSignature_ShouldProduceCAdESBaselineLTArtifact_WhenValidationDataIsProvided()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=CAdES Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=CAdES Test TSA");

        var service = new CAdESBaselineBService();
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate, fixedTimestamp: DateTimeOffset.Parse("2026-04-15T18:40:00Z"));
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048);
        var request = new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, "Hello CAdES-LT"u8.ToArray());

        var signingTime = DateTimeOffset.Parse("2026-04-15T18:30:00Z");
        var baselineBArtifact = service.CreateAttachedSignature(request, certificate, rsa, suite, signingTime);
        var timestampMaterial = await CreateTimestampForAttachedSignatureAsync(baselineBArtifact.Data, timestampProvider);
        var revocationInfo = CreateCrlRevocationInfo(certificate, rsa, DateTimeOffset.Parse("2026-04-15T18:35:00Z"));

        var baselineLTArtifact = service.CreateAttachedSignature(
            request with { Level = SignatureLevel.BaselineLT },
            certificate,
            rsa,
            suite,
            signingTime,
            signatureTimestamp: timestampMaterial,
            validationCertificates: [certificate],
            revocationInfo: [revocationInfo]);

        var descriptor = service.ReadSignature(baselineLTArtifact.Data);
        var validation = service.VerifyAttachedSignature(baselineLTArtifact.Data);

        Assert.Equal(SignatureLevel.BaselineLT, baselineLTArtifact.Level);
        Assert.Equal(SignatureLevel.BaselineLT, descriptor.Level);
        Assert.NotEmpty(descriptor.ValidationMaterial.CertificateValues);
        Assert.NotEmpty(descriptor.ValidationMaterial.RevocationValues);
        Assert.Single(descriptor.ValidationMaterial.RevocationInfo);
        Assert.Equal(ValidationConclusion.Valid, validation.Conclusion);
    }

    [Fact]
    public async Task VerifyDetachedSignature_ShouldFail_WhenTimestampTokenIsModified()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=CAdES Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=CAdES Test TSA");

        var service = new CAdESBaselineBService();
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate);
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048);
        var request = new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, "payload"u8.ToArray());

        var signingTime = DateTimeOffset.Parse("2026-04-13T19:00:00Z");
        var baselineBArtifact = service.CreateDetachedSignature(request, certificate, rsa, suite, signingTime);
        var timestampMaterial = await CreateTimestampForSignatureAsync(baselineBArtifact.Data, request.Payload, timestampProvider);
        var baselineTArtifact = service.CreateDetachedSignature(request with { Level = SignatureLevel.BaselineT }, certificate, rsa, suite, signingTime, signatureTimestamp: timestampMaterial);

        var corrupted = baselineTArtifact.Data.ToArray();
        corrupted[^32] ^= 0xFF;

        var validation = service.VerifyDetachedSignature(request.Payload, corrupted);

        Assert.Equal(ValidationConclusion.Invalid, validation.Conclusion);
        Assert.Contains(validation.Failures, failure =>
            failure.Code is ValidationErrorCodes.TimestampInvalid or ValidationErrorCodes.MalformedSignature);
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

    private static async Task<TimestampMaterial> CreateTimestampForSignatureAsync(
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> payload,
        ITimestampProvider timestampProvider)
    {
        var signedCms = new SignedCms(new ContentInfo(payload.ToArray()), detached: true);
        signedCms.Decode(signature.ToArray());
        return await CreateTimestampFromSignerInfoAsync(signedCms.SignerInfos[0], timestampProvider);
    }

    private static async Task<TimestampMaterial> CreateTimestampForAttachedSignatureAsync(
        ReadOnlyMemory<byte> signature,
        ITimestampProvider timestampProvider)
    {
        var signedCms = new SignedCms();
        signedCms.Decode(signature.ToArray());
        return await CreateTimestampFromSignerInfoAsync(signedCms.SignerInfos[0], timestampProvider);
    }

    private static async Task<TimestampMaterial> CreateTimestampFromSignerInfoAsync(
        SignerInfo signerInfo,
        ITimestampProvider timestampProvider)
    {
        var timestampRequest = Rfc3161TimestampRequest.CreateFromSignerInfo(
            signerInfo,
            HashAlgorithmName.SHA256,
            null,
            null,
            true,
            null);

        var response = await timestampProvider.GetTimestampAsync(
            new TimestampRequest(
                timestampRequest.GetMessageHash(),
                timestampRequest.HashAlgorithmId.Value!,
                timestampRequest.RequestedPolicyId?.Value,
                timestampRequest.GetNonce() is { } nonce ? Convert.ToHexString(nonce.Span) : null,
                timestampRequest.RequestSignerCertificate));

        Assert.True(response.IsSuccess);
        Assert.NotNull(response.Timestamp);
        return response.Timestamp!;
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

    private static X509Certificate2 CreateTsaCertificate(RSA rsa, string subjectName)
    {
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));

        var enhancedKeyUsages = new OidCollection { new("1.3.6.1.5.5.7.3.8") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsages, true));

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
