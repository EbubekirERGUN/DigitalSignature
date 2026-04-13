using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.ASiC.Tests;

public class ASiCSBaselineBServiceTests
{
    [Fact]
    public void CreateContainer_ShouldProduceASiCSArtifact_AndVerifySuccessfully()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=ASiC Test Signer");

        var service = new DigitalSignature.ASiC.ASiCSBaselineBService();
        var request = new SignatureRequest(
            SignatureFormat.ASiC,
            SignatureLevel.BaselineB,
            "Hello ASiC"u8.ToArray(),
            MimeType: "text/plain");
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048,
            IsRecommended: true);

        var artifact = service.CreateContainer(request, "document.txt", certificate, rsa, suite);
        var verification = service.VerifyContainer(artifact.Container.Data);

        Assert.Equal(SignatureFormat.ASiC, artifact.Container.Format);
        Assert.Equal(SignatureLevel.BaselineB, artifact.Container.Level);
        Assert.Equal(DigitalSignature.ASiC.ASiCSBaselineBService.ContainerMediaType, artifact.Container.MediaType);
        Assert.Equal(ValidationConclusion.Valid, verification.Validation.Conclusion);
        Assert.True(verification.HasMimeTypeFile);
        Assert.True(verification.MimeTypeMatchesContainer);
        Assert.True(verification.IsMimeTypeFileFirst);
        Assert.True(verification.IsMimeTypeFileStored);
        Assert.True(verification.HasSignatureFile);
        Assert.True(verification.HasSinglePayloadFile);
        Assert.Equal("document.txt", verification.PayloadEntryName);
        Assert.Equal("META-INF/signature.p7s", verification.SignatureEntryName);

        using var archive = new ZipArchive(new MemoryStream(artifact.Container.Data.ToArray()), ZipArchiveMode.Read);
        Assert.NotNull(archive.GetEntry("mimetype"));
        Assert.NotNull(archive.GetEntry("document.txt"));
        Assert.NotNull(archive.GetEntry("META-INF/signature.p7s"));
    }

    [Fact]
    public async Task CreateContainer_ShouldProduceBaselineTArtifact_WhenTimestampIsProvided()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=ASiC Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=ASiC Test TSA");

        var service = new DigitalSignature.ASiC.ASiCSBaselineBService();
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate, fixedTimestamp: DateTimeOffset.Parse("2026-04-13T20:30:00Z"));
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);
        var payload = "Hello ASiC-T"u8.ToArray();
        var baselineBRequest = new SignatureRequest(SignatureFormat.ASiC, SignatureLevel.BaselineB, payload, MimeType: "text/plain");

        var baselineBArtifact = service.CreateContainer(baselineBRequest, "document.txt", certificate, rsa, suite);
        var timestamp = await CreateTimestampForContainerSignatureAsync(baselineBArtifact.Container.Data, payload, timestampProvider);

        var baselineTArtifact = service.CreateContainer(
            baselineBRequest with { Level = SignatureLevel.BaselineT },
            "document.txt",
            certificate,
            rsa,
            suite,
            signatureTimestamp: timestamp);

        var verification = service.VerifyContainer(baselineTArtifact.Container.Data);

        Assert.Equal(SignatureLevel.BaselineT, baselineTArtifact.Container.Level);
        Assert.Equal(ValidationConclusion.Valid, verification.Validation.Conclusion);
        Assert.NotNull(verification.Validation.Signature);
        Assert.Equal(SignatureLevel.BaselineT, verification.Validation.Signature!.Level);
        Assert.Single(verification.Validation.Signature.ValidationMaterial.Timestamps);
    }

    [Fact]
    public void VerifyContainer_ShouldFail_WhenPayloadDoesNotMatchSignature()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=ASiC Test Signer");

        var service = new DigitalSignature.ASiC.ASiCSBaselineBService();
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048,
            IsRecommended: true);

        var validArtifact = service.CreateContainer(
            new SignatureRequest(SignatureFormat.ASiC, SignatureLevel.BaselineB, "original payload"u8.ToArray()),
            "document.txt",
            certificate,
            rsa,
            suite);

        var tamperedArtifact = service.CreateContainer(
            new SignatureRequest(SignatureFormat.ASiC, SignatureLevel.BaselineB, "tampered payload"u8.ToArray()),
            "document.txt",
            certificate,
            rsa,
            suite);

        var replacedSignatureContainer = ReplaceSignature(validArtifact.Container.Data.ToArray(), tamperedArtifact.Container.Data.ToArray());
        var verification = service.VerifyContainer(replacedSignatureContainer);

        Assert.Equal(ValidationConclusion.Invalid, verification.Validation.Conclusion);
        Assert.Contains(verification.Validation.Failures, failure =>
            failure.Code is ValidationErrorCodes.HashMismatch or ValidationErrorCodes.MalformedSignature);
    }

    [Fact]
    public void CreateContainer_ShouldRejectMetaInfPayloadEntryName()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=ASiC Test Signer");

        var service = new DigitalSignature.ASiC.ASiCSBaselineBService();
        var request = new SignatureRequest(SignatureFormat.ASiC, SignatureLevel.BaselineB, "payload"u8.ToArray());
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048);

        var exception = Assert.Throws<ArgumentException>(() =>
            service.CreateContainer(request, "META-INF/document.txt", certificate, rsa, suite));

        Assert.Contains("root-level filename", exception.Message);
    }

    private static async Task<TimestampMaterial> CreateTimestampForContainerSignatureAsync(
        ReadOnlyMemory<byte> containerBytes,
        ReadOnlyMemory<byte> payload,
        ITimestampProvider timestampProvider)
    {
        using var archive = new ZipArchive(new MemoryStream(containerBytes.ToArray()), ZipArchiveMode.Read);
        var signatureEntry = archive.GetEntry("META-INF/signature.p7s")!;
        using var source = signatureEntry.Open();
        using var ms = new MemoryStream();
        await source.CopyToAsync(ms);

        var signedCms = new SignedCms(new ContentInfo(payload.ToArray()), detached: true);
        signedCms.Decode(ms.ToArray());
        var timestampRequest = Rfc3161TimestampRequest.CreateFromSignerInfo(
            signedCms.SignerInfos[0],
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

    private static byte[] ReplaceSignature(byte[] containerWithPayload, byte[] containerWithDesiredSignature)
    {
        using var payloadArchive = new ZipArchive(new MemoryStream(containerWithPayload), ZipArchiveMode.Read);
        using var signatureArchive = new ZipArchive(new MemoryStream(containerWithDesiredSignature), ZipArchiveMode.Read);

        using var output = new MemoryStream();
        using var target = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true);

        CopyEntry(payloadArchive, target, "mimetype");
        CopyEntry(payloadArchive, target, "document.txt");
        CopyEntry(signatureArchive, target, "META-INF/signature.p7s");

        target.Dispose();
        return output.ToArray();
    }

    private static void CopyEntry(ZipArchive sourceArchive, ZipArchive targetArchive, string name)
    {
        var sourceEntry = sourceArchive.GetEntry(name) ?? throw new InvalidOperationException($"Entry '{name}' was not found.");
        var targetEntry = targetArchive.CreateEntry(name, CompressionLevel.NoCompression);

        using var source = sourceEntry.Open();
        using var target = targetEntry.Open();
        source.CopyTo(target);
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
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));

        var enhancedKeyUsages = new OidCollection { new("1.3.6.1.5.5.7.3.8") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsages, true));

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
