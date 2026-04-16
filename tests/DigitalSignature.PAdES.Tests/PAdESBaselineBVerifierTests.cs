using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;
using DigitalSignature.PAdES;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DigitalSignature.PAdES.Tests;

public class PAdESBaselineBVerifierTests
{
    [Fact]
    public void Verify_ShouldReturnSuccess_WhenPAdESDetachedSubFilterExists()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=PAdES Test Signer");

        var service = new PAdESBaselineBService();
        var verifier = new PAdESBaselineBVerifier();
        var cadesService = new CAdESBaselineBService();
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");
        var binding = service.PrepareDetachedSignaturePlaceholder(pdf, 8192);
        var prepared = service.PrepareDetachedSignatureInput(binding);
        var cms = cadesService.CreateDetachedSignature(new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, prepared.SignedBytes), certificate, rsa, suite, includeSigningTime: false);
        var signed = service.ApplyDetachedSignature(prepared, cms.Data);

        var result = verifier.Verify(signed);

        Assert.Equal(ValidationConclusion.Valid, result.Validation.Conclusion);
        Assert.True(result.HasDetachedCAdESSignature);
        Assert.NotNull(result.Placeholder);
        Assert.Equal(SignatureFormat.PAdES, result.Validation.Signature!.Format);
        Assert.Equal(SignatureLevel.BaselineB, result.Validation.Signature.Level);
    }

    [Fact]
    public async Task Verify_ShouldReadBaselineTLevel_FromEmbeddedCadesSignature()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=PAdES Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=PAdES Test TSA");

        var padesService = new PAdESBaselineBService();
        var verifier = new PAdESBaselineBVerifier();
        var cadesService = new CAdESBaselineBService();
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate, fixedTimestamp: DateTimeOffset.Parse("2026-04-13T20:45:00Z"));
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");

        var binding = padesService.PrepareDetachedSignaturePlaceholder(pdf, 8192);
        var prepared = padesService.PrepareDetachedSignatureInput(binding);
        var signingTime = DateTimeOffset.Parse("2026-04-13T20:15:00Z");
        var baselineBSignature = cadesService.CreateDetachedSignature(new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, prepared.SignedBytes), certificate, rsa, suite, signingTime, includeSigningTime: false);
        var timestamp = await CreateTimestampForSignerInfoAsync(prepared.SignedBytes, baselineBSignature.Data, timestampProvider);
        var baselineTSignature = cadesService.CreateDetachedSignature(
            new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineT, prepared.SignedBytes),
            certificate,
            rsa,
            suite,
            signingTime,
            signatureTimestamp: timestamp,
            includeSigningTime: false);
        var signedPdf = padesService.ApplyDetachedSignature(prepared, baselineTSignature.Data);

        var result = verifier.Verify(signedPdf);

        Assert.Equal(ValidationConclusion.Valid, result.Validation.Conclusion);
        Assert.True(result.HasDetachedCAdESSignature);
        Assert.NotNull(result.Validation.Signature);
        Assert.Equal(SignatureLevel.BaselineT, result.Validation.Signature!.Level);
        Assert.Single(result.Validation.Signature.ValidationMaterial.Timestamps);
    }

    [Fact]
    public async Task Verify_ShouldReadBaselineLTLevel_FromPdfDss()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=PAdES Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=PAdES Test TSA");

        var padesService = new PAdESBaselineBService();
        var verifier = new PAdESBaselineBVerifier();
        var cadesService = new CAdESBaselineBService();
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate, fixedTimestamp: DateTimeOffset.UtcNow.AddMinutes(-5));
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");

        var binding = padesService.PrepareDetachedSignaturePlaceholder(pdf, 8192);
        var prepared = padesService.PrepareDetachedSignatureInput(binding);
        var signingTime = DateTimeOffset.UtcNow.AddMinutes(-10);
        var baselineBSignature = cadesService.CreateDetachedSignature(new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, prepared.SignedBytes), certificate, rsa, suite, signingTime, includeSigningTime: false);
        var timestamp = await CreateTimestampForSignerInfoAsync(prepared.SignedBytes, baselineBSignature.Data, timestampProvider);
        var baselineTSignature = cadesService.CreateDetachedSignature(
            new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineT, prepared.SignedBytes),
            certificate,
            rsa,
            suite,
            signingTime,
            signatureTimestamp: timestamp,
            includeSigningTime: false);
        var baselineTPdf = padesService.ApplyDetachedSignature(prepared, baselineTSignature.Data);
        var baselineLtPdf = padesService.AugmentToBaselineLT(
            baselineTPdf,
            [
                CreateCrlRevocationInfo(certificate, rsa, DateTimeOffset.UtcNow.AddMinutes(-8)),
                CreateCrlRevocationInfo(tsaCertificate, tsaKey, DateTimeOffset.UtcNow.AddMinutes(-7))
            ],
            [certificate, tsaCertificate]);

        var result = verifier.Verify(baselineLtPdf);

        Assert.Equal(ValidationConclusion.Valid, result.Validation.Conclusion);
        Assert.True(result.HasDetachedCAdESSignature);
        Assert.NotNull(result.Validation.Signature);
        Assert.Equal(SignatureLevel.BaselineLT, result.Validation.Signature!.Level);
        Assert.NotEmpty(result.Validation.Signature.ValidationMaterial.CertificateValues);
        Assert.NotEmpty(result.Validation.Signature.ValidationMaterial.RevocationValues);
        Assert.NotEmpty(result.Validation.Signature.ValidationMaterial.RevocationInfo);
    }

    [Fact]
    public async Task Verify_ShouldReadBaselineLTALevel_FromDocumentTimestamp()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=PAdES Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=PAdES Test TSA");

        var padesService = new PAdESBaselineBService();
        var verifier = new PAdESBaselineBVerifier();
        var cadesService = new CAdESBaselineBService();
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate, fixedTimestamp: DateTimeOffset.Parse("2026-04-16T10:45:00Z"));
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");

        var binding = padesService.PrepareDetachedSignaturePlaceholder(pdf, 8192);
        var prepared = padesService.PrepareDetachedSignatureInput(binding);
        var signingTime = DateTimeOffset.Parse("2026-04-16T10:15:00Z");
        var baselineBSignature = cadesService.CreateDetachedSignature(new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, prepared.SignedBytes), certificate, rsa, suite, signingTime, includeSigningTime: false);
        var signatureTimestamp = await CreateTimestampForSignerInfoAsync(prepared.SignedBytes, baselineBSignature.Data, timestampProvider);
        var baselineTSignature = cadesService.CreateDetachedSignature(
            new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineT, prepared.SignedBytes),
            certificate,
            rsa,
            suite,
            signingTime,
            signatureTimestamp: signatureTimestamp,
            includeSigningTime: false);
        var baselineTPdf = padesService.ApplyDetachedSignature(prepared, baselineTSignature.Data);
        var baselineLtPdf = padesService.AugmentToBaselineLT(
            baselineTPdf,
            [
                CreateCrlRevocationInfo(certificate, rsa, DateTimeOffset.Parse("2026-04-16T10:20:00Z")),
                CreateCrlRevocationInfo(tsaCertificate, tsaKey, DateTimeOffset.Parse("2026-04-16T10:21:00Z"))
            ],
            [certificate, tsaCertificate]);

        var documentTimestampInput = padesService.PrepareDocumentTimestampInput(baselineLtPdf, 8192);
        var documentTimestampResponse = await timestampProvider.GetTimestampAsync(
            padesService.CreateDocumentTimestampRequest(documentTimestampInput, suite.HashAlgorithm));
        Assert.True(documentTimestampResponse.IsSuccess);
        Assert.NotNull(documentTimestampResponse.Timestamp);

        var baselineLtaPdf = padesService.ApplyDocumentTimestamp(documentTimestampInput, documentTimestampResponse.Timestamp!);
        var result = verifier.Verify(baselineLtaPdf);

        Assert.Equal(ValidationConclusion.Valid, result.Validation.Conclusion);
        Assert.True(result.HasDetachedCAdESSignature);
        Assert.NotNull(result.Validation.Signature);
        Assert.Equal(SignatureLevel.BaselineLTA, result.Validation.Signature!.Level);
        Assert.Single(result.Validation.Signature.ValidationMaterial.ArchiveTimestamps);
    }

    [Fact]
    public void Verify_ShouldFail_WhenPdfDoesNotContainSignaturePlaceholder()
    {
        var verifier = new PAdESBaselineBVerifier();
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\nplain-content\n%%EOF");

        var result = verifier.Verify(pdf);

        Assert.Equal(ValidationConclusion.Invalid, result.Validation.Conclusion);
        Assert.Contains(result.Validation.Failures, failure => failure.Code == ValidationErrorCodes.MalformedSignature);
    }

    private static async Task<TimestampMaterial> CreateTimestampForSignerInfoAsync(
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signature,
        ITimestampProvider timestampProvider)
    {
        var signedCms = new SignedCms(new ContentInfo(payload.ToArray()), detached: true);
        signedCms.Decode(signature.ToArray());
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
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
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
