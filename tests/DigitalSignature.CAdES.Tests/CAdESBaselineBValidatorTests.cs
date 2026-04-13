using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;
using DigitalSignature.Validation;

namespace DigitalSignature.CAdES.Tests;

public class CAdESBaselineBValidatorTests
{
    [Fact]
    public async Task ValidateDetachedAsync_ShouldReturnIntegrityFailure_WhenPayloadIsTampered()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=CAdES Test Signer");

        var service = new CAdESBaselineBService();
        var validator = new CAdESBaselineBValidator(
            service,
            new SignatureValidationEngine(
                new StubCertificateChainValidator(_ => throw new InvalidOperationException("Chain validator should not run on integrity failure.")),
                new StubTrustAnchorProvider(_ => [new CertificateTrustAnchor("CN=Root", "ROOT", ReadOnlyMemory<byte>.Empty)])));

        var request = new SignatureRequest(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            "original payload"u8.ToArray());
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048);

        var artifact = service.CreateDetachedSignature(request, certificate, rsa, suite);
        var result = await validator.ValidateDetachedAsync(
            "tampered payload"u8.ToArray(),
            artifact.Data,
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));

        Assert.Equal(ValidationConclusion.Invalid, result.Conclusion);
        Assert.Contains(result.Failures, failure => failure.Code == ValidationErrorCodes.HashMismatch);
    }

    [Fact]
    public async Task ValidateDetachedAsync_ShouldReturnCommonValidationFailure_WhenTrustAnchorIsMissing()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=CAdES Test Signer");

        var service = new CAdESBaselineBService();
        var validator = new CAdESBaselineBValidator(
            service,
            new SignatureValidationEngine(
                new StubCertificateChainValidator(_ => throw new InvalidOperationException("Chain validator should not run without anchors.")),
                new StubTrustAnchorProvider(_ => [])));

        var request = new SignatureRequest(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            "payload"u8.ToArray());
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048);

        var artifact = service.CreateDetachedSignature(request, certificate, rsa, suite);
        var result = await validator.ValidateDetachedAsync(
            request.Payload,
            artifact.Data,
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));

        Assert.Equal(ValidationConclusion.Invalid, result.Conclusion);
        Assert.Contains(result.Failures, failure => failure.Code == ValidationErrorCodes.TrustAnchorMissing);
    }

    [Fact]
    public async Task ValidateDetachedAsync_ShouldReturnValid_WhenIntegrityAndCommonValidationPass()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=CAdES Test Signer");

        var service = new CAdESBaselineBService();
        var anchor = new CertificateTrustAnchor("CN=Root", "ROOT", ReadOnlyMemory<byte>.Empty);
        var validator = new CAdESBaselineBValidator(
            service,
            new SignatureValidationEngine(
                new StubCertificateChainValidator(request => CertificateChainValidationResult.Success([request.SigningCertificate], anchor)),
                new StubTrustAnchorProvider(_ => [anchor])));

        var request = new SignatureRequest(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            "payload"u8.ToArray());
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048);

        var artifact = service.CreateDetachedSignature(request, certificate, rsa, suite);
        var result = await validator.ValidateDetachedAsync(
            request.Payload,
            artifact.Data,
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));

        Assert.Equal(ValidationConclusion.Valid, result.Conclusion);
        Assert.NotNull(result.Signature);
        Assert.Equal(SignatureFormat.CAdES, result.Signature!.Format);
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

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));
    }

    private sealed class StubCertificateChainValidator(Func<CertificateChainValidationRequest, CertificateChainValidationResult> callback) : ICertificateChainValidator
    {
        public ValueTask<CertificateChainValidationResult> ValidateAsync(CertificateChainValidationRequest request, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(callback(request));
    }

    private sealed class StubTrustAnchorProvider(Func<(SignatureFormat format, TemporalValidationContext context), IReadOnlyList<CertificateTrustAnchor>> callback) : ITrustAnchorProvider
    {
        public ValueTask<IReadOnlyList<CertificateTrustAnchor>> GetTrustAnchorsAsync(SignatureFormat format, TemporalValidationContext temporalContext, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(callback((format, temporalContext)));
    }
}
