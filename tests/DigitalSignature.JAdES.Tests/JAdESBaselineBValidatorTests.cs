using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using DigitalSignature.JAdES;
using DigitalSignature.Validation;

namespace DigitalSignature.JAdES.Tests;

public class JAdESBaselineBValidatorTests
{
    [Fact]
    public async Task ValidateDetachedAsync_ShouldExposeJAdESMetadata_OnIntegrityFailure()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=JAdES Validation Signer");

        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var validator = new JAdESBaselineBValidator(
            service,
            new SignatureValidationEngine(
                new StubCertificateChainValidator(),
                new StubTrustAnchorProvider()));

        var request = new SignatureRequest(SignatureFormat.JAdES, SignatureLevel.BaselineB, Encoding.UTF8.GetBytes("{}"));
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048);
        var envelope = service.CreateDetachedSignature(request, certificate, rsa, suite);

        var result = await validator.ValidateDetachedAsync(
            Encoding.UTF8.GetBytes("{\"tampered\":true}"),
            envelope.CompactSerialization,
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, null),
            certificate);

        Assert.True(result.HasTypHeader);
        Assert.False(result.HasCanonicalizationClaim);
        Assert.Equal("RS256", result.Algorithm);
        Assert.Equal(ValidationConclusion.Invalid, result.Validation.Conclusion);
    }

    [Fact]
    public async Task ValidateDetachedAsync_ShouldReturnTrustedValidation_WhenIntegrityAndTrustChecksPass()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=JAdES Validation Signer");

        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var validator = new JAdESBaselineBValidator(
            service,
            new SignatureValidationEngine(
                new StubCertificateChainValidator(certificate),
                new StubTrustAnchorProvider(certificate)));

        var request = new SignatureRequest(SignatureFormat.JAdES, SignatureLevel.BaselineB, Encoding.UTF8.GetBytes("{\"b\":2,\"a\":1}"));
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048);
        var envelope = service.CreateDetachedSignature(request, certificate, rsa, suite);

        var result = await validator.ValidateDetachedAsync(
            request.Payload,
            envelope.CompactSerialization,
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, null),
            certificate);

        Assert.Equal(ValidationConclusion.Valid, result.Validation.Conclusion);
        Assert.True(result.HasTypHeader);
        Assert.False(result.HasCanonicalizationClaim);
    }

    [Fact]
    public async Task ValidateDetachedJsonAsync_ShouldExposeJAdESMetadata_OnIntegrityFailure()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=JAdES Validation Signer");

        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var validator = new JAdESBaselineBValidator(
            service,
            new SignatureValidationEngine(
                new StubCertificateChainValidator(),
                new StubTrustAnchorProvider()));

        var request = new SignatureRequest(SignatureFormat.JAdES, SignatureLevel.BaselineB, Encoding.UTF8.GetBytes("{}"));
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048);
        var envelope = service.CreateDetachedJsonSignature(request, certificate, rsa, suite);

        var result = await validator.ValidateDetachedJsonAsync(
            Encoding.UTF8.GetBytes("{\"tampered\":true}"),
            envelope.JsonDocument,
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, null),
            certificate);

        Assert.True(result.HasTypHeader);
        Assert.False(result.HasCanonicalizationClaim);
        Assert.Equal("RS256", result.Algorithm);
        Assert.Equal(ValidationConclusion.Invalid, result.Validation.Conclusion);
    }

    [Fact]
    public async Task ValidateDetachedJsonAsync_ShouldReturnTrustedValidation_WhenIntegrityAndTrustChecksPass()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=JAdES Validation Signer");

        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var validator = new JAdESBaselineBValidator(
            service,
            new SignatureValidationEngine(
                new StubCertificateChainValidator(certificate),
                new StubTrustAnchorProvider(certificate)));

        var request = new SignatureRequest(SignatureFormat.JAdES, SignatureLevel.BaselineB, Encoding.UTF8.GetBytes("{\"b\":2,\"a\":1}"));
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048);
        var envelope = service.CreateDetachedJsonSignature(request, certificate, rsa, suite);

        var result = await validator.ValidateDetachedJsonAsync(
            request.Payload,
            envelope.JsonDocument,
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, null),
            certificate);

        Assert.Equal(ValidationConclusion.Valid, result.Validation.Conclusion);
        Assert.True(result.HasTypHeader);
        Assert.False(result.HasCanonicalizationClaim);
        Assert.Equal(SignatureLevel.BaselineB, result.Validation.Signature?.Level);
    }

    private static X509Certificate2 CreateSelfSignedCertificate(RSA rsa, string subjectName)
    {
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private sealed class StubTrustAnchorProvider(params X509Certificate2[] anchors) : ITrustAnchorProvider
    {
        public ValueTask<IReadOnlyList<CertificateTrustAnchor>> GetTrustAnchorsAsync(SignatureFormat format, TemporalValidationContext temporalContext, CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IReadOnlyList<CertificateTrustAnchor>>(anchors.Select(anchor => new CertificateTrustAnchor(anchor.Subject, anchor.Thumbprint, anchor.RawData)).ToArray());
    }

    private sealed class StubCertificateChainValidator(X509Certificate2? trustedCertificate = null) : ICertificateChainValidator
    {
        public ValueTask<CertificateChainValidationResult> ValidateAsync(CertificateChainValidationRequest request, CancellationToken cancellationToken = default)
        {
            if (trustedCertificate is null)
            {
                return ValueTask.FromResult(CertificateChainValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.TrustAnchorMissing,
                    ValidationErrorCodes.TrustAnchorMissing,
                    "No trust anchors configured for test.")));
            }

            var trustAnchor = new CertificateTrustAnchor(trustedCertificate.Subject, trustedCertificate.Thumbprint, trustedCertificate.RawData);
            var chain = new[]
            {
                request.SigningCertificate,
                new SigningCertificateReference(
                    trustedCertificate.Subject,
                    trustedCertificate.Issuer,
                    trustedCertificate.SerialNumber,
                    trustedCertificate.Thumbprint,
                    trustedCertificate.NotBefore.ToUniversalTime().ToString("O"),
                    trustedCertificate.NotAfter.ToUniversalTime().ToString("O"))
            };

            return ValueTask.FromResult(CertificateChainValidationResult.Success(chain, trustAnchor));
        }
    }
}
