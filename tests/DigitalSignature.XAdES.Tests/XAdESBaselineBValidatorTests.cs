using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using DigitalSignature.Validation;
using DigitalSignature.XAdES;

namespace DigitalSignature.XAdES.Tests;

public class XAdESBaselineBValidatorTests
{
    [Fact]
    public async Task ValidateAsync_ShouldExposeCanonicalizationMetadata_OnIntegrityFailure()
    {
        var service = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
        var validator = new XAdESBaselineBValidator(
            service,
            new SignatureValidationEngine(
                new StubCertificateChainValidator(),
                new StubTrustAnchorProvider()));

        const string xml = "<Invoice><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></ds:SignedInfo></ds:Signature></Invoice>";

        var result = await validator.ValidateAsync(
            Encoding.UTF8.GetBytes(xml),
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, null));

        Assert.False(result.HasSignedPropertiesReference);
        Assert.True(result.HasCanonicalizationMethod);
        Assert.Equal("http://www.w3.org/2001/10/xml-exc-c14n#", result.CanonicalizationMethod);
        Assert.Equal(ValidationConclusion.Invalid, result.Validation.Conclusion);
    }

    [Fact]
    public async Task ValidateAsync_ShouldReturnTrustedValidation_WhenIntegrityAndTrustChecksPass()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=XAdES Validation Signer");

        var service = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
        var validator = new XAdESBaselineBValidator(
            service,
            new SignatureValidationEngine(
                new StubCertificateChainValidator(certificate),
                new StubTrustAnchorProvider(certificate)));

        var request = new SignatureRequest(
            SignatureFormat.XAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("<Invoice Id=\"doc-2\"><Total>84</Total></Invoice>"));
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048);
        var signature = service.CreateEnvelopedSignature(request, certificate, rsa, suite);

        var result = await validator.ValidateAsync(
            Encoding.UTF8.GetBytes(signature.XmlDocument),
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, null));

        Assert.Equal(ValidationConclusion.Valid, result.Validation.Conclusion);
        Assert.True(result.HasSignedPropertiesReference);
        Assert.True(result.HasCanonicalizationMethod);
    }

    [Fact]
    public async Task ValidateAsync_ShouldReturnBaselineT_WhenSignatureTimestampIsPresentAndTrusted()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=XAdES Validation Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=XAdES Validation TSA");

        var service = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
        var validator = new XAdESBaselineBValidator(
            service,
            new SignatureValidationEngine(
                new StubCertificateChainValidator(certificate),
                new StubTrustAnchorProvider(certificate)));
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate);

        var request = new SignatureRequest(
            SignatureFormat.XAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("<Invoice Id=\"doc-3\"><Total>126</Total></Invoice>"),
            MimeType: "application/xml");
        var suite = new SignatureSuite(
            SignatureAlgorithmIdentifier.RsaPkcs1,
            HashAlgorithmIdentifier.Sha256,
            2048);
        var baselineBSignature = service.CreateEnvelopedSignature(request, certificate, rsa, suite);
        var timestampResponse = await timestampProvider.GetTimestampAsync(
            service.CreateSignatureTimestampRequest(
                Encoding.UTF8.GetBytes(baselineBSignature.XmlDocument),
                suite.HashAlgorithm));
        var baselineTSignature = service.AttachSignatureTimestamp(baselineBSignature, timestampResponse.Timestamp!);

        var result = await validator.ValidateAsync(
            Encoding.UTF8.GetBytes(baselineTSignature.XmlDocument),
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, null));

        Assert.True(timestampResponse.IsSuccess);
        Assert.Equal(ValidationConclusion.Valid, result.Validation.Conclusion);
        Assert.NotNull(result.Validation.Signature);
        Assert.Equal(SignatureLevel.BaselineT, result.Validation.Signature!.Level);
        Assert.Single(result.Validation.Signature.ValidationMaterial.Timestamps);
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
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.8") }, true));
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

            var trustAnchor = new CertificateTrustAnchor(
                trustedCertificate.Subject,
                trustedCertificate.Thumbprint,
                trustedCertificate.RawData);

            return ValueTask.FromResult(CertificateChainValidationResult.Success(chain, trustAnchor));
        }
    }
}
