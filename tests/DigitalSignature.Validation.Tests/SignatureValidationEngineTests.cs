using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using DigitalSignature.Validation;

namespace DigitalSignature.Validation.Tests;

public class SignatureValidationEngineTests
{
    [Fact]
    public async Task ValidateAsync_ShouldReturnIntegrityFailure_WhenIntegrityIsInvalid()
    {
        var engine = new SignatureValidationEngine(
            new StubCertificateChainValidator(_ => CertificateChainValidationResult.Success([], new CertificateTrustAnchor("CN=Root", "ROOT", ReadOnlyMemory<byte>.Empty))),
            new StubTrustAnchorProvider(_ => [new CertificateTrustAnchor("CN=Root", "ROOT", ReadOnlyMemory<byte>.Empty)]));

        var integrityFailure = ValidationResult.Failure(new ValidationFailure(
            ValidationFailureKind.HashMismatch,
            ValidationErrorCodes.HashMismatch,
            "Digest mismatch."));

        var input = SignatureValidationInput.Create(
            "payload"u8.ToArray(),
            CreateSignatureDescriptor(),
            integrityFailure,
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, null));

        var result = await engine.ValidateAsync(input);

        Assert.Equal(ValidationConclusion.Invalid, result.Conclusion);
        Assert.Contains(result.Failures, failure => failure.Code == ValidationErrorCodes.HashMismatch);
    }

    [Fact]
    public async Task ValidateAsync_ShouldFail_WhenTrustAnchorsAreMissing()
    {
        var engine = new SignatureValidationEngine(
            new StubCertificateChainValidator(_ => throw new InvalidOperationException("Chain validator should not run without anchors.")),
            new StubTrustAnchorProvider(_ => []));

        var input = SignatureValidationInput.Create(
            "payload"u8.ToArray(),
            CreateSignatureDescriptor(),
            ValidationResult.Success(CreateSignatureDescriptor()),
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));

        var result = await engine.ValidateAsync(input);

        Assert.Equal(ValidationConclusion.Invalid, result.Conclusion);
        Assert.Contains(result.Failures, failure => failure.Code == ValidationErrorCodes.TrustAnchorMissing);
    }

    [Fact]
    public async Task ValidateAsync_ShouldFail_WhenCertificateIsOutsideValidityWindow()
    {
        var engine = new SignatureValidationEngine(
            new StubCertificateChainValidator(_ => throw new InvalidOperationException("Chain validator should not run for expired certificates.")),
            new StubTrustAnchorProvider(_ => [new CertificateTrustAnchor("CN=Root", "ROOT", ReadOnlyMemory<byte>.Empty)]));

        var expiredCertificate = new SigningCertificateReference(
            "CN=Signer",
            "CN=Issuer",
            "01",
            "ABC",
            NotBefore: "2026-04-01T00:00:00Z",
            NotAfter: "2026-04-05T00:00:00Z");

        var signature = CreateSignatureDescriptor(expiredCertificate);
        var input = SignatureValidationInput.Create(
            "payload"u8.ToArray(),
            signature,
            ValidationResult.Success(signature),
            new TemporalValidationContext(
                new DateTimeOffset(2026, 4, 10, 0, 0, 0, TimeSpan.Zero),
                null,
                false,
                []));

        var result = await engine.ValidateAsync(input);

        Assert.Equal(ValidationConclusion.Invalid, result.Conclusion);
        Assert.Contains(result.Failures, failure => failure.Code == ValidationErrorCodes.CertificateExpired);
    }

    [Fact]
    public async Task ValidateAsync_ShouldFail_WhenRevocationEvidenceIsRequiredButMissing()
    {
        var engine = new SignatureValidationEngine(
            new StubCertificateChainValidator(_ => throw new InvalidOperationException("Chain validator should not run without required revocation evidence.")),
            new StubTrustAnchorProvider(_ => [new CertificateTrustAnchor("CN=Root", "ROOT", ReadOnlyMemory<byte>.Empty)]));

        var signature = CreateSignatureDescriptor();
        var input = SignatureValidationInput.Create(
            "payload"u8.ToArray(),
            signature,
            ValidationResult.Success(signature),
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));

        var result = await engine.ValidateAsync(input, new SignatureValidationOptions(RequireRevocationEvidence: true));

        Assert.Equal(ValidationConclusion.Invalid, result.Conclusion);
        Assert.Contains(result.Failures, failure => failure.Code == ValidationErrorCodes.RevocationStatusUnknown);
    }

    [Fact]
    public async Task ValidateAsync_ShouldFail_WhenRevocationEvidenceMarksCertificateAsRevoked()
    {
        var engine = new SignatureValidationEngine(
            new StubCertificateChainValidator(_ => throw new InvalidOperationException("Chain validator should not run for revoked certificates.")),
            new StubTrustAnchorProvider(_ => [new CertificateTrustAnchor("CN=Root", "ROOT", ReadOnlyMemory<byte>.Empty)]));

        var signature = CreateSignatureDescriptor(revocationInfo:
        [
            new RevocationInfo(
                "ocsp",
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddHours(1),
                true,
                DateTimeOffset.UtcNow.AddMinutes(-1),
                "KeyCompromise")
        ]);

        var input = SignatureValidationInput.Create(
            "payload"u8.ToArray(),
            signature,
            ValidationResult.Success(signature),
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));

        var result = await engine.ValidateAsync(input);

        Assert.Equal(ValidationConclusion.Invalid, result.Conclusion);
        Assert.Contains(result.Failures, failure => failure.Code == ValidationErrorCodes.CertificateRevoked);
    }

    [Fact]
    public async Task ValidateAsync_ShouldFail_WhenChainValidationFails()
    {
        var engine = new SignatureValidationEngine(
            new StubCertificateChainValidator(_ => CertificateChainValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.CertificateChainIncomplete,
                ValidationErrorCodes.CertificateChainIncomplete,
                "Missing issuer certificate."))),
            new StubTrustAnchorProvider(_ => [new CertificateTrustAnchor("CN=Root", "ROOT", ReadOnlyMemory<byte>.Empty)]));

        var input = SignatureValidationInput.Create(
            "payload"u8.ToArray(),
            CreateSignatureDescriptor(),
            ValidationResult.Success(CreateSignatureDescriptor()),
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));

        var result = await engine.ValidateAsync(input);

        Assert.Equal(ValidationConclusion.Invalid, result.Conclusion);
        Assert.Contains(result.Failures, failure => failure.Code == ValidationErrorCodes.CertificateChainIncomplete);
    }

    [Fact]
    public async Task ValidateAsync_ShouldReturnValid_WhenIntegrityAndChainChecksPass()
    {
        var anchor = new CertificateTrustAnchor("CN=Root", "ROOT", ReadOnlyMemory<byte>.Empty);
        var engine = new SignatureValidationEngine(
            new StubCertificateChainValidator(_ => CertificateChainValidationResult.Success([CreateSignatureDescriptor().SigningCertificate!], anchor)),
            new StubTrustAnchorProvider(_ => [anchor]));

        var signature = CreateSignatureDescriptor();
        var input = SignatureValidationInput.Create(
            "payload"u8.ToArray(),
            signature,
            ValidationResult.Success(signature),
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));

        var result = await engine.ValidateAsync(input);

        Assert.Equal(ValidationConclusion.Valid, result.Conclusion);
        Assert.NotNull(result.Signature);
        Assert.Equal(SignatureFormat.CAdES, result.Signature!.Format);
    }

    private static SignatureDescriptor CreateSignatureDescriptor(
        SigningCertificateReference? signingCertificate = null,
        IReadOnlyList<RevocationInfo>? revocationInfo = null)
    {
        signingCertificate ??= new SigningCertificateReference("CN=Signer", "CN=Issuer", "01", "ABC");

        return new SignatureDescriptor(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            signingCertificate,
            DateTimeOffset.UtcNow,
            new ValidationMaterial(
                signingCertificate,
                [signingCertificate],
                revocationInfo ?? [],
                [],
                []),
            SignatureAlgorithm: "1.2.840.113549.1.1.1",
            DigestAlgorithm: "2.16.840.1.101.3.4.2.1");
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
