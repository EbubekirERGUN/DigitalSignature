using DigitalSignature.Abstractions;

namespace DigitalSignature.Core.Tests;

public class ValidationResultTests
{
    [Fact]
    public void Success_ShouldProduceValidConclusion_AndNoFailures()
    {
        var result = ValidationResult.Success();

        Assert.Equal(ValidationConclusion.Valid, result.Conclusion);
        Assert.Empty(result.Failures);
        Assert.True(result.EvaluatedAt <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public void Failure_ShouldProduceInvalidConclusion_AndCarryFailures()
    {
        var failure = new ValidationFailure(
            ValidationFailureKind.HashMismatch,
            ValidationErrorCodes.HashMismatch,
            "Digest comparison failed.");

        var result = ValidationResult.Failure(failure);

        Assert.Equal(ValidationConclusion.Invalid, result.Conclusion);
        Assert.Single(result.Failures);
        Assert.Equal(ValidationErrorCodes.HashMismatch, result.Failures[0].Code);
    }

    [Fact]
    public void ValidationMaterial_Empty_ShouldNotAllocateCollectionsPerCall()
    {
        var empty = ValidationMaterial.Empty;

        Assert.Null(empty.SigningCertificate);
        Assert.Empty(empty.CertificateChain);
        Assert.Empty(empty.RevocationInfo);
        Assert.Empty(empty.Timestamps);
        Assert.Empty(empty.EvidenceRecords);
    }
}
