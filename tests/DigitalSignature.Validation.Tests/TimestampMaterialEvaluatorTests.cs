using DigitalSignature.Abstractions;
using DigitalSignature.Validation;

namespace DigitalSignature.Validation.Tests;

public class TimestampMaterialEvaluatorTests
{
    [Fact]
    public void Evaluate_ShouldPass_WhenTimestampIsNotRequired_AndNoneExists()
    {
        var result = TimestampMaterialEvaluator.Evaluate([], new TimestampValidationOptions());

        Assert.True(result.IsValid);
        Assert.Empty(result.Failures);
    }

    [Fact]
    public void Evaluate_ShouldFail_WhenTimestampIsRequired_ButMissing()
    {
        var result = TimestampMaterialEvaluator.Evaluate([], new TimestampValidationOptions(RequireTimestamp: true));

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, failure => failure.Code == ValidationErrorCodes.TimestampInvalid);
    }

    [Fact]
    public void Evaluate_ShouldFail_WhenTimestampTokenIsEmpty()
    {
        TimestampMaterial[] timestamps =
        [
            new TimestampMaterial(ReadOnlyMemory<byte>.Empty, DateTimeOffset.UtcNow, "1.2.3", "SHA-256")
        ];

        var result = TimestampMaterialEvaluator.Evaluate(timestamps, new TimestampValidationOptions());

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, failure => failure.Code == ValidationErrorCodes.TimestampInvalid);
    }
}
