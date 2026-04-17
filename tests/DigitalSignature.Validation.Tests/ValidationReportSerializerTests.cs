using DigitalSignature.Abstractions;
using DigitalSignature.Validation.Reports;

namespace DigitalSignature.Validation.Tests;

public class ValidationReportSerializerTests
{
    [Fact]
    public void ToJson_ShouldSerializeReport_WithReadableShape()
    {
        var report = ValidationReportMapper.Map(ValidationResult.Failure(
            new ValidationFailure(
                ValidationFailureKind.TimestampInvalid,
                ValidationErrorCodes.TimestampInvalid,
                "Timestamp material was invalid.")));

        var json = ValidationReportSerializer.ToJson(report);

        Assert.Contains("TOTAL_FAILED", json, StringComparison.Ordinal);
        Assert.Contains("timestamp_invalid", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("summary", json, StringComparison.OrdinalIgnoreCase);
    }
}
