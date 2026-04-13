using DigitalSignature.Abstractions;

namespace DigitalSignature.Validation.Reports;

public static class ValidationReportSummaryBuilder
{
    public static string Build(ValidationResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        if (result.Conclusion == ValidationConclusion.Valid)
        {
            var format = result.Signature?.Format.ToString() ?? "Unknown";
            var level = result.Signature?.Level.ToString() ?? "Unknown";
            return $"Validation succeeded for {format} at {level}.";
        }

        if (result.Failures.Count == 0)
        {
            return "Validation completed without success, but no explicit failure details were recorded.";
        }

        var codes = string.Join(", ", result.Failures.Select(static failure => failure.Code));
        return $"Validation failed with {result.Failures.Count} issue(s): {codes}.";
    }
}
