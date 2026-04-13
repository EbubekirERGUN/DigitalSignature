using System.Text.Json;

namespace DigitalSignature.Validation.Reports;

public static class ValidationReportSerializer
{
    private static readonly JsonSerializerOptions DefaultOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static string ToJson(ValidationReport report, JsonSerializerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        return JsonSerializer.Serialize(report, options ?? DefaultOptions);
    }
}
