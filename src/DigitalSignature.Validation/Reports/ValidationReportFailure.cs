namespace DigitalSignature.Validation.Reports;

public sealed record ValidationReportFailure(
    string Code,
    string Kind,
    string Message);
