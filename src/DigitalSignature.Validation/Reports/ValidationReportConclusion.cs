namespace DigitalSignature.Validation.Reports;

public sealed record ValidationReportConclusion(
    string Indicator,
    bool IsSuccess,
    string? SubIndication = null);
