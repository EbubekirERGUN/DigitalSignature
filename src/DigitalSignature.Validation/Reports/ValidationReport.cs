using DigitalSignature.Abstractions;

namespace DigitalSignature.Validation.Reports;

public sealed record ValidationReport(
    string Profile,
    ValidationReportConclusion Conclusion,
    DateTimeOffset ProducedAt,
    ValidationReportSignature? Signature,
    IReadOnlyList<ValidationReportFailure> Failures,
    ValidationReportEvidence Evidence,
    string Summary);
