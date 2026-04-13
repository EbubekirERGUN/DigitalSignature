namespace DigitalSignature.Validation.Reports;

public sealed record ValidationReportSignature(
    string Format,
    string Level,
    string? Subject,
    string? Issuer,
    string? SerialNumber,
    string? SigningTime,
    string? SignatureAlgorithm,
    string? DigestAlgorithm);
